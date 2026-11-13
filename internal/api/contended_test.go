package api

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/store"
)

// contendedStore reports ErrContended for its first n collects: other
// collectors won every candidate it tried, with more waiting.
type contendedStore struct {
	store.Backend
	mu sync.Mutex
	n  int
}

func (c *contendedStore) take() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n > 0 {
		c.n--
		return true
	}
	return false
}

func (c *contendedStore) CollectRange(ctx context.Context, mailbox, after, upTo string, max int, visibility time.Duration) ([]store.Message, time.Time, error) {
	if c.take() {
		return nil, time.Time{}, store.ErrContended
	}
	return c.Backend.CollectRange(ctx, mailbox, after, upTo, max, visibility)
}

func (c *contendedStore) Collect(ctx context.Context, mailbox string, max int, visibility time.Duration) ([]store.Message, time.Time, error) {
	if c.take() {
		return nil, time.Time{}, store.ErrContended
	}
	return c.Backend.Collect(ctx, mailbox, max, visibility)
}

// recordingHints is an EmptyHints that never reports empty and records
// the findings it is told.
type recordingHints struct {
	mu     sync.Mutex
	marked int
}

func (h *recordingHints) Bump(context.Context, string) error { return nil }
func (h *recordingHints) Check(context.Context, string) (string, time.Duration, error) {
	return "v", 0, nil
}
func (h *recordingHints) MarkEmpty(context.Context, string, string, time.Duration) {
	h.mu.Lock()
	h.marked++
	h.mu.Unlock()
}
func (h *recordingHints) Clear(context.Context, string) {}

// A collect the store answers ErrContended is never answered empty
// (RELAY-PROTOCOL §6.3): a wait=0 collect tries again and gets the
// message, or answers rate_limited once its budget is spent; a waiting
// one gets the message; no empty finding is recorded.
func TestCollectContendedNotEmpty(t *testing.T) {
	h := &recordingHints{}
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithEmptyHints(h)} })
	cs, inner := &contendedStore{}, f.newSt
	f.newSt = func() store.Backend { cs.Backend = inner(); return cs }
	f.restart()
	owner := newPrincipal(1)
	f.register(owner)
	m, err := f.st.Deposit(context.Background(), owner.mbx, "s", []byte("x"), time.Hour, store.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	set := func(n int) { cs.mu.Lock(); cs.n = n; cs.mu.Unlock() }
	set(1)
	if got := f.collect(owner, ""); len(got.Messages) != 1 || got.Messages[0].MsgID != m.ID {
		t.Fatalf("wait=0 after one contended walk: %+v", got)
	}
	f.ack(owner, m.ID)
	m2, _ := f.st.Deposit(context.Background(), owner.mbx, "s", []byte("y"), time.Hour, store.Limits{})
	set(1000)
	code, b := f.do(req{method: "GET", path: "/v1/mailbox", signer: &owner})
	if code != 429 || !strings.Contains(string(b), CodeRateLimited) {
		t.Fatalf("wait=0 still contended: %d %s", code, b)
	}
	set(2)
	start := time.Now()
	got := f.collect(owner, "?wait=5")
	if len(got.Messages) != 1 || got.Messages[0].MsgID != m2.ID || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v after %v", got, time.Since(start))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.marked != 0 {
		t.Fatalf("%d empty findings recorded after a contended collect", h.marked)
	}
	if f.counter("relay_collect_contended_total") < 3 {
		t.Fatalf("contended counted %d", f.counter("relay_collect_contended_total"))
	}
}

// failingStore fails every collect with a store error (not contention).
type failingStore struct{ store.Backend }

func (failingStore) Collect(context.Context, string, int, time.Duration) ([]store.Message, time.Time, error) {
	return nil, time.Time{}, errors.New("store down")
}

// A collect the store fails is a 5xx, never an empty answer.
func TestCollectStoreErrorNotEmpty(t *testing.T) {
	f := newFixture(t, nil)
	inner := f.newSt
	f.newSt = func() store.Backend { return failingStore{inner()} }
	f.restart()
	owner := newPrincipal(1)
	f.register(owner)
	if code, b := f.do(req{method: "GET", path: "/v1/mailbox", signer: &owner}); code < 500 {
		t.Fatalf("%d %s", code, b)
	}
}

func TestContendedBackoff(t *testing.T) {
	for n, want := range []time.Duration{50, 100, 200, 400, 800, 1000, 1000} {
		want *= time.Millisecond
		if d := contendedBackoff(n); d < want/2 || d > want {
			t.Fatalf("backoff %d: %v, want %v/2..%v", n, d, want, want)
		}
	}
}

// A WebSocket session whose lease attempts are contended keeps going: the
// first delivery and a resend after the lease ends both arrive, and the
// session is not closed.
func TestWebSocketContended(t *testing.T) {
	f := newFixture(t, nil)
	cs, inner := &contendedStore{}, f.newSt
	f.newSt = func() store.Backend { cs.Backend = inner(); return cs }
	f.restart()
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	cs.mu.Lock()
	cs.n = 2
	cs.mu.Unlock()
	id := f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("x"))
	if m := readFrame(t, c, 3*time.Second); m.MsgID != id {
		t.Fatal("first delivery")
	}
	// Not acked: the resend goes through the range path, contended once.
	cs.mu.Lock()
	cs.n = 1
	cs.mu.Unlock()
	f.clk.add(f.cfg.VisibilityTimeout + time.Second)
	f.s.hub.notify(owner.mbx)
	if m := readFrame(t, c, 3*time.Second); m.MsgID != id {
		t.Fatal("unacked message not redelivered under contention")
	}
	if f.counter("relay_collect_contended_total") < 3 {
		t.Fatalf("contended counted %d", f.counter("relay_collect_contended_total"))
	}
}

// emptyHints always reports the mailbox empty: only a forced re-read
// reaches the store.
type emptyHints struct{ recordingHints }

func (*emptyHints) Check(context.Context, string) (string, time.Duration, error) {
	return "v", time.Hour, nil
}

// A forced re-read (WakeAll) whose attempt is contended stays forced: the
// retry reads the store and finds the message, rather than trusting the
// empty finding until the poll's deadline.
func TestForcedReadSurvivesContention(t *testing.T) {
	h := &emptyHints{}
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithEmptyHints(h)} })
	cs, inner := &contendedStore{}, f.newSt
	f.newSt = func() store.Backend { cs.Backend = inner(); return cs }
	f.restart()
	owner := newPrincipal(1)
	f.register(owner)
	done := make(chan collectResp, 1)
	go func() { done <- f.collect(owner, "?wait=10") }()
	time.Sleep(200 * time.Millisecond) // parked, skipping the store
	m, err := f.st.Deposit(context.Background(), owner.mbx, "s", []byte("x"), time.Hour, store.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	cs.n = 1
	cs.mu.Unlock()
	f.s.WakeAll()
	select {
	case got := <-done:
		if len(got.Messages) != 1 || got.Messages[0].MsgID != m.ID {
			t.Fatalf("%+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the forced re-read was spent by a contended attempt")
	}
}

// The same on a WebSocket session.
func TestWebSocketForcedReadSurvivesContention(t *testing.T) {
	h := &emptyHints{}
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithEmptyHints(h)} })
	cs, inner := &contendedStore{}, f.newSt
	f.newSt = func() store.Backend { cs.Backend = inner(); return cs }
	f.restart()
	owner := newPrincipal(1)
	f.register(owner)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	time.Sleep(200 * time.Millisecond) // the session skips the store
	m, err := f.st.Deposit(context.Background(), owner.mbx, "s", []byte("x"), time.Hour, store.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	cs.mu.Lock()
	cs.n = 1
	cs.mu.Unlock()
	f.s.WakeAll()
	if got := readFrame(t, c, 3*time.Second); got.MsgID != m.ID {
		t.Fatalf("%+v", got)
	}
}
