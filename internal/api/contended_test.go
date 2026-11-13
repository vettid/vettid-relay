package api

import (
	"context"
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

// A collect the store answers ErrContended is not taken for an empty
// mailbox: no empty finding is recorded, a wait=0 collect answers empty
// without an error, and a waiting one tries again and gets the message.
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
	cs.mu.Lock()
	cs.n = 1
	cs.mu.Unlock()
	if got := f.collect(owner, ""); len(got.Messages) != 0 {
		t.Fatalf("%+v", got)
	}
	cs.mu.Lock()
	cs.n = 2
	cs.mu.Unlock()
	start := time.Now()
	got := f.collect(owner, "?wait=5")
	if len(got.Messages) != 1 || got.Messages[0].MsgID != m.ID || time.Since(start) > 2*time.Second {
		t.Fatalf("%+v after %v", got, time.Since(start))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.marked != 0 {
		t.Fatalf("%d empty findings recorded after a contended collect", h.marked)
	}
}
