package api

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/coord"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/testutil/vklocal"
)

// Empty hints (internal/coord.EmptyHints) against a real Valkey: the store
// is skipped for known-empty mailboxes, and no message is ever missed.

func hintFixture(t *testing.T, mut func(*config.Config)) (*fixture, *coord.Client) {
	addr := vklocal.Addr(t)
	vc, err := coord.Open(context.Background(), coord.Config{Addr: addr, Prefix: vklocal.Prefix()}, metrics.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vc.Close)
	f := newFixtureWith(t, mut, func(f *fixture) []Option {
		return []Option{WithEmptyHints(vc.EmptyHints(nil, f.cfg.EmptySkipMax, metrics.New()))}
	})
	return f, vc
}

// counter reads one metric from the fixture's registry.
func (f *fixture) counter(name string) int64 {
	var b bytes.Buffer
	f.reg.WriteTo(&b)
	for _, line := range strings.Split(b.String(), "\n") {
		if v, ok := strings.CutPrefix(line, name+" "); ok {
			var n int64
			fmt.Sscan(v, &n)
			return n
		}
	}
	return -1
}

func TestEmptyHintsSkipAndNeverMiss(t *testing.T) {
	f, _ := hintFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)

	for i := 0; i < 4; i++ {
		if got := f.collect(owner, ""); len(got.Messages) != 0 {
			t.Fatal("empty")
		}
	}
	if q, s := f.counter("relay_collect_store_queries_total"), f.counter("relay_collect_store_skips_total"); q != 1 || s != 3 {
		t.Fatalf("queries=%d skips=%d, want 1 and 3", q, s)
	}
	// A deposit through the API bumps the version: the next collect queries.
	id := f.mustDeposit(owner, sender, tok, []byte("x"))
	if got := f.collect(owner, ""); len(got.Messages) != 1 || got.Messages[0].MsgID != id {
		t.Fatalf("deposit after an empty finding was missed: %+v", got)
	}
	f.ack(owner, id)

	// A long-poll parked on a known-empty mailbox (it skipped the store) is
	// woken by a deposit and delivers it.
	f.collect(owner, "") // re-establish the empty finding
	before := f.counter("relay_collect_store_skips_total")
	done := make(chan collectResp, 1)
	go func() { done <- f.collect(owner, "?wait=10") }()
	waitFor(t, func() bool { return f.counter("relay_collect_store_skips_total") > before })
	start := time.Now()
	id2 := f.mustDeposit(owner, sender, tok, []byte("y"))
	select {
	case got := <-done:
		if len(got.Messages) != 1 || got.Messages[0].MsgID != id2 {
			t.Fatalf("parked collector got %+v", got)
		}
		if time.Since(start) > time.Second {
			t.Fatalf("wake latency %v", time.Since(start))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("skipping long-poll not woken by the deposit")
	}
}

// Deposits racing collectors: every message is delivered, however the
// version reads, store queries and hint writes interleave.
func TestEmptyHintsDepositRace(t *testing.T) {
	f, _ := hintFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	const n = 30
	got := map[string]bool{}
	stop := make(chan struct{})
	res := make(chan collectResp, 1000)
	go func() {
		for {
			select {
			case <-stop:
				close(res)
				return
			default:
			}
			r := f.collect(owner, "?wait=1")
			res <- r
		}
	}()
	var ids []string
	for i := 0; i < n; i++ {
		ids = append(ids, f.mustDeposit(owner, sender, tok, []byte{byte(i)}))
		time.Sleep(time.Duration(i%4) * time.Millisecond)
	}
	deadline := time.After(10 * time.Second)
	for len(got) < n {
		select {
		case r := <-res:
			for _, m := range r.Messages {
				got[m.MsgID] = true
				f.ack(owner, m.MsgID)
			}
		case <-deadline:
			t.Fatalf("delivered %d of %d", len(got), n)
		}
	}
	close(stop)
	for _, id := range ids {
		if !got[id] {
			t.Fatalf("missed %s", id)
		}
	}
}

// A leased, unacked message reappears after the visibility timeout even
// though the mailbox looked empty meanwhile: the empty finding is trusted
// only until the lease can expire.
func TestEmptyHintsLeaseExpiryRedelivery(t *testing.T) {
	f, _ := hintFixture(t, func(c *config.Config) { c.VisibilityTimeout = time.Second })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	id := f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("x"))
	if got := f.collect(owner, ""); len(got.Messages) != 1 {
		t.Fatal("first delivery")
	}
	if got := f.collect(owner, ""); len(got.Messages) != 0 {
		t.Fatal("leased")
	}
	if got := f.collect(owner, ""); len(got.Messages) != 0 { // skipped
		t.Fatal("leased")
	}
	if f.counter("relay_collect_store_skips_total") < 1 {
		t.Fatal("expected a skip while the lease is outstanding")
	}
	time.Sleep(1100 * time.Millisecond) // the hint's validity runs on Valkey's clock
	f.clk.add(1100 * time.Millisecond)  // the lease on the store's
	if got := f.collect(owner, ""); len(got.Messages) != 1 || got.Messages[0].MsgID != id {
		t.Fatalf("unacked message not redelivered after its lease: %+v", got)
	}
	// A long-poll parked across the lease expiry is woken for it too.
	done := make(chan collectResp, 1)
	go func() { done <- f.collect(owner, "?wait=10") }()
	time.Sleep(200 * time.Millisecond)
	f.clk.add(1100 * time.Millisecond)
	select {
	case got := <-done:
		if len(got.Messages) != 1 {
			t.Fatalf("%+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parked collector missed the redelivery")
	}
}

// If a deposit's bump is lost (process died between store commit and
// Valkey), the message is hidden at most until the empty finding expires
// (RELAY_EMPTY_SKIP_MAX) — and at once after any forced re-check.
func TestEmptyHintsLostBumpIsBounded(t *testing.T) {
	f, _ := hintFixture(t, func(c *config.Config) { c.EmptySkipMax = time.Second })
	owner := newPrincipal(1)
	f.register(owner)
	f.collect(owner, "") // empty finding
	// Deposit straight into the store: no bump, no wake.
	m, err := f.st.Deposit(context.Background(), owner.mbx, "s", []byte("x"), time.Hour, store.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.collect(owner, ""); len(got.Messages) != 0 {
		t.Fatal("expected the stale finding to be trusted (this is the bounded case)")
	}
	waitFor(t, func() bool { // within EmptySkipMax (1 s)
		got := f.collect(owner, "")
		return len(got.Messages) == 1 && got.Messages[0].MsgID == m.ID
	})

	// WakeAll (resubscribe, Valkey outage) forces a real query at once.
	f.ack(owner, m.ID)
	f.cfg.EmptySkipMax = time.Hour
	f.restart()
	f.collect(owner, "")
	m2, _ := f.st.Deposit(context.Background(), owner.mbx, "s", []byte("y"), time.Hour, store.Limits{})
	done := make(chan collectResp, 1)
	go func() { done <- f.collect(owner, "?wait=10") }()
	time.Sleep(200 * time.Millisecond)
	f.s.WakeAll()
	select {
	case got := <-done:
		if len(got.Messages) != 1 || got.Messages[0].MsgID != m2.ID {
			t.Fatalf("%+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WakeAll did not force a real query")
	}
}

// With Valkey gone every collect queries the store: nothing is missed.
func TestEmptyHintsValkeyDown(t *testing.T) {
	f, vc := hintFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	f.collect(owner, "")
	f.collect(owner, "") // skipped
	vc.Close()
	id := f.mustDeposit(owner, sender, tok, []byte("x")) // bump fails; deposit still 201
	q := f.counter("relay_collect_store_queries_total")
	if got := f.collect(owner, ""); len(got.Messages) != 1 || got.Messages[0].MsgID != id {
		t.Fatalf("Valkey down: %+v", got)
	}
	if f.counter("relay_collect_store_queries_total") != q+1 {
		t.Fatal("must query the store when hints are unavailable")
	}
}
