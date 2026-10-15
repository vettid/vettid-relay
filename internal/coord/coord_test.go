package coord_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/coord"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/testutil/vklocal"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// open returns n clients (n "relay processes") on one Valkey namespace.
func open(t *testing.T, n int) []*coord.Client {
	addr := vklocal.Addr(t)
	prefix := vklocal.Prefix()
	var out []*coord.Client
	for i := 0; i < n; i++ {
		c, err := coord.Open(context.Background(), coord.Config{Addr: addr, Prefix: prefix}, metrics.New())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		out = append(out, c)
	}
	return out
}

func signed(t *testing.T, now time.Time) auth.SignedRequest {
	_, k, _ := ed25519.GenerateKey(nil)
	sig := ed25519.Sign(k, []byte(now.String()))
	return auth.SignedRequest{Key: k.Public().(ed25519.PublicKey), Sig: sig, Time: now}
}

func TestReplayAcrossProcesses(t *testing.T) {
	cs := open(t, 2)
	a, b := cs[0].ReplayGuard(), cs[1].ReplayGuard()
	now := time.Now()
	sr := signed(t, now)
	if err := a.Check(sr, now); err != nil {
		t.Fatal(err)
	}
	if err := b.Check(sr, now); !errors.Is(err, auth.ErrReplay) {
		t.Fatalf("replay on the other process: %v", err)
	}
	if err := a.Check(signed(t, now), now); err != nil {
		t.Fatal("a different request must pass:", err)
	}
	// Concurrent first use: exactly one wins.
	sr2 := signed(t, now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		g := a
		if i%2 == 1 {
			g = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.Check(sr2, now) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d admissions", ok)
	}
}

func TestReplayShedsWhenUnavailable(t *testing.T) {
	c := open(t, 1)[0]
	g := c.ReplayGuard()
	c.Close()
	if err := g.Check(signed(t, time.Now()), time.Now()); !errors.Is(err, auth.ErrReplayCacheFull) {
		t.Fatalf("want shed, got %v", err)
	}
}

func TestLimiterShared(t *testing.T) {
	cs := open(t, 2)
	a, b := cs[0].Limiter("ip", 1, 4), cs[1].Limiter("ip", 1, 4)
	now := time.Now()
	allowed := 0
	for i := 0; i < 8; i++ {
		l := a
		if i%2 == 1 {
			l = b
		}
		if ok, _ := l.Allow("203.0.113.7", now); ok {
			allowed++
		}
	}
	if allowed != 4 {
		t.Fatalf("burst 4 across two processes admitted %d", allowed)
	}
	ok, wait := a.Allow("203.0.113.7", now)
	if ok || wait < time.Second {
		t.Fatalf("refusal: %v %v", ok, wait)
	}
	if p := a.Peak(); p != 1 {
		t.Fatalf("peak after a refusal: %v", p)
	}
	b.Peak()
	if ok, _ := b.Allow("198.51.100.1", now); !ok {
		t.Fatal("other keys are independent")
	}
	if p := b.Peak(); p != 0.25 {
		t.Fatalf("peak after one of four: %v", p)
	}
	time.Sleep(1100 * time.Millisecond) // one token refills (Valkey's clock)
	if ok, _ := b.Allow("203.0.113.7", time.Now()); !ok {
		t.Fatal("refill")
	}
}

func TestLimiterFallsBackLocally(t *testing.T) {
	c := open(t, 1)[0]
	l := c.Limiter("ip", 1, 2)
	c.Close()
	now := time.Now()
	a, _ := l.Allow("k", now)
	b, _ := l.Allow("k", now)
	d, _ := l.Allow("k", now)
	if !a || !b || d {
		t.Fatalf("local fallback: %v %v %v", a, b, d)
	}
}

type waker struct {
	mu  sync.Mutex
	got []string
	all int
	ch  chan string
}

func (w *waker) Wake(mb string) { w.mu.Lock(); w.got = append(w.got, mb); w.mu.Unlock(); w.ch <- mb }
func (w *waker) WakeAll()       { w.mu.Lock(); w.all++; w.mu.Unlock() }
func (w *waker) MailboxGone(mb string) {
	w.mu.Lock()
	w.got = append(w.got, "gone:"+mb)
	w.mu.Unlock()
	w.ch <- "gone:" + mb
}

func TestWakeAcrossProcesses(t *testing.T) {
	cs := open(t, 2)
	wa, wb := &waker{ch: make(chan string, 10)}, &waker{ch: make(chan string, 10)}
	ba, bb := cs[0].NewWakeBus(metrics.New()), cs[1].NewWakeBus(metrics.New())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ba.Start(ctx, wa)
	bb.Start(ctx, wb)
	t.Cleanup(ba.Stop)
	t.Cleanup(bb.Stop)
	start := time.Now()
	ba.Publish("mbx1")
	select {
	case mb := <-wb.ch:
		if mb != "mbx1" {
			t.Fatal(mb)
		}
		t.Logf("cross-process wake latency %v", time.Since(start))
	case <-time.After(2 * time.Second):
		t.Fatal("no wake on the other process")
	}
	select {
	case mb := <-wa.ch:
		t.Fatalf("publisher woke itself for %s", mb)
	case <-time.After(200 * time.Millisecond):
	}
	// A deletion signal (0.5.0) reaches the other process as such.
	ba.PublishGone("mbx2")
	select {
	case mb := <-wb.ch:
		if mb != "gone:mbx2" {
			t.Fatalf("deletion signal arrived as %q", mb)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no deletion signal on the other process")
	}
	wb.mu.Lock()
	defer wb.mu.Unlock()
	if wb.all < 1 {
		t.Fatal("subscription must trigger a WakeAll re-check")
	}
}

func TestEmptyHintsVersioning(t *testing.T) {
	c := open(t, 2)
	a, b := c[0].EmptyHints(nil, time.Minute, metrics.New()), c[1].EmptyHints(nil, time.Minute, metrics.New())
	ctx := context.Background()
	v, left, err := a.Check(ctx, "mbx")
	if err != nil || left != 0 || v != "0" {
		t.Fatalf("fresh: %q %v %v", v, left, err)
	}
	// A deposit (on another process) bumps between the check and the mark:
	// the stale finding is refused.
	if err := b.Bump(ctx, "mbx"); err != nil {
		t.Fatal(err)
	}
	a.MarkEmpty(ctx, "mbx", v, time.Minute)
	if _, left, _ := b.Check(ctx, "mbx"); left != 0 {
		t.Fatal("a finding older than a deposit must not be trusted")
	}
	// Check → mark with the current version: trusted, on every process.
	v, _, _ = a.Check(ctx, "mbx")
	a.MarkEmpty(ctx, "mbx", v, time.Minute)
	if _, left, _ := b.Check(ctx, "mbx"); left <= 50*time.Second {
		t.Fatalf("trusted for %v", left)
	}
	// A deposit invalidates it; Clear does too.
	b.Bump(ctx, "mbx")
	if _, left, _ := a.Check(ctx, "mbx"); left != 0 {
		t.Fatal("bump must invalidate")
	}
	v, _, _ = a.Check(ctx, "mbx")
	a.MarkEmpty(ctx, "mbx", v, time.Minute)
	a.Clear(ctx, "mbx")
	if _, left, _ := a.Check(ctx, "mbx"); left != 0 {
		t.Fatal("clear must invalidate")
	}
	// Validity is capped by MaxSkip and expires.
	v, _, _ = a.Check(ctx, "mbx")
	a.MarkEmpty(ctx, "mbx", v, 300*time.Millisecond)
	if _, left, _ := a.Check(ctx, "mbx"); left <= 0 || left > 300*time.Millisecond {
		t.Fatalf("left %v", left)
	}
	time.Sleep(350 * time.Millisecond)
	if _, left, _ := a.Check(ctx, "mbx"); left != 0 {
		t.Fatal("expired finding still trusted")
	}
	// Valkey unreachable: errors, never a skip.
	c[0].Close()
	if _, left, err := a.Check(ctx, "mbx"); err == nil || left != 0 {
		t.Fatalf("down: %v %v", left, err)
	}
}

// The byte ceilings (§7.2 limits 11 and 12) are one bucket per network for
// every process: two processes together cannot take more than its burst,
// even charging concurrently.
func TestByteLimiterShared(t *testing.T) {
	cs := open(t, 2)
	// 1 byte/s: nothing measurable refills while the test runs.
	a, b := cs[0].ByteLimiter("bytes", 1, 10_000), cs[1].ByteLimiter("bytes", 1, 10_000)
	if a.Burst() != 10_000 {
		t.Fatal(a.Burst())
	}
	now := time.Now()
	const net = "203.0.113.7"
	if ok, _ := a.AllowN(net, 6_000, now); !ok {
		t.Fatal("first charge")
	}
	ok, wait := b.AllowN(net, 6_000, now)
	if ok || wait < 1000*time.Second { // 2,000 bytes short at 1 byte/s
		t.Fatalf("over the shared burst on the other process: %v %v", ok, wait)
	}
	if ok, _ := b.AllowN(net, 4_000, now); !ok {
		t.Fatal("the rest of the burst, on the other process")
	}
	if p := a.Peak(); p != 0.6 {
		t.Fatalf("peak on a: %v", p)
	}
	if p := b.Peak(); p != 1 {
		t.Fatalf("peak on b after a refusal: %v", p)
	}
	if ok, _ := a.AllowN("198.51.100.1", 10_000, now); !ok {
		t.Fatal("other networks are independent")
	}
	if ok, wait := a.AllowN("192.0.2.9", 10_001, now); ok || wait < time.Second {
		t.Fatalf("more than the burst: %v %v", ok, wait)
	}

	// Concurrent charges from both processes: exactly the burst.
	var wg sync.WaitGroup
	var mu sync.Mutex
	took := 0
	for i := 0; i < 40; i++ {
		l := a
		if i%2 == 1 {
			l = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := l.AllowN("192.0.2.1", 500, time.Now()); ok {
				mu.Lock()
				took += 500
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if took != 10_000 {
		t.Fatalf("concurrent charges over two processes took %d bytes of a 10,000 burst", took)
	}
}

// Refunds are shared too, and never fill a bucket above its burst.
func TestByteLimiterRefund(t *testing.T) {
	cs := open(t, 2)
	a, b := cs[0].ByteLimiter("bytes", 1, 10_000), cs[1].ByteLimiter("bytes", 1, 10_000)
	now := time.Now()
	const net = "203.0.113.8"
	if ok, _ := a.AllowN(net, 10_000, now); !ok {
		t.Fatal("charge")
	}
	b.Refund(net, 4_000) // given back on the other process
	if ok, _ := a.AllowN(net, 4_001, now); ok {
		t.Fatal("more than the refund")
	}
	if ok, _ := a.AllowN(net, 4_000, now); !ok {
		t.Fatal("the refund, on the first process")
	}
	// A refund larger than what was charged, or to a fresh bucket, stops
	// at the burst.
	b.Refund(net, 1_000_000)
	b.Refund("192.0.2.2", 1_000_000)
	for _, k := range []string{net, "192.0.2.2"} {
		if ok, _ := a.AllowN(k, 10_001, now); ok {
			t.Fatalf("%s: a refund filled the bucket above its burst", k)
		}
		if ok, _ := a.AllowN(k, 10_000, now); !ok {
			t.Fatalf("%s: the burst after a refund", k)
		}
		if ok, _ := b.AllowN(k, 1, now); ok {
			t.Fatalf("%s: more than the burst after a refund", k)
		}
	}
	b.Refund(net, 0)
	b.Refund(net, -5)
	if ok, _ := a.AllowN(net, 1, now); ok {
		t.Fatal("a zero or negative refund gave something back")
	}
}

// A forced charge (bytes already received) goes into debt; Ready, which
// charges nothing, and AllowN then wait it out, on every process.
func TestByteLimiterChargeAndReady(t *testing.T) {
	cs := open(t, 2)
	a, b := cs[0].ByteLimiter("bytes", 1000, 10_000), cs[1].ByteLimiter("bytes", 1000, 10_000)
	now := time.Now()
	const net = "203.0.113.9"
	if ok, _ := b.Ready(net, now); !ok {
		t.Fatal("a fresh bucket is ready")
	}
	if ok, _ := a.AllowN(net, 9_999, now); !ok {
		t.Fatal("charge")
	}
	for i := 0; i < 3; i++ { // looking charges nothing
		if ok, _ := b.Ready(net, now); !ok {
			t.Fatal("one byte left: ready")
		}
	}
	a.Charge(net, 15_000, now) // into debt: 15,000 - 1 bytes owed, plus the burst
	if p := a.Peak(); p != 1 {
		t.Fatalf("peak in debt: %v", p)
	}
	ok, wait := b.Ready(net, now)
	if ok || wait < 14*time.Second || wait > 16*time.Second {
		t.Fatalf("in debt of about 15,000 bytes at 1,000/s: %v %v", ok, wait)
	}
	if ok, _ := b.AllowN(net, 1, now); ok {
		t.Fatal("a charge while in debt")
	}
	a.Charge(net, 0, now)
	a.Charge(net, -1, now)
	// A refund of a forced charge comes off the debt.
	b.Refund(net, 15_000)
	if ok, _ := a.Ready(net, now); !ok {
		t.Fatal("ready again once the debt is refunded")
	}
}

// If Valkey cannot be reached a per-process bucket of the same size
// answers (as for the request limits): a process alone allows its burst,
// keeps refunds and forced charges, and goes on answering.
func TestByteLimiterFallsBackLocally(t *testing.T) {
	c := open(t, 1)[0]
	l := c.ByteLimiter("bytes", 1, 10_000)
	c.Close()
	now := time.Now()
	if ok, _ := l.AllowN("k", 6_000, now); !ok {
		t.Fatal("local fallback: first charge")
	}
	if ok, _ := l.AllowN("k", 6_000, now); ok {
		t.Fatal("local fallback: over the burst")
	}
	l.Refund("k", 2_000)
	if ok, _ := l.AllowN("k", 6_000, now); !ok {
		t.Fatal("local fallback: refund")
	}
	l.Charge("k", 5_000, now)
	if ok, _ := l.Ready("k", now); ok {
		t.Fatal("local fallback: debt")
	}
	if p := l.Peak(); p != 1 {
		t.Fatalf("local fallback: peak %v", p)
	}
}
