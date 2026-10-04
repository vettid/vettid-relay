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
	if ok, _ := b.Allow("198.51.100.1", now); !ok {
		t.Fatal("other keys are independent")
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
