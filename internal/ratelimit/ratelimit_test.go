package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestBurstThenRefill(t *testing.T) {
	l := New(2, 3, 0)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a", now); !ok {
			t.Fatalf("burst %d refused", i)
		}
	}
	ok, wait := l.Allow("a", now)
	if ok || wait < time.Second {
		t.Fatalf("over burst: ok=%v wait=%v", ok, wait)
	}
	// Other keys are independent.
	if ok, _ := l.Allow("b", now); !ok {
		t.Fatal("independent key refused")
	}
	// 0.5 s at 2/s refills one token.
	if ok, _ := l.Allow("a", now.Add(500*time.Millisecond)); !ok {
		t.Fatal("refill not applied")
	}
	if ok, _ := l.Allow("a", now.Add(500*time.Millisecond)); ok {
		t.Fatal("only one token should have refilled")
	}
}

func TestBoundedKeys(t *testing.T) {
	l := New(1, 1, 2)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.Allow("a", now)
	l.Allow("b", now)
	if ok, _ := l.Allow("c", now); ok {
		t.Fatal("table full of active buckets must refuse new keys")
	}
	if l.Len() != 2 {
		t.Fatalf("len=%d", l.Len())
	}
	// After refill, idle buckets are pruned and new keys admitted.
	if ok, _ := l.Allow("c", now.Add(2*time.Second)); !ok {
		t.Fatal("new key refused after idle buckets pruned")
	}
	l.Prune(now.Add(time.Hour))
	if l.Len() != 0 {
		t.Fatalf("prune left %d", l.Len())
	}
}

func TestConcurrent(t *testing.T) {
	l := New(0.001, 10, 0)
	now := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := l.Allow("k", now); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 10 {
		t.Fatalf("allowed %d, want burst 10", allowed)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for d, want := range map[time.Duration]int{0: 1, 300 * time.Millisecond: 1, 1500 * time.Millisecond: 2, 10 * time.Second: 10} {
		if got := RetryAfterSeconds(d); got != want {
			t.Errorf("%v → %d want %d", d, got, want)
		}
	}
}

func TestPeak(t *testing.T) {
	l := New(1, 4, 10)
	now := time.Unix(1_700_000_000, 0)
	l.Allow("a", now)
	l.Allow("a", now)
	l.Allow("b", now)
	if p := l.Peak(); p != 0.5 {
		t.Fatalf("peak %v, want 0.5 (two of four)", p)
	}
	if p := l.Peak(); p != 0 {
		t.Fatalf("peak not reset: %v", p)
	}
	for i := 0; i < 5; i++ {
		l.Allow("a", now)
	}
	if p := l.Peak(); p != 1 {
		t.Fatalf("peak after a refusal %v, want 1", p)
	}
}

// A byte budget: AllowN charges n tokens or none, and says how long until
// n are there.
func TestAllowN(t *testing.T) {
	l := New(1000, 4000, 0) // 1,000 bytes a second, burst 4,000
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if ok, _ := l.AllowN("a", 3000, now); !ok {
		t.Fatal("within the burst refused")
	}
	ok, wait := l.AllowN("a", 3000, now) // 1,000 left: refused, nothing charged
	if ok || wait != 2*time.Second {
		t.Fatalf("over the budget: ok=%v wait=%v (want 2s)", ok, wait)
	}
	if ok, _ := l.AllowN("a", 1000, now); !ok {
		t.Fatal("a refused request was charged")
	}
	if ok, wait := l.AllowN("a", 1, now); ok || wait != time.Second {
		t.Fatalf("empty bucket: ok=%v wait=%v (at least 1s)", ok, wait)
	}
	if ok, _ := l.AllowN("b", 4000, now); !ok {
		t.Fatal("independent key refused")
	}
	if ok, _ := l.AllowN("c", 4001, now); ok {
		t.Fatal("a request larger than the burst was allowed")
	}
	if p := l.Peak(); p != 1 {
		t.Fatalf("peak %v after refusals", p)
	}
	if ok, _ := l.AllowN("a", 2000, now.Add(2*time.Second)); !ok {
		t.Fatal("refill not applied")
	}
}

// Refund gives back a charge (up to the burst); Ready says whether any
// token is left without taking one.
func TestRefundAndReady(t *testing.T) {
	l := New(1, 100, 0)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !ready(l, "a", now) || l.Burst() != 100 {
		t.Fatal("a fresh bucket is ready; burst 100")
	}
	l.AllowN("a", 100, now)
	if ready(l, "a", now) {
		t.Fatal("an empty bucket is ready")
	}
	l.Refund("a", 60)
	if ok, _ := l.AllowN("a", 60, now); !ok {
		t.Fatal("refund not applied")
	}
	l.Refund("a", 1000)
	if ok, _ := l.AllowN("a", 101, now); ok {
		t.Fatal("a refund raised the bucket above its burst")
	}
	l.Refund("unknown", 5) // no bucket: nothing to give back
	if l.Len() != 1 {
		t.Fatalf("refund created a bucket: %d", l.Len())
	}
}

// Charge takes tokens unconditionally, into debt; the bucket refills from
// there.
func TestChargeIntoDebt(t *testing.T) {
	l := New(100, 100, 0)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.Charge("a", 250, now) // 100 - 250 = -150
	if ready(l, "a", now.Add(time.Second)) {
		t.Fatal("ready while in debt")
	}
	if !ready(l, "a", now.Add(1510*time.Millisecond)) {
		t.Fatal("not ready once the debt is paid")
	}
	if p := l.Peak(); p != 1 {
		t.Fatalf("peak %v", p)
	}
}

func ready(l *Limiter, key string, now time.Time) bool {
	ok, _ := l.Ready(key, now)
	return ok
}

// Ready says how long a bucket in debt waits.
func TestReadyWait(t *testing.T) {
	l := New(100, 100, 0)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.Charge("a", 250, now) // -150: 151 tokens to wait for, at 100 a second
	if ok, wait := l.Ready("a", now); ok || wait != 1510*time.Millisecond {
		t.Fatalf("ok=%v wait=%v", ok, wait)
	}
	l.Charge("b", 100, now) // 0: one token in 10 ms, reported as 1 s
	if ok, wait := l.Ready("b", now); ok || wait != time.Second {
		t.Fatalf("ok=%v wait=%v", ok, wait)
	}
}
