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

func TestDebt(t *testing.T) {
	d := NewDebt(1, 3, time.Minute, 10)
	now := time.Unix(1_700_000_000, 0)
	if d.Wait("a", now) != 0 {
		t.Fatal("fresh key has budget")
	}
	d.Charge("a", now)
	d.Charge("a", now)
	if w := d.Wait("a", now); w != 0 {
		t.Fatalf("two of three used, wait %v", w)
	}
	d.Charge("a", now)
	if w := d.Wait("a", now); w != time.Second {
		t.Fatalf("budget used up: wait %v, want 1s", w)
	}
	if d.Wait("b", now) != 0 || d.Exhausted(now) != 1 {
		t.Fatal("keys are independent")
	}
	// Events beyond the budget run up a debt: ten more, ten more seconds.
	for i := 0; i < 10; i++ {
		d.Charge("a", now)
	}
	if w := d.Wait("a", now); w != 11*time.Second {
		t.Fatalf("debt: wait %v, want 11s", w)
	}
	if w := d.Wait("a", now.Add(11*time.Second)); w != 0 {
		t.Fatalf("after the debt refilled: wait %v", w)
	}
	// The debt is capped.
	for i := 0; i < 1000; i++ {
		d.Charge("a", now)
	}
	if w := d.Wait("a", now); w != time.Minute {
		t.Fatalf("capped debt: wait %v, want 1m", w)
	}
	if p := d.Peak(); p != 1 {
		t.Fatalf("peak %v", p)
	}
	d.Prune(now.Add(time.Hour))
	if d.Len() != 0 {
		t.Fatalf("idle keys not pruned: %d", d.Len())
	}
}

func TestDebtTableFull(t *testing.T) {
	d := NewDebt(1, 1, time.Minute, 2)
	now := time.Unix(1_700_000_000, 0)
	d.Charge("a", now)
	d.Charge("b", now)
	if d.Charge("c", now) { // untracked: never "first"
		t.Fatal("an untracked key was reported as first")
	}
	if d.Len() != 2 || d.Wait("c", now) != 0 {
		t.Fatalf("len %d", d.Len())
	}
	d.Charge("c", now.Add(time.Hour)) // a and b have refilled: pruned
	if d.Len() != 1 {
		t.Fatalf("len after prune %d", d.Len())
	}
}

func TestRecent(t *testing.T) {
	r := NewRecent(time.Minute, 2)
	now := time.Unix(1_700_000_000, 0)
	r.Add("a", now, false)
	if r.Has("a", now) {
		t.Fatal("refresh-only add inserted")
	}
	r.Add("a", now, true)
	r.Add("b", now, true)
	r.Add("c", now, true) // full
	if !r.Has("a", now) || !r.Has("b", now) || r.Has("c", now) {
		t.Fatal("membership")
	}
	r.Add("a", now.Add(50*time.Second), false) // refreshed
	if !r.Has("a", now.Add(100*time.Second)) || r.Has("b", now.Add(100*time.Second)) {
		t.Fatal("expiry")
	}
	r.Add("c", now.Add(100*time.Second), true) // b expired: room again
	if !r.Has("c", now.Add(100*time.Second)) {
		t.Fatal("no room after expiry")
	}
	r.Remove("a")
	if r.Has("a", now.Add(100*time.Second)) {
		t.Fatal("remove")
	}
	r.Prune(now.Add(time.Hour))
	if r.Len() != 0 {
		t.Fatalf("len %d", r.Len())
	}
}

func TestHold(t *testing.T) {
	h := NewHold(time.Second, time.Minute, 2)
	now := time.Unix(1_700_000_000, 0)
	if h.Wait("a", now) != 0 {
		t.Fatal("fresh key held")
	}
	if !h.Fail("a", now) {
		t.Fatal("first failure not reported as first")
	}
	want := time.Second
	for i := 0; i < 8; i++ {
		if w := h.Wait("a", now); w != want {
			t.Fatalf("failure %d: held %v, want %v", i+1, w, want)
		}
		now = now.Add(want) // comes back the moment the hold ends
		if h.Wait("a", now) != 0 {
			t.Fatal("still held at the end of the hold")
		}
		if h.Fail("a", now) {
			t.Fatal("a repeat was reported as first")
		}
		want = min(2*want, time.Minute)
	}
	if w := h.Wait("a", now); w != time.Minute {
		t.Fatalf("hold not capped: %v", w)
	}
	// Coming back long after is a new first failure.
	now = now.Add(3 * time.Minute)
	if !h.Fail("a", now) || h.Wait("a", now) != time.Second {
		t.Fatal("forgotten key not treated as new")
	}
	h.Clear("a")
	if h.Wait("a", now) != 0 || h.Len() != 0 {
		t.Fatal("clear")
	}
	// A full table tracks nothing new, and never calls an untracked key
	// first (or its network would be charged on every repeat).
	h.Fail("b", now)
	h.Fail("c", now)
	once := h.Fail("d", now)
	again := h.Fail("d", now)
	if once || again || h.Wait("d", now) != 0 || h.Len() != 2 {
		t.Fatal("full table")
	}
	// Recheck: at most once per interval per held key.
	if !h.Recheck("b", now, 5*time.Second) || h.Recheck("b", now.Add(4*time.Second), 5*time.Second) ||
		!h.Recheck("b", now.Add(5*time.Second), 5*time.Second) || h.Recheck("nobody", now, 5*time.Second) {
		t.Fatal("recheck")
	}
	// A long first hold does not overflow.
	long := NewHold(time.Minute, time.Hour, 2)
	for i := 0; i < 80; i++ {
		long.Fail("a", now)
	}
	if w := long.Wait("a", now); w != time.Hour {
		t.Fatalf("long hold: %v", w)
	}
	h.Prune(now.Add(time.Hour))
	if h.Len() != 0 {
		t.Fatal("prune")
	}
}
