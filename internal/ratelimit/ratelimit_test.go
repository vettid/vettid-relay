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
