// Package ratelimit provides an in-memory, keyed token-bucket limiter.
//
// Keys come from closed, non-secret domains (an IPv4 address, an IPv6 /64,
// a sender's public key) and are never logged by this package.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter is a set of token buckets keyed by string. Memory is bounded by
// MaxKeys: idle (full) buckets are dropped, and when the table is full of
// active buckets new keys are refused rather than admitted untracked.
type Limiter struct {
	rate    float64 // tokens per second
	burst   float64
	maxKeys int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter allowing rate events/second with the given burst.
func New(rate float64, burst int, maxKeys int) *Limiter {
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &Limiter{rate: rate, burst: float64(burst), maxKeys: maxKeys, buckets: map[string]*bucket{}}
}

// Allow consumes one token for key. When refused it returns the wait until
// a token is available (at least one second).
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.pruneLocked(now)
			if len(l.buckets) >= l.maxKeys {
				return false, time.Second
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// pruneLocked drops buckets that have refilled completely (indistinguishable
// from a fresh bucket).
func (l *Limiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}

// Prune drops idle buckets; run periodically.
func (l *Limiter) Prune(now time.Time) {
	l.mu.Lock()
	l.pruneLocked(now)
	l.mu.Unlock()
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// RetryAfterSeconds converts a wait to the integer seconds used in
// Retry-After / retry_after (minimum 1).
func RetryAfterSeconds(d time.Duration) int {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}
