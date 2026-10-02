package relayauth

import (
	"crypto/sha256"
	"sync"
	"time"
)

const replayShards = 32

// ReplayCache remembers (key, signature) pairs until their timestamp can no
// longer pass the freshness check, rejecting duplicates (spec §4.1, §8.4).
//
// Memory is bounded: when full, new requests fail with ErrReplayCacheFull
// rather than evicting live entries (eviction would re-open replays).
type ReplayCache struct {
	shards   [replayShards]replayShard
	perShard int
}

type replayShard struct {
	mu sync.Mutex
	m  map[[32]byte]int64 // → unix-nano expiry
}

// NewReplayCache returns a cache holding at most max live entries.
func NewReplayCache(max int) *ReplayCache {
	per := max / replayShards
	if per < 1 {
		per = 1
	}
	c := &ReplayCache{perShard: per}
	for i := range c.shards {
		c.shards[i].m = make(map[[32]byte]int64)
	}
	return c
}

func replayKey(sr SignedRequest) [32]byte {
	h := sha256.New()
	h.Write(sr.Key)
	h.Write(sr.Sig)
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// Check records the request; it returns ErrReplay if the same (key, sig) was
// already recorded and has not expired. Call only after Verify succeeded, so
// unauthenticated traffic cannot fill the cache.
func (c *ReplayCache) Check(sr SignedRequest, now time.Time) error {
	k := replayKey(sr)
	// The entry must outlive the last instant at which this timestamp is
	// still fresh.
	exp := sr.Time.Add(FreshnessWindow + time.Second).UnixNano()
	n := now.UnixNano()
	sh := &c.shards[k[0]%replayShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if e, ok := sh.m[k]; ok && e > n {
		return ErrReplay
	}
	if len(sh.m) >= c.perShard {
		for kk, e := range sh.m {
			if e <= n {
				delete(sh.m, kk)
			}
		}
		if len(sh.m) >= c.perShard {
			return ErrReplayCacheFull
		}
	}
	sh.m[k] = exp
	return nil
}

// Sweep removes expired entries; run periodically.
func (c *ReplayCache) Sweep(now time.Time) {
	n := now.UnixNano()
	for i := range c.shards {
		sh := &c.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if e <= n {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

// Len returns the number of entries (including not-yet-swept expired ones).
func (c *ReplayCache) Len() int {
	total := 0
	for i := range c.shards {
		c.shards[i].mu.Lock()
		total += len(c.shards[i].m)
		c.shards[i].mu.Unlock()
	}
	return total
}
