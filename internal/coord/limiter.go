package coord

import (
	"context"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/vettid/vettid-relay/internal/ratelimit"
)

// gcra is a token bucket as a generic cell rate algorithm: one key holding
// the theoretical arrival time (ms, Valkey's clock). ARGV[1] = ms per token,
// ARGV[2] = burst in ms (ms per token × burst). Returns {allowed, wait_ms,
// used}: used is the part of the bucket in use after this request, in
// thousandths (1000 when refused).
const gcra = `
local per = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local tat = tonumber(redis.call('GET', KEYS[1]) or now)
if tat < now then tat = now end
local new = tat + per
local wait = new - burst - now
if wait > 0 then return {0, math.ceil(wait), 1000} end
redis.call('SET', KEYS[1], tostring(new), 'PX', math.ceil(new - now) + 1000)
return {1, 0, math.floor((new - now) * 1000 / burst)}
`

var gcraScript = valkey.NewLuaScript(gcra)

// Limiter is a shared token bucket per key (same parameters and semantics
// as ratelimit.Limiter). If Valkey fails, a per-process bucket answers.
type Limiter struct {
	c        *Client
	name     string
	perMS    float64
	burstMS  float64
	fallback *ratelimit.Limiter
	timeout  time.Duration
	peak     atomic.Int64 // highest `used` (thousandths) since the last Peak call
}

// Limiter returns a shared limiter of rate events/second with burst; name
// namespaces its keys (e.g. "address", "key", "sender", "claim").
func (c *Client) Limiter(name string, rate float64, burst int) *Limiter {
	per := 1000 / rate
	return &Limiter{
		c: c, name: name, perMS: per, burstMS: per * float64(burst),
		fallback: ratelimit.New(rate, burst, 200_000),
		timeout:  250 * time.Millisecond,
	}
}

// Allow implements api.RateLimiter. Keys (IP prefixes, sender keys) are
// hashed by nothing but Valkey's slot function; they expire with the bucket.
func (l *Limiter) Allow(key string, now time.Time) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), l.timeout)
	defer cancel()
	res, err := gcraScript.Exec(ctx, l.c.vk, []string{l.c.key("rl", l.name, key)},
		[]string{formatFloat(l.perMS), formatFloat(l.burstMS)}).AsIntSlice()
	if err != nil || len(res) != 3 {
		l.c.errors.With("ratelimit").Inc()
		return l.fallback.Allow(key, now)
	}
	for {
		p := l.peak.Load()
		if res[2] <= p || l.peak.CompareAndSwap(p, res[2]) {
			break
		}
	}
	if res[0] == 1 {
		return true, 0
	}
	wait := time.Duration(res[1]) * time.Millisecond
	return false, max(wait, time.Second)
}

// Peak returns the highest fraction (0..1) of any one bucket that requests
// through this process found in use since the previous call, and resets it
// (1: a request was refused). It names no key.
func (l *Limiter) Peak() float64 {
	return max(float64(min(l.peak.Swap(0), 1000))/1000, l.fallback.Peak())
}

// Prune prunes the fallback buckets (called by the API's janitor).
func (l *Limiter) Prune(now time.Time) { l.fallback.Prune(now) }

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', 3, 64) }
