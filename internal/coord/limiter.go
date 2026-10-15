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

// gcraBytes is gcra for byte budgets, with every operation the API makes
// on one (api.ByteLimiter). The key holds the theoretical arrival time in
// ms (Valkey's clock), with fractions: a byte is a small part of a ms.
// ARGV[1] = mode, ARGV[2] = ms per byte, ARGV[3] = burst in ms (ms per
// byte × burst), ARGV[4] = n bytes. Modes:
//
//	take    charge n, or nothing if they are not there (a request of more
//	        than the burst never is): {allowed, wait_ms, used}
//	charge  charge n unconditionally, into debt if need be: {1, 0, used}
//	refund  give back n, never above the burst (a bucket cannot hold more
//	        than a fresh one): {1, 0, -1}
//	ready   whether one byte is there, charging nothing: {ready, wait_ms, -1}
//
// used is the part of the bucket in use afterwards, in thousandths (1000
// when refused; above 1000 in debt). -1: not a use (no peak).
const gcraBytes = `
local mode = ARGV[1]
local per = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local n = tonumber(ARGV[4])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + tonumber(t[2]) / 1000
local tat = tonumber(redis.call('GET', KEYS[1]) or now)
if tat < now then tat = now end
local function put(v)
  if v <= now then
    redis.call('DEL', KEYS[1])
  else
    redis.call('SET', KEYS[1], string.format('%.17g', v), 'PX', math.ceil(v - now) + 1000)
  end
end
if mode == 'ready' then
  local wait = tat + per - burst - now
  if wait > 0 then return {0, math.ceil(wait), -1} end
  return {1, 0, -1}
elseif mode == 'refund' then
  put(math.max(tat - n * per, now))
  return {1, 0, -1}
elseif mode == 'charge' then
  local new = tat + n * per
  put(new)
  return {1, 0, math.floor((new - now) * 1000 / burst)}
end
local cost = n * per
if cost > burst then return {0, math.ceil(math.max(tat - now, 1)), 1000} end
local new = tat + cost
local wait = new - burst - now
if wait > 0 then return {0, math.ceil(wait), 1000} end
put(new)
return {1, 0, math.floor((new - now) * 1000 / burst)}
`

var gcraBytesScript = valkey.NewLuaScript(gcraBytes)

// ByteLimiter is a shared byte budget per key (implements api.ByteLimiter
// with the semantics of ratelimit.Limiter's AllowN, Charge, Refund and
// Ready): one bucket per key for every relay process, each operation one
// atomic script, so concurrent charges from several processes cannot take
// more than the bucket holds. If Valkey fails, a per-process bucket of the
// same rate and burst answers, as for Limiter.
type ByteLimiter struct {
	c        *Client
	name     string
	perMS    float64
	burstMS  float64
	burst    int64
	fallback *ratelimit.Limiter
	timeout  time.Duration
	peak     atomic.Int64 // highest `used` (thousandths) since the last Peak call
}

// ByteLimiter returns a shared byte budget of rate bytes/second with burst
// bytes; name namespaces its keys (e.g. "bytes", "blob_bytes").
func (c *Client) ByteLimiter(name string, rate float64, burst int) *ByteLimiter {
	per := 1000 / rate
	return &ByteLimiter{
		c: c, name: name, perMS: per, burstMS: per * float64(burst), burst: int64(burst),
		fallback: ratelimit.New(rate, burst, 200_000),
		timeout:  250 * time.Millisecond,
	}
}

func (l *ByteLimiter) run(mode, key string, n int64) ([]int64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), l.timeout)
	defer cancel()
	res, err := gcraBytesScript.Exec(ctx, l.c.vk, []string{l.c.key("rl", l.name, key)},
		[]string{mode, exactFloat(l.perMS), exactFloat(l.burstMS), strconv.FormatInt(max(n, 0), 10)}).AsIntSlice()
	if err != nil || len(res) != 3 {
		l.c.errors.With("ratelimit").Inc()
		return nil, false
	}
	if res[2] >= 0 {
		for {
			p := l.peak.Load()
			if res[2] <= p || l.peak.CompareAndSwap(p, res[2]) {
				break
			}
		}
	}
	return res, true
}

// Backends of a ByteLimiter charge (api.SourcedByteLimiter).
const (
	SrcShared   = 1 // the bucket in Valkey
	SrcFallback = 2 // the per-process bucket, while Valkey cannot be reached
)

// AllowN charges n bytes to key, or nothing (and the wait until n are
// there, at least a second). More than the burst is never allowed.
func (l *ByteLimiter) AllowN(key string, n int64, now time.Time) (bool, time.Duration) {
	ok, wait, _ := l.AllowNFrom(key, n, now)
	return ok, wait
}

// AllowNFrom is AllowN, and names the backend that took the charge
// (SrcShared or SrcFallback), so that a refund goes back to it
// (RefundTo).
func (l *ByteLimiter) AllowNFrom(key string, n int64, now time.Time) (bool, time.Duration, int) {
	res, ok := l.run("take", key, n)
	if !ok {
		allowed, wait := l.fallback.AllowN(key, n, now)
		return allowed, wait, SrcFallback
	}
	if res[0] == 1 {
		return true, 0, SrcShared
	}
	return false, max(time.Duration(res[1])*time.Millisecond, time.Second), SrcShared
}

// RefundTo gives back n bytes to the backend src that charged them: a
// Valkey flap between a charge and its refund never credits a bucket that
// was not charged. A refund the shared bucket cannot take (Valkey
// unreachable) is dropped: the charge stands, as if the request had
// stored something.
func (l *ByteLimiter) RefundTo(key string, n int64, src int) {
	if n <= 0 {
		return
	}
	switch src {
	case SrcFallback:
		l.fallback.Refund(key, n)
	case SrcShared:
		l.run("refund", key, n)
	}
}

// Charge charges n bytes to key unconditionally (into debt if need be).
func (l *ByteLimiter) Charge(key string, n int64, now time.Time) {
	if n <= 0 {
		return
	}
	if _, ok := l.run("charge", key, n); !ok {
		l.fallback.Charge(key, n, now)
	}
}

// Refund gives back n bytes charged to key, up to the burst, to Valkey or,
// if it cannot be reached, to the per-process bucket. (The API refunds
// with RefundTo, to the backend that took the charge.)
func (l *ByteLimiter) Refund(key string, n int64) {
	if n <= 0 {
		return
	}
	if _, ok := l.run("refund", key, n); !ok {
		l.fallback.Refund(key, n)
	}
}

// Ready reports whether key's bucket holds at least one byte, charging
// nothing; if not, the wait until it does (at least a second).
func (l *ByteLimiter) Ready(key string, now time.Time) (bool, time.Duration) {
	res, ok := l.run("ready", key, 0)
	if !ok {
		return l.fallback.Ready(key, now)
	}
	if res[0] == 1 {
		return true, 0
	}
	return false, max(time.Duration(res[1])*time.Millisecond, time.Second)
}

// Burst returns the bucket size in bytes.
func (l *ByteLimiter) Burst() int64 { return l.burst }

// Peak is Limiter.Peak for the byte budget (1: a charge was refused, or a
// bucket went into debt).
func (l *ByteLimiter) Peak() float64 {
	return max(float64(min(l.peak.Swap(0), 1000))/1000, l.fallback.Peak())
}

// Prune prunes the fallback buckets (called by the API's janitor).
func (l *ByteLimiter) Prune(now time.Time) { l.fallback.Prune(now) }

// exactFloat formats f without losing precision (a byte's share of a ms
// is far below formatFloat's thousandths).
func exactFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }
