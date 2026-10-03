package coord

import (
	"context"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/vettid/vettid-relay/internal/ratelimit"
)

// gcra is a token bucket as a generic cell rate algorithm: one key holding
// the theoretical arrival time (ms, Valkey's clock). ARGV[1] = ms per token,
// ARGV[2] = burst in ms (ms per token × burst). Returns {allowed, wait_ms}.
const gcra = `
local per = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local tat = tonumber(redis.call('GET', KEYS[1]) or now)
if tat < now then tat = now end
local new = tat + per
local wait = new - burst - now
if wait > 0 then return {0, math.ceil(wait)} end
redis.call('SET', KEYS[1], tostring(new), 'PX', math.ceil(new - now) + 1000)
return {1, 0}
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
}

// Limiter returns a shared limiter of rate events/second with burst; name
// namespaces its keys (e.g. "ip", "sender", "claim").
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
	if err != nil || len(res) != 2 {
		l.c.errors.With("ratelimit").Inc()
		return l.fallback.Allow(key, now)
	}
	if res[0] == 1 {
		return true, 0
	}
	wait := time.Duration(res[1]) * time.Millisecond
	return false, max(wait, time.Second)
}

// Prune prunes the fallback buckets (called by the API's janitor).
func (l *Limiter) Prune(now time.Time) { l.fallback.Prune(now) }

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', 3, 64) }
