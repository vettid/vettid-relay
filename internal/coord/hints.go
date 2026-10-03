package coord

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/vettid/vettid-relay/internal/metrics"
)

// EmptyHints lets a collector skip the store query for a mailbox that is
// known to be empty (api.EmptyHints). Always-on collectors re-poll every
// 25 s, so without it nearly every store read finds nothing.
//
// # State
//
// One hash per mailbox, relay:mb:{<mailbox>}, with three fields:
//
//	v  deposit version: incremented by every deposit AFTER its store commit
//	e  the version at which a real store query last found the mailbox empty
//	u  until when that empty finding may be trusted (Valkey clock, ms)
//
// # Invariant
//
// A collector skips the store only if e == v and now < u, where
//
//   - e was written by a collector that read v BEFORE its strongly
//     consistent store query, found no collectable message, and wrote e only
//     if v was still unchanged (one atomic script). Any deposit that
//     committed before that query was seen by it; any deposit that committed
//     after it bumps v (after commit), so e != v from then on.
//   - u is at most the earliest moment a leased-but-unacked message can
//     become visible again (the query reports it), and at most MaxSkip after
//     the query.
//
// So a skip can only hide a message if a deposit committed to the store but
// its bump never reached Valkey (the process died in between, or Valkey lost
// the write in a failover). Even then the message is found by the first real
// query after u, at most MaxSkip later. Every other failure falls back to a
// real query: a missing hash, any Valkey error, a wake bus that is not
// subscribed, and every wake-up the API forces after a resubscribe or while
// Valkey is unreachable (api.Server.WakeAll).
//
// Wake ordering: a deposit bumps v BEFORE it publishes its wake signal, and
// a collector registers for wake-ups BEFORE it checks the hint, so a
// collector that skipped is always woken for a later deposit and then sees
// the new version.
type EmptyHints struct {
	c       *Client
	bus     *WakeBus // skips only while subscribed (nil: no such condition)
	MaxSkip time.Duration
	timeout time.Duration

	bumpFailures metrics.Counter
}

// keepFor is how long an untouched hash lives. Every check refreshes it, so
// a hash cannot expire (and restart its version at 0) between a collector's
// read of v and its write of e.
const keepFor = 24 * time.Hour

var (
	bumpScript = valkey.NewLuaScript(`
redis.call('HINCRBY', KEYS[1], 'v', 1)
redis.call('HDEL', KEYS[1], 'e', 'u')
redis.call('PEXPIRE', KEYS[1], ARGV[1])
return 1`)

	checkScript = valkey.NewLuaScript(`
local v = redis.call('HGET', KEYS[1], 'v') or '0'
if redis.call('EXISTS', KEYS[1]) == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local e = redis.call('HGET', KEYS[1], 'e')
local u = tonumber(redis.call('HGET', KEYS[1], 'u') or '0')
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if e == v and u > now then return {v, u - now} end
return {v, 0}`)

	markScript = valkey.NewLuaScript(`
if (redis.call('HGET', KEYS[1], 'v') or '0') ~= ARGV[1] then return 0 end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('HSET', KEYS[1], 'e', ARGV[1], 'u', tostring(now + tonumber(ARGV[2])))
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1`)
)

// EmptyHints returns the hint store. bus may be nil (tests); maxSkip bounds
// how long one empty finding is trusted.
func (c *Client) EmptyHints(bus *WakeBus, maxSkip time.Duration, reg *metrics.Registry) *EmptyHints {
	return &EmptyHints{
		c: c, bus: bus, MaxSkip: maxSkip, timeout: 500 * time.Millisecond,
		bumpFailures: reg.Counter("relay_empty_hint_bump_failures_total", "Deposits whose empty-hint version bump failed (collectors may skip them for up to the hint lifetime)."),
	}
}

func (h *EmptyHints) key(mailbox string) string { return h.c.key("mb", "{"+mailbox+"}") }

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }

// Bump records a committed deposit. Call after the store commit and before
// publishing the wake signal. It retries briefly; a final failure is counted
// and returned (the deposit itself has succeeded).
func (h *EmptyHints) Bump(ctx context.Context, mailbox string) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 50 * time.Millisecond)
		}
		cctx, cancel := context.WithTimeout(ctx, h.timeout)
		err = bumpScript.Exec(cctx, h.c.vk, []string{h.key(mailbox)}, []string{ms(keepFor)}).Error()
		cancel()
		if err == nil {
			return nil
		}
	}
	h.bumpFailures.Inc()
	h.c.errors.With("hint").Inc()
	return err
}

// Check returns the mailbox's current deposit version and, if the mailbox
// is known empty, for how much longer (0: query the store).
func (h *EmptyHints) Check(ctx context.Context, mailbox string) (version string, emptyFor time.Duration, err error) {
	cctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	res, err := checkScript.Exec(cctx, h.c.vk, []string{h.key(mailbox)}, []string{ms(keepFor)}).ToArray()
	if err != nil || len(res) != 2 {
		h.c.errors.With("hint").Inc()
		return "", 0, errors.Join(errors.New("coord: empty hint check failed"), err)
	}
	version, err = res[0].ToString()
	if err != nil {
		return "", 0, err
	}
	left, err := res[1].AsInt64()
	if err != nil {
		return "", 0, err
	}
	if h.bus != nil && !h.bus.up.Load() {
		left = 0 // not subscribed: a skipping collector might not be woken
	}
	return version, time.Duration(left) * time.Millisecond, nil
}

// MarkEmpty records that a store query, made after Check returned version,
// found nothing collectable; validFor is how long that may be trusted (the
// time until a leased message can reappear, capped at MaxSkip). It does
// nothing if a deposit bumped the version meanwhile.
func (h *EmptyHints) MarkEmpty(ctx context.Context, mailbox, version string, validFor time.Duration) {
	validFor = min(validFor, h.MaxSkip)
	if validFor < time.Millisecond {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	if err := markScript.Exec(cctx, h.c.vk, []string{h.key(mailbox)}, []string{version, ms(validFor), ms(keepFor)}).Error(); err != nil {
		h.c.errors.With("hint").Inc()
	}
}

// Clear drops an empty finding (a real query found messages: if a finding
// was still trusted, a bump was lost — heal it now).
func (h *EmptyHints) Clear(ctx context.Context, mailbox string) {
	cctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	if err := h.c.vk.Do(cctx, h.c.vk.B().Hdel().Key(h.key(mailbox)).Field("e", "u").Build()).Error(); err != nil {
		h.c.errors.With("hint").Inc()
	}
}
