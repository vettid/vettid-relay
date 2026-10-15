// Package logbudget bounds how many log lines a relay process writes.
//
// Log volume is otherwise bounded only by the requests that reach the
// process, and every line costs money to ingest and store. The Handler
// wraps the real slog.Handler:
//
//   - info lines draw on a token bucket (rate a second, burst); a line
//     that finds it empty is dropped and counted;
//   - info lines logged with a context from Audit (the requests that
//     change a mailbox's state: registration, rotation, denylist,
//     deletion) draw on a second bucket of the same size, which the other
//     lines cannot empty;
//   - a warn or error line whose message (with its err, route and panic
//     attributes) was written in the last RepeatWindow is dropped and
//     counted, and the next one written with it carries "repeated": how
//     many were dropped in between;
//   - debug lines pass (they are written only at RELAY_LOG_LEVEL=debug);
//   - a line logged with a context from Exempt always passes: the
//     per-minute "rate limits" report (an alarm watches for it) and the
//     process's start and stop lines.
package logbudget

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RepeatWindow is how often one warn or error message may be written.
const RepeatWindow = 10 * time.Second

// maxMessages bounds the repeat table. Keys beyond it are checked under
// their message alone (constant strings in the relay's code, a few dozen),
// which get a quarter more room; past that a line is written unchecked.
const maxMessages = 1024

type ctxKey int

const (
	exemptKey ctxKey = iota + 1
	auditKey
)

// Exempt returns a context whose lines bypass the budget.
func Exempt(ctx context.Context) context.Context {
	return context.WithValue(ctx, exemptKey, true)
}

// Audit returns a context whose info lines draw on the audit bucket.
func Audit(ctx context.Context) context.Context {
	return context.WithValue(ctx, auditKey, true)
}

type state struct {
	now func() time.Time

	mu      sync.Mutex
	info    bucket
	audit   bucket
	repeats map[string]*repeat

	dropped    atomic.Int64 // info lines over the budget
	suppressed atomic.Int64 // repeated warn/error lines
}

type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func (b *bucket) take(now time.Time) bool {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(b.burst, b.tokens+el*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type repeat struct {
	written time.Time
	skipped int64
}

// Handler is a slog.Handler with a line budget. Handlers derived with
// WithAttrs and WithGroup share their parent's budget.
type Handler struct {
	inner slog.Handler
	st    *state
}

// New wraps inner: at most rate info lines a second with the given burst.
func New(inner slog.Handler, rate float64, burst int) *Handler {
	return newWithClock(inner, rate, burst, time.Now)
}

func newWithClock(inner slog.Handler, rate float64, burst int, now func() time.Time) *Handler {
	b := bucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now()}
	return &Handler{inner: inner, st: &state{info: b, audit: b, now: now, repeats: map[string]*repeat{}}}
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if exempt, _ := ctx.Value(exemptKey).(bool); exempt {
		return h.inner.Handle(ctx, r)
	}
	switch {
	case r.Level >= slog.LevelWarn:
		n, ok := h.st.repeatOK(repeatKey(r))
		if !ok {
			h.st.suppressed.Add(1)
			return nil
		}
		if n > 0 {
			r = r.Clone()
			r.AddAttrs(slog.Int64("repeated", n))
		}
	case r.Level >= slog.LevelInfo:
		audit, _ := ctx.Value(auditKey).(bool)
		if !h.st.take(audit) {
			h.st.dropped.Add(1)
			return nil
		}
	}
	return h.inner.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	return &Handler{inner: h.inner.WithAttrs(as), st: h.st}
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: h.inner.WithGroup(name), st: h.st}
}

// Dropped returns the info lines dropped so far (over the budget).
func (h *Handler) Dropped() int64 { return h.st.dropped.Load() }

// Suppressed returns the warn and error lines dropped so far as repeats.
func (h *Handler) Suppressed() int64 { return h.st.suppressed.Load() }

func (s *state) take(audit bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if audit {
		return s.audit.take(s.now())
	}
	return s.info.take(s.now())
}

// repeatKey identifies a warn/error line for the repeat check: its message
// and the values of its err, route and panic attributes, so that different
// failures under one message are not hidden behind each other.
func repeatKey(r slog.Record) string {
	key := r.Message
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "err", "route", "panic":
			key += "\x00" + a.Key + "=" + a.Value.String()
		}
		return true
	})
	return key
}

// repeatOK reports whether a warn/error line with key may be written now,
// and how many were dropped since the last one written. When the table is
// full, a new key is checked under its message alone (messages are
// constants, so their number is bounded).
func (s *state) repeatOK(key string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	r, ok := s.repeats[key]
	if !ok && len(s.repeats) >= maxMessages {
		if i := strings.IndexByte(key, 0); i >= 0 {
			key = key[:i]
		}
		r, ok = s.repeats[key]
	}
	if !ok {
		if len(s.repeats) >= maxMessages+maxMessages/4 {
			return 0, true
		}
		s.repeats[key] = &repeat{written: now}
		return 0, true
	}
	if d := now.Sub(r.written); d >= 0 && d < RepeatWindow {
		r.skipped++
		return 0, false
	}
	n := r.skipped
	r.written, r.skipped = now, 0
	return n, true
}
