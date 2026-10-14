// Package logbudget bounds how many log lines a relay process writes.
//
// Log volume is otherwise bounded only by the requests that reach the
// process, and every line costs money to ingest and store. The Handler
// wraps the real slog.Handler:
//
//   - info lines draw on a token bucket (rate a second, burst); a line
//     that finds it empty is dropped and counted;
//   - a warn or error line whose message was written in the last
//     RepeatWindow is dropped and counted, and the next one written with
//     that message carries "repeated": how many were dropped in between;
//   - debug lines pass (they are written only at RELAY_LOG_LEVEL=debug);
//   - a line logged with a context from Exempt always passes (the
//     per-minute report that carries the counts).
package logbudget

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// RepeatWindow is how often one warn or error message may be written.
const RepeatWindow = 10 * time.Second

// maxMessages bounds the repeat table. Messages are constant strings in
// the relay's code, so a few dozen exist; beyond the bound new messages
// are written without the repeat check.
const maxMessages = 1024

type exemptKey struct{}

// Exempt returns a context whose lines bypass the budget.
func Exempt(ctx context.Context) context.Context {
	return context.WithValue(ctx, exemptKey{}, true)
}

type state struct {
	rate, burst float64
	now         func() time.Time

	mu      sync.Mutex
	tokens  float64
	last    time.Time
	repeats map[string]*repeat

	dropped    atomic.Int64 // info lines over the budget
	suppressed atomic.Int64 // repeated warn/error lines
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
	return &Handler{inner: inner, st: &state{rate: rate, burst: float64(burst), tokens: float64(burst), now: now, last: now(), repeats: map[string]*repeat{}}}
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	if exempt, _ := ctx.Value(exemptKey{}).(bool); exempt {
		return h.inner.Handle(ctx, r)
	}
	switch {
	case r.Level >= slog.LevelWarn:
		n, ok := h.st.repeatOK(r.Message)
		if !ok {
			h.st.suppressed.Add(1)
			return nil
		}
		if n > 0 {
			r = r.Clone()
			r.AddAttrs(slog.Int64("repeated", n))
		}
	case r.Level >= slog.LevelInfo:
		if !h.st.take() {
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

func (s *state) take() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if el := now.Sub(s.last).Seconds(); el > 0 {
		s.tokens = min(s.burst, s.tokens+el*s.rate)
		s.last = now
	}
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

// repeatOK reports whether a warn/error line with message msg may be
// written now, and how many were dropped since the last one written.
func (s *state) repeatOK(msg string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	r, ok := s.repeats[msg]
	if !ok {
		if len(s.repeats) >= maxMessages {
			return 0, true
		}
		s.repeats[msg] = &repeat{written: now}
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
