package logbudget

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newTest(rate float64, burst int) (*slog.Logger, *Handler, *bytes.Buffer, *clock) {
	var buf bytes.Buffer
	clk := &clock{t: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)}
	h := newWithClock(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}), rate, burst, clk.now)
	return slog.New(h), h, &buf, clk
}

func lines(b *bytes.Buffer) int { return strings.Count(b.String(), "\n") }

// Info lines beyond the budget are dropped and counted; the bucket refills.
func TestInfoBudget(t *testing.T) {
	log, h, buf, clk := newTest(100, 1000)
	for i := 0; i < 1500; i++ {
		log.Info("request", "i", i)
	}
	if n := lines(buf); n != 1000 || h.Dropped() != 500 {
		t.Fatalf("written %d (burst 1000), dropped %d", n, h.Dropped())
	}
	clk.add(time.Second) // 100 more
	for i := 0; i < 150; i++ {
		log.Info("request")
	}
	if n := lines(buf); n != 1100 || h.Dropped() != 550 {
		t.Fatalf("after a second: written %d, dropped %d", n, h.Dropped())
	}
	// Derived loggers share the budget.
	log.With("k", "v").Info("request")
	if h.Dropped() != 551 {
		t.Fatalf("derived logger bypassed the budget: dropped %d", h.Dropped())
	}
	// Debug lines and exempt lines pass; neither draws on the budget.
	log.Debug("probe")
	log.InfoContext(Exempt(context.Background()), "rate limits", "log_dropped", h.Dropped())
	if n := lines(buf); n != 1102 || !strings.Contains(buf.String(), `"msg":"rate limits"`) {
		t.Fatalf("debug or exempt line dropped: %d lines", n)
	}
}

// A warn or error message is written at most once per RepeatWindow; the
// next one written says how many were dropped. Warn lines do not draw on
// the info budget.
func TestRepeatedWarnings(t *testing.T) {
	log, h, buf, clk := newTest(1, 1)
	for i := 0; i < 50; i++ {
		log.Warn("replay cache full", "err", "x")
		log.Error("deposit failed")
	}
	if n := lines(buf); n != 2 || h.Suppressed() != 98 {
		t.Fatalf("written %d, suppressed %d", n, h.Suppressed())
	}
	clk.add(RepeatWindow)
	log.Warn("replay cache full", "err", "x")
	last := buf.String()[strings.LastIndex(strings.TrimSpace(buf.String()), "\n")+1:]
	if !strings.Contains(last, `"repeated":49`) {
		t.Fatalf("repeat count missing: %s", last)
	}
	log.Warn("something else")
	if n := lines(buf); n != 4 {
		t.Fatalf("a different message was held back: %d lines", n)
	}
	log.Info("one")
	log.Info("two")
	if h.Dropped() != 1 {
		t.Fatalf("info budget: dropped %d", h.Dropped())
	}
}

// Audit lines draw on their own bucket: other lines cannot empty it, and
// they do not empty the other.
func TestAuditBucket(t *testing.T) {
	log, h, buf, _ := newTest(0.001, 3)
	audit := Audit(context.Background())
	for i := 0; i < 10; i++ {
		log.Info("request")
	}
	for i := 0; i < 5; i++ {
		log.InfoContext(audit, "request", "route", "POST /v1/register")
	}
	if n := strings.Count(buf.String(), "POST /v1/register"); n != 3 {
		t.Fatalf("%d audit lines written (own budget 3)", n)
	}
	if n := lines(buf); n != 6 || h.Dropped() != 9 {
		t.Fatalf("written %d, dropped %d", n, h.Dropped())
	}
}

// The repeat check tells failures apart by their err, route and panic
// attributes, not by the message alone.
func TestRepeatKey(t *testing.T) {
	log, h, buf, _ := newTest(1, 1)
	log.Error("panic in handler", "route", "POST /v1/register", "panic", "a")
	log.Error("panic in handler", "route", "GET /v1/mailbox", "panic", "a")
	log.Error("panic in handler", "route", "GET /v1/mailbox", "panic", "b")
	log.Error("deposit failed", "err", "throttled")
	log.Error("deposit failed", "err", "conditional check failed")
	log.Error("deposit failed", "err", "throttled", "other", "x") // a repeat
	if n := lines(buf); n != 5 || h.Suppressed() != 1 {
		t.Fatalf("written %d, suppressed %d", n, h.Suppressed())
	}
	// A full table falls back to the message alone: new keys past the
	// bound are repeats of "many", which was written in this window.
	for i := 0; i < maxMessages; i++ {
		log.Warn("many", "err", fmt.Sprint(i))
	}
	before := h.Suppressed()
	log.Warn("many", "err", "new")
	log.Warn("many", "err", "newer")
	if h.Suppressed() != before+2 {
		t.Fatalf("past the table's bound: suppressed %d more", h.Suppressed()-before)
	}
}
