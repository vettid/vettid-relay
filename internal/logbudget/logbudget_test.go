package logbudget

import (
	"bytes"
	"context"
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
	log.Warn("replay cache full")
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
