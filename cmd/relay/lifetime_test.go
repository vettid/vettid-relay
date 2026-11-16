package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/api"
	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/store"
)

// A restart with lowered token lifetimes keeps the retention of the larger
// limit advertised before (RELAY-PROTOCOL 0.12.0 §6.10), in the config the
// server uses and in the store's own tombstone policy; raising them
// extends it.
func TestOpenStoreKeepsLifetimeMark(t *testing.T) {
	ctx := context.Background()
	day := 24 * time.Hour
	path := filepath.Join(t.TempDir(), "relay.db")
	open := func(max time.Duration) config.Config {
		t.Helper()
		cfg := config.Defaults()
		cfg.DBPath = path
		cfg.MaxTokenLifetime = max
		st, err := openStore(ctx, &cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	if cfg := open(400 * day); cfg.RetentionLifetime != 400*day {
		t.Fatalf("first start: %s", cfg.RetentionLifetime)
	}
	cfg := open(30 * day)
	if cfg.RetentionLifetime != 400*day || cfg.MaxTokenLifetime != 30*day {
		t.Fatalf("lowered: retention %s, advertised %s", cfg.RetentionLifetime, cfg.MaxTokenLifetime)
	}
	if p := api.TombstonePolicy(cfg); p.Retention < 400*day {
		t.Fatalf("tombstone retention %s after lowering", p.Retention)
	}
	if cfg := open(500 * day); cfg.RetentionLifetime != 500*day {
		t.Fatalf("raised: %s", cfg.RetentionLifetime)
	}
}

// failingMark is a store whose lifetime mark can't be raised.
type failingMark struct {
	store.Backend
	set bool
}

func (f *failingMark) RaiseLifetimeMark(context.Context, time.Duration) (time.Duration, error) {
	return 0, errors.New("store down")
}
func (f *failingMark) SetTombstones(store.TombstonePolicy) { f.set = true }
func (f *failingMark) LifetimeMark(context.Context) (time.Duration, error) {
	return 0, errors.New("store down")
}

// A mark that can't be raised stops the start (fail closed): no retention
// is guessed from the config alone.
func TestApplyLifetimeMarkFailsClosed(t *testing.T) {
	cfg := config.Defaults()
	st := &failingMark{}
	if err := applyLifetimeMark(context.Background(), st, &cfg); err == nil {
		t.Fatal("started with a failing mark")
	}
	if st.set || cfg.RetentionLifetime != 0 {
		t.Fatalf("policy set %v, retention %s", st.set, cfg.RetentionLifetime)
	}
	if err := applyLifetimeMark(context.Background(), struct{ store.Backend }{}, &cfg); err == nil {
		t.Fatal("started with a store that keeps no mark")
	}
}

// A limit over the bound, allowed by RELAY_ALLOW_LONG_TOKEN_LIFETIME, is
// logged at WARN; one at the bound isn't.
func TestWarnLongLifetime(t *testing.T) {
	for _, c := range []struct {
		max, open time.Duration
		warn      bool
	}{
		{config.MaxTokenLifetimeBound, config.MaxTokenLifetimeBound, false},
		{config.MaxTokenLifetimeBound + time.Second, time.Minute, true},
		{time.Hour, config.MaxTokenLifetimeBound + time.Second, true},
	} {
		var buf bytes.Buffer
		cfg := config.Defaults()
		cfg.MaxTokenLifetime, cfg.OpenTokenMaxLifetime, cfg.AllowLongTokenLifetime = c.max, c.open, true
		warnLongLifetime(context.Background(), slog.New(slog.NewJSONHandler(&buf, nil)), cfg)
		got := buf.String()
		if warned := strings.Contains(got, `"level":"WARN"`) && strings.Contains(got, "RELAY_ALLOW_LONG_TOKEN_LIFETIME"); warned != c.warn {
			t.Errorf("max %s, open %s: warned %v: %q", c.max, c.open, warned, got)
		}
	}
}
