package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/api"
	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/logbudget"
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
// logged at WARN, and so is a stored mark over it; at the bound, neither.
func TestWarnLongLifetime(t *testing.T) {
	b := config.MaxTokenLifetimeBound
	for _, c := range []struct {
		max, open, mark time.Duration
		want            []string
	}{
		{b, b, b, nil},
		{b + time.Second, time.Minute, b + time.Second, []string{"token lifetime limit over 400 days"}},
		{time.Hour, b + time.Second, b + time.Second, []string{"token lifetime limit over 400 days"}},
		{time.Hour, time.Minute, b + time.Second, []string{"stored lifetime mark over 400 days"}},
		// A mark above the limits but at or under the bound: no warning.
		{time.Hour, time.Minute, b, nil},
		{time.Hour, time.Minute, b - 24*time.Hour, nil},
	} {
		var buf bytes.Buffer
		cfg := config.Defaults()
		cfg.MaxTokenLifetime, cfg.OpenTokenMaxLifetime, cfg.RetentionLifetime, cfg.AllowLongTokenLifetime = c.max, c.open, c.mark, true
		warnLongLifetime(slog.New(slog.NewJSONHandler(&buf, nil)), cfg)
		lines := strings.Count(buf.String(), `"level":"WARN"`)
		if lines != len(c.want) {
			t.Errorf("max %s, open %s, mark %s: %d warnings: %q", c.max, c.open, c.mark, lines, buf.String())
		}
		for _, w := range c.want {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("max %s, open %s, mark %s: no %q: %q", c.max, c.open, c.mark, w, buf.String())
			}
		}
	}
}

// The warnings are the process's own lines: the log budget never drops
// them, however often they repeat.
func TestWarnLongLifetimeExempt(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(logbudget.New(slog.NewJSONHandler(&buf, nil), 0, 0))
	cfg := config.Defaults()
	b := config.MaxTokenLifetimeBound
	cfg.MaxTokenLifetime, cfg.RetentionLifetime, cfg.AllowLongTokenLifetime = b+time.Second, b+2*time.Second, true
	for range 3 {
		warnLongLifetime(log, cfg)
	}
	if n := strings.Count(buf.String(), `"level":"WARN"`); n != 6 {
		t.Fatalf("%d warnings of 6: %s", n, buf.String())
	}
}

// The largest limit the config accepts is the largest mark the stores
// read: a limit the relay starts with can always be read back.
func TestLifetimeLimitIsMarkLimit(t *testing.T) {
	if config.MaxTokenLifetimeLimit != store.MaxLifetimeMark {
		t.Fatalf("the config's limit %s and the stores' %s differ", config.MaxTokenLifetimeLimit, store.MaxLifetimeMark)
	}
}

// A stored mark that can't be used (over the limit, too large for int64,
// not a number; stored before the limit existed or by hand) stops the
// start, pointing to its reset. The store refuses to write one, so it is
// written here directly.
func TestOpenStoreRefusesMarkOutOfRange(t *testing.T) {
	ctx := context.Background()
	over := strconv.FormatInt((store.MaxLifetimeMark + time.Hour).Milliseconds(), 10)
	for _, raw := range []string{over, "100000000000000000000", "soon"} {
		path := filepath.Join(t.TempDir(), "relay.db")
		cfg := config.Defaults()
		cfg.DBPath = path
		st, err := openStore(ctx, &cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE lifetime_mark SET lifetime_ms = ? WHERE id = 1`, raw); err != nil {
			t.Fatal(err)
		}
		db.Close()
		cfg = config.Defaults()
		cfg.DBPath = path
		if st, err := openStore(ctx, &cfg); err == nil || !strings.Contains(err.Error(), "Resetting the mark") {
			if st != nil {
				st.Close()
			}
			t.Fatalf("started with the mark %s: %v", raw, err)
		}
	}
}
