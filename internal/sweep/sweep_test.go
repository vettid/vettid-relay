package sweep

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
)

type fakeStore struct {
	calls atomic.Int64
	fail  bool
}

func (f *fakeStore) Sweep(context.Context) (store.SweepStats, error) {
	f.calls.Add(1)
	if f.fail {
		return store.SweepStats{}, errors.New("boom")
	}
	return store.SweepStats{Messages: 2, Blobs: 1}, nil
}

func TestRunAndMetrics(t *testing.T) {
	fs := &fakeStore{}
	reg := metrics.New()
	s := New(fs, 10*time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)), reg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for fs.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if fs.calls.Load() < 3 {
		t.Fatalf("only %d sweeps", fs.calls.Load())
	}
	var b strings.Builder
	reg.WriteTo(&b)
	if !strings.Contains(b.String(), `relay_sweep_removed_total{kind="messages"}`) || strings.Contains(b.String(), "relay_sweep_errors_total 1") {
		t.Fatalf("metrics:\n%s", b.String())
	}
}

func TestOnceError(t *testing.T) {
	reg := metrics.New()
	s := New(&fakeStore{fail: true}, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)), reg)
	s.Once(context.Background())
	var b strings.Builder
	reg.WriteTo(&b)
	if !strings.Contains(b.String(), "relay_sweep_errors_total 1") {
		t.Fatal("error not counted")
	}
}
