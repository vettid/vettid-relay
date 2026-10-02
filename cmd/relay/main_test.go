package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/store"
	client "github.com/vettid/vettid-relay/relayclient"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestLifecycle(t *testing.T) {
	cfg := config.Defaults()
	cfg.ListenAddr = freeAddr(t)
	cfg.MetricsAddr = freeAddr(t)
	cfg.BaseURL = "http://" + cfg.ListenAddr
	cfg.DBPath = filepath.Join(t.TempDir(), "relay.db")
	cfg.ShutdownTimeout = 5 * time.Second
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	// Not running yet → healthcheck fails.
	if runHealthcheck(cfg) != 1 {
		t.Fatal("healthcheck must fail when nothing listens")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("run exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("relay not ready")
	}

	// The database exists in WAL mode before the relay reports healthy.
	for _, f := range []string{cfg.DBPath, cfg.DBPath + "-wal"} {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("%s missing at ready: %v", filepath.Base(f), err)
		}
	}
	if runHealthcheck(cfg) != 0 {
		t.Fatal("healthcheck failed against a running relay")
	}

	// Metrics only on the metrics listener.
	if resp, err := http.Get("http://" + cfg.MetricsAddr + "/metrics"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("metrics listener: %v", err)
	} else {
		resp.Body.Close()
	}
	if resp, err := http.Get(cfg.BaseURL + "/metrics"); err != nil || resp.StatusCode != 404 {
		t.Fatalf("metrics must not be served publicly: %v", err)
	} else {
		resp.Body.Close()
	}

	// Park a long-poll, then "SIGTERM": it must return promptly and run must
	// finish well inside the shutdown timeout.
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	c := client.New(cfg.BaseURL, k)
	c.MaxAttempts = 1
	if _, err := c.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	polled := make(chan error, 1)
	go func() {
		msgs, err := c.Collect(context.Background(), 25*time.Second, 10)
		if err == nil && len(msgs) != 0 {
			err = io.ErrUnexpectedEOF
		}
		polled <- err
	}()
	time.Sleep(200 * time.Millisecond)
	stopAt := time.Now()
	cancel()
	select {
	case err := <-polled:
		if err != nil {
			t.Fatalf("parked long-poll on shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parked long-poll not released on shutdown")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(cfg.ShutdownTimeout + 2*time.Second):
		t.Fatal("run did not return within the shutdown timeout")
	}
	t.Logf("shutdown with a parked long-poll took %v", time.Since(stopAt))
	if runHealthcheck(cfg) != 1 {
		t.Fatal("healthcheck must fail after shutdown")
	}

	// The database was closed cleanly and keeps its state.
	st, err := store.Open(context.Background(), cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Mailbox(context.Background(), c.MailboxID()); err != nil {
		t.Fatalf("registration lost: %v", err)
	}
}
