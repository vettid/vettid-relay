// Command relay runs a VettID relay (see docs/RELAY-PROTOCOL.md).
//
// Configuration is entirely via RELAY_* environment variables (README.md).
//
//	relay               run the relay
//	relay -healthcheck  GET http://127.0.0.1:<port of RELAY_LISTEN_ADDR>/healthz;
//	                    exit 0 on 200, 1 otherwise (for distroless containers)
//	relay -version      print version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/vettid/vettid-relay/internal/api"
	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/coord"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/sweep"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit 0 (healthy) or 1")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Println(buildVersion())
		return
	}
	cfg, err := config.FromEnv()
	if *healthcheck {
		os.Exit(runHealthcheck(cfg))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "relay: invalid configuration:", err)
		os.Exit(2)
	}
	log := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, cfg, log, nil); err != nil {
		log.Error("relay exited with error", "err", err)
		os.Exit(1)
	}
}

// version is stamped at build time (-ldflags "-X main.version=..."); when
// empty, VCS info embedded by the Go toolchain is used.
var version string

func buildVersion() string {
	return "vettid-relay " + buildRevision() + " (protocol " + api.ProtocolVersion + ")"
}

func buildRevision() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
		return bi.Main.Version
	}
	return "unknown"
}

// runHealthcheck only needs RELAY_LISTEN_ADDR, so it works even if some other
// variable fails validation (the running relay would have refused to start).
func runHealthcheck(cfg config.Config) int {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = config.Defaults().ListenAddr
	}
	u, err := cfg.HealthcheckURL()
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

// run serves until ctx is cancelled (SIGTERM/SIGINT in production), then
// drains and shuts down within cfg.ShutdownTimeout. ready, if non-nil, is
// closed once both listeners are accepting.
func run(ctx context.Context, cfg config.Config, log *slog.Logger, ready chan<- struct{}) error {

	reg := metrics.New()
	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := openStore(openCtx, cfg)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Error("close store", "err", err)
		} else {
			log.Info("store closed")
		}
	}()

	// Several relay processes on one shared store also share replay
	// detection, rate limits and wake-on-deposit (internal/coord).
	var opts []api.Option
	var bus *coord.WakeBus
	if cfg.ValkeyAddr != "" {
		vc, err := openCoord(openCtx, cfg, reg)
		if err != nil {
			return err
		}
		defer vc.Close()
		bus = vc.NewWakeBus(reg)
		opts = append(opts,
			api.WithReplayGuard(vc.ReplayGuard()),
			api.WithRateLimiters(
				vc.Limiter("ip", cfg.RateIPPerSec, cfg.RateIPBurst),
				vc.Limiter("sender", cfg.RateSenderPerSec, cfg.RateSenderBurst),
				vc.Limiter("claim", cfg.RateClaimPerSec, cfg.RateClaimBurst),
			),
			api.WithWakeBus(bus),
		)
	}

	srv := api.New(cfg, st, log, reg, opts...)
	defer srv.Close()
	if bus != nil {
		bus.Start(openCtx, srv)
		defer bus.Stop()
	}

	sweepCtx, stopSweep := context.WithCancel(context.Background())
	sweepDone := make(chan struct{})
	go func() { sweep.New(st, cfg.SweepInterval, log, reg).Run(sweepCtx); close(sweepDone) }()
	defer func() { stopSweep(); <-sweepDone }()

	pub := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Bodies are size-bounded; this allows slow mobile uploads of max blobs.
		ReadTimeout:    5 * time.Minute,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 32 << 10,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- pub.Serve(ln) }()

	var msrv *http.Server
	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", reg.Handler())
		msrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		mln, err := net.Listen("tcp", cfg.MetricsAddr)
		if err != nil {
			pub.Close()
			return fmt.Errorf("metrics listener: %w", err)
		}
		go func() { errc <- msrv.Serve(mln) }()
	}
	if ready != nil {
		close(ready)
	}
	log.Info("relay started", "listen", cfg.ListenAddr, "metrics", cfg.MetricsAddr,
		"base_url", cfg.BaseURL, "trust_proxy", cfg.TrustProxy, "store", cfg.Store, "shared_coordination", cfg.ValkeyAddr != "",
		"version", buildVersion())

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutdown signal received; draining", "timeout", cfg.ShutdownTimeout.String())
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}

	// Bounded drain: long-polls and WebSockets end first, then in-flight
	// requests finish, then background work stops (wake bus, janitors),
	// then the store closes (deferred above).
	sctx, scancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer scancel()
	if err := srv.Drain(sctx); err != nil {
		log.Warn("websocket drain incomplete", "err", err)
	}
	if err := pub.Shutdown(sctx); err != nil {
		log.Warn("http shutdown incomplete; closing remaining connections", "err", err)
		pub.Close()
	}
	if msrv != nil {
		msrv.Close()
	}
	log.Info("relay stopped")
	return runErr
}
