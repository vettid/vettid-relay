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
	"github.com/vettid/vettid-relay/internal/logbudget"
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
	log := newLogger(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, cfg, log, nil); err != nil {
		log.ErrorContext(lifecycle, "relay exited with error", "err", err)
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

// lifecycle is the context of the process's own lines (start, drain,
// stop, store close): they are exempt from the log budget.
var lifecycle = logbudget.Exempt(context.Background())

// newLogger writes JSON lines to stdout at RELAY_LOG_LEVEL, within the log
// budget (internal/logbudget).
func newLogger(cfg config.Config) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(logbudget.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}), cfg.LogInfoPerSec, cfg.LogInfoBurst))
}

// warnLongLifetime logs at WARN, once the store is open, a token lifetime
// limit above config.MaxTokenLifetimeBound (config.Load accepts one only
// with RELAY_ALLOW_LONG_TOKEN_LIFETIME), and a stored lifetime mark above
// it and above the limits now (one raised before, with the override then):
// tombstones and denylist entries are kept that long, and the mark is
// never lowered.
func warnLongLifetime(log *slog.Logger, cfg config.Config) {
	limits := max(cfg.MaxTokenLifetime, cfg.OpenTokenMaxLifetime)
	if limits > config.MaxTokenLifetimeBound {
		log.WarnContext(lifecycle, "token lifetime limit over 400 days, allowed by RELAY_ALLOW_LONG_TOKEN_LIFETIME: tombstones and denylist entries are kept that long, and the stored lifetime mark is never lowered",
			"limits", limits.String(), "bound", config.MaxTokenLifetimeBound.String())
	}
	if cfg.RetentionLifetime > max(limits, config.MaxTokenLifetimeBound) {
		log.WarnContext(lifecycle, "stored lifetime mark over 400 days: tombstones and denylist entries are kept that long (README, \"Resetting the mark\")",
			"mark", cfg.RetentionLifetime.String(), "bound", config.MaxTokenLifetimeBound.String())
	}
}

// run serves until ctx is cancelled (SIGTERM/SIGINT in production), then
// drains and shuts down within cfg.ShutdownTimeout. ready, if non-nil, is
// closed once both listeners are accepting.
func run(ctx context.Context, cfg config.Config, log *slog.Logger, ready chan<- struct{}) error {

	// FromEnv validated cfg; again here, so no caller can raise the stored
	// lifetime mark with a limit the configuration refuses.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	reg := metrics.New()
	openCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := openStore(openCtx, &cfg, log)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	if limits := max(cfg.MaxTokenLifetime, cfg.OpenTokenMaxLifetime); cfg.RetentionLifetime > limits {
		// Tokens minted under the larger limit may still be live: their
		// tombstones and revocations are kept that long (§6.10, §5.5).
		log.WarnContext(lifecycle, "token lifetimes lowered: tombstones and denylist entries are kept for the larger limit advertised before",
			"limits", limits.String(), "retention_lifetime", cfg.RetentionLifetime.String())
	}
	warnLongLifetime(log, cfg)
	defer func() {
		if err := st.Close(); err != nil {
			log.ErrorContext(lifecycle, "close store", "err", err)
		} else {
			log.InfoContext(lifecycle, "store closed")
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
			api.WithRateLimiters(api.Limiters{
				Address:  vc.Limiter("address", cfg.RateIPPerSec, cfg.RateIPBurst),
				Key:      vc.Limiter("key", cfg.RateKeyPerSec, cfg.RateKeyBurst),
				Sender:   vc.Limiter("sender", cfg.RateSenderPerSec, cfg.RateSenderBurst),
				Register: vc.Limiter("register", cfg.RateRegisterPerSec, cfg.RateRegisterBurst),
				Claim:    vc.Limiter("claim", cfg.RateClaimPerSec, cfg.RateClaimBurst),
				// The network ceilings of the byte budgets (11, 12) are
				// relay-wide: one network's budget against the shared
				// store is the same however many processes run.
				Bytes:     vc.ByteLimiter("bytes", cfg.RateIPBytesPerSec, cfg.RateIPBytesBurst),
				BlobBytes: vc.ByteLimiter("blob_bytes", cfg.RateBlobBytesPerSec, cfg.RateBlobBytesBurst),
				// Limit 14 (code redeems) is relay-wide too.
				CodeRedeem: func(name string, perSec float64, burst int) api.ByteLimiter {
					return vc.ByteLimiter(name, perSec, burst)
				},
			}),
			api.WithWakeBus(bus),
		)
		if cfg.EmptyHints {
			opts = append(opts, api.WithEmptyHints(vc.EmptyHints(bus, cfg.EmptySkipMax, reg)))
		}
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
	log.InfoContext(lifecycle, "relay started", "listen", cfg.ListenAddr, "metrics", cfg.MetricsAddr,
		"base_url", cfg.BaseURL, "trust_proxy", cfg.TrustProxy, "store", cfg.Store, "shared_coordination", cfg.ValkeyAddr != "",
		"serves_vaults", cfg.ServesVaults, "rotation_grace", cfg.RotationGrace.String(), "message_ttl", cfg.MessageTTL.String(),
		"version", buildVersion())

	var runErr error
	select {
	case <-ctx.Done():
		log.InfoContext(lifecycle, "shutdown signal received; draining", "timeout", cfg.ShutdownTimeout.String())
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
		log.WarnContext(lifecycle, "websocket drain incomplete", "err", err)
	}
	if err := pub.Shutdown(sctx); err != nil {
		log.WarnContext(lifecycle, "http shutdown incomplete; closing remaining connections", "err", err)
		pub.Close()
	}
	if msrv != nil {
		msrv.Close()
	}
	log.InfoContext(lifecycle, "relay stopped")
	return runErr
}
