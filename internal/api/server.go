// Package api implements the VettID relay HTTP API (docs/RELAY-PROTOCOL.md).
package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-relay/internal/auth"
	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	"github.com/vettid/vettid-relay/internal/store"
)

// Server is the relay API.
type Server struct {
	cfg   config.Config
	st    *store.Store
	blobs store.BlobStore
	log   *slog.Logger
	m     *serverMetrics
	now   func() time.Time

	drainCtx    context.Context // cancelled when shutdown starts
	drainCancel context.CancelFunc
	draining    atomic.Bool
	streams     sync.WaitGroup // hijacked WebSocket sessions

	bgCtx    context.Context // background goroutines (cache janitors)
	bgCancel context.CancelFunc
	bg       sync.WaitGroup

	replay   *auth.ReplayCache
	ipLimit  *ratelimit.Limiter // per source IP (IPv4 / IPv6 /64), before any parsing
	subLimit *ratelimit.Limiter // per sender key, after token parse

	mux *http.ServeMux
}

type serverMetrics struct {
	errors   metrics.CounterVec
	requests metrics.Counter
}

func newServerMetrics(reg *metrics.Registry) *serverMetrics {
	m := &serverMetrics{
		errors:   reg.CounterVec("relay_errors_total", "Error responses by canonical code.", "code"),
		requests: reg.Counter("relay_http_requests_total", "HTTP requests received on the public listener."),
	}
	for _, c := range allCodes {
		m.errors.With(c) // pre-create every series so rates start at 0
	}
	return m
}

// Option configures a Server.
type Option func(*Server)

// WithClock overrides the clock used for auth freshness and token times.
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// New builds the API server.
func New(cfg config.Config, st *store.Store, log *slog.Logger, reg *metrics.Registry, opts ...Option) *Server {
	s := &Server{
		cfg:   cfg,
		st:    st,
		blobs: st,
		log:   log,
		m:     newServerMetrics(reg),
		now:   time.Now,
		mux:   http.NewServeMux(),

		replay:   auth.NewReplayCache(cfg.ReplayCacheMax),
		ipLimit:  ratelimit.New(cfg.RateIPPerSec, cfg.RateIPBurst, 200_000),
		subLimit: ratelimit.New(cfg.RateSenderPerSec, cfg.RateSenderBurst, 200_000),
	}
	s.drainCtx, s.drainCancel = context.WithCancel(context.Background())
	s.bgCtx, s.bgCancel = context.WithCancel(context.Background())
	for _, o := range opts {
		o(s)
	}
	s.routes()
	s.every(15*time.Second, func(time.Time) {
		now := s.now()
		s.replay.Sweep(now)
		s.ipLimit.Prune(now)
		s.subLimit.Prune(now)
	})
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { s.writeError(w, fail(CodeNotFound)) })
}

// Handler returns the public HTTP handler with the middleware chain.
func (s *Server) Handler() http.Handler {
	return withSecurityHeaders(s.withAccessLog(s.withIPRateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.m.requests.Inc()
		s.mux.ServeHTTP(w, r)
	}))))
}

// handleHealthz reports 200 when the database is reachable and the server is
// not draining; 503 otherwise (so load balancers stop routing during drain).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.st.Ping(ctx); err != nil {
		s.log.Error("healthz: database unreachable", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Drain begins shutdown: parked long-polls return immediately, WebSocket
// sessions are closed with "going away", and /healthz turns 503. It then
// waits (bounded by ctx) for WebSocket sessions to finish. Call before
// http.Server.Shutdown, which does not track hijacked connections.
func (s *Server) Drain(ctx context.Context) error {
	s.draining.Store(true)
	s.drainCancel()
	done := make(chan struct{})
	go func() { s.streams.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops background goroutines. Call after the HTTP server has shut down
// and before closing the store.
func (s *Server) Close() {
	s.drainCancel()
	s.bgCancel()
	s.bg.Wait()
}

// every runs fn every interval until Close.
func (s *Server) every(interval time.Duration, fn func(now time.Time)) {
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-s.bgCtx.Done():
				return
			case now := <-t.C:
				fn(now)
			}
		}
	}()
}
