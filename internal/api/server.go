// Package api implements the VettID relay HTTP API (docs/RELAY-PROTOCOL.md).
package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// ProtocolVersion is the docs/RELAY-PROTOCOL.md version this relay implements.
const ProtocolVersion = "0.7.0"

// Server is the relay API.
type Server struct {
	cfg   config.Config
	st    store.Backend
	blobs store.BlobStore
	log   *slog.Logger
	m     *serverMetrics
	now   func() time.Time

	drainCtx    context.Context // cancelled when shutdown starts
	drainCancel context.CancelFunc
	draining    atomic.Bool
	streamMu    sync.Mutex     // orders streams.Add against Drain's Wait
	streams     sync.WaitGroup // hijacked WebSocket sessions

	bgCtx    context.Context // background goroutines (cache janitors)
	bgCancel context.CancelFunc
	bg       sync.WaitGroup

	replay   ReplayGuard
	ipLimit  RateLimiter // flood guard per client network (IPv4 / IPv6 /64), before any parsing
	keyLimit RateLimiter // per signing key, after authentication
	subLimit RateLimiter // per sender key, on deposits after the signature
	regLimit RateLimiter // new mailboxes per client network
	rl       *limiterMetrics

	byteLimit     ByteLimiter // bytes of deposits and claims, per client network (per process)
	blobByteLimit ByteLimiter // bytes of blob uploads and downloads, per client network: the ceiling (per process)
	blobKeyLimit  ByteLimiter // bytes of blob uploads and downloads, per authenticated key (per process)
	keyByteLimit  ByteLimiter // bytes of deposits and claims, per authenticated key (per process); byteLimit is the network's ceiling

	smallBodyTimeout time.Duration // how long a small body has to arrive (handlers.go)
	blobPaceWindow   time.Duration // period of cfg.BlobPaceBytes (blobs.go)
	claimLimit       RateLimiter   // unauthenticated claim GETs, per IPv4 / IPv6 /64
	webLimit         RateLimiter   // everything outside /v1/ and /healthz, per IPv4 / IPv6 /64 (always in-process)

	web  *webDocs // /connect, /.well-known/assetlinks.json, /robots.txt (§6.11)
	hsts bool     // public base URL is https: send Strict-Transport-Security

	hub      *hub
	wsOpen   atomic.Int64      // WebSocket sessions holding a slot (cfg.MaxWebSocketSessions)
	health   storeHealth       // /healthz: the last store ping
	healthTO time.Duration     // how long that ping may take (healthPingTimeout; tests shorten it)
	bus      WakeBus           // cross-process wake-on-deposit (nil: single process)
	hints    EmptyHints        // known-empty mailboxes (nil: always query)
	forceGen atomic.Uint64     // bumped by WakeAll: collectors then query for real
	xfers    *blobTransfers    // blob transfers in progress (slots, blobs.go)
	blobRes  *blobReservations // blob uploads' reserved quota (blobquota.go)
	mux      *http.ServeMux
}

type serverMetrics struct {
	errors        metrics.CounterVec
	requests      metrics.Counter
	registrations metrics.Counter
	deposits      metrics.Counter
	depositBytes  metrics.Counter
	collects      metrics.Counter
	collected     metrics.Counter
	acks          metrics.Counter
	revocations   metrics.Counter
	rotations     metrics.Counter
	deletions     metrics.Counter
	parked        metrics.Gauge
	wsSessions    metrics.Gauge
	blobPuts      metrics.Counter
	blobBytes     metrics.Counter
	blobGets      metrics.Counter
	blobDeletes   metrics.Counter
	claimPuts     metrics.Counter
	claimGets     metrics.Counter
	storeQueries  metrics.Counter
	storeSkips    metrics.Counter
}

func newServerMetrics(reg *metrics.Registry) *serverMetrics {
	m := &serverMetrics{
		errors:   reg.CounterVec("relay_errors_total", "Error responses by canonical code.", "code"),
		requests: reg.Counter("relay_http_requests_total", "HTTP requests received on the public listener."),

		registrations: reg.Counter("relay_registrations_total", "New mailboxes registered."),
		deposits:      reg.Counter("relay_deposits_total", "Messages deposited."),
		depositBytes:  reg.Counter("relay_deposit_bytes_total", "Decoded payload bytes deposited."),
		collects:      reg.Counter("relay_collects_total", "Collect responses sent (long-poll)."),
		collected:     reg.Counter("relay_collected_messages_total", "Messages delivered (long-poll and WebSocket)."),
		acks:          reg.Counter("relay_acks_total", "Messages acknowledged and deleted."),
		revocations:   reg.Counter("relay_denylist_entries_total", "Denylist entries added."),
		rotations:     reg.Counter("relay_rotations_total", "Mailbox key rotations."),
		deletions:     reg.Counter("relay_mailbox_deletions_total", "Mailboxes deleted by their owners (rotated predecessors included)."),
		parked:        reg.Gauge("relay_parked_collectors", "Long-poll requests currently parked waiting for a deposit."),
		wsSessions:    reg.Gauge("relay_ws_sessions", "Open WebSocket collect sessions."),
		blobPuts:      reg.Counter("relay_blob_puts_total", "Blobs uploaded."),
		blobBytes:     reg.Counter("relay_blob_bytes_total", "Blob bytes uploaded."),
		blobGets:      reg.Counter("relay_blob_gets_total", "Blobs fetched."),
		blobDeletes:   reg.Counter("relay_blob_deletes_total", "Blob delete requests."),
		claimPuts:     reg.Counter("relay_claim_puts_total", "Claims created."),
		claimGets:     reg.Counter("relay_claim_fetches_total", "Claims fetched (and thereby deleted)."),
		storeQueries:  reg.Counter("relay_collect_store_queries_total", "Collect attempts that queried the store."),
		storeSkips:    reg.Counter("relay_collect_store_skips_total", "Collect attempts that skipped the store: mailbox known empty (empty hints)."),
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

// New builds the API server. By default the replay cache, rate limiters and
// wake-on-deposit are in-process, which is correct for exactly one relay
// process; multi-process deployments pass shared ones (WithReplayGuard,
// WithRateLimiters, WithWakeBus — see internal/coord).
func New(cfg config.Config, st store.Backend, log *slog.Logger, reg *metrics.Registry, opts ...Option) *Server {
	s := &Server{
		cfg:   cfg,
		st:    st,
		blobs: st,
		log:   log,
		m:     newServerMetrics(reg),
		now:   time.Now,
		mux:   http.NewServeMux(),
		hub:   newHub(),

		xfers:   newBlobTransfers(),
		blobRes: newBlobReservations(),

		byteLimit:     ratelimit.New(cfg.RateIPBytesPerSec, cfg.RateIPBytesBurst, 200_000),
		blobByteLimit: ratelimit.New(cfg.RateBlobBytesPerSec, cfg.RateBlobBytesBurst, 200_000),
		blobKeyLimit:  ratelimit.New(cfg.RateBlobKeyBytesPerSec, cfg.RateBlobKeyBytesBurst, 200_000),
		keyByteLimit:  ratelimit.New(cfg.RateKeyBytesPerSec, cfg.RateKeyBytesBurst, 200_000),

		replay:   auth.NewReplayCache(cfg.ReplayCacheMax),
		ipLimit:  ratelimit.New(cfg.RateIPPerSec, cfg.RateIPBurst, 200_000),
		keyLimit: ratelimit.New(cfg.RateKeyPerSec, cfg.RateKeyBurst, 200_000),
		regLimit: ratelimit.New(cfg.RateRegisterPerSec, cfg.RateRegisterBurst, 200_000),
		rl:       newLimiterMetrics(reg),

		smallBodyTimeout: smallBodyTimeout,
		blobPaceWindow:   config.BlobPaceWindow,
		healthTO:         healthPingTimeout,
		subLimit:         ratelimit.New(cfg.RateSenderPerSec, cfg.RateSenderBurst, 200_000),
		claimLimit:       ratelimit.New(cfg.RateClaimPerSec, cfg.RateClaimBurst, 200_000),
		webLimit:         ratelimit.New(cfg.RateWebPerSec, cfg.RateWebBurst, 100_000),
		hsts:             strings.HasPrefix(cfg.BaseURL, "https://"),
	}
	web, err := newWebDocs(cfg.AndroidPackage, cfg.AndroidCertFingerprints, s.hsts)
	if err != nil {
		panic("relay web documents: " + err.Error()) // the embedded page is malformed: a build defect
	}
	s.web = web
	s.drainCtx, s.drainCancel = context.WithCancel(context.Background())
	s.bgCtx, s.bgCancel = context.WithCancel(context.Background())
	for _, o := range opts {
		o(s)
	}
	s.routes()
	if rc, ok := s.replay.(interface{ Len() int }); ok {
		reg.GaugeFunc("relay_replay_cache_entries", "Entries in the signature replay cache.", func() int64 { return int64(rc.Len()) })
	}
	if lb, ok := log.Handler().(logCounts); ok {
		reg.CounterFunc("relay_log_lines_dropped_total", "Info log lines not written: over the log budget (RELAY_LOG_INFO_RPS).", lb.Dropped)
		reg.CounterFunc("relay_log_lines_suppressed_total", "Warn and error log lines not written: the same message was written in the last 10 s.", lb.Suppressed)
	}
	reg.GaugeFunc("relay_active_collectors", "Active collectors (parked long-polls and WebSocket sessions).", func() int64 { return int64(s.hub.collectors()) })
	reg.GaugeFunc("relay_draining", "1 while the relay is draining for shutdown.", func() int64 {
		if s.draining.Load() {
			return 1
		}
		return 0
	})
	s.every(15*time.Second, func(time.Time) {
		now := s.now()
		if c, ok := s.replay.(interface{ Sweep(time.Time) }); ok {
			c.Sweep(now)
		}
		for _, l := range []any{s.ipLimit, s.keyLimit, s.subLimit, s.regLimit, s.claimLimit, s.webLimit, s.byteLimit, s.blobByteLimit, s.blobKeyLimit, s.keyByteLimit} {
			if p, ok := l.(interface{ Prune(time.Time) }); ok {
				p.Prune(now)
			}
		}
		s.pruneNetClocks(now)
	})
	s.every(time.Minute, func(time.Time) { s.reportLimits() })
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.HandleFunc("POST /v1/register", s.handleRegister)
	s.mux.HandleFunc("POST /v1/mailbox/{mailbox_id}", s.handleDeposit)
	s.mux.HandleFunc("GET /v1/mailbox", s.handleCollect)
	s.mux.HandleFunc("GET /v1/mailbox/ws", s.handleWS)
	s.mux.HandleFunc("DELETE /v1/mailbox/{msg_id}", s.handleAck)
	s.mux.HandleFunc("POST /v1/mailbox/denylist", s.handleDenylist)
	s.mux.HandleFunc("POST /v1/mailbox/rotate", s.handleRotate)
	s.mux.HandleFunc("DELETE /v1/mailbox", s.handleDeleteMailbox)
	s.mux.HandleFunc("PUT /v1/claim", s.handleClaimPut)
	s.mux.HandleFunc("PUT /v1/claim/ttl/{ttl_seconds}", s.handleClaimPut)
	s.mux.HandleFunc("GET /v1/claim/{claim_id}", s.handleClaimGet)
	s.mux.HandleFunc("DELETE /v1/claim/{claim_id}", s.handleClaimDelete)
	if s.cfg.BlobsEnabled {
		s.mux.HandleFunc("PUT /v1/blob/{mailbox_id}", s.handleBlobPut)
		s.mux.HandleFunc("GET /v1/blob/{blob_id}", s.handleBlobGet)
		s.mux.HandleFunc("DELETE /v1/blob/{blob_id}", s.handleBlobDelete)
		s.mux.HandleFunc("POST /v1/blobs", s.handleBlobList)
	}
	s.webRoutes()
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { s.writeError(w, fail(CodeNotFound)) })
}

// Handler returns the public HTTP handler with the middleware chain.
func (s *Server) Handler() http.Handler {
	return withSecurityHeaders(s.hsts, s.withAccessLog(s.withIPRateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.m.requests.Inc()
		if r.Method != http.MethodConnect && !canonicalPath(r.URL.Path) {
			// ServeMux would redirect to the cleaned path; the relay
			// answers every non-canonical path with the ordinary 404.
			s.writeError(w, fail(CodeNotFound))
			return
		}
		s.mux.ServeHTTP(w, r)
	}))))
}

// healthPingTTL is how long /healthz answers from its last look at the
// store. /healthz is public and outside every rate limit (load balancers
// and vault hosts probe it), so what a request to it can cost is bounded
// here: one store read per interval per process, however many ask. A
// store that fails turns the answer within the interval (plus the read's
// own timeout); so does one that recovers.
const (
	healthPingTTL     = 2 * time.Second
	healthPingTimeout = 2 * time.Second
)

// storeHealth is the last store ping and when it finished.
type storeHealth struct {
	mu     sync.Mutex
	at     time.Time
	err    error
	looked bool
}

// storeReachable returns the outcome of a store ping no older than
// healthPingTTL. One caller at a time looks; the others wait for its
// answer and share it. The ping is not bound to the caller's request: a
// caller that goes away must not leave a failure behind for the others.
func (s *Server) storeReachable() error {
	h := &s.health
	h.mu.Lock()
	defer h.mu.Unlock()
	// A negative age is a clock set back: look again.
	if age := s.now().Sub(h.at); h.looked && age >= 0 && age < healthPingTTL {
		return h.err
	}
	// With its own deadline: a store that hangs must turn the answer to
	// unhealthy, not hold every /healthz caller behind this one.
	ctx, cancel := context.WithTimeout(context.Background(), s.healthTO)
	defer cancel()
	h.err = s.st.Ping(ctx)
	h.at, h.looked = s.now(), true
	if h.err != nil {
		s.log.Error("healthz: database unreachable", "err", h.err)
	}
	return h.err
}

// handleHealthz reports 200 when the database is reachable and the server is
// not draining; 503 otherwise (so load balancers stop routing during drain).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	if err := s.storeReachable(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "protocol": ProtocolVersion})
}

// Drain begins shutdown: parked long-polls return immediately, WebSocket
// sessions are closed with "going away", and /healthz turns 503. It then
// waits (bounded by ctx) for WebSocket sessions to finish. Call before
// http.Server.Shutdown, which does not track hijacked connections.
func (s *Server) Drain(ctx context.Context) error {
	s.streamMu.Lock()
	s.draining.Store(true)
	s.streamMu.Unlock()
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

// beginStream registers a WebSocket session unless draining has started.
func (s *Server) beginStream() bool {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.draining.Load() {
		return false
	}
	s.streams.Add(1)
	return true
}
