package api

import (
	"net/http"
	"sync"

	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Rate limiting (spec §7.2).
//
// A client network (an IPv4 address, an IPv6 /64) is the right key for a
// limit only while the caller is not authenticated: networks are shared
// (every vault of a vault host has the host's one address). So:
//
//	address   flood guard per network, first, before anything is parsed.
//	          It bounds everything one network can make the relay do:
//	          signature checks, replay records, store reads. Shared.
//	key       per signing key, once a request is authenticated: owner
//	          routes, registration, mailbox deletion. Shared.
//	sender    per sender key, on deposits after the signature. Shared.
//	register  new mailboxes (registration of a new key, rotation) per
//	          network. Registering an existing key again is free. Shared.
//	claim     unauthenticated claim fetches per network. Shared.
//	web       everything outside /v1/, per network. Per process.
//
// A WebSocket session passes address and key once, at its upgrade. Its ack
// frames are requests too: those the relay did not ask for by sending a
// message on that session draw on address and key again (ws.go).
//
// Nothing else is keyed on a network. A request properly signed by a key
// with a mailbox can be refused on account of its network only by the
// flood guard and, if it would create a mailbox, by the registration
// budget.
const (
	limAddress  = "address"
	limKey      = "key"
	limSender   = "sender"
	limRegister = "register"
	limClaim    = "claim"
	limWeb      = "web"
)

var allLimiters = []string{limAddress, limKey, limSender, limRegister, limClaim, limWeb}

// maxCounted bounds the per-minute tally of requests per network and per
// key (limiterMetrics.busiest); beyond it new ones go uncounted.
const maxCounted = 50_000

type limiterMetrics struct {
	allowed metrics.CounterVec
	refused metrics.CounterVec
	peak    metrics.GaugeVec
	busiest metrics.GaugeVec

	mu      sync.Mutex
	lastRef map[string]int64          // refused counts at the previous report
	count   map[string]map[string]int // this minute's requests, by limiter and key
	hit     map[string]struct{}       // networks the flood guard refused this minute
}

func newLimiterMetrics(reg *metrics.Registry) *limiterMetrics {
	m := &limiterMetrics{
		allowed: reg.CounterVec("relay_ratelimit_allowed_total", "Requests a rate limiter let through, by limiter.", "limiter"),
		refused: reg.CounterVec("relay_ratelimit_refused_total", "Requests a rate limiter refused (429 rate_limited), by limiter.", "limiter"),
		peak:    reg.GaugeVec("relay_ratelimit_peak_permille", "How full the busiest bucket of each limiter got during the last full minute, in thousandths of its burst (1000: something was refused).", "limiter"),
		busiest: reg.GaugeVec("relay_ratelimit_busiest_per_minute", "Requests of the busiest single client network (limiter address) and of the busiest single key (limiter key) during the last full minute.", "limiter"),
		lastRef: map[string]int64{},
		count:   map[string]map[string]int{limAddress: {}, limKey: {}},
		hit:     map[string]struct{}{},
	}
	for _, l := range allLimiters {
		m.allowed.With(l)
		m.refused.With(l)
		m.peak.With(l)
	}
	m.busiest.With(limAddress)
	m.busiest.With(limKey)
	return m
}

// tally counts one request for key under limiter (address or key), for
// the busiest-per-minute figures. Nothing of key is ever reported.
func (m *limiterMetrics) tally(limiter, key string, refused bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.count[limiter]
	if _, ok := c[key]; ok || len(c) < maxCounted {
		c[key]++
	}
	if refused && limiter == limAddress && len(m.hit) < maxCounted {
		m.hit[key] = struct{}{}
	}
}

// take consumes one token of limiter l for key, or returns the 429.
func (s *Server) take(name string, l RateLimiter, key string) *apiError {
	ok, wait := l.Allow(key, s.now())
	if name == limAddress || name == limKey {
		s.rl.tally(name, key, !ok)
	}
	if ok {
		s.rl.allowed.With(name).Inc()
		return nil
	}
	s.rl.refused.With(name).Inc()
	return &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)}
}

// allowKey applies the per-key bucket to a caller that has proved it holds
// key (its signature verified).
func (s *Server) allowKey(key []byte) *apiError {
	return s.take(limKey, s.keyLimit, auth.EncodeKey(key))
}

// allowSender applies the per-sender bucket (keyed by the token's sub, or
// the open token's jti).
func (s *Server) allowSender(sub string) *apiError {
	return s.take(limSender, s.subLimit, sub)
}

// allowRegistration applies the per-network budget of new mailboxes.
func (s *Server) allowRegistration(r *http.Request) *apiError {
	return s.take(limRegister, s.regLimit, rateKey(clientIP(r, s.cfg.TrustProxy)))
}

// refuseUnread answers a request whose body has not been read and will not
// be: the connection is closed after the answer, so that net/http does not
// first wait for a body the client may never send.
func (s *Server) refuseUnread(w http.ResponseWriter, r *http.Request, e *apiError) {
	if r.ContentLength != 0 {
		w.Header().Set("Connection", "close")
	}
	s.writeError(w, e)
}

// reportLimits publishes, once a minute, how close each limiter's busiest
// bucket came to its limit, how many requests the busiest network and the
// busiest key made, and how many collectors this process carries; and logs
// it. Nothing here names a client.
func (s *Server) reportLimits() {
	s.rl.mu.Lock()
	defer s.rl.mu.Unlock()
	peaks := map[string]float64{}
	for name, l := range map[string]RateLimiter{
		limAddress: s.ipLimit, limKey: s.keyLimit, limSender: s.subLimit,
		limRegister: s.regLimit, limClaim: s.claimLimit, limWeb: s.webLimit,
	} {
		if p, ok := l.(interface{ Peak() float64 }); ok {
			peaks[name] = p.Peak()
		}
	}
	attrs := make([]any, 0, 24)
	for _, name := range allLimiters {
		pm := int64(peaks[name] * 1000)
		s.rl.peak.With(name).Set(pm)
		total := s.rl.refused.With(name).Value()
		refused := total - s.rl.lastRef[name]
		s.rl.lastRef[name] = total
		attrs = append(attrs, name+"_peak", pm, name+"_refused", refused)
	}
	for _, name := range []string{limAddress, limKey} {
		most := 0
		for _, n := range s.rl.count[name] {
			most = max(most, n)
		}
		s.rl.busiest.With(name).Set(int64(most))
		seen := map[string]string{limAddress: "addresses_seen", limKey: "keys_seen"}[name]
		attrs = append(attrs, name+"_busiest_per_min", most, seen, len(s.rl.count[name]))
		s.rl.count[name] = map[string]int{}
	}
	attrs = append(attrs, "addresses_refused", len(s.rl.hit),
		"collectors", s.hub.collectors(), "parked", s.m.parked.Value(), "ws_sessions", s.m.wsSessions.Value())
	s.rl.hit = map[string]struct{}{}
	// At info level every minute: this line is what the limits are sized
	// from (how close a vault host is to the flood guard, how many
	// collectors a process carries). One line a minute per process.
	s.log.Info("rate limits", attrs...)
}
