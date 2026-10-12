package api

import (
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Rate limiting (spec §7.2). The principle: a client network (an IPv4
// address, an IPv6 /64) is the right key only while the caller is not
// authenticated; once a request is attributed to a key, that key is limited,
// so that a host carrying a thousand vaults, or a carrier NAT carrying many
// phones, is not one bucket.
//
//	authfail  a small budget of FAILED authentications per network (bad
//	          signature, stale timestamp, replay, unknown mailbox, bad token,
//	          unknown claim). While a network has used it up, the relay does
//	          no unauthenticated work for it: only requests carrying a key
//	          that authenticated from that network recently are looked at.
//	          Per process, in memory: it is checked first and costs a map
//	          lookup, so a penalised network's flood costs nothing more.
//	address   before anything is parsed: a flood guard per network. It is
//	          sized for a whole host's worth of valid traffic and bounds what
//	          one network can make the relay do, valid keys or not. Shared.
//	key       after authentication: per signing key, on owner routes,
//	          registration and deletion. Shared.
//	sender    after the deposit's signature and token verify: per sender
//	          key. Shared.
//	register  new mailboxes (registration, rotation) per network. Shared.
//	claim     unauthenticated claim fetches per network. Shared.
//	web       everything outside /v1/, per network. Per process.
//
// No limit answers differently depending on whether a mailbox or key
// exists: the network limits never look at the target, and the key limits
// apply only after the caller has proved the key is its own.
const (
	limAddress    = "address"
	limAuthFail   = "authfail"
	limKey        = "key"
	limSender     = "sender"
	limRegister   = "register"
	limClaim      = "claim"
	limWeb        = "web"
	limCollectors = "collectors"
)

var allLimiters = []string{limAddress, limAuthFail, limKey, limSender, limRegister, limClaim, limWeb, limCollectors}

const (
	// knownKeyTTL is how long a key stays "recently authenticated" from a
	// network after its last successful request. Several long-poll periods:
	// an idle collector refreshes it every 25 s.
	knownKeyTTL = 10 * time.Minute
	// maxKnownKeys bounds that set (about 150 bytes each).
	maxKnownKeys = 200_000
	// retryJitterMax spreads the retry_after of refusals that hit many
	// clients of one network at once, so they do not all return together.
	retryJitterMax = 4
	// maxPenaltyRetry caps the retry_after told to a penalised network.
	maxPenaltyRetry = 60
)

type limiterMetrics struct {
	allowed   metrics.CounterVec
	refused   metrics.CounterVec
	peak      metrics.GaugeVec
	mu        sync.Mutex
	lastRef   map[string]int64 // refused counts at the previous report
	penalised metrics.Gauge
}

func newLimiterMetrics(reg *metrics.Registry) *limiterMetrics {
	m := &limiterMetrics{
		allowed:   reg.CounterVec("relay_ratelimit_allowed_total", "Requests a rate limiter let through, by limiter.", "limiter"),
		refused:   reg.CounterVec("relay_ratelimit_refused_total", "Requests a rate limiter refused (429 rate_limited), by limiter.", "limiter"),
		peak:      reg.GaugeVec("relay_ratelimit_peak_permille", "How full the busiest bucket of each limiter got during the last full minute, in thousandths (1000: something was refused).", "limiter"),
		penalised: reg.Gauge("relay_ratelimit_penalised_networks", "Client networks currently out of failed-authentication budget."),
		lastRef:   map[string]int64{},
	}
	for _, l := range allLimiters {
		m.allowed.With(l)
		m.refused.With(l)
		m.peak.With(l)
	}
	return m
}

// reqState is what the middleware learned about a request before its
// handler ran. It lives on the access-log recorder.
type reqState struct {
	addr      string // rate key of the client network
	penalised bool   // the network is out of failed-authentication budget
}

func stateOf(w http.ResponseWriter) *reqState {
	if rec, ok := w.(*recorder); ok {
		return &rec.rl
	}
	return &reqState{}
}

// take consumes one token of limiter l for key, or returns the 429. With
// crowd set the retry_after is spread (many clients share the key).
func (s *Server) take(name string, l RateLimiter, key string, crowd bool) *apiError {
	ok, wait := l.Allow(key, s.now())
	if ok {
		s.rl.allowed.With(name).Inc()
		return nil
	}
	s.rl.refused.With(name).Inc()
	ra := ratelimit.RetryAfterSeconds(wait)
	if crowd {
		ra += s.jitter()
	}
	return &apiError{code: CodeRateLimited, retryAfter: ra}
}

func (s *Server) jitter() int {
	if s.retryJitter != nil {
		return s.retryJitter()
	}
	return rand.IntN(retryJitterMax + 1)
}

// headerKey returns the request's X-VettID-Key value if it has the shape
// of one (nothing is decoded or verified), else "".
func headerKey(r *http.Request) string {
	v := r.Header.Values(auth.HeaderKey)
	if len(v) != 1 || len(v[0]) != 44 {
		return ""
	}
	return v[0]
}

func knownKey(addr, key string) string { return addr + "|" + key }

// penalty returns the 429 for a network that is out of failed-
// authentication budget, or nil if it has budget.
func (s *Server) penalty(addr string) *apiError {
	wait := s.fails.Wait(addr, s.now())
	if wait <= 0 {
		return nil
	}
	return &apiError{code: CodeRateLimited, retryAfter: min(ratelimit.RetryAfterSeconds(wait), maxPenaltyRetry) + s.jitter()}
}

// authFailed charges one failed authentication to the request's network
// and returns the error to send. key, if not nil, is a key the request
// was proved to come from (its signature verified and was not a replay):
// it stops counting as recently authenticated, so its holder cannot keep
// failing on a penalised network. A failure nobody proved a key for never
// removes one, or anyone could do that to someone else's.
//
// uniform is set for failures of the signature itself. On a penalised
// network they are answered with the same 429 as a request carrying an
// unknown key, so that the answer does not say whether a key has been
// authenticating from the caller's own network.
func (s *Server) authFailed(w http.ResponseWriter, e *apiError, key []byte, uniform bool) *apiError {
	st := stateOf(w)
	if st.addr == "" {
		return e
	}
	s.fails.Charge(st.addr, s.now())
	if key != nil {
		s.known.Remove(knownKey(st.addr, auth.EncodeKey(key)))
	}
	if uniform && st.penalised {
		if p := s.penalty(st.addr); p != nil {
			s.rl.refused.With(limAuthFail).Inc()
			return p
		}
	}
	return e
}

// authenticated records that key just authenticated from the request's
// network. A penalised network gets no new keys this way (or it could buy
// each further failure with one cheap valid request); a key it already has
// is kept alive.
func (s *Server) authenticated(w http.ResponseWriter, key []byte) {
	st := stateOf(w)
	if st.addr == "" {
		return
	}
	s.known.Add(knownKey(st.addr, auth.EncodeKey(key)), s.now(), !st.penalised)
}

// allowKey applies the per-key bucket to a caller that has proved it holds
// key.
func (s *Server) allowKey(key []byte) *apiError {
	return s.take(limKey, s.keyLimit, auth.EncodeKey(key), false)
}

// allowSender applies the per-sender bucket (keyed by the token's sub, or
// the open token's jti).
func (s *Server) allowSender(sub string) *apiError {
	return s.take(limSender, s.subLimit, sub, false)
}

// allowRegistration applies the per-network budget of new mailboxes.
func (s *Server) allowRegistration(w http.ResponseWriter) *apiError {
	st := stateOf(w)
	if st.addr == "" {
		return nil
	}
	return s.take(limRegister, s.regLimit, st.addr, false)
}

// refuseCollector is the answer when a mailbox already has its maximum of
// concurrent collectors.
func (s *Server) refuseCollector() *apiError {
	s.rl.refused.With(limCollectors).Inc()
	return &apiError{code: CodeRateLimited, retryAfter: 1}
}

// reportLimits publishes, once a minute, how close each limiter's busiest
// bucket came to its limit, and logs it when anything was refused or came
// within reach of a limit. Nothing here names a client.
func (s *Server) reportLimits() {
	s.rl.mu.Lock()
	defer s.rl.mu.Unlock()
	now := s.now()
	peaks := map[string]float64{}
	for name, l := range map[string]any{
		limAddress: s.addrLimit, limAuthFail: s.fails, limKey: s.keyLimit, limSender: s.subLimit,
		limRegister: s.regLimit, limClaim: s.claimLimit, limWeb: s.webLimit,
	} {
		if p, ok := l.(interface{ Peak() float64 }); ok {
			peaks[name] = p.Peak()
		}
	}
	s.rl.penalised.Set(int64(s.fails.Exhausted(now)))
	attrs := make([]any, 0, 4*len(allLimiters))
	notable := false
	for _, name := range allLimiters {
		pm := int64(peaks[name] * 1000)
		s.rl.peak.With(name).Set(pm)
		total := s.rl.refused.With(name).Value()
		refused := total - s.rl.lastRef[name]
		s.rl.lastRef[name] = total
		if name != limCollectors {
			attrs = append(attrs, name+"_peak", pm)
		}
		attrs = append(attrs, name+"_refused", refused)
		// The web bucket is hit by scanners all day and says nothing about
		// members; it is reported but does not make the line notable.
		if name != limWeb && (refused > 0 || pm >= limitsLogThreshold) {
			notable = true
		}
	}
	if notable {
		s.log.Info("rate limits", attrs...)
	} else {
		s.log.Debug("rate limits", attrs...)
	}
}

// limitsLogThreshold: a limiter whose busiest bucket was at least half used
// in a minute makes that minute's "rate limits" line an info line.
const limitsLogThreshold = 500
