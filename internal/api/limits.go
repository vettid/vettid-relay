package api

import (
	"context"
	"crypto/subtle"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Rate limiting (spec §7.2).
//
// The principle: a client network (an IPv4 address, an IPv6 /64) is the
// right key only while the caller is not authenticated. Networks are
// shared: every vault of a vault host has the host's one address. So a
// limit is keyed by the signing key as soon as there is one, and the same
// goes for penalties: a failure of a properly signed request belongs to
// its key.
//
// The blast-radius rule that follows from it: beyond the flood guard,
// nothing keyed on a network may refuse a request that is properly signed
// by a key with a mailbox.
//
//	address   flood guard per network, sized for a whole host's valid
//	          traffic. It bounds everything one network can make the relay
//	          do beyond checking signatures. Shared.
//	authfail  a small budget of failures nobody can be held to: wrong
//	          signatures, unsigned requests, replays, unknown claims,
//	          unsigned refused deposits, and the FIRST failure of each key
//	          that signs properly but has no mailbox (keys are free to
//	          make, so each new one is the network's). Per process.
//	          A network that has used it up is "penalised": requests
//	          without a key are refused unread, every other request has its
//	          signature checked before anything else (bounded by verify),
//	          and only then meets the flood guard, so that the network's
//	          bad requests cannot use up what its good ones need. New
//	          mailboxes, and deposits by signers without a mailbox, wait.
//	          Everything properly signed by a key with a mailbox is served.
//	verify    signature checks per penalised network: the only work done
//	          for a request there before its signature is known to be good.
//	          Per process.
//	nomailbox keys that signed an owner request properly and had no
//	          mailbox are remembered and held for 1 s, 2 s, 4 s ... (a
//	          client whose mailbox is gone and that keeps asking): refused
//	          by reading one header, until the key registers. Per process.
//	keyfail   refused deposits per properly signing sender key (an expired
//	          token, a peer that is gone): the key's own small budget. Its
//	          network is not charged if the key has a mailbox, and once per
//	          key otherwise. Per process.
//	key       per signing key, after authentication. Shared.
//	sender    per sender key, on deposits after the signature. Shared.
//	register  new mailboxes (registration, rotation) per network. Shared.
//	claim     unauthenticated claim fetches per network. Shared.
//	web       everything outside /v1/, per network. Per process.
//
// No limit answers differently depending on whether a mailbox exists, except
// to the holder of its key (who is told mailbox_unknown anyway).
const (
	limAddress    = "address"
	limVerify     = "verify"
	limAuthFail   = "authfail"
	limNoMailbox  = "nomailbox"
	limKeyFail    = "keyfail"
	limKey        = "key"
	limSender     = "sender"
	limRegister   = "register"
	limClaim      = "claim"
	limWeb        = "web"
	limCollectors = "collectors"
)

var allLimiters = []string{limAddress, limVerify, limAuthFail, limNoMailbox, limKeyFail, limKey, limSender, limRegister, limClaim, limWeb, limCollectors}

const (
	// maxHeldKeys bounds the table of keys without a mailbox, and the table
	// of keys already charged for a stale timestamp (about 150 bytes each).
	maxHeldKeys = 200_000
	// holdBase is the first hold of a key found without a mailbox.
	holdBase = time.Second
	// retryJitterMax spreads the retry_after of refusals that hit many
	// clients of one network at once, so they do not all return together.
	retryJitterMax = 4
	// maxPenaltyRetry caps the retry_after of penalties (a client sleeps
	// that long inside one call).
	maxPenaltyRetry = 60
)

type limiterMetrics struct {
	allowed   metrics.CounterVec
	refused   metrics.CounterVec
	peak      metrics.GaugeVec
	mu        sync.Mutex
	lastRef   map[string]int64 // refused counts at the previous report
	penalised metrics.Gauge
	charged   metrics.Counter
}

func newLimiterMetrics(reg *metrics.Registry) *limiterMetrics {
	m := &limiterMetrics{
		allowed:   reg.CounterVec("relay_ratelimit_allowed_total", "Requests a rate limiter let through, by limiter.", "limiter"),
		refused:   reg.CounterVec("relay_ratelimit_refused_total", "Requests a rate limiter refused (429 rate_limited), by limiter.", "limiter"),
		peak:      reg.GaugeVec("relay_ratelimit_peak_permille", "How full the busiest bucket of each limiter got during the last full minute, in thousandths (1000: something was refused).", "limiter"),
		penalised: reg.Gauge("relay_ratelimit_penalised_networks", "Client networks currently out of failed-authentication budget."),
		charged:   reg.Counter("relay_ratelimit_authfail_charged_total", "Failures charged to a client network's failed-authentication budget."),
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
	admitted  bool   // the flood guard has been passed
}

func stateOf(w http.ResponseWriter) *reqState {
	if rec, ok := w.(*recorder); ok {
		return &rec.rl
	}
	return &reqState{admitted: true}
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

// penalty returns the 429 for a network that is out of failed-
// authentication budget, or nil if it has budget.
func (s *Server) penalty(addr string) *apiError {
	wait := s.fails.Wait(addr, s.now())
	if wait <= 0 {
		return nil
	}
	return &apiError{code: CodeRateLimited, retryAfter: min(ratelimit.RetryAfterSeconds(wait), maxPenaltyRetry) + s.jitter()}
}

// floodGuard is the flood guard for one request, taken once. On a network
// with budget the middleware takes it before anything else; on a penalised
// one it is taken only once the request's signature has verified.
func (s *Server) floodGuard(w http.ResponseWriter) *apiError {
	st := stateOf(w)
	if st.admitted || st.addr == "" {
		return nil
	}
	if e := s.take(limAddress, s.addrLimit, st.addr, true); e != nil {
		return e
	}
	st.admitted = true
	return nil
}

// chargeNetwork uses one unit of a network's failed-authentication budget.
func (s *Server) chargeNetwork(addr string) {
	s.fails.Charge(addr, s.now())
	s.rl.charged.Inc()
}

// authFailed charges a failure nobody can be held to (a wrong signature,
// an unsigned request, a replay, an unknown claim) to the request's
// network and returns the error to send.
func (s *Server) authFailed(w http.ResponseWriter, e *apiError) *apiError {
	if st := stateOf(w); st.addr != "" {
		s.chargeNetwork(st.addr)
	}
	return e
}

// staleFailed charges a properly signed request with a timestamp outside
// the freshness window: a client with a wrong clock, retrying. It is its
// key's failure; the network pays once per key (keys are free), not once
// per retry. The key is not held: an old request can be sent again by
// anyone who saw it, and that must not be a way to hold someone's key.
func (s *Server) staleFailed(w http.ResponseWriter, e *apiError, key []byte) *apiError {
	st := stateOf(w)
	if st.addr == "" {
		return e
	}
	k, now := auth.EncodeKey(key), s.now()
	if !s.staleSeen.Has(k, now) { // also when the table is full and remembers nothing
		s.chargeNetwork(st.addr)
	}
	s.staleSeen.Add(k, now, true)
	return e
}

// noMailbox handles a request that was properly signed (and no replay) by
// a key that has no mailbox. The key is remembered and held, for longer
// each time it comes back (the middleware then refuses it by its header
// alone, heldKey); its network is charged once, when the key is first
// seen, not on every repeat. So one client whose mailbox is gone costs its
// network one unit however long it keeps asking, and someone making fresh
// keys still pays the network for each.
func (s *Server) noMailbox(w http.ResponseWriter, e *apiError, key []byte) *apiError {
	st := stateOf(w)
	if st.addr == "" {
		return e
	}
	now := s.now()
	if s.orphans.Fail(auth.EncodeKey(key), now) {
		s.chargeNetwork(st.addr)
	}
	return e
}

// heldKey refuses a request naming a key that is held for having no
// mailbox, by reading one header. Registration is exempt: it is the way
// out. The header is not verified: only properly signed requests ever put
// a key here, and all the answer says is what anyone who knows a public
// key can ask the relay anyway (§5.3 step 1).
func (s *Server) heldKey(r *http.Request) *apiError {
	k := headerKey(r)
	if k == "" || r.Method == http.MethodPost && r.URL.Path == "/v1/register" {
		return nil
	}
	wait := s.orphans.Wait(k, s.now())
	if wait <= 0 {
		return nil
	}
	s.rl.refused.With(limNoMailbox).Inc()
	return &apiError{code: CodeRateLimited, retryAfter: min(ratelimit.RetryAfterSeconds(wait), maxPenaltyRetry)}
}

// hasMailbox reports whether key is the registered key of its mailbox.
func (s *Server) hasMailbox(ctx context.Context, key []byte) bool {
	mb, err := s.st.Mailbox(ctx, auth.MailboxID(key))
	return err == nil && subtle.ConstantTimeCompare(mb.PubKey, key) == 1
}

// depositFailed charges a refused deposit (§5.3 steps 1–7) to whoever it
// belongs to. Properly signed (a vault whose token expired, or whose peer
// is gone): the key's own small budget of refused deposits; its network is
// never charged if the key has a mailbox, and once per key otherwise. Not
// properly signed: the network. signed is the verified
// signature if the caller has checked it; if not, it is checked here when
// the body has been read (bodyHash non-nil), one verification on a path
// that is budgeted anyway.
func (s *Server) depositFailed(w http.ResponseWriter, r *http.Request, e *apiError, signed *auth.SignedRequest, bodyHash *[32]byte) *apiError {
	if stateOf(w).addr == "" {
		return e
	}
	now := s.now()
	if signed == nil && bodyHash != nil {
		if sr, err := auth.ParseHeaders(r.Header); err == nil && sr.Verify(r.Method, r.URL.EscapedPath(), *bodyHash, now) == nil {
			signed = &sr
		}
	}
	if signed == nil {
		return s.authFailed(w, e)
	}
	// The key's own budget. Its network pays only for a key without a
	// mailbox (free to make), and then once, not per repeat.
	if first := s.keyFails.Charge(auth.EncodeKey(signed.Key), now); first && !s.hasMailbox(r.Context(), signed.Key) {
		s.chargeNetwork(stateOf(w).addr)
	}
	return e
}

// senderOverFailures refuses a deposit naming a sender key that has used
// up its budget of refused deposits. The header is not verified here: only
// properly signed failures were ever charged to the key, so nobody else
// can run it up.
func (s *Server) senderOverFailures(r *http.Request) *apiError {
	k := headerKey(r)
	if k == "" {
		return nil
	}
	wait := s.keyFails.Wait(k, s.now())
	if wait <= 0 {
		return nil
	}
	s.rl.refused.With(limKeyFail).Inc()
	return &apiError{code: CodeRateLimited, retryAfter: min(ratelimit.RetryAfterSeconds(wait), maxPenaltyRetry)}
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

// allowRegistration applies the per-network budget of new mailboxes. On a
// penalised network new mailboxes wait.
func (s *Server) allowRegistration(w http.ResponseWriter) *apiError {
	st := stateOf(w)
	if st.addr == "" {
		return nil
	}
	if st.penalised {
		if e := s.penalty(st.addr); e != nil {
			s.rl.refused.With(limAuthFail).Inc()
			return e
		}
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
		limAddress: s.addrLimit, limVerify: s.verifyLimit, limAuthFail: s.fails, limKeyFail: s.keyFails, limKey: s.keyLimit, limSender: s.subLimit,
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
		if name != limCollectors && name != limNoMailbox {
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
