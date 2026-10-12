package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
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
// The blast-radius rule that follows from it: nothing keyed on a network
// may refuse a request that is properly signed by a key with a mailbox,
// except the flood guard and the resource caps (collectors, body bytes),
// which are sized well above a full host.
//
//	address   flood guard per network, sized for a whole host's valid
//	          traffic. It bounds everything one network can make the relay
//	          do beyond checking signatures. Shared.
//	authfail  a small budget of failures nobody can be held to: wrong
//	          signatures, unsigned requests, unknown claims, unsigned
//	          refused deposits, and ONCE per key: a key that signs properly
//	          but has no mailbox, a replay, a stale timestamp. Per process.
//	          A network that has used it up is "penalised": requests
//	          without a key are refused unread, every other request has its
//	          signature checked before anything else (bounded by verify),
//	          and only then meets the flood guard, so that the network's
//	          bad requests cannot use up what its good ones need.
//	          Everything properly signed by a key with a mailbox is served.
//	          New mailboxes, claim fetches and deposits by signers without
//	          a mailbox get through at a trickle.
//	verify    signature checks per penalised network: the only work done
//	          for a request there before its signature is known to be good.
//	          Per process.
//	trickle   what a penalised network still gets of the things that wait.
//	          Per process.
//	nomailbox keys that signed an owner request properly and had no
//	          mailbox are remembered and held for 1 s, 2 s, 4 s ... (a
//	          client whose mailbox is gone and that keeps asking), until
//	          the key registers, on this process or (re-checked every few
//	          seconds) on another. Per process.
//	keyfail   refused deposits per properly signing sender key (an expired
//	          token, a peer that is gone): a small budget per sender and
//	          mailbox, and a larger one per sender. Its network is not
//	          charged if the key has a mailbox, and once per key otherwise.
//	          Per process.
//	key       per signing key, after authentication. Shared.
//	sender    per sender key, on deposits after the signature. Shared.
//	register  new mailboxes (registration, rotation) per network. Shared.
//	claim     unauthenticated claim fetches per network. Shared.
//	collectors parked long-polls and WebSocket sessions: per mailbox, per
//	          network and per process.
//	bodies    request body bytes being read: per network and per process.
//	web       everything outside /v1/, per network. Per process.
//
// Every refusal that depends on a key (held, over its refused deposits,
// over its bucket) is made only after that key's signature has verified,
// so only its holder ever sees it.
const (
	limAddress    = "address"
	limVerify     = "verify"
	limAuthFail   = "authfail"
	limTrickle    = "trickle"
	limTrickleAny = "trickleclaim"
	limNoMailbox  = "nomailbox"
	limKeyFail    = "keyfail"
	limKey        = "key"
	limSender     = "sender"
	limRegister   = "register"
	limClaim      = "claim"
	limWeb        = "web"
	limCollectors = "collectors"
	limBodies     = "bodies"
)

var allLimiters = []string{limAddress, limVerify, limAuthFail, limTrickle, limTrickleAny, limNoMailbox, limKeyFail, limKey, limSender, limRegister, limClaim, limWeb, limCollectors, limBodies}

const (
	// maxHeldKeys bounds each per-key table (keys without a mailbox, keys
	// already charged once, refused deposits): about 150 bytes a key. A
	// full table tracks no new key and charges nobody for it.
	maxHeldKeys = 50_000
	// perNetworkKeys is the share of each of those tables one client
	// network may fill: more than a full host's worth of keys, and little
	// enough that filling a table takes twenty networks.
	perNetworkKeys = maxHeldKeys / 20
	// localKeys bounds each in-process bucket table (per network or key).
	localKeys = 20_000
	// Small bodies being read: per process and per network.
	smallBodyPool, smallBodyPoolPerNetwork = 4 << 20, 512 << 10
	// wsMaxLifetime: a WebSocket session is closed (1013) after this long
	// and the client reconnects.
	wsMaxLifetime = time.Hour
	// holdRecheck is how often a held key's mailbox is looked up again:
	// it may have registered on another process.
	holdRecheck = 5 * time.Second
	// Refused deposits per (sender, mailbox): one peer that is gone must
	// not stop a sender's deposits to its other peers.
	pairFailRate, pairFailBurst = 0.1, 5
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
// an unsigned request, an unknown claim) to the request's network and
// returns the error to send.
func (s *Server) authFailed(w http.ResponseWriter, e *apiError) *apiError {
	if st := stateOf(w); st.addr != "" {
		s.chargeNetwork(st.addr)
	}
	return e
}

// keyFailedOnce charges a failure of a request that carries key's good
// signature, but that its holder cannot be punished for: a timestamp
// outside the window (a wrong clock) or a replay (a retry bug; or someone
// else re-sending what they saw, which must not be a way to hold a key).
// The network pays once per key, kind and window (the cap of a penalty),
// not once per repeat: one such client behind an address costs it one unit
// a minute, while a whole host of them (a wrong host clock) keeps its
// address in signature-first mode for as long as it lasts, so that their
// requests do not use up the flood guard the correct ones will need.
func (s *Server) keyFailedOnce(w http.ResponseWriter, e *apiError, kind string, key []byte) *apiError {
	st := stateOf(w)
	if st.addr == "" {
		return e
	}
	k, now := kind+auth.EncodeKey(key), s.now()
	if s.onceSeen.Has(k, now) {
		return e // already paid for in this window (the entry is not renewed)
	}
	s.onceSeen.AddIn(st.addr, k, now, true)
	// A full table remembers nothing: then nobody is charged, or one
	// client's repeats would be charged to its network every time.
	if s.onceSeen.Has(k, now) {
		s.chargeNetwork(st.addr)
	}
	return e
}

// noMailbox handles a request that was properly signed (and no replay) by
// a key that has no mailbox. The key is remembered and held, for longer
// each time it comes back (held); its network is charged once, when the
// key is first seen, not on every repeat. So one client whose mailbox is
// gone costs its network one unit however long it keeps asking, and
// someone making fresh keys still pays the network for each.
func (s *Server) noMailbox(w http.ResponseWriter, e *apiError, key []byte) *apiError {
	st := stateOf(w)
	if st.addr == "" {
		return e
	}
	if s.orphans.FailIn(st.addr, auth.EncodeKey(key), s.now()) {
		s.chargeNetwork(st.addr)
	}
	return e
}

// held refuses a properly signed request by a key that is held for having
// no mailbox. Registration is exempt: it is the way out. Because the key
// may have registered on another relay process since, its mailbox is
// looked up again every holdRecheck before a refusal. The caller has
// verified the signature, so only the key's holder is ever answered from
// this table.
func (s *Server) held(r *http.Request, key []byte) *apiError {
	if r.Method == http.MethodPost && r.URL.Path == "/v1/register" {
		return nil
	}
	k, now := auth.EncodeKey(key), s.now()
	wait := s.orphans.Wait(k, now)
	if wait <= 0 {
		return nil
	}
	if s.orphans.Recheck(k, now, holdRecheck) && s.hasMailbox(r.Context(), key) {
		s.orphans.Clear(k)
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

func pairKey(senderB64, mailbox string) string { return senderB64 + "|" + mailbox }

// depositFailed charges a refused deposit (§5.3 steps 1–7) to whoever it
// belongs to. Properly signed by a key with a mailbox (a vault whose token
// expired, or whose peer is gone): the sender key's own budgets of refused
// deposits, one per mailbox and one overall; its network is never charged.
// Anything else: the network.
// signed is the verified signature if the caller has checked it; if not,
// it is checked here when the body can be had (hash non-nil), and recorded
// against replay, so that a captured failing deposit cannot be sent again
// to run up its sender's budget.
func (s *Server) depositFailed(w http.ResponseWriter, r *http.Request, e *apiError, mailboxID string, signed *auth.SignedRequest, hash func() *[32]byte) *apiError {
	if stateOf(w).addr == "" {
		return e
	}
	now := s.now()
	if signed == nil && hash != nil {
		// Whose failure is it? Finding out takes the body (for the
		// signature), and a body is not read for just anyone: only if the
		// key the request names has a mailbox. Anything else is its
		// network's failure, unread.
		if sr, err := auth.ParseHeaders(r.Header); err == nil && s.hasMailbox(r.Context(), sr.Key) {
			if h := hash(); h != nil && sr.Verify(r.Method, r.URL.EscapedPath(), *h, now) == nil {
				switch err := s.replay.Check(sr, now); {
				case err == nil:
					signed = &sr
				case errors.Is(err, auth.ErrReplay):
					return s.keyFailedOnce(w, e, onceReplay, sr.Key)
				default: // cannot be recorded now: nobody is charged
					return e
				}
			}
		}
	}
	if signed == nil {
		return s.authFailed(w, e)
	}
	// The key's own budgets, per peer and overall.
	k := auth.EncodeKey(signed.Key)
	s.pairFails.Charge(pairKey(k, mailboxID), now)
	s.keyFails.Charge(k, now)
	// A signer with a mailbox never costs its network anything. One
	// without (it got here through a penalised network's trickle) costs it
	// one unit a minute, like the other failures a key cannot answer for.
	if !s.hasMailbox(r.Context(), signed.Key) {
		return s.keyFailedOnce(w, e, onceDeposit, signed.Key)
	}
	return e
}

const (
	onceStale   = "s|"
	onceReplay  = "r|"
	onceDeposit = "d|"
)

// senderOverFailures is the 429 for a deposit by a sender key that has
// used up its budget of refused deposits, to this mailbox or overall. It
// reads the key from the header: the caller answers with it only once the
// signature has verified.
func (s *Server) senderOverFailures(r *http.Request, mailboxID string) *apiError {
	k := headerKey(r)
	if k == "" {
		return nil
	}
	now := s.now()
	wait := max(s.keyFails.Wait(k, now), s.pairFails.Wait(pairKey(k, mailboxID), now))
	if wait <= 0 {
		return nil
	}
	return &apiError{code: CodeRateLimited, retryAfter: min(ratelimit.RetryAfterSeconds(wait), maxPenaltyRetry)}
}

// bodyPool counts memory held for request bodies that are being read. The
// count grows as bytes arrive, never by what a request announces: a client
// that announces a body and sends nothing holds nothing.
//
// There are three pools, so that none can be filled, by requests that cost
// nothing to make, at the expense of requests that have earned their place
// (spec §7.2 item 8):
//
//	small   bodies of at most smallBodyLimit: registrations, rotations,
//	        denylist updates, claims. They are read before the signature
//	        can be checked, and they are tiny.
//	open    deposit bodies read before the request is authenticated: on a
//	        penalised network (signature first), and to tell whose failure
//	        a refused deposit is. A small share per network.
//	keyed   deposit bodies read after the deposit token has verified
//	        (§5.3 steps 1–6): nothing unauthenticated ever counts here.
type bodyPool struct {
	max, maxNet int64

	mu     sync.Mutex
	total  int64
	perNet map[string]int64
	peak   int64 // thousandths of max, since the last report
}

func newBodyPool(max, maxNet int64) *bodyPool {
	return &bodyPool{max: max, maxNet: maxNet, perNet: map[string]int64{}}
}

func (p *bodyPool) take(net string, n int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.total+n > p.max || net != "" && p.perNet[net]+n > p.maxNet {
		p.peak = 1000
		return false
	}
	p.total += n
	if net != "" {
		p.perNet[net] += n
	}
	if used := p.total * 1000 / p.max; used > p.peak {
		p.peak = used
	}
	return true
}

func (p *bodyPool) give(net string, n int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total -= n
	if net != "" {
		if p.perNet[net] -= n; p.perNet[net] <= 0 {
			delete(p.perNet, net)
		}
	}
}

func (p *bodyPool) inFlight() (total int64, nets int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total, len(p.perNet)
}

func (p *bodyPool) takePeak() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.peak
	p.peak = 0
	return v
}

// bodyPace is how fast a body has to arrive: something every idle, all of
// it within total.
type bodyPace struct{ idle, total time.Duration }

// Before a request is authenticated its body has to come promptly: a
// largest deposit (about 350 KiB) in 20 s is 140 kbit/s. That only applies
// to deposits on a penalised network and to small bodies (16 KiB in 20 s:
// 7 kbit/s). Once the deposit token has verified the sender has minutes,
// as before: 350 KiB in 5 minutes is under 10 kbit/s.
var (
	paceOpen  = bodyPace{idle: 5 * time.Second, total: 20 * time.Second}
	paceKeyed = bodyPace{idle: 30 * time.Second, total: 5 * time.Minute}
)

const bodyChunk = 4096

// readBodyFrom reads a request body of at most limit bytes, counting the
// memory it holds against pool as it grows and holding the sender to pace.
func (s *Server) readBodyFrom(w http.ResponseWriter, r *http.Request, limit int64, pool *bodyPool, pace bodyPace) ([]byte, *apiError) {
	if r.ContentLength > limit {
		return nil, fail(CodePayloadTooLarge)
	}
	if r.ContentLength == 0 {
		return []byte{}, nil
	}
	want := limit // the most the buffer may have to hold
	if r.ContentLength > 0 {
		want = r.ContentLength
	}
	addr := stateOf(w).addr
	held := min(bodyChunk, want)
	refuse := func() ([]byte, *apiError) {
		s.rl.refused.With(limBodies).Inc()
		return nil, &apiError{code: CodeRateLimited, retryAfter: 1 + s.jitter()}
	}
	if !pool.take(addr, held) {
		return refuse()
	}
	defer func() { pool.give(addr, held) }()
	buf := make([]byte, 0, held)
	src := http.MaxBytesReader(w, r.Body, limit)
	rc := http.NewResponseController(w)
	start, timed := time.Now(), true
	for {
		if len(buf) == cap(buf) {
			if int64(cap(buf)) >= want && r.ContentLength > 0 {
				break
			}
			grown := min(2*int64(cap(buf)), want)
			if grown == int64(cap(buf)) {
				grown++ // length not declared and limit reached: room for the byte that proves it too long
			}
			if !pool.take(addr, grown-held) {
				return refuse()
			}
			held = grown
			buf = append(make([]byte, 0, grown), buf...)
		}
		if timed {
			deadline := start.Add(pace.total)
			if d := time.Now().Add(pace.idle); d.Before(deadline) {
				deadline = d
			}
			timed = rc.SetReadDeadline(deadline) == nil
		}
		n, err := src.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		var mbe *http.MaxBytesError
		switch {
		case err == io.EOF:
		case errors.As(err, &mbe):
			return nil, fail(CodePayloadTooLarge)
		case err != nil:
			return nil, fail(CodeBadRequest) // also: too slow
		default:
			continue
		}
		break
	}
	if timed {
		rc.SetReadDeadline(time.Time{})
	}
	if r.ContentLength > 0 && int64(len(buf)) != r.ContentLength {
		return nil, fail(CodeBadRequest)
	}
	return buf, nil
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
// penalised network they get through at a trickle only.
func (s *Server) allowRegistration(w http.ResponseWriter) *apiError {
	st := stateOf(w)
	if st.addr == "" {
		return nil
	}
	if st.penalised {
		if e := s.take(limTrickle, s.trickle, st.addr, true); e != nil {
			return e
		}
	}
	return s.take(limRegister, s.regLimit, st.addr, false)
}

// refuseCollector is the answer when a mailbox, its network or this
// process already has its maximum of concurrent collectors.
func (s *Server) refuseCollector(why string) *apiError {
	s.rl.refused.With(limCollectors).Inc()
	if why == fullMailbox {
		return &apiError{code: CodeRateLimited, retryAfter: 1}
	}
	return &apiError{code: CodeRateLimited, retryAfter: 1 + s.jitter()} // many clients at once
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
		limAddress: s.addrLimit, limVerify: s.verifyLimit, limAuthFail: s.fails, limTrickle: s.trickle, limTrickleAny: s.trickleClaim, limKeyFail: s.keyFails, limKey: s.keyLimit, limSender: s.subLimit,
		limRegister: s.regLimit, limClaim: s.claimLimit, limWeb: s.webLimit,
	} {
		if p, ok := l.(interface{ Peak() float64 }); ok {
			peaks[name] = p.Peak()
		}
	}
	peaks[limBodies] = float64(max(s.smallBodies.takePeak(), s.openBodies.takePeak(), s.keyedBodies.takePeak())) / 1000
	peaks[limCollectors] = float64(s.hub.collectors()) / float64(s.cfg.MaxCollectors)
	s.rl.penalised.Set(int64(s.fails.Exhausted(now)))
	attrs := make([]any, 0, 4*len(allLimiters))
	notable := false
	for _, name := range allLimiters {
		pm := int64(peaks[name] * 1000)
		s.rl.peak.With(name).Set(pm)
		total := s.rl.refused.With(name).Value()
		refused := total - s.rl.lastRef[name]
		s.rl.lastRef[name] = total
		if name != limNoMailbox {
			attrs = append(attrs, name+"_peak", pm)
		}
		attrs = append(attrs, name+"_refused", refused)
		// The web bucket is hit by scanners all day and says nothing about
		// members; it is reported but does not make the line notable.
		if name != limWeb && (refused > 0 || pm >= limitsLogThreshold) {
			notable = true
		}
	}
	// The absolute number, for scaling the service on (the peak above is
	// relative to one process's cap).
	attrs = append(attrs, "collectors", s.hub.collectors())
	if notable {
		s.log.Info("rate limits", attrs...)
	} else {
		s.log.Debug("rate limits", attrs...)
	}
}

// limitsLogThreshold: a limiter whose busiest bucket was at least half used
// in a minute makes that minute's "rate limits" line an info line.
const limitsLogThreshold = 500
