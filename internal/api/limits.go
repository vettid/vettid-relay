package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/internal/logbudget"
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
// Two byte budgets per network bound what one network can make the relay
// store and move, whatever number of keys and mailboxes it holds. They are
// charged with a request's declared length (Content-Length) before its
// body is read. Shared (relay-wide, proposed for 0.9.4: with several
// processes on one store, a per-process ceiling multiplied by the process
// count could take the store's whole write capacity):
//
//	bytes       deposits (after §5.3 steps 1–6) and claims (after the
//	            claim's signature verified).
//	blob_bytes  blob uploads (after the token checks) and downloads
//	            (after the owner's signature verified, with the blob's
//	            size).
//
// A WebSocket session passes address and key once, at its upgrade. Its ack
// frames are requests too: those that do not answer a message the relay
// sent on that session draw on address and key again (ws.go).
//
// Nothing else is keyed on a network. A request properly signed by a key
// with a mailbox can be refused on account of its network only by the
// flood guard, the byte budgets and, if it would create a mailbox, by the
// registration budget. The byte budgets, like the flood guard, never look
// at a request's target.
const (
	limAddress  = "address"
	limKey      = "key"
	limSender   = "sender"
	limRegister = "register"
	limClaim    = "claim"
	limWeb      = "web"
)

// limWSSessions labels the upgrades refused because the process carries
// its maximum of WebSocket sessions (cfg.MaxWebSocketSessions). It is a
// count, not a bucket: it has a refused series and nothing else.
const limWSSessions = "ws_sessions"

// limWSNetwork labels the upgrades refused because the caller's network
// holds its maximum of WebSocket sessions on this process
// (cfg.MaxWebSocketSessionsPerNetwork). Likewise a count.
const limWSNetwork = "ws_network"

// limWSNetworkHard labels the upgrades refused because the caller's
// network holds as many sessions as any network may on this process
// (cfg.MaxWebSocketSessionsPerNetworkHard), a mailbox's first included.
const limWSNetworkHard = "ws_network_hard"

var allLimiters = []string{limAddress, limKey, limSender, limRegister, limClaim, limWeb}

// The byte budgets: bytes and blob_bytes per network (shared),
// blob_key_bytes and key_bytes per authenticated key (per process). They are reported after every
// other field of the "rate limits" line.
const (
	limBytes        = "bytes"
	limBlobBytes    = "blob_bytes"
	limBlobKeyBytes = "blob_key_bytes"
	limKeyBytes     = "key_bytes"
)

var byteLimiters = []string{limBytes, limBlobBytes, limBlobKeyBytes, limKeyBytes}

// limBlobSlots and limBlobMailboxSlots label blob transfers refused
// because the process (cfg.MaxConcurrentBlobTransfers) or the mailbox
// (cfg.MaxBlobTransfersPerMailbox) has no transfer slot free. Counts.
// limBlobSenderSlots labels uploads refused because the same sender
// already has an upload to that mailbox in progress.
const (
	limBlobSlots        = "blob_slots"
	limBlobMailboxSlots = "blob_mailbox_slots"
	limBlobSenderSlots  = "blob_sender_slots"
)

// limBlobEvicted counts uploads cut off to give their slot to a newer one
// (the slowest evictable upload: see evictableLocked and victimLocked in
// blobs.go). It is a count in relay_ratelimit_refused_total, and the last
// field of the "rate limits" line, blob_evicted.
const limBlobEvicted = "blob_evicted"

// ByteLimiter is a keyed byte budget: AllowN consumes n tokens (bytes), or
// none and reports how long until n are available. Refund gives back a
// charge for a request that stored or moved nothing; Ready reports whether
// any token is left; Burst is the bucket size (the most one request can
// be charged).
type ByteLimiter interface {
	AllowN(key string, n int64, now time.Time) (bool, time.Duration)
	Refund(key string, n int64)
	Ready(key string, now time.Time) (bool, time.Duration)
	Charge(key string, n int64, now time.Time)
	Burst() int64
}

// maxCounted bounds the per-minute tally of requests per network and per
// key (limiterMetrics.busiest); beyond it new ones go uncounted.
const maxCounted = 50_000

type limiterMetrics struct {
	allowed metrics.CounterVec
	refused metrics.CounterVec
	peak    metrics.GaugeVec
	busiest metrics.GaugeVec
	bytes   metrics.GaugeVec // busiest network's bytes per minute, by byte budget

	mu      sync.Mutex
	lastRef map[string]int64          // refused counts at the previous report
	lastLog [2]int64                  // log lines dropped, suppressed at the previous report
	count   map[string]map[string]int // this minute's requests (bytes for the byte budgets), by limiter and key
	hit     map[string]struct{}       // networks the flood guard refused this minute
}

func newLimiterMetrics(reg *metrics.Registry) *limiterMetrics {
	m := &limiterMetrics{
		allowed: reg.CounterVec("relay_ratelimit_allowed_total", "Requests a rate limiter let through, by limiter.", "limiter"),
		refused: reg.CounterVec("relay_ratelimit_refused_total", "Requests a rate limiter refused (429 rate_limited), by limiter.", "limiter"),
		peak:    reg.GaugeVec("relay_ratelimit_peak_permille", "How full the busiest bucket of each limiter got during the last full minute, in thousandths of its burst (1000: something was refused).", "limiter"),
		busiest: reg.GaugeVec("relay_ratelimit_busiest_per_minute", "Requests of the busiest single client network (limiter address) and of the busiest single key (limiter key) during the last full minute.", "limiter"),
		bytes:   reg.GaugeVec("relay_ratelimit_busiest_bytes_per_minute", "Bytes charged to the busiest single client network (bytes, blob_bytes) or key (key_bytes, blob_key_bytes) during the last full minute, by byte budget (bytes and key_bytes: deposits and claims; blob_bytes and blob_key_bytes: blob uploads and downloads).", "limiter"),
		lastRef: map[string]int64{},
		count:   map[string]map[string]int{limAddress: {}, limKey: {}, limBytes: {}, limBlobBytes: {}, limBlobKeyBytes: {}, limKeyBytes: {}},
		hit:     map[string]struct{}{},
	}
	for _, l := range allLimiters {
		m.allowed.With(l)
		m.refused.With(l)
		m.peak.With(l)
	}
	m.busiest.With(limAddress)
	m.busiest.With(limKey)
	m.refused.With(limWSSessions)
	m.refused.With(limWSNetwork)
	m.refused.With(limWSNetworkHard)
	for _, l := range byteLimiters {
		m.allowed.With(l)
		m.refused.With(l)
		m.peak.With(l)
		m.bytes.With(l)
	}
	m.refused.With(limBlobSlots)
	m.refused.With(limBlobMailboxSlots)
	m.refused.With(limBlobSenderSlots)
	m.refused.With(limBlobEvicted)
	return m
}

// tally counts n for key under limiter (one request under address or
// key, the bytes charged under a byte budget), for the busiest-per-minute
// figures. Nothing of key is ever reported.
func (m *limiterMetrics) tally(limiter, key string, n int, refused bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.count[limiter]
	if _, ok := c[key]; ok || (n > 0 && len(c) < maxCounted) {
		c[key] += n
	}
	if refused && limiter == limAddress && len(m.hit) < maxCounted {
		m.hit[key] = struct{}{}
	}
}

// take consumes one token of limiter l for key, or returns the 429.
func (s *Server) take(name string, l RateLimiter, key string) *apiError {
	ok, wait := l.Allow(key, s.now())
	if name == limAddress || name == limKey {
		s.rl.tally(name, key, 1, !ok)
	}
	if ok {
		s.rl.allowed.With(name).Inc()
		return nil
	}
	s.rl.refused.With(name).Inc()
	return &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)}
}

// takeBytes charges n bytes to the byte budget l (name: limBytes or
// limBlobBytes) of network, or returns the 429. Refused, it charges
// nothing.
func (s *Server) takeBytes(name string, l ByteLimiter, network string, n int64) *apiError {
	ok, wait := l.AllowN(network, n, s.now())
	if !ok {
		s.rl.refused.With(name).Inc()
		return &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)}
	}
	s.rl.allowed.With(name).Inc()
	s.rl.tally(name, network, int(n), false)
	return nil
}

// refundBytes gives back n bytes charged by takeBytes for a request that
// stored or moved nothing (refused later, failed, or not stored).
func (s *Server) refundBytes(name string, l ByteLimiter, network string, n int64) {
	l.Refund(network, n)
	s.rl.tally(name, network, -int(n), false)
}

// takeBlobBytes charges n blob bytes to key's budget and to network's
// ceiling, or neither (the 429 of the one that refused).
// (Used for blob downloads, whose key, the owner's, is verified first.)
func (s *Server) takeBlobBytes(key, network string, n int64) *apiError {
	return s.takeKeyAndNetwork(limBlobKeyBytes, s.blobKeyLimit, key, limBlobBytes, s.blobByteLimit, network, n)
}

// takeKeyAndNetwork charges n bytes to a verified key's budget (keyName,
// keyL) and to its network's ceiling (netName, netL), or to neither.
func (s *Server) takeKeyAndNetwork(keyName string, keyL ByteLimiter, key, netName string, netL ByteLimiter, network string, n int64) *apiError {
	now := s.now()
	if ok, wait := keyL.AllowN(key, n, now); !ok {
		s.rl.refused.With(keyName).Inc()
		return &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)}
	}
	if ok, wait := netL.AllowN(network, n, now); !ok {
		keyL.Refund(key, n)
		s.rl.refused.With(netName).Inc()
		return &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)}
	}
	for _, x := range [][2]string{{keyName, key}, {netName, network}} {
		s.rl.allowed.With(x[0]).Inc()
		s.rl.tally(x[0], x[1], int(n), false)
	}
	return nil
}

// chargeBlobKey charges n bytes to key's blob budget after the fact,
// even into debt (the bytes have arrived; the sender's key is proved only
// now). Never refuses.
func (s *Server) chargeBlobKey(key string, n int64) {
	s.forceBytes(limBlobKeyBytes, s.blobKeyLimit, key, n)
}

// forceBytes charges n bytes to key's budget l after the fact, even into
// debt. Never refuses.
func (s *Server) forceBytes(name string, l ByteLimiter, key string, n int64) {
	l.Charge(key, n, s.now())
	s.rl.allowed.With(name).Inc()
	s.rl.tally(name, key, int(n), false)
}

// keyReady is the read-only look at key's budget l made before a body is
// read, when the key is not yet proved: an empty budget is refused (the
// 429), nothing is charged.
func (s *Server) keyReady(name string, l ByteLimiter, key string) *apiError {
	if ok, wait := l.Ready(key, s.now()); !ok {
		s.rl.refused.With(name).Inc()
		return &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)}
	}
	return nil
}

// declaredLength is what a byte budget charges for a body before it is
// read: its Content-Length, or limit (the most it may be) when the length
// is not declared.
func declaredLength(r *http.Request, limit int64) int64 {
	if r.ContentLength >= 0 {
		return min(r.ContentLength, limit)
	}
	return limit
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
	for name, l := range map[string]any{
		limAddress: s.ipLimit, limKey: s.keyLimit, limSender: s.subLimit,
		limRegister: s.regLimit, limClaim: s.claimLimit, limWeb: s.webLimit,
		limBytes: s.byteLimit, limBlobBytes: s.blobByteLimit, limBlobKeyBytes: s.blobKeyLimit, limKeyBytes: s.keyByteLimit,
	} {
		if p, ok := l.(interface{ Peak() float64 }); ok {
			peaks[name] = p.Peak()
		}
	}
	attrs := make([]any, 0, 48)
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
	for _, name := range []string{limWSSessions, limWSNetwork, limWSNetworkHard} { // appended last, in this order
		total := s.rl.refused.With(name).Value()
		attrs = append(attrs, name+"_refused", total-s.rl.lastRef[name])
		s.rl.lastRef[name] = total
	}
	// The byte budgets, the blob transfer slots and the log budget come
	// after everything above (which is unchanged), in this order.
	for _, name := range byteLimiters {
		pm := int64(peaks[name] * 1000)
		s.rl.peak.With(name).Set(pm)
		total := s.rl.refused.With(name).Value()
		most := 0
		for _, n := range s.rl.count[name] {
			most = max(most, n)
		}
		s.rl.bytes.With(name).Set(int64(most))
		s.rl.count[name] = map[string]int{}
		attrs = append(attrs, name+"_peak", pm, name+"_refused", total-s.rl.lastRef[name], name+"_busiest_per_min", most)
		s.rl.lastRef[name] = total
	}
	for _, name := range []string{limBlobSlots, limBlobMailboxSlots, limBlobSenderSlots} {
		total := s.rl.refused.With(name).Value()
		attrs = append(attrs, name+"_refused", total-s.rl.lastRef[name])
		s.rl.lastRef[name] = total
	}
	if lb, ok := s.log.Handler().(logCounts); ok {
		d, sup := lb.Dropped(), lb.Suppressed()
		attrs = append(attrs, "log_dropped", d-s.rl.lastLog[0], "log_suppressed", sup-s.rl.lastLog[1])
		s.rl.lastLog = [2]int64{d, sup}
	}
	total := s.rl.refused.With(limBlobEvicted).Value()
	attrs = append(attrs, "blob_evicted", total-s.rl.lastRef[limBlobEvicted])
	s.rl.lastRef[limBlobEvicted] = total
	// At info level every minute: this line is what the limits are sized
	// from (how close a vault host is to the flood guard, how many
	// collectors a process carries). One line a minute per process.
	// It is exempt from the log budget: it reports what the budget dropped.
	s.log.InfoContext(logbudget.Exempt(context.Background()), "rate limits", attrs...)
}

// logCounts is implemented by a log handler with a line budget
// (logbudget.Handler).
type logCounts interface {
	Dropped() int64
	Suppressed() int64
}
