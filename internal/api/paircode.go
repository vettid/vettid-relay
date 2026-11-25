package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/paircode"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Code claims (spec §6.9.1): a claim found by a short pairing code. The
// relay receives an Argon2id tag of the code, never the code, and stores
// only code_mac = HMAC-SHA-256(k_pc, tag). Tags, code_macs, salts, blobs
// and claim ids are never logged; the access log has the route pattern
// only.

// Limit 14 (§7.2): code redeems per IPv4 address, and per IPv6 /64 with
// ceilings per /48 and /32, each in 10 minutes (chosen; not in the card).
const (
	codeWindow     = 10 * time.Minute
	codeRedeemIPv4 = 20
	codeRedeem64   = 10
	codeRedeem48   = 200
	codeRedeem32   = 1000
)

// codeHold is the fixed hold of every redeem answer (§6.9.1, chosen; not
// in the card): an answer is sent this long after receipt, or at the next
// multiple of it if the work took longer.
const codeHold = 250 * time.Millisecond

// codeRedeemMax bounds a redeem's body: two tags and their salt ids.
const codeRedeemMax = 1024

// Limiter names (metrics, the per-minute log line).
const (
	limCode4  = "code_redeem"
	limCode64 = "code_redeem_64"
	limCode48 = "code_redeem_48"
	limCode32 = "code_redeem_32"
)

// pairCodes is the relay's code-claim state; nil when it offers none.
type pairCodes struct {
	key   []byte
	keyID string
	r     string // the relay's canonical base URL

	mu     sync.Mutex
	nonces map[int64][]byte // an epoch's nonce, once stored (it never changes)

	hold                      time.Duration
	lim4, lim64, lim48, lim32 ByteLimiter
	dummyTags                 [][]byte
}

// newPairCodes returns the code-claim state of cfg, or nil (and a log line
// naming what is missing, never a key) when the relay offers none.
func newPairCodes(cfg config.Config, log *slog.Logger) *pairCodes {
	k := cfg.PairCodeKey.Bytes()
	if len(k) != paircode.KeySize {
		// A key that was given but can't be used is worth a warning; no
		// key at all is the default.
		if cfg.PairCodeKeyProblem != "" && !strings.HasPrefix(cfg.PairCodeKeyProblem, "no ") {
			log.Warn("pair codes are off", "reason", cfg.PairCodeKeyProblem)
		} else {
			log.Debug("pair codes are off", "reason", cfg.PairCodeKeyProblem)
		}
		return nil
	}
	r, err := paircode.CanonicalRelay(cfg.BaseURL)
	if err != nil {
		log.Warn("pair codes are off", "reason", "RELAY_BASE_URL has no canonical https form")
		return nil
	}
	p := &pairCodes{key: k, keyID: paircode.KeyID(k), r: r, nonces: map[int64][]byte{}, hold: codeHold}
	p.limiters(func(_ string, perSec float64, burst int) ByteLimiter { return ratelimit.New(perSec, burst, 200_000) })
	for i := range 2 {
		t := make([]byte, paircode.TagSize)
		t[0] = byte(i + 1)
		p.dummyTags = append(p.dummyTags, t)
	}
	log.Info("pair codes are on", "key_id", p.keyID)
	return p
}

// limiters makes limit 14's four budgets with mk (per process, or
// relay-wide on the shared store).
func (p *pairCodes) limiters(mk func(name string, perSec float64, burst int) ByteLimiter) {
	per := func(name string, n int) ByteLimiter { return mk(name, float64(n)/codeWindow.Seconds(), n) }
	p.lim4, p.lim64 = per(limCode4, codeRedeemIPv4), per(limCode64, codeRedeem64)
	p.lim48, p.lim32 = per(limCode48, codeRedeem48), per(limCode32, codeRedeem32)
}

// WithPairCodeHold sets the redeem hold (tests).
func WithPairCodeHold(d time.Duration) Option {
	return func(s *Server) {
		if s.pc != nil {
			s.pc.hold = d
		}
	}
}

// nonce returns epoch's nonce: cached, or stored now with a fresh random
// one if the store has none yet (the first time the epoch is listed).
func (s *Server) nonce(r *http.Request, epoch int64) ([]byte, error) {
	p := s.pc
	p.mu.Lock()
	n, ok := p.nonces[epoch]
	p.mu.Unlock()
	if ok {
		return n, nil
	}
	fresh := make([]byte, paircode.NonceSize)
	rand.Read(fresh)
	n, err := s.st.PairCodeNonce(r.Context(), epoch, fresh)
	if err != nil {
		return nil, err
	}
	if len(n) != paircode.NonceSize {
		return nil, errors.New("pair code nonce of the wrong size")
	}
	p.mu.Lock()
	p.nonces[epoch] = n
	for e := range p.nonces {
		if e < epoch-2 {
			delete(p.nonces, e)
		}
	}
	p.mu.Unlock()
	return n, nil
}

type pairCodeSalt struct {
	SaltID string `json:"salt_id"`
	Epoch  int64  `json:"epoch"`
	Nonce  []byte `json:"nonce"`
}

// salts returns the salts listed for epochs.
func (s *Server) salts(r *http.Request, epochs []int64) ([]pairCodeSalt, error) {
	var out []pairCodeSalt
	for _, e := range epochs {
		n, err := s.nonce(r, e)
		if err != nil {
			return nil, err
		}
		out = append(out, pairCodeSalt{SaltID: paircode.SaltID(paircode.SaltR(s.pc.r, e, n)), Epoch: e, Nonce: n})
	}
	return out, nil
}

// GET /v1/pair-code/salts — unauthenticated; the same answer for every
// caller, which may be cached for 60 s.
func (s *Server) handlePairCodeSalts(w http.ResponseWriter, r *http.Request) {
	list, err := s.salts(r, paircode.Listed(s.now()))
	if err != nil {
		s.log.Error("pair code salts failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=60")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string][]pairCodeSalt{"salts": list})
}

type pairCodePut struct {
	SaltID string `json:"salt_id"`
	Tag    []byte `json:"tag"`
	Salt   []byte `json:"salt"`
	Blob   []byte `json:"blob"`
}

// PUT /v1/pair-code/{claim_id} — signed by a registered mailbox key. The
// checks run in §6.9.1's order.
func (s *Server) handlePairCodePut(w http.ResponseWriter, r *http.Request) {
	// The blob is base64 in JSON: 4/3 of it, and the other fields.
	body, e := s.readBody(w, r, (s.cfg.MaxClaimBytes+2)/3*4+512)
	if e != nil {
		s.writeError(w, e)
		return
	}
	mb, e := s.authorizeOwner(r.Context(), r, auth.BodyHash(body))
	if e != nil {
		s.writeError(w, e)
		return
	}
	// 1. The mailbox's live code claim goes, whatever follows.
	if err := s.st.DeleteMailboxCode(r.Context(), mb.ID); err != nil {
		s.log.Error("pair code put failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	// 2. A canonical claim id.
	claimID := r.PathValue("claim_id")
	if _, ok := auth.ParseClaimID(claimID); !ok {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	var p pairCodePut
	if !decodeJSON(body, &p) || len(p.Tag) != paircode.TagSize || len(p.Salt) != paircode.SaltSize ||
		len(p.Blob) == 0 || int64(len(p.Blob)) > s.cfg.MaxClaimBytes {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	// 3. The current epoch's salt, or the next one's once it is listed.
	creatable, err := s.salts(r, paircode.Creatable(s.now()))
	if err != nil {
		s.log.Error("pair code put failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	if !slices.ContainsFunc(creatable, func(c pairCodeSalt) bool { return c.SaltID == p.SaltID }) {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	// Stored bytes (limit 11), like a claim.
	network, owner, n := s.network(r), auth.EncodeKey(mb.PubKey), int64(len(p.Blob))
	src, e := s.takeKeyAndNetwork(limKeyBytes, s.keyByteLimit, owner, limBytes, s.byteLimit, network, n)
	if e != nil {
		s.writeError(w, e)
		return
	}
	// 4. The collision check, in the store with the put.
	exp, err := s.st.PutCode(r.Context(), store.CodePut{
		Mailbox: mb.ID, ClaimID: claimID, KeyID: s.pc.keyID, SaltID: p.SaltID,
		CodeMAC: paircode.MAC(s.pc.key, p.Tag), Salt: p.Salt, Blob: p.Blob,
	}, s.cfg.MailboxMaxBlobBytes)
	if err != nil {
		s.refundBytes(limKeyBytes, s.keyByteLimit, owner, n, 0)
		s.refundBytes(limBytes, s.byteLimit, network, n, src)
	}
	switch {
	case errors.Is(err, store.ErrCodeTaken):
		s.writeError(w, fail(CodeCodeTaken))
		return
	case errors.Is(err, store.ErrClaimIDTaken):
		s.writeError(w, fail(CodeBadRequest))
		return
	case errors.Is(err, store.ErrQuota):
		s.writeError(w, quotaFail(err))
		return
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, fail(CodeMailboxUnknown))
		return
	case err != nil:
		s.log.Error("pair code put failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	s.m.claimPuts.Inc()
	writeJSON(w, http.StatusCreated, map[string]string{"expires_at": exp.Format(timeFormat)})
}

// DELETE /v1/pair-code/{claim_id} — signed by the creating key; 204,
// idempotent.
func (s *Server) handlePairCodeDelete(w http.ResponseWriter, r *http.Request) {
	body, e := s.readBody(w, r, smallBodyLimit)
	if e != nil {
		s.writeError(w, e)
		return
	}
	mb, e := s.authorizeOwner(r.Context(), r, auth.BodyHash(body))
	if e != nil {
		s.writeError(w, e)
		return
	}
	if id := r.PathValue("claim_id"); len(id) == auth.ClaimIDLen {
		if err := s.st.DeleteCode(r.Context(), mb.ID, id); err != nil {
			s.log.Error("pair code delete failed", "err", err)
			s.writeError(w, fail(CodeInternal))
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type pairCodeRedeem struct {
	Tags []struct {
		SaltID string `json:"salt_id"`
		Tag    []byte `json:"tag"`
	} `json:"tags"`
}

// takeCodeRedeem charges limit 14 for a redeem from a: its IPv4 address,
// or its IPv6 /64, /48 and /32 together; all or none.
func (s *Server) takeCodeRedeem(a netip.Addr) bool {
	p, now := s.pc, s.now()
	type charge struct {
		name, key string
		l         ByteLimiter
	}
	var cs []charge
	switch {
	case a.Is4():
		cs = []charge{{limCode4, a.String(), p.lim4}}
	case a.Is6():
		for _, c := range []struct {
			name string
			bits int
			l    ByteLimiter
		}{{limCode64, 64, p.lim64}, {limCode48, 48, p.lim48}, {limCode32, 32, p.lim32}} {
			pre, _ := a.Prefix(c.bits)
			cs = append(cs, charge{c.name, pre.String(), c.l})
		}
	default:
		cs = []charge{{limCode4, "unknown", p.lim4}}
	}
	var srcs []int
	for i, c := range cs {
		ok, _, src := allowNFrom(c.l, c.key, 1, now)
		if !ok {
			for j := range i {
				refundTo(cs[j].l, cs[j].key, 1, srcs[j])
			}
			s.rl.refused.With(c.name).Inc()
			return false
		}
		srcs = append(srcs, src)
	}
	for _, c := range cs {
		s.rl.allowed.With(c.name).Inc()
	}
	return true
}

// POST /v1/pair-code/redeem — unauthenticated, single fetch. Every
// failure, limit 14 included, gets the same 404 code_unknown after the
// same work, and every answer leaves at the fixed hold.
func (s *Server) handlePairCodeRedeem(w http.ResponseWriter, r *http.Request) {
	received := time.Now()
	answer := s.redeem(r)
	// Nothing is written before the hold: the answer is buffered until
	// then.
	s.holdUntil(received)
	answer(w)
}

// redeem does a redeem's work and returns its answer, to be written at
// the hold.
func (s *Server) redeem(r *http.Request) func(http.ResponseWriter) {
	allowed := s.takeCodeRedeem(clientIP(r, s.cfg.TrustProxy))
	listed := paircode.Listed(s.now())
	lookups, ok := s.redeemLookups(r, listed)
	dry := !allowed || !ok
	if dry {
		// The same work on fixed dummy tags, under a salt_id no salt
		// has: nothing can match, and nothing is changed.
		lookups = lookups[:0]
		for i := range listed {
			lookups = append(lookups, store.CodeLookup{SaltID: "00000000", CodeMAC: paircode.MAC(s.pc.key, s.pc.dummyTags[i])})
		}
	}
	c, err := s.st.RedeemCode(r.Context(), s.pc.keyID, lookups, dry)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return func(w http.ResponseWriter) { s.writeError(w, fail(CodeCodeUnknown)) }
	case err != nil:
		s.log.Error("pair code redeem failed", "err", err)
		return func(w http.ResponseWriter) { s.writeError(w, fail(CodeInternal)) }
	}
	s.m.claimGets.Inc()
	return func(w http.ResponseWriter) {
		writeJSON(w, http.StatusOK, map[string]string{
			"claim_id": c.ClaimID, "salt": base64.StdEncoding.EncodeToString(c.Salt),
			"blob": base64.StdEncoding.EncodeToString(c.Blob), "expires_at": c.ExpiresAt.Format(timeFormat),
		})
	}
}

// redeemLookups reads a redeem's body: at most as many tags as salts are
// listed, one per listed salt_id, each 32 bytes. ok is false for anything
// else (it gets the same answer as a miss).
func (s *Server) redeemLookups(r *http.Request, listed []int64) ([]store.CodeLookup, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, codeRedeemMax+1))
	if err != nil || len(body) > codeRedeemMax {
		return nil, false
	}
	var req pairCodeRedeem
	if !decodeJSON(body, &req) || len(req.Tags) == 0 || len(req.Tags) > len(listed) {
		return nil, false
	}
	salts, err := s.salts(r, listed)
	if err != nil {
		return nil, false
	}
	var out []store.CodeLookup
	for _, t := range req.Tags {
		if len(t.Tag) != paircode.TagSize || !slices.ContainsFunc(salts, func(c pairCodeSalt) bool { return c.SaltID == t.SaltID }) ||
			slices.ContainsFunc(out, func(l store.CodeLookup) bool { return l.SaltID == t.SaltID }) {
			return nil, false
		}
		out = append(out, store.CodeLookup{SaltID: t.SaltID, CodeMAC: paircode.MAC(s.pc.key, t.Tag)})
	}
	return out, true
}

// holdUntil sleeps until the hold after received, or the next multiple of
// it if the work took longer.
func (s *Server) holdUntil(received time.Time) {
	h := s.pc.hold
	if h <= 0 {
		return
	}
	steps := max(1, (time.Since(received)+h-1)/h)
	time.Sleep(time.Until(received.Add(steps * h)))
}
