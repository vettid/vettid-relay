package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/internal/store"
)

const (
	maxWait          = 25 * time.Second // spec §6.3 cap
	maxCollectMax    = 100              // spec §6.3 cap
	defaultCollect   = 32
	smallBodyLimit   = 16 << 10 // register / denylist / rotate / bodiless routes
	maxRevokePerCall = 100
	timeFormat       = "2006-01-02T15:04:05Z" // RFC 3339 UTC, second precision (spec examples)
)

// readBody reads the whole body, enforcing limit while reading (spec §8.5:
// size limits precede signature verification).
func (s *Server) readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, *apiError) {
	if r.ContentLength > limit {
		return nil, fail(CodePayloadTooLarge)
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		return nil, fail(CodePayloadTooLarge)
	case err != nil:
		return nil, fail(CodeBadRequest)
	}
	return b, nil
}

// depositBodyLimit is the JSON envelope cap: base64 of the max payload plus
// headroom for {"payload":""} and whitespace.
func (s *Server) depositBodyLimit() int64 {
	return 4*((s.cfg.MaxPayloadBytes+2)/3) + 1024
}

func decodeJSON(b []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(v); err != nil || dec.More() {
		return false
	}
	return true
}

func setLog(w http.ResponseWriter, key string, v any) {
	if rec, ok := w.(*recorder); ok {
		rec.attrs = append(rec.attrs, key, v)
	}
}

// ---------------------------------------------------------------- register

// limitsBody is the registration limits object (spec §6.1), fields in the
// spec's order.
type limitsBody struct {
	MaxPayloadBytes             int64  `json:"max_payload_bytes"`
	MessageTTLSeconds           int64  `json:"message_ttl_seconds"`
	VisibilityTimeoutSeconds    int64  `json:"visibility_timeout_seconds"`
	MaxTokenLifetimeSeconds     int64  `json:"max_token_lifetime_seconds"`
	OpenTokenMaxLifetimeSeconds int64  `json:"open_token_max_lifetime_seconds"`
	MaxClaimBytes               int64  `json:"max_claim_bytes"`
	ClaimTTLSeconds             int64  `json:"claim_ttl_seconds"`
	MaxBlobBytes                *int64 `json:"max_blob_bytes,omitempty"`
	BlobTTLSeconds              *int64 `json:"blob_ttl_seconds,omitempty"`
}

type registerResponse struct {
	MailboxID string     `json:"mailbox_id"`
	Limits    limitsBody `json:"limits"`
}

func (s *Server) limits() limitsBody {
	l := limitsBody{
		MaxPayloadBytes:          s.cfg.MaxPayloadBytes,
		MessageTTLSeconds:        int64(s.cfg.MessageTTL / time.Second),
		VisibilityTimeoutSeconds: int64(s.cfg.VisibilityTimeout / time.Second),

		MaxTokenLifetimeSeconds:     int64(s.cfg.MaxTokenLifetime / time.Second),
		OpenTokenMaxLifetimeSeconds: int64(s.cfg.OpenTokenMaxLifetime / time.Second),
		MaxClaimBytes:               s.cfg.MaxClaimBytes,
		ClaimTTLSeconds:             int64(s.cfg.ClaimTTL / time.Second),
	}
	if s.cfg.BlobsEnabled {
		mb, ttl := s.cfg.MaxBlobBytes, int64(s.cfg.BlobTTL/time.Second)
		l.MaxBlobBytes, l.BlobTTLSeconds = &mb, &ttl
	}
	return l
}

// POST /v1/register (spec §6.1)
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	body, e := s.readBody(w, r, smallBodyLimit)
	if e != nil {
		s.writeError(w, e)
		return
	}
	sr, e := s.authorizeSigner(r, auth.BodyHash(body))
	if e != nil {
		s.writeError(w, e)
		return
	}
	var req struct {
		PubKey string `json:"pubkey"`
	}
	if !decodeJSON(body, &req) {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	pub, ok := auth.DecodeKey(req.PubKey)
	if !ok {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	// Proof of possession: the request must be signed by the key registered.
	if !bytes.Equal(pub, sr.Key) {
		s.writeError(w, fail(CodeSignatureInvalid))
		return
	}
	id := auth.MailboxID(pub)
	created, err := s.st.Register(r.Context(), id, pub)
	if err != nil {
		s.log.Error("register failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		s.m.registrations.Inc()
	}
	writeJSON(w, status, registerResponse{MailboxID: id, Limits: s.limits()})
}

// ----------------------------------------------------------------- deposit

// POST /v1/mailbox/{mailbox_id} (spec §6.2, validation order §5.3)
func (s *Server) handleDeposit(w http.ResponseWriter, r *http.Request) {
	body, e := s.readBody(w, r, s.depositBodyLimit())
	if e != nil {
		s.writeError(w, e)
		return
	}
	mailboxID := r.PathValue("mailbox_id")
	da, e := s.authorizeDepositToken(r.Context(), r, mailboxID) // steps 1–6
	if e != nil {
		s.writeError(w, e)
		return
	}
	if e := s.allowSender(senderRateKey(da)); e != nil {
		s.writeError(w, e)
		return
	}
	sender, e := s.verifySender(r, da, auth.BodyHash(body)) // step 7
	if e != nil {
		s.writeError(w, e)
		return
	}
	var req struct {
		Payload *string `json:"payload"`
	}
	if !decodeJSON(body, &req) || req.Payload == nil {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	if int64(base64.StdEncoding.DecodedLen(len(*req.Payload))) > s.cfg.MaxPayloadBytes+2 {
		s.writeError(w, fail(CodePayloadTooLarge))
		return
	}
	payload, err := auth.DecodeStd(*req.Payload)
	if err != nil {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	if int64(len(payload)) > s.cfg.MaxPayloadBytes {
		s.writeError(w, fail(CodePayloadTooLarge))
		return
	}
	// Step 8 (quota) is enforced atomically with the insert.
	msg, err := s.st.Deposit(r.Context(), mailboxID, sender, payload, s.cfg.MessageTTL, s.limitsFor(da, false))
	switch {
	case errors.Is(err, store.ErrTokenUsed):
		s.writeError(w, fail(CodeTokenUsed))
		return
	case errors.Is(err, store.ErrQuota):
		s.writeError(w, fail(CodeQuotaExceeded))
		return
	case err != nil:
		s.log.Error("deposit failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	s.hub.notify(mailboxID) // wake-on-deposit
	s.m.deposits.Inc()
	s.m.depositBytes.Add(int64(len(payload)))
	setLog(w, "msg_id", msg.ID)
	setLog(w, "size", len(payload))
	writeJSON(w, http.StatusCreated, map[string]string{"msg_id": msg.ID})
}

// senderRateKey keys the per-sender bucket: the bound sender's key, or the
// open token's jti (the signer is only known after step 7, and an open token
// is single-use anyway).
func senderRateKey(da *depositAuth) string {
	if da.claims.Open() {
		return "open:" + da.mailbox.ID + ":" + da.claims.Jti
	}
	return da.claims.Sub
}

func (s *Server) limitsFor(da *depositAuth, blob bool) store.Limits {
	l := store.Limits{TokenJTI: da.claims.Jti, TokenExpires: da.claims.Exp, ConsumeJTI: da.claims.Open()}
	if blob {
		l.MailboxMaxBytes = s.cfg.MailboxMaxBlobBytes
	} else {
		l.MailboxMaxMsgs, l.MailboxMaxBytes = s.cfg.MailboxMaxMessages, s.cfg.MailboxMaxBytes
	}
	if q := da.claims.Quota; q != nil {
		l.TokenQuotaMsgs, l.TokenQuotaBytes = q.Msgs, q.Bytes
	}
	return l
}

// ----------------------------------------------------------------- collect

type wireMessage struct {
	MsgID       string `json:"msg_id"`
	DepositedAt string `json:"deposited_at"`
	Sender      string `json:"sender"`  // base64 key that signed the deposit (spec §6.3)
	Payload     []byte `json:"payload"` // encoding/json: standard padded base64
}

func toWire(m store.Message) wireMessage {
	return wireMessage{MsgID: m.ID, DepositedAt: m.DepositedAt.UTC().Format(timeFormat), Sender: m.Sender, Payload: m.Payload}
}

func parseCollectParams(r *http.Request) (wait time.Duration, max int, ok bool) {
	q := r.URL.Query()
	max = defaultCollect
	if v := q.Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, 0, false
		}
		wait = min(time.Duration(n)*time.Second, maxWait)
	}
	if v := q.Get("max"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 0, 0, false
		}
		max = min(n, maxCollectMax)
	}
	return wait, max, true
}

// GET /v1/mailbox?wait=25&max=32 (spec §6.3)
func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
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
	wait, max, ok := parseCollectParams(r)
	if !ok {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	if !s.hub.acquire(mb.ID, s.cfg.MaxCollectorsPerMailbox) {
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: 1})
		return
	}
	defer s.hub.release(mb.ID)

	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	parked := false
	defer func() {
		if parked {
			s.m.parked.Dec()
		}
	}()
	for {
		wake := s.hub.wait(mb.ID) // before leasing: no lost wakeups
		msgs, err := s.st.Lease(r.Context(), mb.ID, max, s.cfg.VisibilityTimeout)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			s.log.Error("lease failed", "err", err)
			s.writeError(w, fail(CodeInternal))
			return
		}
		if len(msgs) > 0 || wait == 0 {
			s.respondMessages(w, msgs)
			return
		}
		if !parked {
			parked = true
			s.m.parked.Inc()
		}
		// Also wake when a leased-but-unacked message becomes visible again.
		var leaseC <-chan time.Time
		var leaseT *time.Timer
		if next, ok, err := s.st.NextLeaseExpiry(r.Context(), mb.ID); err == nil && ok {
			leaseT = time.NewTimer(max0(next.Sub(s.now())) + 5*time.Millisecond)
			leaseC = leaseT.C
		}
		done := false
		select {
		case <-wake:
		case <-leaseC:
		case <-deadline.C:
			s.respondMessages(w, nil)
			done = true
		case <-s.drainCtx.Done():
			s.respondMessages(w, nil) // shutting down: release the client now
			done = true
		case <-r.Context().Done():
			done = true
		}
		if leaseT != nil {
			leaseT.Stop()
		}
		if done {
			return
		}
	}
}

func max0(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}

func (s *Server) respondMessages(w http.ResponseWriter, msgs []store.Message) {
	out := make([]wireMessage, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, toWire(m))
	}
	s.m.collects.Inc()
	s.m.collected.Add(int64(len(out)))
	setLog(w, "count", len(out))
	writeJSON(w, http.StatusOK, map[string][]wireMessage{"messages": out})
}

// --------------------------------------------------------------------- ack

// DELETE /v1/mailbox/{msg_id} (spec §6.5)
func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
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
	msgID := r.PathValue("msg_id")
	if e := s.ack(r.Context(), mb.ID, msgID); e != nil {
		s.writeError(w, e)
		return
	}
	setLog(w, "msg_id", msgID)
	w.WriteHeader(http.StatusNoContent)
}

// ack is shared by DELETE and WebSocket ack frames. Spec §6.5 (0.3.0):
// always success — whether the message existed, was already acked, or
// belongs to another mailbox (then nothing happens) — so ack cannot be used
// to probe which message ids exist.
func (s *Server) ack(ctx context.Context, mailbox, msgID string) *apiError {
	if len(msgID) != 26 {
		return nil // cannot exist
	}
	deleted, err := s.st.Ack(ctx, mailbox, msgID)
	if err != nil {
		s.log.Error("ack failed", "err", err)
		return fail(CodeInternal)
	}
	if deleted {
		s.m.acks.Inc()
	}
	return nil
}

// ---------------------------------------------------------------- denylist

// denylistRetention is how long a denylist entry must live (spec §5.5):
// every token it could match has iat ≤ now and a lifetime bounded by the
// configured caps (sender-bound or open), so it expires within the larger
// cap; a margin covers the freshness window.
func (s *Server) denylistRetention() time.Duration {
	return max(s.cfg.MaxTokenLifetime, s.cfg.OpenTokenMaxLifetime) + auth.FreshnessWindow + time.Minute
}

// POST /v1/mailbox/denylist (spec §5.5)
func (s *Server) handleDenylist(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		Revoke []struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"revoke"`
	}
	if !decodeJSON(body, &req) || len(req.Revoke) > maxRevokePerCall {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	entries := make([]store.DenyEntry, 0, len(req.Revoke))
	for _, rv := range req.Revoke {
		switch rv.Kind {
		case "jti":
			if rv.Value == "" || len(rv.Value) > auth.MaxJTILen {
				s.writeError(w, fail(CodeBadRequest))
				return
			}
			entries = append(entries, store.DenyEntry{Kind: "jti", Value: rv.Value})
		case "sub":
			k, ok := auth.DecodeKey(rv.Value)
			if !ok {
				s.writeError(w, fail(CodeBadRequest))
				return
			}
			entries = append(entries, store.DenyEntry{Kind: "sub", Value: auth.EncodeKey(k)})
		default:
			s.writeError(w, fail(CodeBadRequest))
			return
		}
	}
	exp := s.now().Add(s.denylistRetention())
	switch err := s.st.AddDenylist(r.Context(), mb.ID, entries, exp, s.cfg.MailboxMaxDenylist); {
	case errors.Is(err, store.ErrQuota):
		s.writeError(w, fail(CodeQuotaExceeded))
		return
	case err != nil:
		s.log.Error("denylist update failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	s.m.revocations.Add(int64(len(entries)))
	setLog(w, "count", len(entries))
	w.WriteHeader(http.StatusNoContent)
}

// ------------------------------------------------------------------ rotate

// POST /v1/mailbox/rotate (spec §6.7)
func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		NewPubKey   string `json:"new_pubkey"`
		NewKeyProof string `json:"new_key_proof"`
	}
	if !decodeJSON(body, &req) {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	newPub, ok := auth.DecodeKey(req.NewPubKey)
	if !ok || bytes.Equal(newPub, mb.PubKey) {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	proof, err := auth.DecodeStd(req.NewKeyProof)
	// The proof is an Ed25519 signature by the new key over the ASCII bytes
	// of the current mailbox_id.
	if err != nil || len(proof) != ed25519.SignatureSize || !ed25519.Verify(newPub, []byte(mb.ID), proof) {
		s.writeError(w, fail(CodeSignatureInvalid))
		return
	}
	newID := auth.MailboxID(newPub)
	switch err := s.st.Rotate(r.Context(), mb.ID, newID, newPub, s.now().Add(s.cfg.RotationGrace)); {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, fail(CodeMailboxUnknown))
		return
	case err != nil:
		s.log.Error("rotate failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	s.m.rotations.Inc()
	writeJSON(w, http.StatusOK, map[string]string{"mailbox_id": newID})
}
