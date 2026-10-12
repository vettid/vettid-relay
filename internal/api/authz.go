package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// depositAuth is the result of spec §5.3 steps 1–6.
type depositAuth struct {
	mailbox store.Mailbox
	claims  auth.Claims
}

const depositScheme = "vettid-deposit "

// bearerToken extracts the token from "Authorization: VettID-Deposit <tok>".
// The scheme is matched case-insensitively (RFC 9110 §11.1).
func bearerToken(r *http.Request) (string, bool) {
	v := r.Header.Values("Authorization")
	if len(v) != 1 || len(v[0]) <= len(depositScheme) || !strings.EqualFold(v[0][:len(depositScheme)], depositScheme) {
		return "", false
	}
	tok := v[0][len(depositScheme):]
	if len(tok) > auth.MaxTokenLen {
		return "", false
	}
	return tok, true
}

// authorizeDepositToken runs spec §5.3 steps 1–6 for deposits and blob puts.
// It needs only headers, so it runs before any body is read. Every refusal
// here is a failed authentication (limits.go depositFailed): signed is the
// request's verified signature if it has been checked already; bodyHash
// reads the body and returns its hash (a deposit: the body is read only if
// a refusal has to be attributed), nil for a blob upload.
func (s *Server) authorizeDepositToken(ctx context.Context, w http.ResponseWriter, r *http.Request, mailboxID string, signed *auth.SignedRequest, bodyHash func() *[32]byte) (*depositAuth, *apiError) {
	refuse := func(code string) (*depositAuth, *apiError) {
		return nil, s.depositFailed(w, r, fail(code), mailboxID, signed, bodyHash)
	}
	// 1. Mailbox exists.
	if !auth.ValidMailboxID(mailboxID) {
		return refuse(CodeMailboxUnknown)
	}
	mb, err := s.st.Mailbox(ctx, mailboxID)
	if errors.Is(err, store.ErrNotFound) {
		return refuse(CodeMailboxUnknown)
	}
	if err != nil {
		s.log.Error("mailbox lookup failed", "err", err)
		return nil, fail(CodeInternal)
	}
	// 2. PASETO v4.public signature against the registered pubkey of {mailbox_id}.
	tok, ok := bearerToken(r)
	if !ok {
		return refuse(CodeTokenInvalid)
	}
	claims, err := auth.ParseToken(tok, mb.PubKey)
	if err != nil {
		return refuse(CodeTokenInvalid)
	}
	// 3–5. iss, aud, iat ≤ now < exp (+ max lifetime policy).
	switch err := auth.ValidateClaims(claims, mailboxID, s.tokenPolicy(), s.now()); {
	case errors.Is(err, auth.ErrTokenExpired):
		return refuse(CodeTokenExpired)
	case err != nil:
		return refuse(CodeTokenInvalid)
	}
	// 6. Denylist (jti, sub).
	denied, err := s.st.IsDenied(ctx, mailboxID, claims.Jti, claims.Sub)
	if err != nil {
		s.log.Error("denylist lookup failed", "err", err)
		return nil, fail(CodeInternal)
	}
	if denied {
		return refuse(CodeTokenRevoked)
	}
	// 6a. (0.5.0, §6.10) A token issued before this mailbox id was deleted
	// predates the current registration of its key. (The store re-checks
	// atomically with the write.)
	if claims.Iat.Before(mb.TokensNotBefore) {
		return refuse(CodeTokenRevoked)
	}
	// 6b. One-shot open tokens (§5.6): not already consumed. (Consumption is
	// recorded atomically with the deposit, which re-checks under the write
	// lock; this early check just avoids work for an obviously used token.)
	if claims.Open() {
		used, err := s.st.IsConsumed(ctx, mailboxID, claims.Jti)
		if err != nil {
			s.log.Error("consumed-token lookup failed", "err", err)
			return nil, fail(CodeInternal)
		}
		if used {
			return refuse(CodeTokenUsed)
		}
	}
	return &depositAuth{mailbox: mb, claims: claims}, nil
}

func (s *Server) tokenPolicy() auth.TokenPolicy {
	return auth.TokenPolicy{Audience: s.cfg.BaseURL, MaxLifetime: s.cfg.MaxTokenLifetime, OpenMaxLifetime: s.cfg.OpenTokenMaxLifetime}
}

// verifySender is spec §5.3 step 7: the request signature verifies and
// X-VettID-Key equals the token's sub (sender binding). For one-shot open
// tokens (§5.6) the signature alone suffices and the signing key becomes the
// deposit's sender. It returns the canonical base64 sender key. signed is
// the already verified signature, if the caller had to check it first (a
// penalised network, limits.go).
func (s *Server) verifySender(w http.ResponseWriter, r *http.Request, da *depositAuth, bodyHash [32]byte, signed *auth.SignedRequest) (string, *apiError) {
	if signed == nil {
		sr, e := s.authorizeSigner(w, r, bodyHash)
		if e != nil {
			return "", e
		}
		signed = &sr
	}
	sender := da.claims.Sub
	if da.claims.Open() {
		sender = auth.EncodeKey(signed.Key)
	} else if subtle.ConstantTimeCompare(signed.Key, da.claims.SubKey) != 1 {
		return "", s.depositFailed(w, r, fail(CodeSignatureInvalid), da.mailbox.ID, signed, nil)
	}
	return sender, nil
}

// verifySignature parses and verifies the §4.1 headers (freshness + signature).
func (s *Server) verifySignature(w http.ResponseWriter, r *http.Request, bodyHash [32]byte) (auth.SignedRequest, *apiError) {
	sr, err := auth.ParseHeaders(r.Header)
	if err != nil {
		return sr, s.authFailed(w, fail(CodeSignatureInvalid))
	}
	switch err := sr.Verify(r.Method, r.URL.EscapedPath(), bodyHash, s.now()); {
	case errors.Is(err, auth.ErrTimestampStale):
		// A wrong clock, not a wrong key, if the signature is good.
		if sr.SignatureValid(r.Method, r.URL.EscapedPath(), bodyHash) {
			return sr, s.keyFailedOnce(w, fail(CodeTimestampStale), onceStale, sr.Key)
		}
		return sr, s.authFailed(w, fail(CodeTimestampStale))
	case err != nil:
		return sr, s.authFailed(w, fail(CodeSignatureInvalid))
	}
	return sr, nil
}

func (s *Server) checkReplay(w http.ResponseWriter, sr auth.SignedRequest) *apiError {
	switch err := s.replay.Check(sr, s.now()); {
	case errors.Is(err, auth.ErrReplay):
		// The signature is good, so it is this key's request sent twice: a
		// retry bug, or someone re-sending what they saw.
		return s.keyFailedOnce(w, fail(CodeReplayDetected), onceReplay, sr.Key)
	case errors.Is(err, auth.ErrReplayCacheFull):
		s.log.Warn("replay cache full or unavailable; shedding load", "err", err)
		return &apiError{code: CodeRateLimited, retryAfter: 5}
	case err != nil:
		return fail(CodeInternal)
	}
	return nil
}

// authorizeSigner verifies a §4.1 signed request (signature, freshness,
// replay) and returns the parsed headers: the request comes from the holder
// of sr.Key. Used where the key need not be registered (registration,
// deletion) and as the first half of every other authorization.
func (s *Server) authorizeSigner(w http.ResponseWriter, r *http.Request, bodyHash [32]byte) (auth.SignedRequest, *apiError) {
	sr, e := s.verifySignature(w, r, bodyHash)
	if e != nil {
		return sr, e
	}
	// A key held for having no mailbox: its holder is told to wait.
	if e := s.held(r, sr.Key); e != nil {
		return sr, e
	}
	// On a penalised network the flood guard was put off until here, so
	// that the network's bad requests cannot use up what its good ones
	// need. It comes before the replay record: what one network can write
	// to the replay store is bounded by its flood guard.
	if e := s.floodGuard(w); e != nil {
		return sr, e
	}
	return sr, s.checkReplay(w, sr)
}

// authorizeOwner authenticates an owner route (collect, ack, denylist,
// rotate, blob get/delete): the request is signed by X-VettID-Key and that
// key is the registered pubkey of the mailbox it derives. An unregistered
// signer gets mailbox_unknown. Only then is the per-key rate limit applied,
// so a 429 from it is only ever seen by the owner of the key.
func (s *Server) authorizeOwner(ctx context.Context, w http.ResponseWriter, r *http.Request, bodyHash [32]byte) (store.Mailbox, *apiError) {
	sr, e := s.authorizeSigner(w, r, bodyHash)
	if e != nil {
		return store.Mailbox{}, e
	}
	mb, err := s.st.Mailbox(ctx, auth.MailboxID(sr.Key))
	if errors.Is(err, store.ErrNotFound) {
		return store.Mailbox{}, s.noMailbox(w, fail(CodeMailboxUnknown), sr.Key)
	}
	if err != nil {
		s.log.Error("mailbox lookup failed", "err", err)
		return store.Mailbox{}, fail(CodeInternal)
	}
	if subtle.ConstantTimeCompare(mb.PubKey, sr.Key) != 1 {
		return store.Mailbox{}, s.noMailbox(w, fail(CodeMailboxUnknown), sr.Key)
	}
	if e := s.allowKey(sr.Key); e != nil {
		return store.Mailbox{}, e
	}
	return mb, nil
}
