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
// It needs only headers, so it runs before any body is read.
func (s *Server) authorizeDepositToken(ctx context.Context, r *http.Request, mailboxID string) (*depositAuth, *apiError) {
	// 1. Mailbox exists.
	if !auth.ValidMailboxID(mailboxID) {
		return nil, fail(CodeMailboxUnknown)
	}
	mb, err := s.st.Mailbox(ctx, mailboxID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fail(CodeMailboxUnknown)
	}
	if err != nil {
		s.log.Error("mailbox lookup failed", "err", err)
		return nil, fail(CodeInternal)
	}
	// 2. PASETO v4.public signature against the registered pubkey of {mailbox_id}.
	tok, ok := bearerToken(r)
	if !ok {
		return nil, fail(CodeTokenInvalid)
	}
	claims, err := auth.ParseToken(tok, mb.PubKey)
	if err != nil {
		return nil, fail(CodeTokenInvalid)
	}
	// 3–5. iss, aud, iat ≤ now < exp (+ max lifetime policy).
	switch err := auth.ValidateClaims(claims, mailboxID, s.tokenPolicy(), s.now()); {
	case errors.Is(err, auth.ErrTokenExpired):
		return nil, fail(CodeTokenExpired)
	case err != nil:
		return nil, fail(CodeTokenInvalid)
	}
	// 6. Denylist (jti, sub).
	denied, err := s.st.IsDenied(ctx, mailboxID, claims.Jti, claims.Sub)
	if err != nil {
		s.log.Error("denylist lookup failed", "err", err)
		return nil, fail(CodeInternal)
	}
	if denied {
		return nil, fail(CodeTokenRevoked)
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
			return nil, fail(CodeTokenUsed)
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
// deposit's sender. It returns the canonical base64 sender key.
func (s *Server) verifySender(r *http.Request, da *depositAuth, bodyHash [32]byte) (string, *apiError) {
	sr, e := s.verifySignature(r, bodyHash)
	if e != nil {
		return "", e
	}
	sender := da.claims.Sub
	if da.claims.Open() {
		sender = auth.EncodeKey(sr.Key)
	} else if subtle.ConstantTimeCompare(sr.Key, da.claims.SubKey) != 1 {
		return "", fail(CodeSignatureInvalid)
	}
	return sender, s.checkReplay(sr)
}

// verifySignature parses and verifies the §4.1 headers (freshness + signature).
func (s *Server) verifySignature(r *http.Request, bodyHash [32]byte) (auth.SignedRequest, *apiError) {
	sr, err := auth.ParseHeaders(r.Header)
	if err != nil {
		return sr, fail(CodeSignatureInvalid)
	}
	switch err := sr.Verify(r.Method, r.URL.EscapedPath(), bodyHash, s.now()); {
	case errors.Is(err, auth.ErrTimestampStale):
		return sr, fail(CodeTimestampStale)
	case err != nil:
		return sr, fail(CodeSignatureInvalid)
	}
	return sr, nil
}

func (s *Server) checkReplay(sr auth.SignedRequest) *apiError {
	switch err := s.replay.Check(sr, s.now()); {
	case errors.Is(err, auth.ErrReplay):
		return fail(CodeReplayDetected)
	case errors.Is(err, auth.ErrReplayCacheFull):
		s.log.Warn("replay cache full or unavailable; shedding load", "err", err)
		return &apiError{code: CodeRateLimited, retryAfter: 5}
	case err != nil:
		return fail(CodeInternal)
	}
	return nil
}

// authorizeSigner verifies a §4.1 signed request (signature, freshness,
// replay) and returns the parsed headers. Used where the key need not be
// registered yet (registration).
func (s *Server) authorizeSigner(r *http.Request, bodyHash [32]byte) (auth.SignedRequest, *apiError) {
	sr, e := s.verifySignature(r, bodyHash)
	if e != nil {
		return sr, e
	}
	return sr, s.checkReplay(sr)
}

// authorizeOwner authenticates an owner route (collect, ack, denylist,
// rotate, blob get/delete): the request is signed by X-VettID-Key and that
// key is the registered pubkey of the mailbox it derives. An unregistered
// signer gets mailbox_unknown.
func (s *Server) authorizeOwner(ctx context.Context, r *http.Request, bodyHash [32]byte) (store.Mailbox, *apiError) {
	sr, e := s.authorizeSigner(r, bodyHash)
	if e != nil {
		return store.Mailbox{}, e
	}
	mb, err := s.st.Mailbox(ctx, auth.MailboxID(sr.Key))
	if errors.Is(err, store.ErrNotFound) {
		return store.Mailbox{}, fail(CodeMailboxUnknown)
	}
	if err != nil {
		s.log.Error("mailbox lookup failed", "err", err)
		return store.Mailbox{}, fail(CodeInternal)
	}
	if subtle.ConstantTimeCompare(mb.PubKey, sr.Key) != 1 {
		return store.Mailbox{}, fail(CodeMailboxUnknown)
	}
	return mb, nil
}
