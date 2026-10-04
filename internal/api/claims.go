package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/vettid/vettid-relay/internal/ratelimit"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Claims (spec §6.9): single-fetch bootstrap bundles for first contact.
// Claim ids are bearer secrets: they are never logged and never appear in
// metrics (the access log records only the route pattern).

// defaultClaimTTL applies to a bare PUT /v1/claim (spec §6.9), capped by the
// relay's claim_ttl_seconds.
const defaultClaimTTL = 900 * time.Second

// claimTTL reads the requested TTL from the path (PUT /v1/claim/ttl/{seconds}),
// which the request signature covers (§4.1): integer seconds in
// [1, claim_ttl_seconds]. The 0.3.0-draft X-VettID-Claim-TTL header was
// unsigned and is refused rather than silently ignored.
func (s *Server) claimTTL(r *http.Request) (time.Duration, bool) {
	if len(r.Header.Values("X-VettID-Claim-TTL")) > 0 {
		return 0, false
	}
	v := r.PathValue("ttl_seconds")
	if v == "" {
		return min(defaultClaimTTL, s.cfg.ClaimTTL), true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 || n > int64(s.cfg.ClaimTTL/time.Second) || strconv.FormatInt(n, 10) != v {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// PUT /v1/claim[/ttl/{seconds}] — signed by a registered mailbox key.
func (s *Server) handleClaimPut(w http.ResponseWriter, r *http.Request) {
	body, e := s.readBody(w, r, s.cfg.MaxClaimBytes) // size first (§8.5)
	if e != nil {
		s.writeError(w, e)
		return
	}
	mb, e := s.authorizeOwner(r.Context(), r, auth.BodyHash(body))
	if e != nil {
		s.writeError(w, e)
		return
	}
	ttl, ok := s.claimTTL(r)
	if !ok || len(body) == 0 {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	id, exp, err := s.st.PutClaim(r.Context(), mb.ID, body, ttl, s.cfg.MailboxMaxBlobBytes)
	switch {
	case errors.Is(err, store.ErrQuota):
		s.writeError(w, fail(CodeQuotaExceeded))
		return
	case errors.Is(err, store.ErrNotFound): // deleted mid-request
		s.writeError(w, fail(CodeMailboxUnknown))
		return
	case err != nil:
		s.log.Error("claim put failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	s.m.claimPuts.Inc()
	setLog(w, "size", len(body))
	writeJSON(w, http.StatusCreated, map[string]string{"claim_id": id, "expires_at": exp.Format(timeFormat)})
}

// GET /v1/claim/{claim_id} — unauthenticated, rate-limited per client
// network, single fetch. Every miss is the same 404 claim_unknown.
func (s *Server) handleClaimGet(w http.ResponseWriter, r *http.Request) {
	if ok, wait := s.claimLimit.Allow(rateKey(clientIP(r, s.cfg.TrustProxy)), s.now()); !ok {
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)})
		return
	}
	id := r.PathValue("claim_id")
	if _, ok := auth.ParseClaimID(id); !ok {
		s.writeError(w, fail(CodeClaimUnknown))
		return
	}
	data, err := s.st.TakeClaim(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, fail(CodeClaimUnknown))
		return
	case err != nil:
		s.log.Error("claim get failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	s.m.claimGets.Inc()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// DELETE /v1/claim/{claim_id} — signed by the creating key; idempotent 204.
func (s *Server) handleClaimDelete(w http.ResponseWriter, r *http.Request) {
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
		if err := s.st.DeleteClaim(r.Context(), mb.ID, id); err != nil {
			s.log.Error("claim delete failed", "err", err)
			s.writeError(w, fail(CodeInternal))
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
