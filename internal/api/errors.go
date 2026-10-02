package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Canonical error codes (spec §7.1, §6.8).
const (
	CodeTokenInvalid     = "token_invalid"
	CodeTokenExpired     = "token_expired"
	CodeTokenRevoked     = "token_revoked"
	CodeMailboxUnknown   = "mailbox_unknown"
	CodeBlobUnknown      = "blob_unknown"
	CodePayloadTooLarge  = "payload_too_large"
	CodeQuotaExceeded    = "quota_exceeded"
	CodeRateLimited      = "rate_limited"
	CodeSignatureInvalid = "signature_invalid"
	CodeTimestampStale   = "timestamp_stale"
	CodeReplayDetected   = "replay_detected"
	CodeInternal         = "internal"
	CodeBadRequest       = "bad_request"
	CodeNotFound         = "not_found"
	CodeTokenUsed        = "token_used"    // 0.3.0 §5.6
	CodeClaimUnknown     = "claim_unknown" // 0.3.0 §6.9
)

// allCodes is the closed set used for metric labels.
var allCodes = []string{
	CodeTokenInvalid, CodeTokenExpired, CodeTokenRevoked, CodeMailboxUnknown,
	CodeBlobUnknown, CodePayloadTooLarge, CodeQuotaExceeded, CodeRateLimited,
	CodeSignatureInvalid, CodeTimestampStale, CodeReplayDetected, CodeInternal,
	CodeBadRequest, CodeNotFound, CodeTokenUsed, CodeClaimUnknown,
}

// statusFor maps codes to HTTP status exactly as the spec §7.1 table does.
func statusFor(code string) int {
	switch code {
	case CodeTokenInvalid, CodeTokenExpired, CodeSignatureInvalid, CodeTimestampStale, CodeReplayDetected:
		return http.StatusUnauthorized
	case CodeTokenRevoked:
		return http.StatusForbidden
	case CodeMailboxUnknown, CodeBlobUnknown, CodeClaimUnknown, CodeNotFound:
		return http.StatusNotFound
	case CodeTokenUsed:
		return http.StatusConflict
	case CodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case CodeQuotaExceeded, CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeBadRequest:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

var defaultMessages = map[string]string{
	CodeTokenInvalid:     "deposit token is invalid",
	CodeTokenExpired:     "deposit token is expired or not yet valid",
	CodeTokenRevoked:     "deposit token has been revoked",
	CodeMailboxUnknown:   "mailbox unknown",
	CodeBlobUnknown:      "blob unknown",
	CodePayloadTooLarge:  "payload too large",
	CodeQuotaExceeded:    "quota exceeded",
	CodeRateLimited:      "rate limited",
	CodeSignatureInvalid: "request signature invalid",
	CodeTimestampStale:   "request timestamp outside the freshness window",
	CodeReplayDetected:   "request replay detected",
	CodeInternal:         "internal error",
	CodeBadRequest:       "malformed request",
	CodeNotFound:         "not found",
	CodeTokenUsed:        "one-shot token already used",
	CodeClaimUnknown:     "claim unknown",
}

type errorBody struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// apiError is returned by handler helpers and rendered by writeError.
type apiError struct {
	code       string
	retryAfter int
}

func (e *apiError) Error() string { return e.code }

func fail(code string) *apiError { return &apiError{code: code} }

// writeError renders the error body. Messages are fixed strings per code —
// they never echo request content (no ids, keys, tokens or payloads).
func (s *Server) writeError(w http.ResponseWriter, e *apiError) {
	if rec, ok := w.(*recorder); ok {
		rec.code = e.code
	}
	s.m.errors.With(e.code).Inc()
	if e.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(e.retryAfter))
	}
	writeJSON(w, statusFor(e.code), errorBody{Code: e.code, Message: defaultMessages[e.code], RetryAfter: e.retryAfter})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
