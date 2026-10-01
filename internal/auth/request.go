// Package auth implements the relay's authentication primitives: mailbox id
// derivation (spec §3.2), signed requests (§4.1), the replay cache, and
// PASETO v4.public deposit tokens (§5).
//
// Nothing in this package logs. Errors are sentinel values that never carry
// key, signature, token or payload material.
package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
)

// FreshnessWindow is the maximum |server_now − timestamp| (spec §4.1).
const FreshnessWindow = 90 * time.Second

// Header names (spec §4.1).
const (
	HeaderKey       = "X-VettID-Key"
	HeaderTimestamp = "X-VettID-Timestamp"
	HeaderSig       = "X-VettID-Sig"
)

var (
	// ErrSignatureInvalid: headers missing/malformed or signature mismatch.
	ErrSignatureInvalid = errors.New("auth: signature invalid")
	// ErrTimestampStale: timestamp outside the freshness window.
	ErrTimestampStale = errors.New("auth: timestamp stale")
	// ErrReplay: (key, signature) seen before within the window.
	ErrReplay = errors.New("auth: replay detected")
	// ErrReplayCacheFull: the replay cache is at capacity (overload).
	ErrReplayCacheFull = errors.New("auth: replay cache full")
)

// b64 is standard base64 with padding, strict (rejects non-canonical input).
var b64 = base64.StdEncoding.Strict()

var mailboxEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// MailboxID derives the mailbox id from a raw 32-byte Ed25519 public key:
// lowercase(base32(SHA-256(pubkey))) without padding, truncated to 26 chars.
func MailboxID(pub []byte) string {
	h := sha256.Sum256(pub)
	return strings.ToLower(mailboxEncoding.EncodeToString(h[:]))[:26]
}

// ValidMailboxID reports whether s has the shape of a mailbox id.
func ValidMailboxID(s string) bool {
	if len(s) != 26 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// EncodeKey returns the canonical (standard, padded) base64 of a public key.
func EncodeKey(pub []byte) string { return b64.EncodeToString(pub) }

// DecodeStd strictly decodes standard padded base64. Unlike
// encoding/base64 alone it also rejects embedded '\r'/'\n' (which the
// standard decoder skips), so every value has exactly one spelling.
func DecodeStd(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, base64.CorruptInputError(strings.IndexAny(s, "\r\n"))
	}
	return b64.DecodeString(s)
}

// DecodeKey strictly decodes a base64 raw Ed25519 public key.
func DecodeKey(s string) (ed25519.PublicKey, bool) {
	if len(s) != 44 {
		return nil, false
	}
	k, err := DecodeStd(s)
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(k), true
}

// BodyHash is SHA-256 over the raw request body ("" for bodiless requests).
func BodyHash(body []byte) [32]byte { return sha256.Sum256(body) }

// Canonical builds the canonical request string:
//
//	METHOD "\n" PATH "\n" timestamp "\n" lowercase-hex(SHA-256(body))
func Canonical(method, path, timestamp string, bodyHash [32]byte) []byte {
	b := make([]byte, 0, len(method)+len(path)+len(timestamp)+3+64)
	b = append(b, strings.ToUpper(method)...)
	b = append(b, '\n')
	b = append(b, path...)
	b = append(b, '\n')
	b = append(b, timestamp...)
	b = append(b, '\n')
	b = hex.AppendEncode(b, bodyHash[:])
	return b
}

// Digest is SHA-256(Canonical(...)); the value that is Ed25519-signed.
func Digest(method, path, timestamp string, bodyHash [32]byte) [32]byte {
	return sha256.Sum256(Canonical(method, path, timestamp, bodyHash))
}

// SignRequest signs a request digest with priv (client side).
func SignRequest(priv ed25519.PrivateKey, method, path, timestamp string, bodyHash [32]byte) []byte {
	d := Digest(method, path, timestamp, bodyHash)
	return ed25519.Sign(priv, d[:])
}

// SetHeaders sets the three signed-request headers on h (client side).
//
// The timestamp keeps sub-second precision (RFC 3339 fractional seconds,
// trailing zeros trimmed, so whole seconds render exactly as in the spec
// vectors). This matters: the canonical string omits the query string and
// Ed25519 is deterministic, so two requests with the same method, path, body
// and a second-precision timestamp would carry identical signatures and the
// second would be rejected as a replay — e.g. a long-poll re-issued within
// the same second.
func SetHeaders(h http.Header, priv ed25519.PrivateKey, method, path string, t time.Time, bodyHash [32]byte) {
	ts := t.UTC().Format(time.RFC3339Nano)
	h.Set(HeaderKey, EncodeKey(priv.Public().(ed25519.PublicKey)))
	h.Set(HeaderTimestamp, ts)
	h.Set(HeaderSig, b64.EncodeToString(SignRequest(priv, method, path, ts, bodyHash)))
}

// SignedRequest holds the parsed signed-request headers.
type SignedRequest struct {
	Key       ed25519.PublicKey
	Timestamp string
	Time      time.Time
	Sig       []byte
}

// ParseHeaders extracts and decodes the signed-request headers. It does not
// verify anything; call Verify.
func ParseHeaders(h http.Header) (SignedRequest, error) {
	var sr SignedRequest
	kv, ts, sv := h.Values(HeaderKey), h.Values(HeaderTimestamp), h.Values(HeaderSig)
	if len(kv) != 1 || len(ts) != 1 || len(sv) != 1 {
		return sr, ErrSignatureInvalid
	}
	k, ok := DecodeKey(kv[0])
	if !ok {
		return sr, ErrSignatureInvalid
	}
	if len(sv[0]) != 88 {
		return sr, ErrSignatureInvalid
	}
	sig, err := DecodeStd(sv[0])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return sr, ErrSignatureInvalid
	}
	if len(ts[0]) > 64 {
		return sr, ErrSignatureInvalid
	}
	t, err := time.Parse(time.RFC3339, ts[0])
	if err != nil {
		return sr, ErrSignatureInvalid
	}
	return SignedRequest{Key: k, Timestamp: ts[0], Time: t, Sig: sig}, nil
}

// Verify checks freshness (±FreshnessWindow around now) and the signature
// over the canonical digest. It does not consult the replay cache.
func (sr SignedRequest) Verify(method, path string, bodyHash [32]byte, now time.Time) error {
	if d := now.Sub(sr.Time); d > FreshnessWindow || d < -FreshnessWindow {
		return ErrTimestampStale
	}
	dg := Digest(method, path, sr.Timestamp, bodyHash)
	if !ed25519.Verify(sr.Key, dg[:], sr.Sig) {
		return ErrSignatureInvalid
	}
	return nil
}
