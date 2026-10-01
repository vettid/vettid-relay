package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// PASETO v4.public (https://github.com/paseto-standard/paseto-spec,
// docs/01-Protocol-Versions/Version4.md), implemented directly on
// crypto/ed25519. Footer and implicit assertion are empty in relay protocol
// v1 (spec §5.1); tokens carrying a footer are rejected.

const tokenHeader = "v4.public."

// MaxTokenLen bounds token parsing work (a deposit token is ~450 bytes).
const MaxTokenLen = 4096

var (
	// ErrTokenInvalid covers malformed tokens, bad signatures and claim
	// mismatches (spec code token_invalid).
	ErrTokenInvalid = errors.New("auth: token invalid")
	// ErrTokenExpired: now outside [iat, exp) (spec code token_expired).
	ErrTokenExpired = errors.New("auth: token expired")
)

var b64url = base64.RawURLEncoding.Strict()

// pae is PASETO Pre-Authentication Encoding.
func pae(pieces ...[]byte) []byte {
	n := 8
	for _, p := range pieces {
		n += 8 + len(p)
	}
	out := make([]byte, 0, n)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(pieces))&^(1<<63))
	for _, p := range pieces {
		out = binary.LittleEndian.AppendUint64(out, uint64(len(p))&^(1<<63))
		out = append(out, p...)
	}
	return out
}

// SignToken produces a v4.public token over the exact message bytes m
// (empty footer, empty implicit assertion). Ed25519 is deterministic, so the
// same key and bytes always yield the same token.
func SignToken(priv ed25519.PrivateKey, m []byte) string {
	sig := ed25519.Sign(priv, pae([]byte(tokenHeader), m, nil, nil))
	body := make([]byte, 0, len(m)+len(sig))
	body = append(append(body, m...), sig...)
	return tokenHeader + b64url.EncodeToString(body)
}

// VerifyToken checks the token's form and signature against pub and returns
// the signed message bytes.
func VerifyToken(token string, pub ed25519.PublicKey) ([]byte, error) {
	if len(token) > MaxTokenLen || !strings.HasPrefix(token, tokenHeader) || len(pub) != ed25519.PublicKeySize {
		return nil, ErrTokenInvalid
	}
	rest := token[len(tokenHeader):]
	if strings.IndexByte(rest, '.') >= 0 {
		return nil, ErrTokenInvalid // footer present (or garbage); v1 footers are empty
	}
	raw, err := b64url.DecodeString(rest)
	if err != nil || len(raw) < ed25519.SignatureSize {
		return nil, ErrTokenInvalid
	}
	m := raw[:len(raw)-ed25519.SignatureSize]
	sig := raw[len(raw)-ed25519.SignatureSize:]
	if !ed25519.Verify(pub, pae([]byte(tokenHeader), m, nil, nil), sig) {
		return nil, ErrTokenInvalid
	}
	return m, nil
}

// Quota is the optional per-token deposit cap (spec §5.2).
type Quota struct {
	Msgs  *int64 `json:"msgs,omitempty"`
	Bytes *int64 `json:"bytes,omitempty"`
}

// Claims are the deposit-token claims (spec §5.2).
type Claims struct {
	Iss   string // issuing mailbox_id
	Sub   string // canonical base64 sender relay pubkey
	Aud   string // relay base URL
	Iat   time.Time
	Exp   time.Time
	Jti   string
	Scope string
	Quota *Quota

	SubKey ed25519.PublicKey // decoded Sub
}

type wireClaims struct {
	Iss   *string `json:"iss"`
	Sub   *string `json:"sub"`
	Aud   *string `json:"aud"`
	Iat   *string `json:"iat"`
	Exp   *string `json:"exp"`
	Jti   *string `json:"jti"`
	Scope *string `json:"scope"`
	Quota *Quota  `json:"quota,omitempty"`
}

// MaxJTILen bounds the jti claim (and denylist values).
const MaxJTILen = 128

// ParseClaims decodes and structurally validates the claim JSON. All
// required claims must be present with the right types; unknown claims are
// ignored.
func ParseClaims(m []byte) (Claims, error) {
	if !utf8.Valid(m) {
		return Claims{}, ErrTokenInvalid
	}
	var w wireClaims
	dec := json.NewDecoder(bytes.NewReader(m))
	dec.UseNumber()
	if err := dec.Decode(&w); err != nil || dec.More() {
		return Claims{}, ErrTokenInvalid
	}
	if w.Iss == nil || w.Sub == nil || w.Aud == nil || w.Iat == nil || w.Exp == nil || w.Jti == nil || w.Scope == nil {
		return Claims{}, ErrTokenInvalid
	}
	c := Claims{Iss: *w.Iss, Sub: *w.Sub, Aud: *w.Aud, Jti: *w.Jti, Scope: *w.Scope, Quota: w.Quota}
	var err error
	if c.Iat, err = time.Parse(time.RFC3339, *w.Iat); err != nil {
		return Claims{}, ErrTokenInvalid
	}
	if c.Exp, err = time.Parse(time.RFC3339, *w.Exp); err != nil {
		return Claims{}, ErrTokenInvalid
	}
	var ok bool
	if c.SubKey, ok = DecodeKey(c.Sub); !ok {
		return Claims{}, ErrTokenInvalid
	}
	if c.Scope != "deposit" || c.Jti == "" || len(c.Jti) > MaxJTILen || !ValidMailboxID(c.Iss) {
		return Claims{}, ErrTokenInvalid
	}
	if q := c.Quota; q != nil {
		if (q.Msgs != nil && *q.Msgs < 0) || (q.Bytes != nil && *q.Bytes < 0) {
			return Claims{}, ErrTokenInvalid
		}
	}
	return c, nil
}

// TokenPolicy holds the relay-side inputs to claim validation.
type TokenPolicy struct {
	Audience    string        // exact-match aud (relay base URL)
	MaxLifetime time.Duration // exp−iat bound; 0 disables
}

// ValidateClaims applies spec §5.3 steps 3–5 for the given mailbox:
// iss == mailbox (token_invalid), aud == audience (token_invalid),
// iat ≤ now < exp (token_expired). Additionally, as relay policy that keeps
// denylists bounded (§5.5), exp−iat must not exceed MaxLifetime
// (token_invalid).
func ValidateClaims(c Claims, mailboxID string, p TokenPolicy, now time.Time) error {
	if c.Iss != mailboxID {
		return ErrTokenInvalid
	}
	if c.Aud != p.Audience {
		return ErrTokenInvalid
	}
	if p.MaxLifetime > 0 && c.Exp.Sub(c.Iat) > p.MaxLifetime {
		return ErrTokenInvalid
	}
	if now.Before(c.Iat) || !now.Before(c.Exp) {
		return ErrTokenExpired
	}
	return nil
}

// ParseToken verifies the token signature against the issuer mailbox's
// registered pubkey and parses its claims (spec §5.3 step 2).
func ParseToken(token string, issuerPub ed25519.PublicKey) (Claims, error) {
	m, err := VerifyToken(token, issuerPub)
	if err != nil {
		return Claims{}, err
	}
	return ParseClaims(m)
}

// MintToken builds and signs claims as compact JSON in spec key order
// (iss, sub, aud, iat, exp, jti, scope[, quota]); used by clients/tests.
func MintToken(priv ed25519.PrivateKey, c Claims) (string, error) {
	iat, exp := c.Iat.UTC().Format(time.RFC3339), c.Exp.UTC().Format(time.RFC3339)
	scope := c.Scope
	if scope == "" {
		scope = "deposit"
	}
	w := wireClaims{Iss: &c.Iss, Sub: &c.Sub, Aud: &c.Aud, Iat: &iat, Exp: &exp, Jti: &c.Jti, Scope: &scope, Quota: c.Quota}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(w); err != nil {
		return "", err
	}
	return SignToken(priv, bytes.TrimSuffix(buf.Bytes(), []byte("\n"))), nil
}
