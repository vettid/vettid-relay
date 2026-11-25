package relayclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

// Code claims (RELAY-PROTOCOL 0.14.0 §6.9.1; VAULT-MESSAGING 0.94.0
// §6.7.2): the hourly lookup salts, the creator's PUT and DELETE. Each
// call makes one attempt and is never retried here: the creator decides
// (one try on the other salt after a bad_request, a new code after a
// code_taken), and owns any §7.2 backoff after a 429 or a 5xx. The redeem
// is the new device's, not a vault's, and is not here.
//
// The tag, the salts and the blob are secrets of a live code: nothing here
// logs them.

// PairCodeSalt is one entry of GET /v1/pair-code/salts, as listed. The
// caller checks the list (VAULT-MESSAGING §6.7.2) before using any entry.
type PairCodeSalt struct {
	SaltID string `json:"salt_id"`
	Epoch  int64  `json:"epoch"`
	Nonce  []byte `json:"nonce"` // base64, 16 bytes when well formed
}

// PairCodePut is the body of PUT /v1/pair-code/{claim_id}.
type PairCodePut struct {
	SaltID string `json:"salt_id"`
	Tag    []byte `json:"tag"`  // 32 bytes
	Salt   []byte `json:"salt"` // s_c, 16 bytes
	Blob   []byte `json:"blob"`
}

// The codes a creator acts on.
const (
	// CodeCodeTaken: the tag matched a live code claim, and the relay
	// deleted both (409). The creator makes a new code.
	CodeCodeTaken = "code_taken"
	// CodeBadRequest: for a PUT, among others, a salt_id the relay does
	// not accept now (400).
	CodeBadRequest = "bad_request"
)

// Errors found before any request is sent.
var (
	// ErrClaimID is a claim id that is not a canonical claim id (128 bits,
	// 26 lowercase base32 characters, relayauth.ParseClaimID).
	ErrClaimID = errors.New("relayclient: malformed code claim id")
	// ErrPairCodePut is a PUT body of the wrong form: so a bad_request
	// from the relay never stands for a local mistake.
	ErrPairCodePut = errors.New("relayclient: malformed code claim body")
	// ErrPairCodeAnswer wraps a 2xx PUT answer that does not read: the
	// relay may hold the claim.
	ErrPairCodeAnswer = errors.New("relayclient: pair-code put answer unreadable")
	// ErrPairCodeSalts is a salts answer that does not read.
	ErrPairCodeSalts = errors.New("relayclient: pair-code salts answer unreadable")
)

// OffersPairCodes reports whether the relay advertised code claims
// (limits.pair_codes; only true counts).
func (l Limits) OffersPairCodes() bool {
	var b bool
	return json.Unmarshal(l.PairCodes, &b) == nil && b
}

// Answer bounds: the salts answer (two entries are about 160 bytes) and
// the PUT's ({"expires_at": ...}).
const (
	maxSaltsBody = 4096
	maxPutAnswer = 4096
)

// PairCodeSalts lists the relay's lookup salts (unauthenticated). An
// answer without salts gives an empty list, which the caller refuses with
// the rest of its checks.
func (c *Client) PairCodeSalts(ctx context.Context) ([]PairCodeSalt, error) {
	resp, err := c.once(ctx, request{method: "GET", path: "/v1/pair-code/salts", unsigned: true})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Salts []PairCodeSalt `json:"salts"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxSaltsBody))
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPairCodeSalts, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrPairCodeSalts // anything after the object
	}
	return out.Salts, nil
}

// PutPairCode creates the code claim claimID, which the creator chose
// (signed). It returns the claim's expiry. A 409 is an *Error with code
// CodeCodeTaken, a refused salt one with CodeBadRequest.
func (c *Client) PutPairCode(ctx context.Context, claimID string, p PairCodePut) (time.Time, error) {
	if _, ok := relayauth.ParseClaimID(claimID); !ok {
		return time.Time{}, ErrClaimID
	}
	if !validSaltID(p.SaltID) || len(p.Tag) != 32 || len(p.Salt) != 16 || len(p.Blob) == 0 {
		return time.Time{}, ErrPairCodePut
	}
	body, err := json.Marshal(p)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := c.once(ctx, request{method: "PUT", path: "/v1/pair-code/" + claimID, body: body})
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()
	var out struct {
		ExpiresAt string `json:"expires_at"`
	}
	// A 2xx answer means the relay stored the claim; an answer that does
	// not read is said so, not taken for a request that never arrived.
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPutAnswer)).Decode(&out); err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrPairCodeAnswer, err)
	}
	exp, err := time.Parse(time.RFC3339, out.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrPairCodeAnswer, err)
	}
	return exp, nil
}

// DeletePairCode deletes a code claim this mailbox created (signed;
// idempotent: 204 whether or not it still exists).
func (c *Client) DeletePairCode(ctx context.Context, claimID string) error {
	if _, ok := relayauth.ParseClaimID(claimID); !ok {
		return ErrClaimID
	}
	resp, err := c.once(ctx, request{method: "DELETE", path: "/v1/pair-code/" + claimID})
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxPutAnswer))
	return resp.Body.Close()
}

// validSaltID: 8 lowercase hex characters (§6.9.1).
func validSaltID(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
