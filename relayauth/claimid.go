package relayauth

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// Claim ids (spec §6.9): 26-char lowercase unpadded base32 of 128 bits from
// a CSPRNG. 128 bits fill 25 characters plus 3 bits of the 26th, so the last
// character's two low bits are always zero; ParseClaimID accepts only the
// canonical spelling.

var claimEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ClaimIDLen is the length of an encoded claim id.
const ClaimIDLen = 26

// NewClaimID returns a fresh random claim id.
func NewClaimID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("auth: crypto/rand failed: " + err.Error())
	}
	return strings.ToLower(claimEncoding.EncodeToString(b[:]))
}

// ParseClaimID strictly parses a claim id into its 16 bytes.
func ParseClaimID(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) != ClaimIDLen {
		return out, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7') {
			return out, false
		}
	}
	b, err := claimEncoding.DecodeString(strings.ToUpper(s))
	if err != nil || len(b) != 16 {
		return out, false
	}
	copy(out[:], b)
	// Reject non-canonical spellings (non-zero trailing bits).
	if strings.ToLower(claimEncoding.EncodeToString(out[:])) != s {
		return out, false
	}
	return out, true
}
