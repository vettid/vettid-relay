package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// §9.2: signing the exact claim bytes with the recipient key reproduces the
// spec token byte-for-byte, and MintToken emits the same claim bytes.
func TestVectorToken(t *testing.T) {
	recipient := vecKey(t, vecRecipientSeed)
	if got := SignToken(recipient, []byte(vecClaims)); got != vecToken {
		t.Fatalf("SignToken:\n got %s\nwant %s", got, vecToken)
	}
	minted, err := MintToken(recipient, Claims{
		Iss: vecRecipientMailbox, Sub: vecSenderPub, Aud: vecAud,
		Iat: vecTime(t, "2026-06-10T00:00:00Z"), Exp: vecTime(t, "2026-07-10T00:00:00Z"),
		Jti: "01JXAMPLE0000000000000000", Scope: "deposit",
	})
	if err != nil || minted != vecToken {
		t.Fatalf("MintToken:\n got %s\nwant %s (%v)", minted, vecToken, err)
	}

	pub := recipient.Public().(ed25519.PublicKey)
	m, err := VerifyToken(vecToken, pub)
	if err != nil || string(m) != vecClaims {
		t.Fatalf("VerifyToken: %q %v", m, err)
	}
	c, err := ParseToken(vecToken, pub)
	if err != nil {
		t.Fatal(err)
	}
	if c.Iss != vecRecipientMailbox || c.Sub != vecSenderPub || c.Aud != vecAud || c.Jti != "01JXAMPLE0000000000000000" ||
		c.Scope != "deposit" || !c.Iat.Equal(vecTime(t, "2026-06-10T00:00:00Z")) || !c.Exp.Equal(vecTime(t, "2026-07-10T00:00:00Z")) {
		t.Fatalf("claims: %+v", c)
	}
	if EncodeKey(c.SubKey) != vecSenderPub {
		t.Fatal("SubKey mismatch")
	}
	pol := TokenPolicy{Audience: vecAud, MaxLifetime: 30 * 24 * time.Hour}
	if err := ValidateClaims(c, vecRecipientMailbox, pol, vecTime(t, vecTimestamp)); err != nil {
		t.Fatalf("vector token must validate at 2026-06-10T12:00:00Z: %v", err)
	}
}

func TestTokenNegative(t *testing.T) {
	recipient := vecKey(t, vecRecipientSeed)
	sender := vecKey(t, vecSenderSeed)
	pub := recipient.Public().(ed25519.PublicKey)
	now := vecTime(t, vecTimestamp)
	pol := TokenPolicy{Audience: vecAud, MaxLifetime: 30 * 24 * time.Hour}
	base := Claims{Iss: vecRecipientMailbox, Sub: vecSenderPub, Aud: vecAud,
		Iat: vecTime(t, "2026-06-10T00:00:00Z"), Exp: vecTime(t, "2026-07-10T00:00:00Z"), Jti: "j1"}
	mint := func(c Claims) string {
		tok, err := MintToken(recipient, c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	check := func(tok string, want error) {
		t.Helper()
		c, err := ParseToken(tok, pub)
		if err == nil {
			err = ValidateClaims(c, vecRecipientMailbox, pol, now)
		}
		if !errors.Is(err, want) {
			t.Fatalf("got %v want %v", err, want)
		}
	}

	t.Run("expired", func(t *testing.T) {
		c := base
		c.Exp = now // exp is exclusive
		check(mint(c), ErrTokenExpired)
		c.Exp = now.Add(-time.Second)
		check(mint(c), ErrTokenExpired)
	})
	t.Run("not yet valid", func(t *testing.T) {
		c := base
		c.Iat = now.Add(time.Second)
		check(mint(c), ErrTokenExpired)
	})
	t.Run("wrong aud", func(t *testing.T) {
		for _, aud := range []string{"https://other.relay", vecAud + "/", strings.ToUpper(vecAud), ""} {
			c := base
			c.Aud = aud
			check(mint(c), ErrTokenInvalid)
		}
	})
	t.Run("wrong iss", func(t *testing.T) {
		c := base
		c.Iss = vecSenderMailbox
		check(mint(c), ErrTokenInvalid)
	})
	t.Run("lifetime over policy", func(t *testing.T) {
		c := base
		c.Exp = c.Iat.Add(31 * 24 * time.Hour)
		check(mint(c), ErrTokenInvalid)
	})
	t.Run("signed by wrong key", func(t *testing.T) {
		tok, _ := MintToken(sender, base)
		check(tok, ErrTokenInvalid)
	})
	t.Run("tampered", func(t *testing.T) {
		raw, _ := base64.RawURLEncoding.DecodeString(vecToken[len(tokenHeader):])
		for _, i := range []int{0, 20, len(raw) - 70, len(raw) - 1} {
			mod := append([]byte{}, raw...)
			mod[i] ^= 1
			check(tokenHeader+base64.RawURLEncoding.EncodeToString(mod), ErrTokenInvalid)
		}
	})
	t.Run("structural", func(t *testing.T) {
		for _, tok := range []string{
			"", "v4.public.", "v4.local." + vecToken[len(tokenHeader):], "v3.public." + vecToken[len(tokenHeader):],
			vecToken + ".Zm9vdGVy", vecToken + ".", vecToken + "=", vecToken[:len(vecToken)-1],
			strings.Replace(vecToken, "_", "/", 1), "v4.public." + strings.Repeat("A", MaxTokenLen),
		} {
			check(tok, ErrTokenInvalid)
		}
	})
	t.Run("claims", func(t *testing.T) {
		for _, m := range []string{
			`{}`, `[]`, `null`, `{"iss":1}`,
			strings.Replace(vecClaims, `"scope":"deposit"`, `"scope":"admin"`, 1),
			strings.Replace(vecClaims, `,"scope":"deposit"`, ``, 1),
			strings.Replace(vecClaims, `"jti":"01JXAMPLE0000000000000000"`, `"jti":""`, 1),
			strings.Replace(vecClaims, vecSenderPub, "AAAA", 1),
			strings.Replace(vecClaims, `"iat":"2026-06-10T00:00:00Z"`, `"iat":1749513600`, 1),
			strings.Replace(vecClaims, `"exp":"2026-07-10T00:00:00Z"`, `"exp":"tomorrow"`, 1),
			strings.Replace(vecClaims, `}`, `,"quota":{"msgs":-1}}`, 1),
			strings.Replace(vecClaims, `}`, `,"quota":{"bytes":1.5}}`, 1),
			vecClaims + `{}`,
			"\xff" + vecClaims,
		} {
			check(SignToken(recipient, []byte(m)), ErrTokenInvalid)
		}
	})
	t.Run("quota parsed", func(t *testing.T) {
		m := strings.Replace(vecClaims, `}`, `,"quota":{"msgs":5,"bytes":1024}}`, 1)
		c, err := ParseToken(SignToken(recipient, []byte(m)), pub)
		if err != nil || c.Quota == nil || *c.Quota.Msgs != 5 || *c.Quota.Bytes != 1024 {
			t.Fatalf("quota: %+v %v", c.Quota, err)
		}
	})
}

func FuzzParseToken(f *testing.F) {
	f.Add(vecToken)
	f.Add("v4.public.")
	f.Add("v4.public.AAAA")
	f.Add(vecToken + ".Zm9vdGVy")
	f.Add("v4.local.eyJ9")
	recipient := vecKey(f, vecRecipientSeed)
	pub := recipient.Public().(ed25519.PublicKey)
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := ParseToken(tok, pub)
		if err != nil {
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		// Anything that verifies must have been signed by the recipient key:
		// in the fuzzer that can only be the vector token itself.
		if tok != vecToken {
			t.Fatalf("forged token accepted: %q", tok)
		}
		if c.Iss != vecRecipientMailbox {
			t.Fatal("claims mismatch")
		}
	})
}

func FuzzParseClaims(f *testing.F) {
	f.Add([]byte(vecClaims))
	f.Add([]byte(`{"quota":{"msgs":1}}`))
	f.Add([]byte(`{"iss":"a","iss":"b"}`))
	f.Add([]byte(strings.Replace(strings.Replace(vecClaims, vecSenderPub, "*", 1), `"deposit"`, `"deposit_open"`, 1)))
	f.Fuzz(func(t *testing.T, m []byte) {
		c, err := ParseClaims(m)
		if err != nil {
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		okSub := (c.Scope == ScopeDeposit && len(c.SubKey) == ed25519.PublicKeySize) || (c.Scope == ScopeDepositOpen && c.Sub == OpenSub && c.SubKey == nil)
		if !okSub || !ValidMailboxID(c.Iss) || c.Jti == "" {
			t.Fatalf("invalid claims accepted: %+v", c)
		}
	})
}

// Regression (found by FuzzParseToken): encoding/base64 skips CR/LF even in
// strict mode, which let one token have many spellings.
func TestTokenRejectsEmbeddedNewlines(t *testing.T) {
	pub := vecKey(t, vecRecipientSeed).Public().(ed25519.PublicKey)
	for _, ins := range []string{"\r", "\n", "\r\n", " ", "="} {
		mod := vecToken[:100] + ins + vecToken[100:]
		if _, err := ParseToken(mod, pub); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("token with %q accepted", ins)
		}
	}
	for _, s := range []string{vecSenderPub[:10] + "\n" + vecSenderPub[10:], vecSigB64[:20] + "\r" + vecSigB64[20:]} {
		if _, err := DecodeStd(s); err == nil {
			t.Errorf("DecodeStd accepted %q", s)
		}
	}
}

func TestOpenTokenClaims(t *testing.T) {
	recipient := vecKey(t, vecRecipientSeed)
	pub := recipient.Public().(ed25519.PublicKey)
	now := vecTime(t, vecTimestamp)
	pol := TokenPolicy{Audience: vecAud, MaxLifetime: 30 * 24 * time.Hour, OpenMaxLifetime: 600 * time.Second}
	open := Claims{Iss: vecRecipientMailbox, Sub: OpenSub, Aud: vecAud, Iat: now.Add(-time.Second),
		Exp: now.Add(599 * time.Second), Jti: "first-contact", Scope: ScopeDepositOpen}
	tok, err := MintToken(recipient, open)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mustVerify(t, tok, pub)), `"sub":"*"`) || !strings.Contains(string(mustVerify(t, tok, pub)), `"scope":"deposit_open"`) {
		t.Fatal("open token claims not encoded as expected")
	}
	c, err := ParseToken(tok, pub)
	if err != nil || !c.Open() || c.SubKey != nil {
		t.Fatalf("parse open: %+v %v", c, err)
	}
	if err := ValidateClaims(c, vecRecipientMailbox, pol, now); err != nil {
		t.Fatalf("valid open token: %v", err)
	}
	// Lifetime above the open cap (but far below the bound-token cap).
	long := open
	long.Exp = long.Iat.Add(601 * time.Second)
	tl, _ := MintToken(recipient, long)
	if c, err := ParseToken(tl, pub); err != nil || !errors.Is(ValidateClaims(c, vecRecipientMailbox, pol, now), ErrTokenInvalid) {
		t.Fatal("open token above open_token_max_lifetime accepted")
	}
	// An unset open cap admits no open token at all.
	if !errors.Is(ValidateClaims(c, vecRecipientMailbox, TokenPolicy{Audience: vecAud}, now), ErrTokenInvalid) {
		t.Fatal("open token accepted without an open cap")
	}
	// Scope and sub must agree.
	for _, m := range []Claims{
		{Iss: vecRecipientMailbox, Sub: vecSenderPub, Aud: vecAud, Iat: now, Exp: now.Add(time.Minute), Jti: "x", Scope: ScopeDepositOpen},
		{Iss: vecRecipientMailbox, Sub: OpenSub, Aud: vecAud, Iat: now, Exp: now.Add(time.Minute), Jti: "x", Scope: ScopeDeposit},
		{Iss: vecRecipientMailbox, Sub: "", Aud: vecAud, Iat: now, Exp: now.Add(time.Minute), Jti: "x", Scope: ScopeDepositOpen},
	} {
		bad, _ := MintToken(recipient, m)
		if _, err := ParseToken(bad, pub); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("scope %q with sub %q accepted", m.Scope, m.Sub)
		}
	}
}

func mustVerify(t *testing.T, tok string, pub ed25519.PublicKey) []byte {
	t.Helper()
	m, err := VerifyToken(tok, pub)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
