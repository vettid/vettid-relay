package auth

// Test vectors from docs/RELAY-PROTOCOL.md §9. Every value here is copied
// verbatim from the spec and must be reproduced byte-for-byte.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
	"time"
)

const (
	vecRecipientSeed    = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	vecRecipientPub     = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
	vecRecipientMailbox = "gr2q7gf5lh6pzfdnurnkvputhp"
	vecSenderSeed       = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	vecSenderPub        = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="
	vecSenderMailbox    = "ni4ahvpqlgicuhdnv66jxjdssi"

	vecClaims = `{"iss":"gr2q7gf5lh6pzfdnurnkvputhp","sub":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=","aud":"https://relay.example.vettid.org","iat":"2026-06-10T00:00:00Z","exp":"2026-07-10T00:00:00Z","jti":"01JXAMPLE0000000000000000","scope":"deposit"}`
	vecToken  = "v4.public.eyJpc3MiOiJncjJxN2dmNWxoNnB6ZmRudXJua3ZwdXRocCIsInN1YiI6ImdUbDNEcWg5RjE5V28xUm13MHgrek11TmlwRzA3amVpWGZZUFc0L0pzNVE9IiwiYXVkIjoiaHR0cHM6Ly9yZWxheS5leGFtcGxlLnZldHRpZC5vcmciLCJpYXQiOiIyMDI2LTA2LTEwVDAwOjAwOjAwWiIsImV4cCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwianRpIjoiMDFKWEFNUExFMDAwMDAwMDAwMDAwMDAwMCIsInNjb3BlIjoiZGVwb3NpdCJ9rWQjEmgif2o_c9SNTUXzHPPLWKZCPMAPUk3VPpbWkTIY0pfihNHpVZeX-YDM35FN_u1FVYPHj4BrO4sGJQj6BA"
	vecAud    = "https://relay.example.vettid.org"

	vecMethod     = "POST"
	vecPath       = "/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp"
	vecBody       = `{"payload":"b3BhcXVlLWNpcGhlcnRleHQtYnl0ZXM="}`
	vecBodyHex    = "0237514b3df17b219036f1b8fa6ca70d4ca597eb630933841707380055d7e12a"
	vecTimestamp  = "2026-06-10T12:00:00Z"
	vecCanonical  = "POST\n/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp\n2026-06-10T12:00:00Z\n0237514b3df17b219036f1b8fa6ca70d4ca597eb630933841707380055d7e12a"
	vecDigestB64  = "l+mc5XMNElCBLC49xJH4Lc8LHEAlAK1HunqaS+LZ33k="
	vecSigB64     = "pOZT7Pb981+3K4wWv6Zryb43miSLBfKdCZ4Wc/qNzQyxFtOPrsSSkK1Gj5mF+Zb3z3yC4Bi7AyjIyVkeN+nsDA=="
	emptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func vecKey(t testing.TB, seedB64 string) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != 32 {
		t.Fatalf("bad seed: %v", err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func vecTime(t testing.TB, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

// §9.1
func TestVectorKeysAndMailboxIDs(t *testing.T) {
	for _, v := range []struct{ seed, pub, mbx string }{
		{vecRecipientSeed, vecRecipientPub, vecRecipientMailbox},
		{vecSenderSeed, vecSenderPub, vecSenderMailbox},
	} {
		priv := vecKey(t, v.seed)
		pub := priv.Public().(ed25519.PublicKey)
		if got := EncodeKey(pub); got != v.pub {
			t.Errorf("pubkey: got %s want %s", got, v.pub)
		}
		if got := MailboxID(pub); got != v.mbx {
			t.Errorf("mailbox_id: got %s want %s", got, v.mbx)
		}
		if !ValidMailboxID(v.mbx) {
			t.Errorf("ValidMailboxID(%s) = false", v.mbx)
		}
	}
}

// §9.3
func TestVectorSignedRequest(t *testing.T) {
	bh := BodyHash([]byte(vecBody))
	if got := hex.EncodeToString(bh[:]); got != vecBodyHex {
		t.Fatalf("sha256(body): got %s want %s", got, vecBodyHex)
	}
	if got := string(Canonical(vecMethod, vecPath, vecTimestamp, bh)); got != vecCanonical {
		t.Fatalf("canonical:\n got %q\nwant %q", got, vecCanonical)
	}
	d := Digest(vecMethod, vecPath, vecTimestamp, bh)
	if got := base64.StdEncoding.EncodeToString(d[:]); got != vecDigestB64 {
		t.Fatalf("digest: got %s want %s", got, vecDigestB64)
	}
	sender := vecKey(t, vecSenderSeed)
	sig := SignRequest(sender, vecMethod, vecPath, vecTimestamp, bh)
	if got := base64.StdEncoding.EncodeToString(sig); got != vecSigB64 {
		t.Fatalf("signature: got %s want %s", got, vecSigB64)
	}

	// Client helper produces exactly the spec headers.
	h := http.Header{}
	SetHeaders(h, sender, vecMethod, vecPath, vecTime(t, vecTimestamp), bh)
	if h.Get(HeaderKey) != vecSenderPub || h.Get(HeaderTimestamp) != vecTimestamp || h.Get(HeaderSig) != vecSigB64 {
		t.Fatalf("headers: %v", h)
	}

	// Server side: the spec's headers verify at the spec's time.
	sr, err := ParseHeaders(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := sr.Verify(vecMethod, vecPath, bh, vecTime(t, vecTimestamp)); err != nil {
		t.Fatalf("verify vector: %v", err)
	}
}

func TestEmptyBodyHash(t *testing.T) {
	bh := BodyHash(nil)
	if hex.EncodeToString(bh[:]) != emptyBodyHash {
		t.Fatal("empty body hash mismatch with spec §4.1")
	}
}

func TestCanonicalUppercasesMethod(t *testing.T) {
	bh := BodyHash(nil)
	if !bytes.Equal(Canonical("get", "/v1/mailbox", "t", bh), Canonical("GET", "/v1/mailbox", "t", bh)) {
		t.Fatal("METHOD must be uppercase in the canonical string")
	}
}
