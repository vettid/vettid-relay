package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/auth"
	"github.com/vettid/vettid-relay/internal/store"
)

// These exercise spec §5.3 steps 1–7 directly; the HTTP-level negative
// suite lives in deposit_test.go.

func (f *fixture) depositReq(owner, sender principal, token string, body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/v1/mailbox/"+owner.mbx, nil)
	auth.SetHeaders(r.Header, sender.priv, "POST", r.URL.EscapedPath(), f.clk.now(), auth.BodyHash(body))
	if token != "" {
		r.Header.Set("Authorization", "VettID-Deposit "+token)
	}
	return r
}

func code(e *apiError) string {
	if e == nil {
		return ""
	}
	return e.code
}

func TestAuthorizeDepositOrder(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	owner, sender, other := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	if _, err := f.st.Register(ctx, owner.mbx, owner.pub); err != nil {
		t.Fatal(err)
	}
	body := depositBody([]byte("x"))
	good := f.mint(owner, sender, nil)

	// Happy path through step 7.
	r := f.depositReq(owner, sender, good, body)
	da, e := f.s.authorizeDepositToken(ctx, r, owner.mbx)
	if e != nil {
		t.Fatalf("steps 1-6: %v", e)
	}
	if e := f.s.verifySender(r, da, auth.BodyHash(body)); e != nil {
		t.Fatalf("step 7: %v", e)
	}
	// Same request again → replay.
	if e := f.s.verifySender(r, da, auth.BodyHash(body)); code(e) != CodeReplayDetected {
		t.Fatalf("replay: %v", code(e))
	}

	// Step 1 precedes everything: unknown mailbox wins over a bad token.
	for _, tok := range []string{"", "garbage", good} {
		r := f.depositReq(other, sender, tok, body)
		if _, e := f.s.authorizeDepositToken(ctx, r, other.mbx); code(e) != CodeMailboxUnknown {
			t.Fatalf("unknown mailbox with token %q: %v", tok, code(e))
		}
	}
	if _, e := f.s.authorizeDepositToken(ctx, r, "NOT-A-MAILBOX"); code(e) != CodeMailboxUnknown {
		t.Fatal("malformed mailbox id")
	}

	// Step 2: token signed by someone other than the mailbox owner.
	forged := f.mint(other, sender, func(c *auth.Claims) { c.Iss = owner.mbx })
	if _, e := f.s.authorizeDepositToken(ctx, f.depositReq(owner, sender, forged, body), owner.mbx); code(e) != CodeTokenInvalid {
		t.Fatalf("forged: %v", code(e))
	}
	// Missing / wrong scheme.
	r = f.depositReq(owner, sender, "", body)
	r.Header.Set("Authorization", "Bearer "+good)
	if _, e := f.s.authorizeDepositToken(ctx, r, owner.mbx); code(e) != CodeTokenInvalid {
		t.Fatalf("wrong scheme: %v", code(e))
	}
	r.Header.Set("Authorization", "vettid-deposit "+good) // scheme is case-insensitive
	if _, e := f.s.authorizeDepositToken(ctx, r, owner.mbx); e != nil {
		t.Fatalf("lowercase scheme: %v", code(e))
	}

	// Step 6 precedes step 7: revoked token with a bad request signature → token_revoked.
	revoked := f.mint(owner, sender, func(c *auth.Claims) { c.Jti = "revoked-1" })
	if err := f.st.AddDenylist(ctx, owner.mbx, []store.DenyEntry{{Kind: "jti", Value: "revoked-1"}}, f.clk.now().Add(time.Hour), 0); err != nil {
		t.Fatal(err)
	}
	r = f.depositReq(owner, other, revoked, body) // signed by the wrong key too
	if _, e := f.s.authorizeDepositToken(ctx, r, owner.mbx); code(e) != CodeTokenRevoked {
		t.Fatalf("revoked jti: %v", code(e))
	}

	// Step 7: token for sender presented with other's signature.
	r = f.depositReq(owner, other, good, body)
	da, e = f.s.authorizeDepositToken(ctx, r, owner.mbx)
	if e != nil {
		t.Fatal(code(e))
	}
	if e := f.s.verifySender(r, da, auth.BodyHash(body)); code(e) != CodeSignatureInvalid {
		t.Fatalf("sender binding: %v", code(e))
	}
}

func TestAuthorizeOwner(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	owner, stranger := newPrincipal(1), newPrincipal(2)
	f.st.Register(ctx, owner.mbx, owner.pub)
	mk := func(p principal, at time.Time) *http.Request {
		r := httptest.NewRequest("GET", "/v1/mailbox", nil)
		auth.SetHeaders(r.Header, p.priv, "GET", "/v1/mailbox", at, auth.BodyHash(nil))
		return r
	}
	if mb, e := f.s.authorizeOwner(ctx, mk(owner, f.clk.now()), auth.BodyHash(nil)); e != nil || mb.ID != owner.mbx {
		t.Fatalf("owner: %v", code(e))
	}
	if _, e := f.s.authorizeOwner(ctx, mk(stranger, f.clk.now()), auth.BodyHash(nil)); code(e) != CodeMailboxUnknown {
		t.Fatalf("unregistered: %v", code(e))
	}
	if _, e := f.s.authorizeOwner(ctx, mk(owner, f.clk.now().Add(-2*time.Minute)), auth.BodyHash(nil)); code(e) != CodeTimestampStale {
		t.Fatalf("stale: %v", code(e))
	}
	if _, e := f.s.authorizeOwner(ctx, mk(owner, f.clk.now()), auth.BodyHash([]byte("x"))); code(e) != CodeSignatureInvalid {
		t.Fatalf("body mismatch: %v", code(e))
	}
}
