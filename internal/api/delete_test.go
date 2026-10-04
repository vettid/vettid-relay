package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	auth "github.com/vettid/vettid-relay/relayauth"
)

func (f *fixture) deleteMailbox(owner principal) (int, []byte) {
	f.t.Helper()
	return f.do(req{method: "DELETE", path: "/v1/mailbox", signer: &owner})
}

// Spec §6.10 (0.5.0): an owner-signed DELETE /v1/mailbox removes the
// mailbox and everything in it; afterwards the id behaves as never
// registered, and the call is idempotent.
func TestDeleteMailbox(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	f.mustDeposit(owner, sender, tok, []byte("pending"))
	code, b := f.do(req{method: "PUT", path: "/v1/claim", body: []byte("bundle"), signer: &owner})
	if code != http.StatusCreated {
		t.Fatalf("claim: %d %s", code, b)
	}
	var claim struct {
		ClaimID string `json:"claim_id"`
	}
	json.Unmarshal(b, &claim)

	// Not the owner's request: a body, or no signature.
	f.expectCode(req{method: "DELETE", path: "/v1/mailbox", body: []byte("{}"), signer: &owner}, 400, CodeBadRequest)
	f.expectCode(req{method: "DELETE", path: "/v1/mailbox"}, 401, CodeSignatureInvalid)
	if c := f.collect(owner, ""); len(c.Messages) != 1 {
		t.Fatal("refused deletes must not delete")
	}

	if code, b := f.deleteMailbox(owner); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("late")), signer: &sender, token: tok}, 404, CodeMailboxUnknown)
	f.expectCode(req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: []byte("blob"), signer: &sender, token: tok}, 404, CodeMailboxUnknown)
	f.expectCode(req{method: "GET", path: "/v1/mailbox", signer: &owner}, 404, CodeMailboxUnknown)
	f.expectCode(req{method: "POST", path: "/v1/mailbox/denylist", body: []byte(`{"revoke":[]}`), signer: &owner}, 404, CodeMailboxUnknown)
	f.expectCode(req{method: "GET", path: "/v1/claim/" + claim.ClaimID}, 404, CodeClaimUnknown)
	// Idempotent, also for a key that never registered.
	if code, b := f.deleteMailbox(owner); code != http.StatusNoContent {
		t.Fatalf("repeat delete: %d %s", code, b)
	}
	stranger := newPrincipal(3)
	if code, b := f.deleteMailbox(stranger); code != http.StatusNoContent {
		t.Fatalf("delete of an unregistered key: %d %s", code, b)
	}
	if got := f.s.m.deletions.Value(); got != 1 {
		t.Fatalf("deletions metric %d", got)
	}
}

// Re-registering a deleted key gives a fresh mailbox; tokens issued before
// the deletion (whose revocations went with it) stay refused, and tokens
// issued at least the freshness window after it work.
func TestDeleteMailboxReRegister(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	old := f.mint(owner, sender, nil)
	f.revoke(owner, "jti", "tok-"+sender.mbx[:8]) // this revocation is lost with the mailbox
	if code, b := f.deleteMailbox(owner); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	f.register(owner)
	if c := f.collect(owner, ""); len(c.Messages) != 0 {
		t.Fatal("a re-registered mailbox starts empty")
	}
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("old")), signer: &sender, token: old}, 403, CodeTokenRevoked)
	f.clk.add(2 * time.Minute)
	fresh := f.mint(owner, sender, func(c *auth.Claims) { c.Iat = f.clk.now(); c.Jti = "fresh" })
	f.mustDeposit(owner, sender, fresh, []byte("new"))
	// Still refused later on: the tombstone outlives the old token.
	f.clk.add(time.Hour)
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("old")), signer: &sender, token: old}, 403, CodeTokenRevoked)
}

// A collector parked on a deleted mailbox gets a terminal mailbox_unknown,
// at once; a WebSocket session is closed with 4404.
func TestDeleteMailboxEndsCollectors(t *testing.T) {
	f := newFixture(t, nil)
	owner := newPrincipal(1)
	f.register(owner)
	conn, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	type res struct {
		code int
		body []byte
	}
	got := make(chan res, 1)
	go func() {
		code, b := f.do(req{method: "GET", path: "/v1/mailbox?wait=25", signer: &owner})
		got <- res{code, b}
	}()
	waitFor(t, func() bool { return f.s.m.parked.Value() == 1 && f.s.hub.collectors() == 2 })
	if code, b := f.deleteMailbox(owner); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	select {
	case r := <-got:
		var e errorBody
		json.Unmarshal(r.body, &e)
		if r.code != 404 || e.Code != CodeMailboxUnknown {
			t.Fatalf("parked collect: %d %s", r.code, r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parked collect not ended by the deletion")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err = conn.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != wsStatusMailboxUnknown || ce.Reason != CodeMailboxUnknown {
		t.Fatalf("websocket after delete: %v", err)
	}
}

// Deleting a rotation successor also deletes the predecessor in its grace
// period, so tokens issued under the old key stop working too.
func TestDeleteMailboxAfterRotation(t *testing.T) {
	f := newFixture(t, nil)
	owner, next, sender := newPrincipal(1), newPrincipal(4), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	proof := ed25519.Sign(next.priv, []byte(owner.mbx))
	body, _ := json.Marshal(map[string]any{"new_pubkey": next.b64, "new_key_proof": proof})
	if code, b := f.do(req{method: "POST", path: "/v1/mailbox/rotate", body: body, signer: &owner}); code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, b)
	}
	f.mustDeposit(owner, sender, tok, []byte("grace")) // old mailbox still accepts
	if code, b := f.deleteMailbox(next); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("late")), signer: &sender, token: tok}, 404, CodeMailboxUnknown)
	f.expectCode(req{method: "GET", path: "/v1/mailbox", signer: &owner}, 404, CodeMailboxUnknown)
	if got := f.s.m.deletions.Value(); got != 2 {
		t.Fatalf("deletions metric %d, want 2", got)
	}
}

func TestHealthzProtocolVersion(t *testing.T) {
	f := newFixture(t, nil)
	code, b := f.do(req{method: "GET", path: "/healthz"})
	var h map[string]string
	json.Unmarshal(b, &h)
	if code != 200 || h["protocol"] != "0.5.0" {
		t.Fatalf("healthz %d %s", code, b)
	}
}

// A rotated-away mailbox removed at the end of its grace leaves the same
// tombstone (§6.7): re-registering the old key gives a fresh mailbox in
// which tokens issued before the removal are refused, although their
// revocations are gone.
func TestRotatedMailboxTombstone(t *testing.T) {
	f := newFixture(t, nil)
	owner, next, sender := newPrincipal(1), newPrincipal(4), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, func(c *auth.Claims) { c.Exp = c.Iat.Add(30 * 24 * time.Hour) })
	f.revoke(owner, "sub", sender.b64)
	proof := ed25519.Sign(next.priv, []byte(owner.mbx))
	body, _ := json.Marshal(map[string]any{"new_pubkey": next.b64, "new_key_proof": proof})
	if code, b := f.do(req{method: "POST", path: "/v1/mailbox/rotate", body: body, signer: &owner}); code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, b)
	}
	f.clk.add(f.cfg.RotationGrace + 11*time.Minute) // past the grace and any purge delay
	if _, err := f.st.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.register(owner)
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("old")), signer: &sender, token: tok}, 403, CodeTokenRevoked)
	f.clk.add(2 * time.Minute)
	fresh := f.mint(owner, sender, func(c *auth.Claims) { c.Iat = f.clk.now(); c.Exp = c.Iat.Add(time.Hour); c.Jti = "fresh" })
	f.mustDeposit(owner, sender, fresh, []byte("new"))
}
