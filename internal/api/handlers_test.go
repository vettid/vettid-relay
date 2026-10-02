package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	auth "github.com/vettid/vettid-relay/relayauth"
)

type collectResp struct {
	Messages []struct {
		MsgID       string `json:"msg_id"`
		DepositedAt string `json:"deposited_at"`
		Sender      string `json:"sender"`
		JTI         string `json:"jti"`
		Payload     []byte `json:"payload"`
	} `json:"messages"`
}

func (f *fixture) deposit(owner, sender principal, token string, payload []byte) (int, []byte) {
	f.t.Helper()
	return f.do(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody(payload), signer: &sender, token: token})
}

func (f *fixture) mustDeposit(owner, sender principal, token string, payload []byte) string {
	f.t.Helper()
	code, b := f.deposit(owner, sender, token, payload)
	if code != http.StatusCreated {
		f.t.Fatalf("deposit: %d %s", code, b)
	}
	var out struct {
		MsgID string `json:"msg_id"`
	}
	json.Unmarshal(b, &out)
	if len(out.MsgID) != 26 {
		f.t.Fatalf("bad msg_id in %s", b)
	}
	return out.MsgID
}

func (f *fixture) collect(owner principal, query string) collectResp {
	f.t.Helper()
	code, b := f.do(req{method: "GET", path: "/v1/mailbox" + query, signer: &owner})
	if code != http.StatusOK {
		f.t.Fatalf("collect: %d %s", code, b)
	}
	var out collectResp
	if err := json.Unmarshal(b, &out); err != nil || out.Messages == nil {
		f.t.Fatalf("collect body %s: %v", b, err)
	}
	return out
}

func (f *fixture) ack(owner principal, msgID string) (int, []byte) {
	f.t.Helper()
	return f.do(req{method: "DELETE", path: "/v1/mailbox/" + msgID, signer: &owner})
}

func (f *fixture) revoke(owner principal, kind, value string) {
	f.t.Helper()
	body := []byte(fmt.Sprintf(`{"revoke":[{"kind":%q,"value":%q}]}`, kind, value))
	if code, b := f.do(req{method: "POST", path: "/v1/mailbox/denylist", body: body, signer: &owner}); code != http.StatusNoContent {
		f.t.Fatalf("denylist: %d %s", code, b)
	}
}

func TestRegister(t *testing.T) {
	f := newFixture(t, nil)
	p := newPrincipal(1)
	body := []byte(`{"pubkey":"` + p.b64 + `"}`)
	code, b := f.do(req{method: "POST", path: "/v1/register", body: body, signer: &p})
	if code != http.StatusCreated {
		t.Fatalf("%d %s", code, b)
	}
	want := `{"mailbox_id":"` + p.mbx + `","limits":{"max_payload_bytes":262144,"message_ttl_seconds":1209600,"visibility_timeout_seconds":60,` +
		`"max_token_lifetime_seconds":2592000,"open_token_max_lifetime_seconds":600,"max_claim_bytes":16384,"claim_ttl_seconds":900,` +
		`"max_blob_bytes":8388608,"blob_ttl_seconds":604800}}` + "\n"
	if string(b) != want {
		t.Fatalf("register body:\n got %s\nwant %s", b, want)
	}
	// Idempotent → 200 with the same body (a fresh signature, not a replay).
	f.clk.add(time.Second)
	code, b2 := f.do(req{method: "POST", path: "/v1/register", body: body, signer: &p})
	if code != http.StatusOK || !bytes.Equal(b, b2) {
		t.Fatalf("re-register: %d %s", code, b2)
	}
	// Proof of possession: signer must be the key being registered.
	other := newPrincipal(2)
	f.expectCode(req{method: "POST", path: "/v1/register", body: body, signer: &other}, 401, CodeSignatureInvalid)
	f.expectCode(req{method: "POST", path: "/v1/register", body: body}, 401, CodeSignatureInvalid)
	f.expectCode(req{method: "POST", path: "/v1/register", body: []byte(`{"pubkey":"AAAA"}`), signer: &p}, 400, CodeBadRequest)
	f.expectCode(req{method: "POST", path: "/v1/register", body: []byte(`not json`), signer: &p}, 400, CodeBadRequest)
}

func TestRegisterWithoutBlobs(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.BlobsEnabled = false })
	p := newPrincipal(1)
	_, b := f.do(req{method: "POST", path: "/v1/register", body: []byte(`{"pubkey":"` + p.b64 + `"}`), signer: &p})
	if strings.Contains(string(b), "blob") {
		t.Fatalf("blob limits advertised while disabled: %s", b)
	}
}

func TestDepositCollectAck(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)

	var ids []string
	for i := 0; i < 3; i++ {
		ids = append(ids, f.mustDeposit(owner, sender, tok, []byte(fmt.Sprintf("ciphertext-%d", i))))
	}
	got := f.collect(owner, "?max=2")
	if len(got.Messages) != 2 || got.Messages[0].MsgID != ids[0] || string(got.Messages[1].Payload) != "ciphertext-1" ||
		got.Messages[0].Sender != sender.b64 {
		t.Fatalf("collect: %+v", got)
	}
	if _, err := time.Parse(time.RFC3339, got.Messages[0].DepositedAt); err != nil || !strings.HasSuffix(got.Messages[0].DepositedAt, "Z") {
		t.Fatalf("deposited_at %q", got.Messages[0].DepositedAt)
	}
	// Leased messages are not returned again; the third is.
	if got := f.collect(owner, ""); len(got.Messages) != 1 || got.Messages[0].MsgID != ids[2] {
		t.Fatalf("second collect: %+v", got)
	}
	// Ack: 204, idempotent.
	for _, id := range append(ids, ids[0], "01J00000000000000000000000", "short") {
		if code, b := f.ack(owner, id); code != http.StatusNoContent {
			t.Fatalf("ack %s: %d %s", id, code, b)
		}
	}
	// Nothing left even after the visibility timeout.
	f.clk.add(61 * time.Second)
	if got := f.collect(owner, ""); len(got.Messages) != 0 {
		t.Fatalf("acked messages redelivered: %+v", got)
	}
}

func TestVisibilityTimeoutRedelivery(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	id := f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("x"))
	if got := f.collect(owner, ""); len(got.Messages) != 1 {
		t.Fatal("first delivery")
	}
	f.clk.add(30 * time.Second)
	if got := f.collect(owner, ""); len(got.Messages) != 0 {
		t.Fatal("redelivered inside the lease")
	}
	f.clk.add(31 * time.Second)
	if got := f.collect(owner, ""); len(got.Messages) != 1 || got.Messages[0].MsgID != id {
		t.Fatal("not redelivered after the visibility timeout (at-least-once)")
	}
}

// The Phase 3 negative suite, end to end over HTTP.
func TestDepositNegative(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxPayloadBytes = 1024 })
	owner, sender, mallory := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	path := "/v1/mailbox/" + owner.mbx
	body := depositBody([]byte("hello"))

	t.Run("expired", func(t *testing.T) {
		exp := f.mint(owner, sender, func(c *auth.Claims) { c.Iat = f.clk.now().Add(-2 * time.Hour); c.Exp = f.clk.now().Add(-time.Hour) })
		f.expectCode(req{method: "POST", path: path, body: body, signer: &sender, token: exp}, 401, CodeTokenExpired)
	})
	t.Run("wrong aud", func(t *testing.T) {
		bad := f.mint(owner, sender, func(c *auth.Claims) { c.Aud = "https://other-relay.example" })
		f.expectCode(req{method: "POST", path: path, body: body, signer: &sender, token: bad}, 401, CodeTokenInvalid)
	})
	t.Run("token for another mailbox", func(t *testing.T) {
		other := newPrincipal(4)
		f.register(other)
		otherTok := f.mint(other, sender, nil)
		f.expectCode(req{method: "POST", path: path, body: body, signer: &sender, token: otherTok}, 401, CodeTokenInvalid)
	})
	t.Run("missing token", func(t *testing.T) {
		f.expectCode(req{method: "POST", path: path, body: body, signer: &sender}, 401, CodeTokenInvalid)
	})
	t.Run("revoked jti", func(t *testing.T) {
		rt := f.mint(owner, sender, func(c *auth.Claims) { c.Jti = "to-revoke" })
		f.mustDeposit(owner, sender, rt, []byte("ok before revocation"))
		f.revoke(owner, "jti", "to-revoke")
		f.expectCode(req{method: "POST", path: path, body: body, signer: &sender, token: rt}, 403, CodeTokenRevoked)
		f.mustDeposit(owner, sender, tok, []byte("other tokens unaffected"))
	})
	t.Run("revoked sub", func(t *testing.T) {
		victim := newPrincipal(5)
		vt := f.mint(owner, victim, func(c *auth.Claims) { c.Jti = "victim-1" })
		vt2 := f.mint(owner, victim, func(c *auth.Claims) { c.Jti = "victim-2" })
		f.mustDeposit(owner, victim, vt, []byte("x"))
		f.revoke(owner, "sub", victim.b64)
		f.expectCode(req{method: "POST", path: path, body: body, signer: &victim, token: vt}, 403, CodeTokenRevoked)
		f.expectCode(req{method: "POST", path: path, body: body, signer: &victim, token: vt2}, 403, CodeTokenRevoked)
	})
	t.Run("tampered body", func(t *testing.T) {
		hr := f.build(req{method: "POST", path: path, body: body, signer: &sender, token: tok})
		tampered := depositBody([]byte("HELLO"))
		hr.Body = http.NoBody
		hr, _ = http.NewRequest("POST", hr.URL.String(), bytes.NewReader(tampered))
		signed := f.build(req{method: "POST", path: path, body: body, signer: &sender, token: tok})
		hr.Header = signed.Header
		code, b, _ := f.send(hr)
		if code != 401 || !strings.Contains(string(b), CodeSignatureInvalid) {
			t.Fatalf("%d %s", code, b)
		}
	})
	t.Run("stale timestamp", func(t *testing.T) {
		for _, skew := range []time.Duration{-91 * time.Second, 91 * time.Second} {
			f.expectCode(req{method: "POST", path: path, body: body, signer: &sender, token: tok, at: f.clk.now().Add(skew)}, 401, CodeTimestampStale)
		}
	})
	t.Run("replayed signature", func(t *testing.T) {
		at := f.clk.now().Add(-10 * time.Second)
		b2 := depositBody([]byte("replay me"))
		code, _ := f.do(req{method: "POST", path: path, body: b2, signer: &sender, token: tok, at: at})
		if code != http.StatusCreated {
			t.Fatalf("first: %d", code)
		}
		f.expectCode(req{method: "POST", path: path, body: b2, signer: &sender, token: tok, at: at}, 401, CodeReplayDetected)
	})
	t.Run("oversized body", func(t *testing.T) {
		// Decoded payload over the limit.
		f.expectCode(req{method: "POST", path: path, body: depositBody(make([]byte, 1025)), signer: &sender, token: tok}, 413, CodePayloadTooLarge)
		// Exactly at the limit is fine.
		f.mustDeposit(owner, sender, tok, make([]byte, 1024))
		// Envelope over the body cap is refused before auth (unsigned, no token).
		f.expectCode(req{method: "POST", path: path, body: make([]byte, 64<<10)}, 413, CodePayloadTooLarge)
		// Without Content-Length (chunked), enforced while reading.
		hr := f.build(req{method: "POST", path: path, signer: &sender, token: tok})
		hr.Body = io.NopCloser(struct{ io.Reader }{bytes.NewReader(make([]byte, 64<<10))})
		hr.ContentLength = -1
		code, b, _ := f.send(hr)
		if code != 413 || !strings.Contains(string(b), CodePayloadTooLarge) {
			t.Fatalf("chunked oversize: %d %s", code, b)
		}
	})
	t.Run("sig/key mismatch", func(t *testing.T) {
		// Mallory steals sender's token but cannot sign as sender.
		f.expectCode(req{method: "POST", path: path, body: body, signer: &mallory, token: tok}, 401, CodeSignatureInvalid)
		// Mallory sets sender's key header but signs with her own key.
		hr := f.build(req{method: "POST", path: path, body: body, signer: &mallory, token: tok})
		hr.Header.Set(auth.HeaderKey, sender.b64)
		if code, b, _ := f.send(hr); code != 401 || !strings.Contains(string(b), CodeSignatureInvalid) {
			t.Fatalf("%d %s", code, b)
		}
	})
	t.Run("unknown mailbox no oracle", func(t *testing.T) {
		ghost := newPrincipal(9) // never registered
		ghostTok := f.mint(ghost, sender, nil)
		var bodies []string
		for _, r := range []req{
			{method: "POST", path: "/v1/mailbox/" + ghost.mbx, body: body, signer: &sender, token: ghostTok},
			{method: "POST", path: "/v1/mailbox/" + ghost.mbx, body: body, signer: &sender, token: "garbage"},
			{method: "POST", path: "/v1/mailbox/" + ghost.mbx, body: body},
			{method: "POST", path: "/v1/mailbox/" + strings.Repeat("a", 26), body: body, signer: &mallory, token: tok},
			{method: "POST", path: "/v1/mailbox/not-even-an-id", body: body, signer: &sender, token: tok},
		} {
			bodies = append(bodies, string(f.expectCode(r, 404, CodeMailboxUnknown)))
		}
		for _, b := range bodies[1:] {
			if b != bodies[0] {
				t.Fatalf("responses differ: %q vs %q", b, bodies[0])
			}
		}
		// Owner routes by an unregistered key: the same response.
		if b := f.expectCode(req{method: "GET", path: "/v1/mailbox", signer: &ghost}, 404, CodeMailboxUnknown); string(b) != bodies[0] {
			t.Fatal("collect response differs")
		}
		if b := f.expectCode(req{method: "POST", path: "/v1/mailbox/denylist", body: []byte(`{"revoke":[]}`), signer: &ghost}, 404, CodeMailboxUnknown); string(b) != bodies[0] {
			t.Fatal("denylist response differs")
		}
	})
	t.Run("malformed envelope", func(t *testing.T) {
		for _, b := range []string{`{}`, `{"payload":1}`, `{"payload":"not base64!"}`, `{"payload":"YQ"}`, `[]`, `{"payload":"YQ=="}{}`} {
			f.expectCode(req{method: "POST", path: path, body: []byte(b), signer: &sender, token: tok}, 400, CodeBadRequest)
		}
	})
}

func TestAckForeignMessage(t *testing.T) {
	f := newFixture(t, nil)
	alice, bob, sender := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(alice)
	f.register(bob)
	id := f.mustDeposit(alice, sender, f.mint(alice, sender, nil), []byte("for alice"))
	// Spec §6.5 (0.3.0): acking another mailbox's message is a uniform 204
	// no-op — indistinguishable from acking a nonexistent id.
	code, b := f.ack(bob, id)
	code2, b2 := f.ack(bob, "01J00000000000000000000000")
	if code != 204 || code2 != 204 || !bytes.Equal(b, b2) {
		t.Fatalf("foreign ack: %d %q vs %d %q", code, b, code2, b2)
	}
	if got := f.collect(alice, ""); len(got.Messages) != 1 {
		t.Fatal("foreign ack deleted the message")
	}
	// Bob's collect never sees Alice's mail.
	if got := f.collect(bob, ""); len(got.Messages) != 0 {
		t.Fatal("cross-mailbox leak")
	}
}

func TestQuotaExceeded(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MailboxMaxMessages = 3 })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	one := int64(1)
	qt := f.mint(owner, sender, func(c *auth.Claims) { c.Jti = "quota"; c.Quota = &auth.Quota{Msgs: &one} })
	f.mustDeposit(owner, sender, qt, []byte("1"))
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("2")), signer: &sender, token: qt}, 429, CodeQuotaExceeded)
	tok := f.mint(owner, sender, nil)
	f.mustDeposit(owner, sender, tok, []byte("3"))
	f.mustDeposit(owner, sender, tok, []byte("4"))
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("5")), signer: &sender, token: tok}, 429, CodeQuotaExceeded)
}

func TestSenderRateLimit(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateSenderPerSec, c.RateSenderBurst = 0.01, 2 })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	f.mustDeposit(owner, sender, tok, []byte("1"))
	f.mustDeposit(owner, sender, tok, []byte("2"))
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("3")), signer: &sender, token: tok}, 429, CodeRateLimited)
}

func TestLongPollWakeOnDeposit(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)

	type result struct {
		resp collectResp
		at   time.Time
	}
	done := make(chan result, 1)
	go func() {
		r := f.collect(owner, "?wait=25")
		done <- result{r, time.Now()}
	}()
	// Wait until the collector is parked.
	waitFor(t, func() bool { return f.s.m.parked.Value() == 1 })
	depositAt := time.Now()
	id := f.mustDeposit(owner, sender, tok, []byte("wake up"))
	select {
	case r := <-done:
		lat := r.at.Sub(depositAt)
		if len(r.resp.Messages) != 1 || r.resp.Messages[0].MsgID != id {
			t.Fatalf("woken collect: %+v", r.resp)
		}
		if lat >= time.Second {
			t.Fatalf("wake-on-deposit latency %v ≥ 1s", lat)
		}
		t.Logf("deposit→delivery latency: %v", lat)
	case <-time.After(5 * time.Second):
		t.Fatal("parked collect not woken by deposit")
	}
}

func TestLongPollTimeoutAndDrain(t *testing.T) {
	f := newFixture(t, nil)
	owner := newPrincipal(1)
	f.register(owner)
	start := time.Now()
	if got := f.collect(owner, "?wait=1"); len(got.Messages) != 0 {
		t.Fatal("expected empty")
	}
	if el := time.Since(start); el < 900*time.Millisecond || el > 3*time.Second {
		t.Fatalf("wait=1 took %v", el)
	}
	// wait above the cap is clamped, not rejected; bad values are rejected.
	f.expectCode(req{method: "GET", path: "/v1/mailbox?wait=-1", signer: &owner}, 400, CodeBadRequest)
	f.expectCode(req{method: "GET", path: "/v1/mailbox?max=0", signer: &owner}, 400, CodeBadRequest)

	done := make(chan time.Time, 1)
	go func() { f.collect(owner, "?wait=999"); done <- time.Now() }()
	waitFor(t, func() bool { return f.s.m.parked.Value() == 1 })
	drainAt := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	f.s.Drain(ctx)
	select {
	case at := <-done:
		if at.Sub(drainAt) > time.Second {
			t.Fatalf("drain took %v", at.Sub(drainAt))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("parked long-poll not released by drain")
	}
}

func TestCollectorCap(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxCollectorsPerMailbox = 1 })
	owner := newPrincipal(1)
	f.register(owner)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); f.collect(owner, "?wait=2") }()
	waitFor(t, func() bool { return f.s.m.parked.Value() == 1 })
	f.expectCode(req{method: "GET", path: "/v1/mailbox?wait=1", signer: &owner}, 429, CodeRateLimited)
	wg.Wait()
}

func TestRotate(t *testing.T) {
	f := newFixture(t, nil)
	oldKey, newKey, sender := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(oldKey)
	pending := f.mustDeposit(oldKey, sender, f.mint(oldKey, sender, nil), []byte("pre-rotation"))

	proof := base64.StdEncoding.EncodeToString(ed25519.Sign(newKey.priv, []byte(oldKey.mbx)))
	badProof := base64.StdEncoding.EncodeToString(ed25519.Sign(newKey.priv, []byte(newKey.mbx)))
	mk := func(p string) []byte {
		return []byte(fmt.Sprintf(`{"new_pubkey":%q,"new_key_proof":%q}`, newKey.b64, p))
	}
	f.expectCode(req{method: "POST", path: "/v1/mailbox/rotate", body: mk(badProof), signer: &oldKey}, 401, CodeSignatureInvalid)
	// Only the current registered key may rotate.
	f.expectCode(req{method: "POST", path: "/v1/mailbox/rotate", body: mk(proof), signer: &newKey}, 404, CodeMailboxUnknown)

	code, b := f.do(req{method: "POST", path: "/v1/mailbox/rotate", body: mk(proof), signer: &oldKey})
	if code != 200 || string(b) != `{"mailbox_id":"`+newKey.mbx+`"}`+"\n" {
		t.Fatalf("rotate: %d %s", code, b)
	}
	// During the grace period both mailboxes collect.
	if got := f.collect(oldKey, ""); len(got.Messages) != 1 || got.Messages[0].MsgID != pending {
		t.Fatal("old mailbox lost its pending message")
	}
	f.mustDeposit(newKey, sender, f.mint(newKey, sender, nil), []byte("post-rotation"))
	if got := f.collect(newKey, ""); len(got.Messages) != 1 {
		t.Fatal("new mailbox does not collect")
	}
	// After the grace period the old mailbox (and its tokens) are gone.
	f.clk.add(f.cfg.RotationGrace)
	f.expectCode(req{method: "GET", path: "/v1/mailbox", signer: &oldKey}, 404, CodeMailboxUnknown)
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + oldKey.mbx, body: depositBody([]byte("x")), signer: &sender, token: f.mint(oldKey, sender, nil)}, 404, CodeMailboxUnknown)
}

func TestDenylistValidation(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MailboxMaxDenylist = 2 })
	owner := newPrincipal(1)
	f.register(owner)
	for _, b := range []string{
		`{"revoke":[{"kind":"jwt","value":"x"}]}`,
		`{"revoke":[{"kind":"jti","value":""}]}`,
		`{"revoke":[{"kind":"sub","value":"not a key"}]}`,
		`{"revoke":"x"}`,
	} {
		f.expectCode(req{method: "POST", path: "/v1/mailbox/denylist", body: []byte(b), signer: &owner}, 400, CodeBadRequest)
	}
	f.revoke(owner, "jti", "a")
	f.revoke(owner, "jti", "a") // idempotent
	f.revoke(owner, "jti", "b")
	f.expectCode(req{method: "POST", path: "/v1/mailbox/denylist", body: []byte(`{"revoke":[{"kind":"jti","value":"c"}]}`), signer: &owner}, 429, CodeQuotaExceeded)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// vettid.org runs a ~400-day cap for reconnect tokens and 7-day open
// tokens/claims; registration advertises the configured values and the
// denylist keeps entries for the whole configured lifetime.
func TestLongLifetimePolicy(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.MaxTokenLifetime = 400 * 24 * time.Hour
		c.OpenTokenMaxLifetime = 7 * 24 * time.Hour
		c.ClaimTTL = 7 * 24 * time.Hour
	})
	owner, sender := newPrincipal(1), newPrincipal(2)
	body := []byte(`{"pubkey":"` + owner.b64 + `"}`)
	_, b := f.do(req{method: "POST", path: "/v1/register", body: body, signer: &owner})
	for _, want := range []string{`"max_token_lifetime_seconds":34560000`, `"open_token_max_lifetime_seconds":604800`, `"claim_ttl_seconds":604800`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("limits missing %s: %s", want, b)
		}
	}
	reconnect := f.mint(owner, sender, func(c *auth.Claims) { c.Jti = "reconnect"; c.Exp = c.Iat.Add(400 * 24 * time.Hour) })
	f.mustDeposit(owner, sender, reconnect, []byte("year-long token works"))
	tooLong := f.mint(owner, sender, func(c *auth.Claims) { c.Jti = "too-long"; c.Exp = c.Iat.Add(401 * 24 * time.Hour) })
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("x")), signer: &sender, token: tooLong}, 401, CodeTokenInvalid)

	f.revoke(owner, "jti", "reconnect")
	// 300 days later the token is still unexpired, so the entry must survive sweeps.
	f.clk.add(300 * 24 * time.Hour)
	if _, err := f.st.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("x")), signer: &sender, token: reconnect}, 403, CodeTokenRevoked)
}
