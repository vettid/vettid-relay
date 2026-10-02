package api

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	auth "github.com/vettid/vettid-relay/relayauth"
)

// Spec §5.6: one-shot open tokens.
func TestOpenTokenSingleUse(t *testing.T) {
	f := newFixture(t, nil)
	owner, stranger, other := newPrincipal(1), newPrincipal(7), newPrincipal(8)
	f.register(owner) // the stranger never registers: first contact
	tok := f.mintOpen(owner, "otk-1", 5*time.Minute)
	path := "/v1/mailbox/" + owner.mbx

	// A failed attempt (bad signature) does not consume the token.
	f.expectCode(req{method: "POST", path: path, body: depositBody([]byte("x")), token: tok}, 401, CodeSignatureInvalid)
	f.expectCode(req{method: "POST", path: path, body: depositBody([]byte("x")), signer: &stranger, token: tok,
		at: f.clk.now().Add(-2 * time.Minute)}, 401, CodeTimestampStale)

	id := f.mustDeposit(owner, stranger, tok, []byte("hello, it's me"))

	// Second use — by anyone — is 409 token_used.
	f.expectCode(req{method: "POST", path: path, body: depositBody([]byte("again")), signer: &stranger, token: tok}, 409, CodeTokenUsed)
	f.expectCode(req{method: "POST", path: path, body: depositBody([]byte("me too")), signer: &other, token: tok}, 409, CodeTokenUsed)

	// The owner learns the stranger's key as `sender` and can answer with a
	// normal sender-bound token.
	got := f.collect(owner, "")
	if len(got.Messages) != 1 || got.Messages[0].MsgID != id || got.Messages[0].Sender != stranger.b64 {
		t.Fatalf("collect: %+v", got)
	}
	bound := f.mint(owner, stranger, func(c *auth.Claims) { c.Sub = got.Messages[0].Sender; c.Jti = "bound" })
	f.mustDeposit(owner, stranger, bound, []byte("now with a bound token"))
}

func TestOpenTokenPolicy(t *testing.T) {
	f := newFixture(t, nil) // open_token_max_lifetime = 600 s
	owner, stranger := newPrincipal(1), newPrincipal(7)
	f.register(owner)
	path := "/v1/mailbox/" + owner.mbx

	// Lifetime cap.
	f.expectCode(req{method: "POST", path: path, body: depositBody([]byte("x")), signer: &stranger,
		token: f.mintOpen(owner, "long", 601*time.Second)}, 401, CodeTokenInvalid)
	f.mustDeposit(owner, stranger, f.mintOpen(owner, "exactly-cap", 600*time.Second), []byte("ok"))

	// Expired.
	exp := f.mintOpen(owner, "expiring", time.Minute)
	f.clk.add(2 * time.Minute)
	f.expectCode(req{method: "POST", path: path, body: depositBody([]byte("x")), signer: &stranger, token: exp}, 401, CodeTokenExpired)

	// Revocation by jti works; denylist (step 6) is checked before consumption.
	rv := f.mintOpen(owner, "revoke-me", 5*time.Minute)
	f.revoke(owner, "jti", "revoke-me")
	f.expectCode(req{method: "POST", path: path, body: depositBody([]byte("x")), signer: &stranger, token: rv}, 403, CodeTokenRevoked)
	used := f.mintOpen(owner, "used-then-revoked", 5*time.Minute)
	f.mustDeposit(owner, stranger, used, []byte("x"))
	f.revoke(owner, "jti", "used-then-revoked")
	f.expectCode(req{method: "POST", path: path, body: depositBody([]byte("x")), signer: &stranger, token: used}, 403, CodeTokenRevoked)

	// Not valid for another mailbox, and not usable for blob uploads.
	other := newPrincipal(2)
	f.register(other)
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + other.mbx, body: depositBody([]byte("x")), signer: &stranger,
		token: f.mintOpen(owner, "wrong-box", time.Minute)}, 401, CodeTokenInvalid)
	f.expectCode(req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: []byte("blob"), signer: &stranger,
		token: f.mintOpen(owner, "for-blob", time.Minute)}, 401, CodeTokenInvalid)
}

// Consumption is persisted: a relay restart (or a Litestream restore of the
// file) does not make a used open token usable again.
func TestOpenTokenSingleUseAcrossRestart(t *testing.T) {
	f := newFixture(t, nil)
	owner, stranger := newPrincipal(1), newPrincipal(7)
	f.register(owner)
	tok := f.mintOpen(owner, "persist", 5*time.Minute)
	f.mustDeposit(owner, stranger, tok, []byte("before restart"))
	f.restart()
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("after")), signer: &stranger, token: tok}, 409, CodeTokenUsed)
	if got := f.collect(owner, ""); len(got.Messages) != 1 || got.Messages[0].Sender != stranger.b64 {
		t.Fatalf("after restart: %+v", got)
	}
}

func TestOpenTokenConcurrentUse(t *testing.T) {
	f := newFixture(t, nil)
	owner := newPrincipal(1)
	f.register(owner)
	tok := f.mintOpen(owner, "race", 5*time.Minute)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := newPrincipal(byte(100 + i))
			c, _ := f.do(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte(fmt.Sprint(i))), signer: &p, token: tok})
			mu.Lock()
			codes[c]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if codes[http.StatusCreated] != 1 || codes[http.StatusConflict] != 15 {
		t.Fatalf("codes: %v", codes)
	}
}

func TestOpenTokenSenderOverWebSocket(t *testing.T) {
	f := newFixture(t, nil)
	owner, stranger := newPrincipal(1), newPrincipal(7)
	f.register(owner)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	f.mustDeposit(owner, stranger, f.mintOpen(owner, "ws", time.Minute), []byte("hi"))
	if m := readFrame(t, c, 2*time.Second); m.Sender != stranger.b64 {
		t.Fatalf("ws sender %q", m.Sender)
	}
}
