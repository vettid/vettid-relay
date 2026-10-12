package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/config"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// from sends r through the relay's handler as if it came from the client
// address addr (no socket: the handler is called directly).
func (f *fixture) from(addr string, r req) (int, errorBody, http.Header) {
	f.t.Helper()
	hr := f.build(r)
	hr.RemoteAddr = addr + ":40000"
	if strings.Contains(addr, ":") {
		hr.RemoteAddr = "[" + addr + "]:40000"
	}
	rec := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(rec, hr)
	var e errorBody
	json.Unmarshal(rec.Body.Bytes(), &e)
	return rec.Code, e, rec.Header()
}

func (f *fixture) expectFrom(addr string, r req, status int, code string) errorBody {
	f.t.Helper()
	got, e, _ := f.from(addr, r)
	if got != status || e.Code != code {
		f.t.Fatalf("%s %s from %s: got %d %q, want %d %q", r.method, r.path, addr, got, e.Code, status, code)
	}
	return e
}

func collectReq(p principal) req { return req{method: "GET", path: "/v1/mailbox", signer: &p} }

func registerReq(p principal) req {
	body, _ := json.Marshal(map[string]string{"pubkey": p.b64})
	return req{method: "POST", path: "/v1/register", body: body, signer: &p}
}

// badSig is p's collect with a signature that does not verify.
func badSig(f *fixture, p principal) req {
	h := http.Header{}
	auth.SetHeaders(h, p.priv, "GET", "/v1/other", f.sigTime(), auth.BodyHash(nil))
	return req{method: "GET", path: "/v1/mailbox", header: h}
}

const (
	hostA = "203.0.113.10"
	hostB = "203.0.113.20"
)

// The per-key bucket: one key's requests are limited, whatever address
// they come from, and nobody else's are.
func TestKeyRateLimit(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 1, 3 })
	a, b := newPrincipal(1), newPrincipal(2)
	f.register(a)
	f.register(b)
	// Registration used one of a's three.
	f.expectFrom(hostA, collectReq(a), 200, "")
	f.expectFrom(hostB, collectReq(a), 200, "") // the bucket follows the key, not the address
	code, e, h := f.from(hostA, collectReq(a))
	if code != 429 || e.Code != CodeRateLimited || e.RetryAfter != 1 || h.Get("Retry-After") != "1" {
		t.Fatalf("%d %q retry_after %d, header %q (no jitter on a single key's limit)", code, e.Code, e.RetryAfter, h.Get("Retry-After"))
	}
	// Another key behind the same address is untouched: an address is not a bucket.
	f.expectFrom(hostA, collectReq(b), 200, "")
	// Every owner route draws on it.
	f.expectFrom(hostA, req{method: "DELETE", path: "/v1/mailbox/01ARZ3NDEKTSV4RRFFQ69G5FAV", signer: &a}, 429, CodeRateLimited)
	f.expectFrom(hostA, req{method: "DELETE", path: "/v1/mailbox", signer: &a}, 429, CodeRateLimited)
	f.expectFrom(hostA, registerReq(a), 429, CodeRateLimited)
	f.clk.add(2 * time.Second)
	f.expectFrom(hostA, collectReq(a), 200, "")
	if v := f.s.rl.refused.With(limKey).Value(); v != 4 {
		t.Fatalf("refused counter %d", v)
	}
}

// A per-key 429 is only ever given to the key's owner: a signer without a
// mailbox, or a wrong signature for a limited key, gets what it always got.
func TestKeyLimitIsNoOracle(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 1 })
	a, stranger := newPrincipal(1), newPrincipal(9)
	f.register(a) // a's one token
	f.expectFrom(hostA, collectReq(a), 429, CodeRateLimited)
	for i := 0; i < 3; i++ {
		f.expectFrom(hostB, collectReq(stranger), 404, CodeMailboxUnknown)
		f.expectFrom(hostB, badSig(f, a), 401, CodeSignatureInvalid)
	}
	// Deposits into a limited owner's mailbox are unaffected.
	tok := f.mint(a, stranger, nil)
	f.expectFrom(hostB, req{method: "POST", path: "/v1/mailbox/" + a.mbx, body: depositBody([]byte("x")), signer: &stranger, token: tok}, 201, "")
}

func failBudget(burst int) func(*config.Config) {
	return func(c *config.Config) {
		c.RateAuthFailPerSec, c.RateAuthFailBurst, c.AuthFailMaxPenalty = 0.1, burst, time.Minute
	}
}

// The failed-authentication budget: failures are what an address is limited
// by. Once it is used up the relay does nothing unauthenticated for that
// address, and the keys that were already authenticating from it carry on.
func TestAuthFailBudget(t *testing.T) {
	f := newFixtureWith(t, failBudget(3), func(*fixture) []Option { return []Option{WithRetryJitter(func() int { return 2 })} })
	vault, late, stranger := newPrincipal(1), newPrincipal(2), newPrincipal(9)
	f.register(vault)
	f.register(late)
	f.expectFrom(hostA, collectReq(vault), 200, "") // vault is known at hostA

	for i := 0; i < 3; i++ {
		f.expectFrom(hostA, badSig(f, stranger), 401, CodeSignatureInvalid)
	}
	// Budget used up: anything not carrying a known key is refused unparsed.
	e := f.expectFrom(hostA, badSig(f, stranger), 429, CodeRateLimited)
	if e.RetryAfter != 10+2 {
		t.Fatalf("retry_after %d, want the refill time (10 s) plus jitter (2)", e.RetryAfter)
	}
	f.expectFrom(hostA, req{method: "GET", path: "/v1/mailbox"}, 429, CodeRateLimited)
	f.expectFrom(hostA, req{method: "GET", path: "/v1/claim/aaaaaaaaaaaaaaaaaaaaaaaaaa"}, 429, CodeRateLimited)
	f.expectFrom(hostA, collectReq(late), 429, CodeRateLimited) // a valid key that was not seen here before waits too
	// The key that was authenticating from this address is not touched.
	for i := 0; i < 5; i++ {
		f.expectFrom(hostA, collectReq(vault), 200, "")
	}
	// Other addresses are not involved, IPv4 or IPv6.
	f.expectFrom(hostB, collectReq(late), 200, "")
	f.expectFrom(hostB, badSig(f, stranger), 401, CodeSignatureInvalid)
	// A wrong signature under the known key is answered like an unknown
	// key's (so the answer does not say the key is in use at this address)
	// and does not cost the key its standing (anyone can send one).
	f.expectFrom(hostA, badSig(f, vault), 429, CodeRateLimited)
	f.expectFrom(hostA, collectReq(vault), 200, "")
	if n := f.s.fails.Exhausted(f.clk.now()); n != 1 {
		t.Fatalf("penalised networks: %d", n)
	}
	// The budget refills; debts are paid first (4 failures ran it up).
	f.clk.add(9 * time.Second)
	f.expectFrom(hostA, collectReq(late), 429, CodeRateLimited)
	f.clk.add(11 * time.Second)
	f.expectFrom(hostA, collectReq(late), 200, "")
	f.expectFrom(hostA, badSig(f, stranger), 401, CodeSignatureInvalid)
}

// A refused deposit that is properly signed by a key known at its address
// is that key's failure, not its address's: one vault with expired tokens
// does not spend the budget its whole host shares, and one key cannot keep
// failing either.
func TestRefusedDepositsChargeTheSenderKey(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		failBudget(2)(c)
		c.RateKeyFailPerSec, c.RateKeyFailBurst = 0.1, 2
	})
	owner, vault, passerby, nobody := newPrincipal(1), newPrincipal(2), newPrincipal(3), newPrincipal(8)
	f.register(owner)
	f.register(vault)
	f.expectFrom(hostA, collectReq(vault), 200, "") // vault is known at hostA
	tok := f.mint(owner, vault, nil)
	gone := func(signer principal) req {
		return req{method: "POST", path: "/v1/mailbox/" + nobody.mbx, body: depositBody([]byte("x")), signer: &signer, token: tok}
	}
	for i := 0; i < 2; i++ {
		f.expectFrom(hostA, gone(vault), 404, CodeMailboxUnknown)
	}
	if f.s.fails.Len() != 0 {
		t.Fatal("a known key's refused deposits were charged to its address")
	}
	// The key's own budget of refused deposits is used up: its deposits
	// wait, valid ones too; everything else of it carries on.
	e := f.expectFrom(hostA, gone(vault), 429, CodeRateLimited)
	if e.RetryAfter != 10 {
		t.Fatalf("retry_after %d", e.RetryAfter)
	}
	f.expectFrom(hostA, req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("x")), signer: &vault, token: tok}, 429, CodeRateLimited)
	f.expectFrom(hostA, collectReq(vault), 200, "")
	if v := f.s.rl.refused.With(limKeyFail).Value(); v != 2 {
		t.Fatalf("refused counter %d", v)
	}
	// Nobody else can run a key's budget up: an unsigned deposit naming the
	// key, and a signed one by a key not known here, are the address's.
	f.clk.add(30 * time.Second)
	h := http.Header{auth.HeaderKey: {vault.b64}}
	f.expectFrom(hostB, req{method: "POST", path: "/v1/mailbox/" + nobody.mbx, body: depositBody([]byte("x")), header: h}, 404, CodeMailboxUnknown)
	f.expectFrom(hostB, gone(passerby), 404, CodeMailboxUnknown)
	if f.s.keyFails.Wait(vault.b64, f.clk.now()) != 0 || f.s.fails.Wait(hostB, f.clk.now()) == 0 {
		t.Fatal("unproven failures were charged to the key, or not to the address")
	}
	f.expectFrom(hostA, req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("y")), signer: &vault, token: tok}, 201, "")
	// On a penalised address it is the same: the known key's refused
	// deposits are answered from its own budget, then wait.
	for i := 0; i < 2; i++ {
		f.expectFrom(hostA, badSig(f, nobody), 401, CodeSignatureInvalid)
	}
	f.expectFrom(hostA, gone(passerby), 429, CodeRateLimited) // not known here: nothing is looked at
	f.expectFrom(hostA, gone(vault), 404, CodeMailboxUnknown)
	f.expectFrom(hostA, gone(vault), 404, CodeMailboxUnknown)
	f.expectFrom(hostA, gone(vault), 429, CodeRateLimited)
	f.expectFrom(hostA, collectReq(vault), 200, "")
}

// A signer that turns out to have no mailbox stops counting as known at
// its address.
func TestNoStandingWithoutAMailbox(t *testing.T) {
	f := newFixture(t, failBudget(2))
	vault, nobody := newPrincipal(1), newPrincipal(8)
	f.register(vault)
	f.expectFrom(hostA, collectReq(vault), 200, "")
	f.expectFrom(hostA, req{method: "DELETE", path: "/v1/mailbox", signer: &vault}, 204, "")
	f.expectFrom(hostA, collectReq(vault), 404, CodeMailboxUnknown) // first failure
	f.expectFrom(hostA, badSig(f, nobody), 401, CodeSignatureInvalid)
	// Penalised now, and the key is no longer known here.
	f.expectFrom(hostA, collectReq(vault), 429, CodeRateLimited)
}

func TestAuthFailDepositSignatureFirstWhenPenalised(t *testing.T) {
	f := newFixture(t, failBudget(1))
	owner, sender, nobody := newPrincipal(1), newPrincipal(2), newPrincipal(8)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	dep := func(payload string) req {
		return req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte(payload)), signer: &sender, token: tok}
	}
	f.expectFrom(hostA, dep("1"), 201, "") // sender is known at hostA
	f.expectFrom(hostA, badSig(f, nobody), 401, CodeSignatureInvalid)
	// Penalised: valid deposits from the known sender still go through...
	f.expectFrom(hostA, dep("2"), 201, "")
	// ...a deposit naming the sender's key without its signature gets the
	// uniform 429 although the mailbox does not exist (signature first:
	// no store lookup, no existence answer)...
	h := http.Header{}
	auth.SetHeaders(h, sender.priv, "POST", "/v1/elsewhere", f.sigTime(), auth.BodyHash(nil))
	f.expectFrom(hostA, req{method: "POST", path: "/v1/mailbox/" + nobody.mbx, body: depositBody([]byte("x")), header: h, token: tok}, 429, CodeRateLimited)
	// ...and did not cost the sender its standing.
	f.expectFrom(hostA, dep("3"), 201, "")
	// Blob uploads wait: their signature cannot be checked before the body.
	code, e, _ := f.from(hostA, req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: []byte("blob"), signer: &sender, token: tok})
	if code != 429 || e.Code != CodeRateLimited {
		t.Fatalf("blob put while penalised: %d %q", code, e.Code)
	}
	f.clk.add(time.Minute)
	if code, e, _ := f.from(hostA, req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: []byte("blob"), signer: &sender, token: tok}); code != 201 {
		t.Fatalf("blob put after the penalty: %d %q", code, e.Code)
	}
}

// Every kind of failed authentication is charged, and nothing else is.
func TestAuthFailKinds(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RateAuthFailPerSec, c.RateAuthFailBurst, c.AuthFailMaxPenalty = 1, 1, time.Second
		c.RateRegisterPerSec, c.RateRegisterBurst = 0.001, 3
	})
	owner, sender, stranger := newPrincipal(1), newPrincipal(2), newPrincipal(9)
	f.register(owner)
	f.register(sender)
	tok := f.mint(owner, sender, nil)
	expired := f.mint(owner, sender, func(c *auth.Claims) { c.Exp = f.clk.now().Add(-time.Second); c.Jti = "old" })
	n := 0
	addr := func() string { n++; return "198.51.100." + strconv.Itoa(n) }
	charged := func(name string, want bool, a string) {
		t.Helper()
		if got := f.s.fails.Wait(a, f.clk.now()) > 0; got != want {
			t.Errorf("%s: charged=%v, want %v", name, got, want)
		}
	}
	dep := func(mbx, token string, signer *principal) req {
		return req{method: "POST", path: "/v1/mailbox/" + mbx, body: depositBody([]byte("x")), signer: signer, token: token}
	}
	stale := collectReq(owner)
	stale.at = f.clk.now().Add(-5 * time.Minute)
	replayAt := f.sigTime()
	replay := collectReq(owner)
	replay.at = replayAt
	a0 := addr()
	f.expectFrom(a0, replay, 200, "")
	charged("valid collect", false, a0)

	for _, c := range []struct {
		name   string
		r      req
		status int
		code   string
	}{
		{"bad signature", badSig(f, owner), 401, CodeSignatureInvalid},
		{"no signature", req{method: "GET", path: "/v1/mailbox"}, 401, CodeSignatureInvalid},
		{"stale timestamp", stale, 401, CodeTimestampStale},
		{"replay", replay, 401, CodeReplayDetected},
		{"owner route, no mailbox", collectReq(stranger), 404, CodeMailboxUnknown},
		{"deposit, unknown mailbox", dep(stranger.mbx, tok, &sender), 404, CodeMailboxUnknown},
		{"deposit, bad token", dep(owner.mbx, "garbage", &sender), 401, CodeTokenInvalid},
		{"deposit, expired token", dep(owner.mbx, expired, &sender), 401, CodeTokenExpired},
		{"deposit, not the token's sender", dep(owner.mbx, tok, &stranger), 401, CodeSignatureInvalid},
		{"blob put, unknown mailbox", req{method: "PUT", path: "/v1/blob/" + stranger.mbx, body: []byte("b"), signer: &sender, token: tok}, 404, CodeMailboxUnknown},
		{"claim, malformed id", req{method: "GET", path: "/v1/claim/nope"}, 404, CodeClaimUnknown},
		{"claim, unknown", req{method: "GET", path: "/v1/claim/aaaaaaaaaaaaaaaaaaaaaaaaaa"}, 404, CodeClaimUnknown},
		{"delete, no mailbox (still 204)", req{method: "DELETE", path: "/v1/mailbox", signer: &stranger}, 204, ""},
	} {
		a := addr()
		f.expectFrom(a, c.r, c.status, c.code)
		charged(c.name, true, a)
	}
	for _, c := range []struct {
		name   string
		r      req
		status int
		code   string
	}{
		{"valid deposit", dep(owner.mbx, tok, &sender), 201, ""},
		{"ack of nothing", req{method: "DELETE", path: "/v1/mailbox/01ARZ3NDEKTSV4RRFFQ69G5FAV", signer: &owner}, 204, ""},
		{"re-registration", registerReq(owner), 200, ""},
		{"bad request after authentication", req{method: "GET", path: "/v1/mailbox?wait=x", signer: &owner}, 400, CodeBadRequest},
		{"oversized body", req{method: "GET", path: "/v1/mailbox", body: bytes.Repeat([]byte("x"), smallBodyLimit+1), signer: &owner}, 413, CodePayloadTooLarge},
		{"unknown blob (the owner's own question)", req{method: "GET", path: "/v1/blob/01ARZ3NDEKTSV4RRFFQ69G5FAV", signer: &owner}, 404, CodeBlobUnknown},
		{"unknown route", req{method: "GET", path: "/v1/nothing"}, 404, CodeNotFound},
	} {
		a := addr()
		f.expectFrom(a, c.r, c.status, c.code)
		charged(c.name, false, a)
	}
	// Registrations over the address's budget are refused and charged.
	a := addr()
	for i := byte(0); i < 3; i++ {
		f.expectFrom(a, registerReq(newPrincipal(50+i)), 201, "")
	}
	charged("new mailboxes within budget", false, a)
	f.expectFrom(a, registerReq(newPrincipal(60)), 429, CodeRateLimited)
	charged("new mailbox over budget", true, a)
}

// New mailboxes are limited per address; registering an existing one again
// (every vault does at unlock) is not.
func TestRegistrationBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateRegisterPerSec, c.RateRegisterBurst = 0.5, 2 })
	a, b, c, d := newPrincipal(1), newPrincipal(2), newPrincipal(3), newPrincipal(4)
	f.expectFrom(hostA, registerReq(a), 201, "")
	f.expectFrom(hostA, registerReq(b), 201, "")
	e := f.expectFrom(hostA, registerReq(c), 429, CodeRateLimited)
	if e.RetryAfter != 2 {
		t.Fatalf("retry_after %d", e.RetryAfter)
	}
	for i := 0; i < 5; i++ {
		f.expectFrom(hostA, registerReq(a), 200, "") // idempotent re-registration: free
	}
	f.expectFrom(hostB, registerReq(c), 201, "") // another address has its own budget
	// A rotation makes a new mailbox too.
	rot := func(old, next principal) req {
		proof := ed25519.Sign(next.priv, []byte(old.mbx)) // json: standard base64
		body, _ := json.Marshal(map[string]any{"new_pubkey": next.b64, "new_key_proof": proof})
		return req{method: "POST", path: "/v1/mailbox/rotate", body: body, signer: &old}
	}
	f.expectFrom(hostA, rot(a, d), 429, CodeRateLimited)
	f.clk.add(2 * time.Second)
	f.expectFrom(hostA, rot(a, d), 200, "")
	if v := f.s.rl.refused.With(limRegister).Value(); v != 2 {
		t.Fatalf("refused counter %d", v)
	}
}

// A deposit token without its sender's key cannot use up the sender's
// budget: the per-sender limit is applied after the signature.
func TestSenderLimitAfterSignature(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateSenderPerSec, c.RateSenderBurst = 0.01, 2 })
	owner, sender, thief := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	dep := func(signer principal, payload string) req {
		return req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte(payload)), signer: &signer, token: tok}
	}
	for i := 0; i < 5; i++ {
		f.expectFrom(hostB, dep(thief, "stolen"), 401, CodeSignatureInvalid)
	}
	f.expectFrom(hostA, dep(sender, "1"), 201, "")
	f.expectFrom(hostA, dep(sender, "2"), 201, "")
	f.expectFrom(hostA, dep(sender, "3"), 429, CodeRateLimited)
}

// The flood guard: per client network, before anything is parsed, with a
// spread retry_after; IPv6 clients are one network per /64.
func TestFloodGuard(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) { c.RateIPPerSec, c.RateIPBurst = 2, 3 },
		func(*fixture) []Option { return []Option{WithRetryJitter(func() int { return 3 })} })
	a := newPrincipal(1)
	f.register(a)
	for i := 0; i < 3; i++ {
		f.expectFrom("2001:db8:1:2::"+strconv.Itoa(i+1), collectReq(a), 200, "")
	}
	e := f.expectFrom("2001:db8:1:2::9", collectReq(a), 429, CodeRateLimited)
	if e.RetryAfter != 1+3 {
		t.Fatalf("retry_after %d, want 1 plus the jitter", e.RetryAfter)
	}
	f.expectFrom("2001:db8:1:3::1", collectReq(a), 200, "") // the next /64
	f.expectFrom(hostA, req{method: "POST", path: "/v1/whatever", body: []byte("x")}, 404, CodeNotFound)
	if got := f.s.rl.refused.With(limAddress).Value(); got != 1 {
		t.Fatalf("refused counter %d", got)
	}
	// A refusal by the flood guard is not a failed authentication.
	if f.s.fails.Len() != 0 {
		t.Fatal("flood refusals were charged as failures")
	}
}

// The defaults carry a full vault host: 1,000 unlocked vaults behind one
// address, all re-polling in the same instant (as after a relay deploy),
// and again 25 s later, with no refusal; the old default (20/s, burst 40)
// refused 960 of the first thousand.
func TestDefaultsCarryAVaultHost(t *testing.T) {
	d := config.Defaults()
	if d.RateIPBurst < 2000 || d.RateIPPerSec*25 < 2000 {
		t.Fatalf("flood guard %v/s burst %d does not carry two synchronised thousands per long-poll period", d.RateIPPerSec, d.RateIPBurst)
	}
	if d.RateKeyBurst < 100 || d.RateKeyPerSec < 4 {
		t.Fatalf("key bucket %v/s burst %d: below one full batch with its acks", d.RateKeyPerSec, d.RateKeyBurst)
	}
	if d.RateAuthFailPerSec > 1 || d.RateAuthFailBurst > 60 {
		t.Fatalf("failed-authentication budget %v/s burst %d is not small", d.RateAuthFailPerSec, d.RateAuthFailBurst)
	}
}

// WebSocket acks draw on the key's bucket like DELETE acks.
func TestWebSocketAckRateLimited(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 4 })
	owner := newPrincipal(1)
	f.register(owner) // 1 of 4
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ { // the upgrade was the second; two acks fit, the third does not
		if err := c.Write(ctx, websocket.MessageText, []byte(`{"ack":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}`)); err != nil {
			break
		}
	}
	_, _, err = c.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusTryAgainLater {
		t.Fatalf("want close 1013, got %v", err)
	}
}

// Limiter metrics carry the limiter's name and nothing about clients; the
// minute report is an info line only when there is something to see.
func TestLimiterMetricsAndReport(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 4 }, &logs)
	a := newPrincipal(1)
	f.register(a)
	f.expectFrom(hostA, collectReq(a), 200, "")
	f.s.reportLimits()
	var out strings.Builder
	f.reg.WriteTo(&out)
	for _, want := range []string{
		`relay_ratelimit_allowed_total{limiter="key"} 2`,
		`relay_ratelimit_refused_total{limiter="key"} 0`,
		`relay_ratelimit_peak_permille{limiter="key"} 500`,
		`relay_ratelimit_allowed_total{limiter="address"} 2`,
		`relay_ratelimit_refused_total{limiter="authfail"} 0`,
		`relay_ratelimit_refused_total{limiter="collectors"} 0`,
		"relay_ratelimit_penalised_networks 0",
		"relay_ratelimit_known_keys 2", // the key, at each of the two addresses it was used from
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	line := lastLine(t, logs.String(), `"msg":"rate limits"`)
	if !strings.Contains(line, `"level":"INFO"`) || !strings.Contains(line, `"key_peak":500`) || !strings.Contains(line, `"key_refused":0`) {
		t.Fatalf("report line: %s", line)
	}
	for _, leak := range []string{hostA, a.b64, a.mbx} {
		if strings.Contains(out.String(), leak) || strings.Contains(line, leak) {
			t.Fatalf("metrics or report name a client: %q", leak)
		}
	}
	// A quiet minute is a debug line; a refusal makes it an info line again.
	logs.reset()
	f.s.reportLimits()
	if line := lastLine(t, logs.String(), `"msg":"rate limits"`); !strings.Contains(line, `"level":"DEBUG"`) {
		t.Fatalf("quiet minute: %s", line)
	}
	for i := 0; i < 3; i++ {
		f.from(hostA, collectReq(a))
	}
	logs.reset()
	f.s.reportLimits()
	if line := lastLine(t, logs.String(), `"msg":"rate limits"`); !strings.Contains(line, `"level":"INFO"`) || !strings.Contains(line, `"key_refused":1`) || !strings.Contains(line, `"key_peak":1000`) {
		t.Fatalf("after a refusal: %s", line)
	}
}

func lastLine(t *testing.T, logs, containing string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], containing) {
			return lines[i]
		}
	}
	t.Fatalf("no log line containing %s", containing)
	return ""
}
