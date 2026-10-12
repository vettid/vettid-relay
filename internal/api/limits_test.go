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

// keyHeader names p's key without signing anything.
func keyHeader(p principal) http.Header {
	h := http.Header{}
	h.Set(auth.HeaderKey, p.b64)
	return h
}

func failBudget(burst int) func(*config.Config) {
	return func(c *config.Config) {
		c.RateAuthFailPerSec, c.RateAuthFailBurst, c.AuthFailMaxPenalty = 0.1, burst, time.Minute
	}
}

func depositReq(to, signer principal, tok, payload string) req {
	return req{method: "POST", path: "/v1/mailbox/" + to.mbx, body: depositBody([]byte(payload)), signer: &signer, token: tok}
}

// The blast-radius rule: a network that is out of failed-authentication
// budget still has every request served that is properly signed by a key
// with a mailbox, whether or not that key was seen there before. What
// waits is what is not that: unsigned requests, claim fetches, new
// mailboxes, signers without a mailbox.
func TestPenalisedNetworkServesEveryMailbox(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		failBudget(3)(c)
		c.RateTricklePerSec, c.RateTrickleBurst = 0.05, 2
	}, func(*fixture) []Option { return []Option{WithRetryJitter(func() int { return 2 })} })
	vault, late, owner, stranger, fresh := newPrincipal(1), newPrincipal(2), newPrincipal(3), newPrincipal(9), newPrincipal(10)
	for _, p := range []principal{vault, late, owner} {
		f.register(p)
	}
	tok := f.mint(owner, vault, nil)
	strangerTok := f.mint(owner, stranger, nil)
	for i := 0; i < 3; i++ {
		f.expectFrom(hostA, badSig(f, stranger), 401, CodeSignatureInvalid)
	}
	if n := f.s.fails.Exhausted(f.clk.now()); n != 1 {
		t.Fatalf("penalised networks: %d", n)
	}
	// A request without a key is refused unread.
	e := f.expectFrom(hostA, req{method: "GET", path: "/v1/mailbox"}, 429, CodeRateLimited)
	if e.RetryAfter != 10+2 {
		t.Fatalf("retry_after %d, want the refill time (10 s) plus jitter (2)", e.RetryAfter)
	}
	// What has no key with a mailbox to serve it by gets through at a
	// trickle (here two, then one per 20 s): claim fetches, new mailboxes,
	// deposits by a signer without a mailbox.
	f.expectFrom(hostA, req{method: "GET", path: "/v1/claim/aaaaaaaaaaaaaaaaaaaaaaaaaa"}, 404, CodeClaimUnknown)
	f.expectFrom(hostA, registerReq(newPrincipal(12)), 201, "")
	e = f.expectFrom(hostA, req{method: "GET", path: "/v1/claim/aaaaaaaaaaaaaaaaaaaaaaaaaa", header: keyHeader(vault)}, 429, CodeRateLimited)
	if e.RetryAfter != 20+2 {
		t.Fatalf("trickle retry_after %d", e.RetryAfter)
	}
	f.expectFrom(hostA, registerReq(fresh), 429, CodeRateLimited)
	f.expectFrom(hostA, depositReq(owner, stranger, strangerTok, "x"), 429, CodeRateLimited)
	// Everything properly signed by a key with a mailbox is served: a key
	// never seen from this address (a vault unlocked after a night: its
	// first request re-registers its existing key), owner routes, deposits,
	// blob uploads.
	f.expectFrom(hostA, registerReq(late), 200, "")
	f.expectFrom(hostA, collectReq(late), 200, "")
	f.expectFrom(hostA, collectReq(vault), 200, "")
	f.expectFrom(hostA, depositReq(owner, vault, tok, "1"), 201, "")
	if code, e, _ := f.from(hostA, req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: []byte("blob"), signer: &vault, token: tok}); code != 201 {
		t.Fatalf("blob upload on a penalised network: %d %q", code, e.Code)
	}
	// A wrong signature is still just that; it is checked, and goes no further.
	f.expectFrom(hostA, badSig(f, vault), 401, CodeSignatureInvalid)
	f.expectFrom(hostA, collectReq(vault), 200, "")
	// A refused deposit of a key with a mailbox is the key's own; answered as ever.
	f.expectFrom(hostA, depositReq(stranger, vault, tok, "x"), 404, CodeMailboxUnknown)
	// Other addresses are not involved.
	f.expectFrom(hostB, registerReq(fresh), 201, "")
	// On a penalised network the flood guard is met after the signature:
	// the unsigned and wrongly signed requests above used none of it.
	before := f.s.rl.allowed.With(limAddress).Value()
	f.expectFrom(hostA, badSig(f, vault), 401, CodeSignatureInvalid)
	f.expectFrom(hostA, req{method: "GET", path: "/v1/mailbox"}, 429, CodeRateLimited)
	if got := f.s.rl.allowed.With(limAddress).Value(); got != before {
		t.Fatalf("bad requests took %d flood guard tokens on a penalised network", got-before)
	}
	f.expectFrom(hostA, collectReq(vault), 200, "")
	if got := f.s.rl.allowed.With(limAddress).Value(); got != before+1 {
		t.Fatalf("a served request took %d flood guard tokens", got-before)
	}
	f.clk.add(2 * time.Minute)
	f.expectFrom(hostA, registerReq(newPrincipal(11)), 201, "")
	f.expectFrom(hostA, req{method: "GET", path: "/v1/claim/aaaaaaaaaaaaaaaaaaaaaaaaaa"}, 404, CodeClaimUnknown)
}

// One client whose mailbox is gone and that keeps asking (a vault retries
// a collect answered mailbox_unknown every second) costs its network one
// unit of failure budget, however long it goes on, and is itself refused by
// its key, for longer each time.
func TestOrphanCostsItsNetworkOnce(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) { failBudget(3)(c); c.AuthFailMaxPenalty = 10 * time.Minute },
		func(*fixture) []Option { return []Option{WithNoMailboxHold(time.Second)} })
	vault, orphan := newPrincipal(1), newPrincipal(7)
	f.register(vault)
	f.expectFrom(hostA, collectReq(orphan), 404, CodeMailboxUnknown)
	// Held: its properly signed requests are refused before the store is
	// asked, on every route but registration, from any address.
	e := f.expectFrom(hostA, collectReq(orphan), 429, CodeRateLimited)
	if e.RetryAfter != 1 {
		t.Fatalf("first hold: retry_after %d", e.RetryAfter)
	}
	f.expectFrom(hostB, req{method: "DELETE", path: "/v1/mailbox", signer: &orphan}, 429, CodeRateLimited)
	// Only the key's holder is told: someone naming the key without its
	// signature gets what they get for any key (no oracle), and pays for it.
	f.expectFrom(hostB, badSig(f, orphan), 401, CodeSignatureInvalid)
	f.expectFrom(hostB, req{method: "GET", path: "/v1/mailbox", header: keyHeader(orphan)}, 401, CodeSignatureInvalid)
	// It comes back the moment each hold ends, for a week's worth of holds.
	hold := time.Second
	var told []int
	for i := 0; i < 40; i++ {
		f.clk.add(hold)
		f.expectFrom(hostA, collectReq(orphan), 404, CodeMailboxUnknown)
		hold = min(2*hold, 10*time.Minute)
		e := f.expectFrom(hostA, collectReq(orphan), 429, CodeRateLimited)
		told = append(told, e.RetryAfter)
		f.expectFrom(hostA, collectReq(vault), 200, "") // its neighbours never notice
	}
	if told[0] != 2 || told[1] != 4 || told[4] != 32 || told[5] != 60 || told[39] != 60 {
		t.Fatalf("retry_after does not grow to its cap: %v", told)
	}
	if f.s.fails.Wait(hostA, f.clk.now()) != 0 || f.s.rl.charged.Value() != 1+2 { // the orphan once; hostB's two probes
		t.Fatalf("the orphan's repeats were charged to its network (%d charges)", f.s.rl.charged.Value())
	}
	if v := f.s.rl.refused.With(limNoMailbox).Value(); v != 42 {
		t.Fatalf("refused counter %d", v)
	}
	// Registration is the way out, held or not.
	f.expectFrom(hostA, registerReq(orphan), 201, "")
	f.expectFrom(hostA, collectReq(orphan), 200, "")
	// Fresh keys are free to make, so each new one is the network's: three
	// of them use the budget up.
	for i := byte(0); i < 3; i++ {
		f.expectFrom(hostA, collectReq(newPrincipal(40+i)), 404, CodeMailboxUnknown)
	}
	if f.s.fails.Exhausted(f.clk.now()) != 1 {
		t.Fatal("fresh keys without a mailbox did not use up the network's budget")
	}
	f.expectFrom(hostA, collectReq(vault), 200, "")
}

// A host whose clock is wrong makes every one of its vaults fail with
// timestamp_stale at once, again and again. That degrades to "those
// requests are refused": each key costs the network one unit, no key is
// held, and the moment a request is right it is served.
func TestStaleClockDegradesToRefusals(t *testing.T) {
	f := newFixture(t, failBudget(3))
	vaults := make([]principal, 6)
	for i := range vaults {
		vaults[i] = newPrincipal(byte(20 + i))
		f.register(vaults[i])
	}
	stale := func(p principal) req {
		r := collectReq(p)
		r.at = f.sigTime().Add(-5 * time.Minute)
		return r
	}
	for round := 0; round < 4; round++ {
		for i, v := range vaults[:2] {
			f.expectFrom(hostA, stale(v), 401, CodeTimestampStale)
			if round == 0 && i == 1 && f.s.fails.Exhausted(f.clk.now()) != 0 {
				t.Fatal("two keys used up a budget of three")
			}
		}
	}
	if f.s.fails.Exhausted(f.clk.now()) != 0 {
		t.Fatal("repeats by the same keys were charged to the network")
	}
	for _, v := range vaults[2:] {
		f.expectFrom(hostA, stale(v), 401, CodeTimestampStale)
	}
	if f.s.fails.Exhausted(f.clk.now()) != 1 {
		t.Fatal("six stale keys did not use up a budget of three")
	}
	// Penalised, and still: stale requests get their own answer, correct
	// ones are served at once, for every vault.
	for _, v := range vaults {
		f.expectFrom(hostA, stale(v), 401, CodeTimestampStale)
		f.expectFrom(hostA, collectReq(v), 200, "")
	}
	if v := f.s.m.errors.With(CodeTimestampStale).Value(); v != 4*2+4+6 {
		t.Fatalf("timestamp_stale counter %d: the event must be visible in metrics", v)
	}
	// A stale timestamp under a wrong signature is nobody's key's: the network's, every time.
	g := newFixture(t, failBudget(2))
	for i := 0; i < 2; i++ {
		r := badSig(g, vaults[0])
		r.header.Set(auth.HeaderTimestamp, g.clk.now().Add(-time.Hour).UTC().Format(time.RFC3339))
		g.expectFrom(hostA, r, 401, CodeTimestampStale)
	}
	if g.s.fails.Exhausted(g.clk.now()) != 1 {
		t.Fatal("unsigned stale requests were not charged each time")
	}
}

// A refused deposit that is properly signed is its key's failure: a small
// budget of refused deposits per sender key. Its network is never charged
// if the key has a mailbox (one vault with expired tokens does not spend
// what its whole host shares), and once per key otherwise.
func TestRefusedDepositsChargeTheSenderKey(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		failBudget(3)(c)
		c.RateKeyFailPerSec, c.RateKeyFailBurst = 0.1, 2
	})
	owner, vault, passerby, nobody := newPrincipal(1), newPrincipal(2), newPrincipal(3), newPrincipal(8)
	f.register(owner)
	f.register(vault)
	tok := f.mint(owner, vault, nil)
	for i := 0; i < 2; i++ {
		f.expectFrom(hostA, depositReq(nobody, vault, tok, "x"), 404, CodeMailboxUnknown)
	}
	if f.s.fails.Len() != 0 {
		t.Fatal("refused deposits of a key with a mailbox were charged to its address")
	}
	// The key's own budget of refused deposits is used up: its deposits
	// wait, valid ones too; everything else of it carries on.
	e := f.expectFrom(hostA, depositReq(nobody, vault, tok, "x"), 429, CodeRateLimited)
	if e.RetryAfter != 10 {
		t.Fatalf("retry_after %d", e.RetryAfter)
	}
	f.expectFrom(hostA, depositReq(owner, vault, tok, "x"), 429, CodeRateLimited)
	f.expectFrom(hostA, collectReq(vault), 200, "")
	if v := f.s.rl.refused.With(limKeyFail).Value(); v != 2 {
		t.Fatalf("refused counter %d", v)
	}
	// Nobody else can run a key's budget up: an unsigned deposit naming the
	// key is its address's.
	f.clk.add(30 * time.Second)
	h := keyHeader(vault)
	f.expectFrom(hostB, req{method: "POST", path: "/v1/mailbox/" + nobody.mbx, body: depositBody([]byte("x")), header: h}, 404, CodeMailboxUnknown)
	if f.s.keyFails.Wait(vault.b64, f.clk.now()) != 0 || f.s.fails.Len() != 1 {
		t.Fatal("an unsigned failure was charged to the key, or not to the address")
	}
	f.expectFrom(hostA, depositReq(owner, vault, tok, "y"), 201, "")
	// A signer without a mailbox: its key's budget too, and its address
	// once, for the first.
	for i := 0; i < 2; i++ {
		f.expectFrom(hostB, depositReq(nobody, passerby, tok, "x"), 404, CodeMailboxUnknown)
	}
	f.expectFrom(hostB, depositReq(nobody, passerby, tok, "x"), 429, CodeRateLimited)
	// Budget 3: the unsigned one and passerby once so far; one more uses it up.
	if f.s.fails.Exhausted(f.clk.now()) != 0 {
		t.Fatal("a signer without a mailbox was charged to its address more than once")
	}
	f.expectFrom(hostB, badSig(f, nobody), 401, CodeSignatureInvalid)
	if f.s.fails.Exhausted(f.clk.now()) != 1 {
		t.Fatal("a signer without a mailbox was not charged to its address")
	}
}

// On a penalised network a deposit's own signature is checked before the
// mailbox and the token are looked at.
func TestDepositSignatureFirstWhenPenalised(t *testing.T) {
	f := newFixture(t, failBudget(1))
	owner, sender, nobody := newPrincipal(1), newPrincipal(2), newPrincipal(8)
	f.register(owner)
	f.register(sender)
	tok := f.mint(owner, sender, nil)
	f.expectFrom(hostA, badSig(f, nobody), 401, CodeSignatureInvalid)
	f.expectFrom(hostA, depositReq(owner, sender, tok, "1"), 201, "")
	// Unsigned, to a mailbox that does not exist: signature_invalid, where
	// §5.3's order would have looked the mailbox up and said mailbox_unknown.
	h := http.Header{}
	auth.SetHeaders(h, sender.priv, "POST", "/v1/elsewhere", f.sigTime(), auth.BodyHash(nil))
	f.expectFrom(hostA, req{method: "POST", path: "/v1/mailbox/" + nobody.mbx, body: depositBody([]byte("x")), header: h, token: tok}, 401, CodeSignatureInvalid)
	f.expectFrom(hostA, depositReq(owner, sender, tok, "2"), 201, "")
}

// What is charged to the network, and what is not.
func TestAuthFailKinds(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RateAuthFailPerSec, c.RateAuthFailBurst, c.AuthFailMaxPenalty = 1, 1, time.Second
		c.RateRegisterPerSec, c.RateRegisterBurst = 0.001, 3
	})
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	f.register(sender)
	tok := f.mint(owner, sender, nil)
	expired := f.mint(owner, sender, func(c *auth.Claims) { c.Exp = f.clk.now().Add(-time.Second); c.Jti = "old" })
	n := 0
	addr := func() string { n++; return "198.51.100." + strconv.Itoa(n) }
	k := byte(100)
	freshKey := func() *principal { k++; p := newPrincipal(k); return &p }
	charged := func(name string, want bool, a string) {
		t.Helper()
		if got := f.s.fails.Wait(a, f.clk.now()) > 0; got != want {
			t.Errorf("%s: charged=%v, want %v", name, got, want)
		}
	}
	dep := func(mbx, token string, signer *principal) req {
		return req{method: "POST", path: "/v1/mailbox/" + mbx, body: depositBody([]byte("x")), signer: signer, token: token}
	}
	unsigned := func(r req) req { r.signer = nil; return r }
	stale := func(p principal) req {
		r := collectReq(p)
		r.at = f.clk.now().Add(-5 * time.Minute)
		return r
	}
	replay := collectReq(owner)
	replay.at = f.sigTime()
	a0 := addr()
	f.expectFrom(a0, replay, 200, "")
	charged("valid collect", false, a0)
	gone := newPrincipal(90)
	type kase struct {
		name   string
		r      req
		status int
		code   string
	}
	run := func(want bool, cases []kase) {
		t.Helper()
		for _, c := range cases {
			a := addr()
			f.expectFrom(a, c.r, c.status, c.code)
			charged(c.name, want, a)
		}
	}
	run(true, []kase{
		// Nobody can be held to these.
		{"bad signature", badSig(f, owner), 401, CodeSignatureInvalid},
		{"no signature", req{method: "GET", path: "/v1/mailbox"}, 401, CodeSignatureInvalid},
		{"replay", replay, 401, CodeReplayDetected},
		{"claim, malformed id", req{method: "GET", path: "/v1/claim/nope"}, 404, CodeClaimUnknown},
		{"claim, unknown", req{method: "GET", path: "/v1/claim/aaaaaaaaaaaaaaaaaaaaaaaaaa"}, 404, CodeClaimUnknown},
		{"unsigned deposit, unknown mailbox", unsigned(dep(gone.mbx, tok, nil)), 404, CodeMailboxUnknown},
		{"blob put, unknown mailbox (unverifiable before the body)", req{method: "PUT", path: "/v1/blob/" + gone.mbx, body: []byte("b"), signer: &sender, token: tok}, 404, CodeMailboxUnknown},
		// The first failure of a key without a mailbox: keys are free.
		{"owner route, fresh key", collectReq(*freshKey()), 404, CodeMailboxUnknown},
		{"delete, fresh key (still 204)", req{method: "DELETE", path: "/v1/mailbox", signer: freshKey()}, 204, ""},
		{"stale timestamp, first for its key", stale(*freshKey()), 401, CodeTimestampStale},
		{"refused deposit, signer without a mailbox", dep(gone.mbx, tok, freshKey()), 404, CodeMailboxUnknown},
		{"deposit, not the token's sender, signer without a mailbox", dep(owner.mbx, tok, freshKey()), 401, CodeSignatureInvalid},
	})
	orphan := newPrincipal(k - 4) // "owner route, fresh key" above
	run(false, []kase{
		// A key with a mailbox: its failures are its own.
		{"refused deposit, unknown mailbox", dep(gone.mbx, tok, &sender), 404, CodeMailboxUnknown},
		{"refused deposit, bad token", dep(owner.mbx, "garbage", &sender), 401, CodeTokenInvalid},
		{"refused deposit, expired token", dep(owner.mbx, expired, &sender), 401, CodeTokenExpired},
		{"deposit, not the token's sender", dep(owner.mbx, tok, &owner), 401, CodeSignatureInvalid},
		// Repeats by a key already charged once.
		{"owner route, the same key again", collectReq(orphan), 404, CodeMailboxUnknown},
		{"delete, the same key again", req{method: "DELETE", path: "/v1/mailbox", signer: &orphan}, 204, ""},
		// Not failures.
		{"valid deposit", dep(owner.mbx, tok, &sender), 201, ""},
		{"ack of nothing", req{method: "DELETE", path: "/v1/mailbox/01ARZ3NDEKTSV4RRFFQ69G5FAV", signer: &owner}, 204, ""},
		{"re-registration", registerReq(owner), 200, ""},
		{"bad request after authentication", req{method: "GET", path: "/v1/mailbox?wait=x", signer: &owner}, 400, CodeBadRequest},
		{"oversized body", req{method: "GET", path: "/v1/mailbox", body: bytes.Repeat([]byte("x"), smallBodyLimit+1), signer: &owner}, 413, CodePayloadTooLarge},
		{"unknown blob (the owner's own question)", req{method: "GET", path: "/v1/blob/01ARZ3NDEKTSV4RRFFQ69G5FAV", signer: &owner}, 404, CodeBlobUnknown},
		{"unknown route", req{method: "GET", path: "/v1/nothing"}, 404, CodeNotFound},
	})
	// The same key's stale repeats, from one address.
	// The same key's stale repeats (seen from a second address, to tell
	// the charges apart).
	a := addr()
	sk := freshKey()
	f.expectFrom(a, stale(*sk), 401, CodeTimestampStale)
	charged("stale timestamp", true, a)
	a = addr()
	f.expectFrom(a, stale(*sk), 401, CodeTimestampStale)
	charged("stale timestamp, the same key again", false, a)
	// A registration over the address's budget is refused; it is a rate
	// limit, not a failed authentication.
	a = addr()
	for i := byte(0); i < 3; i++ {
		f.expectFrom(a, registerReq(newPrincipal(50+i)), 201, "")
	}
	f.expectFrom(a, registerReq(newPrincipal(60)), 429, CodeRateLimited)
	charged("new mailbox over budget", false, a)
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
		"relay_ratelimit_held_keys 0",
		`relay_ratelimit_refused_total{limiter="nomailbox"} 0`,
		`relay_ratelimit_allowed_total{limiter="verify"} 0`,
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
