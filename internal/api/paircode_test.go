package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/paircode"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	"github.com/vettid/vettid-relay/relayclient"
)

// Code claims (§6.9.1).

var testPairKey = bytes.Repeat([]byte{0x5a}, 32)

// withPairKey gives c the test key and the least open-token limit with
// which config.Load keeps a key, so the fixtures run a config that can
// occur.
func withPairKey(c *config.Config) {
	c.PairCodeKey = config.NewSecret(testPairKey)
	c.OpenTokenMaxLifetime = config.PairCodeOpenTokenMin
}

// A key set aside for a short open-token limit is said at WARN, not
// DEBUG: the operator meant codes on.
func TestPairCodesOffForShortLifetimeWarns(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(testPairKey)
	cfg, err := config.Load(func(k string) (string, bool) {
		switch k {
		case "RELAY_PAIR_CODE_KEY":
			return b64, true
		case "RELAY_BASE_URL":
			return "https://relay.example", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	if pc := newPairCodes(cfg, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))); pc != nil {
		t.Fatal("pair codes on with the default open-token limit")
	}
	if out := logs.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "RELAY_OPEN_TOKEN_MAX_LIFETIME") || strings.Contains(out, b64) {
		t.Fatalf("log: %s", out)
	}
}

// pcHour is a fixed hour for the tests: 2026-03-31T12:00:00Z (epoch 493044).
var pcHour = time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC)

const pcHold = 40 * time.Millisecond

// pairCodeFixture runs a relay with a pair-code key and a short hold.
// Limit 14 is out of the way (large budgets) unless realLimits.
func pairCodeFixture(t *testing.T, mut func(*config.Config), realLimits ...bool) *fixture {
	return pairCodeFixtureWith(t, mut, len(realLimits) > 0)
}

// pairCodeFixtureWith is pairCodeFixture with extra server options (applied
// last).
func pairCodeFixtureWith(t *testing.T, mut func(*config.Config), realLimits bool, extra ...Option) *fixture {
	f := newFixtureWith(t, func(c *config.Config) {
		withPairKey(c)
		if mut != nil {
			mut(c)
		}
	}, func(*fixture) []Option {
		return append([]Option{WithPairCodeHold(pcHold), func(s *Server) {
			s.pc.syncRefunds = true
			if !realLimits {
				s.pc.limiters(func(string, float64, int) ByteLimiter { return ratelimit.New(1000, 100_000, 1000) })
			}
		}}, extra...)
	})
	f.clk.set(pcHour.Add(30 * time.Minute))
	return f
}

func (f *fixture) salts() []pairCodeSalt {
	f.t.Helper()
	code, b := f.do(req{method: "GET", path: "/v1/pair-code/salts"})
	var out struct{ Salts []pairCodeSalt }
	if code != http.StatusOK || json.Unmarshal(b, &out) != nil {
		f.t.Fatalf("salts: %d %s", code, b)
	}
	return out.Salts
}

func tagOf(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func putBody(saltID string, tag []byte, blob string) []byte {
	b, _ := json.Marshal(map[string]any{"salt_id": saltID, "tag": tag, "salt": bytes.Repeat([]byte{7}, 16), "blob": []byte(blob)})
	return b
}

func redeemBody(tags ...map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"tags": tags})
	return b
}

func tagEntry(saltID string, tag []byte) map[string]any {
	return map[string]any{"salt_id": saltID, "tag": tag}
}

func (f *fixture) redeem(body []byte) (int, []byte, time.Duration) {
	f.t.Helper()
	start := time.Now()
	code, b := f.do(req{method: "POST", path: "/v1/pair-code/redeem", body: body})
	return code, b, time.Since(start)
}

const (
	pcID1 = "q4f7m2xk5n3p6r7t2v4w6y7z3a"
	pcID2 = "b4f7m2xk5n3p6r7t2v4w6y7z3a"
)

// Without a key, or with a base URL that has no canonical form, the relay
// offers no code claims: the routes are not there and the limits say
// nothing.
func TestPairCodesOff(t *testing.T) {
	for _, mut := range []func(*config.Config){
		nil,
		func(c *config.Config) {
			withPairKey(c)
			c.BaseURL = "http://localhost:8080"
		},
	} {
		f := newFixture(t, mut)
		f.expectCode(req{method: "GET", path: "/v1/pair-code/salts"}, http.StatusNotFound, CodeNotFound)
		f.expectCode(req{method: "POST", path: "/v1/pair-code/redeem", body: redeemBody()}, http.StatusNotFound, CodeNotFound)
		a := newPrincipal(1)
		body, _ := json.Marshal(map[string]string{"pubkey": a.b64})
		_, b := f.do(req{method: "POST", path: "/v1/register", body: body, signer: &a})
		if strings.Contains(string(b), "pair_codes") {
			t.Fatalf("limits advertise pair codes: %s", b)
		}
	}
}

func TestPairCodeSalts(t *testing.T) {
	f := pairCodeFixture(t, nil)
	a := newPrincipal(1)
	body, _ := json.Marshal(map[string]string{"pubkey": a.b64})
	if _, b := f.do(req{method: "POST", path: "/v1/register", body: body, signer: &a}); !strings.Contains(string(b), `"pair_codes":true`) {
		t.Fatalf("limits: %s", b)
	}
	r, _ := paircode.CanonicalRelay(testAud)
	check := func(want ...int64) []pairCodeSalt {
		t.Helper()
		l := f.salts()
		if len(l) != len(want) {
			t.Fatalf("%v: %d salts, want %v", f.clk.now(), len(l), want)
		}
		for i, s := range l {
			if s.Epoch != want[i] || len(s.Nonce) != 16 || s.SaltID != paircode.SaltID(paircode.SaltR(r, s.Epoch, s.Nonce)) {
				t.Fatalf("salt %d: %+v, want epoch %d", i, s, want[i])
			}
		}
		return l
	}
	const e = 493044
	mid := check(e)
	f.clk.set(pcHour.Add(58 * time.Minute))
	near := check(e, e+1)
	if near[0].SaltID != mid[0].SaltID {
		t.Fatal("an epoch's salt changed")
	}
	f.clk.set(pcHour.Add(time.Hour + 9*time.Minute))
	late := check(e, e+1)
	if late[1].SaltID != near[1].SaltID {
		t.Fatal("the next epoch's salt changed once its hour began")
	}
	f.clk.set(pcHour.Add(time.Hour + 10*time.Minute))
	check(e + 1)
	// Another process (a restart, here) lists the same nonces.
	f.restart()
	f.clk.set(pcHour.Add(time.Hour + 5*time.Minute))
	if again := check(e, e+1); again[0].SaltID != late[0].SaltID || again[1].SaltID != late[1].SaltID {
		t.Fatal("salts changed across a restart")
	}
}

func TestPairCodePutRedeem(t *testing.T) {
	f := pairCodeFixture(t, nil)
	a, b := newPrincipal(1), newPrincipal(2)
	f.register(a)
	f.register(b)
	salt := f.salts()[0].SaltID
	put := func(p principal, id string, body []byte) (int, []byte) {
		return f.do(req{method: "PUT", path: "/v1/pair-code/" + id, body: body, signer: &p})
	}
	code, out := put(a, pcID1, putBody(salt, tagOf(1), "bundle"))
	var created struct {
		ExpiresAt string `json:"expires_at"`
	}
	if code != http.StatusCreated || json.Unmarshal(out, &created) != nil ||
		created.ExpiresAt != f.clk.now().Add(600*time.Second).UTC().Format(timeFormat) {
		t.Fatalf("put: %d %s", code, out)
	}
	// A miss, with the hold.
	miss, missBody, d := f.redeem(redeemBody(tagEntry(salt, tagOf(9))))
	if miss != http.StatusNotFound || d < pcHold {
		t.Fatalf("miss: %d %s in %v", miss, missBody, d)
	}
	if string(missBody) != "{\"code\":\"code_unknown\",\"message\":\"no such code\"}\n" {
		t.Fatalf("miss body %q", missBody)
	}
	// The match.
	code, got, d := f.redeem(redeemBody(tagEntry(salt, tagOf(1))))
	var c struct {
		ClaimID   string `json:"claim_id"`
		Salt      []byte `json:"salt"`
		Blob      []byte `json:"blob"`
		ExpiresAt string `json:"expires_at"`
	}
	if code != http.StatusOK || d < pcHold || json.Unmarshal(got, &c) != nil || c.ClaimID != pcID1 ||
		string(c.Blob) != "bundle" || !bytes.Equal(c.Salt, bytes.Repeat([]byte{7}, 16)) || c.ExpiresAt != created.ExpiresAt {
		t.Fatalf("redeem: %d %s in %v", code, got, d)
	}
	// Single fetch.
	if code, again, _ := f.redeem(redeemBody(tagEntry(salt, tagOf(1)))); code != http.StatusNotFound || !bytes.Equal(again, missBody) {
		t.Fatalf("second redeem: %d %s", code, again)
	}
	// Every malformed redeem gets the same bytes.
	for name, body := range map[string][]byte{
		"empty":           nil,
		"not json":        []byte("{"),
		"no tags":         redeemBody(),
		"short tag":       redeemBody(tagEntry(salt, tagOf(1)[:31])),
		"unknown salt":    redeemBody(tagEntry("00000000", tagOf(1))),
		"same salt twice": redeemBody(tagEntry(salt, tagOf(1)), tagEntry(salt, tagOf(2))),
		"too many tags":   redeemBody(tagEntry(salt, tagOf(1)), tagEntry(salt, tagOf(2)), tagEntry(salt, tagOf(3))),
		"too large":       bytes.Repeat([]byte(" "), 2000),
	} {
		if code, b, d := f.redeem(body); code != http.StatusNotFound || !bytes.Equal(b, missBody) || d < pcHold {
			t.Errorf("%s: %d %q in %v", name, code, b, d)
		}
	}
	// One live code claim per mailbox; a PUT of a bad claim id or a
	// previous epoch's salt is refused, and still replaces the live one.
	put(a, pcID1, putBody(salt, tagOf(2), "x"))
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID2, body: putBody(salt, tagOf(3), "y"), signer: &a}, http.StatusCreated, "")
	if code, _, _ := f.redeem(redeemBody(tagEntry(salt, tagOf(2)))); code != http.StatusNotFound {
		t.Fatal("the replaced claim was redeemed")
	}
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/Q4F7M2XK5N3P6R7T2V4W6Y7Z3A", body: putBody(salt, tagOf(4), "z"), signer: &a}, http.StatusBadRequest, CodeBadRequest)
	if code, _, _ := f.redeem(redeemBody(tagEntry(salt, tagOf(3)))); code != http.StatusNotFound {
		t.Fatal("a refused PUT left the live claim")
	}
	// The claim id is taken by another mailbox's live claim.
	put(a, pcID1, putBody(salt, tagOf(5), "x"))
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(salt, tagOf(6), "y"), signer: &b}, http.StatusBadRequest, CodeBadRequest)
	// A collision deletes both.
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID2, body: putBody(salt, tagOf(5), "y"), signer: &b}, http.StatusConflict, CodeCodeTaken)
	if code, _, _ := f.redeem(redeemBody(tagEntry(salt, tagOf(5)))); code != http.StatusNotFound {
		t.Fatal("a collided claim was redeemed")
	}
	// DELETE by its creator only.
	put(a, pcID1, putBody(salt, tagOf(7), "x"))
	if code, _ := f.do(req{method: "DELETE", path: "/v1/pair-code/" + pcID1, signer: &b}); code != http.StatusNoContent {
		t.Fatal(code)
	}
	if code, _ := f.do(req{method: "DELETE", path: "/v1/pair-code/" + pcID1, signer: &a}); code != http.StatusNoContent {
		t.Fatal(code)
	}
	if code, _, _ := f.redeem(redeemBody(tagEntry(salt, tagOf(7)))); code != http.StatusNotFound {
		t.Fatal("a deleted claim was redeemed")
	}
	// Unsigned PUTs are refused.
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(salt, tagOf(8), "x")}, http.StatusUnauthorized, CodeSignatureInvalid)
}

// A PUT names the current epoch's salt, or the next one's once listed;
// never the previous one's.
func TestPairCodePutEpochs(t *testing.T) {
	f := pairCodeFixture(t, nil)
	a := newPrincipal(1)
	f.register(a)
	f.clk.set(pcHour.Add(58 * time.Minute))
	l := f.salts() // current, next
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(l[1].SaltID, tagOf(1), "x"), signer: &a}, http.StatusCreated, "")
	f.clk.set(pcHour.Add(time.Hour + 5*time.Minute))
	l2 := f.salts() // previous (l[0]), current (l[1])
	if l2[0].SaltID != l[0].SaltID {
		t.Fatal("salts")
	}
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(l[0].SaltID, tagOf(2), "x"), signer: &a}, http.StatusBadRequest, CodeBadRequest)
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(l2[1].SaltID, tagOf(2), "x"), signer: &a}, http.StatusCreated, "")
	// Two tags for one salt, with two listed (so "too many" doesn't catch
	// it): refused even with the right tag, and the claim stays.
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(l2[1].SaltID, tagOf(4), "x"), signer: &a}, http.StatusCreated, "")
	if code, _, _ := f.redeem(redeemBody(tagEntry(l2[1].SaltID, tagOf(4)), tagEntry(l2[1].SaltID, tagOf(4)))); code != http.StatusNotFound {
		t.Fatalf("two tags for one salt: %d", code)
	}
	if code, _, _ := f.redeem(redeemBody(tagEntry(l2[1].SaltID, tagOf(4)))); code != http.StatusOK {
		t.Fatalf("the claim after a refused redeem: %d", code)
	}
	// A redeem may name the previous salt while it is listed.
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(l2[1].SaltID, tagOf(3), "x"), signer: &a}, http.StatusCreated, "")
	if code, _, _ := f.redeem(redeemBody(tagEntry(l2[0].SaltID, tagOf(9)), tagEntry(l2[1].SaltID, tagOf(3)))); code != http.StatusOK {
		t.Fatalf("redeem with two tags: %d", code)
	}
}

// Limit 14: 20 redeems per IPv4 address in 10 minutes; the 21st is
// answered like a miss and doesn't spend a live code.
func TestPairCodeRedeemLimitIPv4(t *testing.T) {
	f := pairCodeFixture(t, nil, true)
	a := newPrincipal(1)
	f.register(a)
	salt := f.salts()[0].SaltID
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(salt, tagOf(1), "x"), signer: &a}, http.StatusCreated, "")
	_, missBody, _ := f.redeem([]byte("{"))
	for range codeRedeemIPv4 - 1 {
		f.redeem([]byte("{")) // malformed: charged, but no misses
	}
	code, b, d := f.redeem(redeemBody(tagEntry(salt, tagOf(1))))
	if code != http.StatusNotFound || !bytes.Equal(b, missBody) || d < pcHold {
		t.Fatalf("refused redeem: %d %s in %v", code, b, d)
	}
	// One redeem comes back every 30 s (20 in 10 minutes); the code
	// (600 s) is still live.
	f.clk.add(31 * time.Second)
	if code, b, _ := f.redeem(redeemBody(tagEntry(salt, tagOf(1)))); code != http.StatusOK {
		t.Fatalf("once a redeem came back: %d %s", code, b)
	}
}

// Limit 14 for IPv6: a request is charged to its /64, /48 and /32
// together, and refused if any is empty; a refusal charges none of them.
// (Small budgets here: /64 2, /48 3, /32 4.)
func TestPairCodeRedeemLimitIPv6(t *testing.T) {
	f := pairCodeFixture(t, func(c *config.Config) { c.TrustProxy = true }, true)
	budget := map[string]int{limCode64: 2, limCode48: 3, limCode32: 4, limCode4: 1}
	f.s.pc.limiters(func(name string, _ float64, _ int) ByteLimiter { return ratelimit.New(1e-9, budget[name], 1000) })
	take := func(ip string) bool {
		t.Helper()
		return f.s.takeCodeRedeem(clientIP(f.build(req{method: "POST", path: "/", header: http.Header{"X-Forwarded-For": {ip}}}), true))
	}
	left := func(l ByteLimiter, key string, n int64) bool {
		t.Helper()
		ok, _ := l.AllowN(key, n, f.clk.now())
		if ok {
			l.Refund(key, n)
		}
		return ok
	}
	// The /64's own budget.
	if !take("2001:db8:1:a::1") || !take("2001:db8:1:a::2") || take("2001:db8:1:a::3") {
		t.Fatal("the /64's budget of 2")
	}
	// The refused third request charged neither the /48 nor the /32.
	if !left(f.s.pc.lim48, "2001:db8:1::/48", 1) || left(f.s.pc.lim48, "2001:db8:1::/48", 2) {
		t.Fatal("the /48 was charged by a refusal")
	}
	if !left(f.s.pc.lim32, "2001:db8::/32", 2) || left(f.s.pc.lim32, "2001:db8::/32", 3) {
		t.Fatal("the /32 was charged by a refusal")
	}
	// Another /64 of the /48 takes the /48's last unit; the next is
	// refused at the /48, and its /64 is refunded.
	if !take("2001:db8:1:b::1") || take("2001:db8:1:c::1") {
		t.Fatal("the /48's budget of 3")
	}
	if !left(f.s.pc.lim64, "2001:db8:1:c::/64", 2) {
		t.Fatal("a refusal at the /48 kept its /64's charge")
	}
	// Another /48 takes the /32's last unit; the next is refused at the
	// /32, and its /64 and /48 are refunded.
	if !take("2001:db8:2::1") || take("2001:db8:3::1") {
		t.Fatal("the /32's budget of 4")
	}
	if !left(f.s.pc.lim64, "2001:db8:3::/64", 2) || !left(f.s.pc.lim48, "2001:db8:3::/48", 3) {
		t.Fatal("a refusal at the /32 kept its /64's or /48's charge")
	}
	// Another /32 is untouched; IPv4 has its own.
	if !take("2001:db9::1") || !take("192.0.2.1") || take("192.0.2.1") {
		t.Fatal("other networks")
	}
}

// The merged relayclient's calls work against the server.
func TestPairCodeRelayclient(t *testing.T) {
	f := pairCodeFixture(t, nil)
	a := newPrincipal(1)
	f.register(a)
	c := relayclient.New(f.ts.URL, a.priv)
	c.Now = f.clk.now
	ctx := context.Background()
	salts, err := c.PairCodeSalts(ctx)
	if err != nil || len(salts) != 1 {
		t.Fatalf("salts: %v %v", salts, err)
	}
	put := relayclient.PairCodePut{SaltID: salts[0].SaltID, Tag: tagOf(1), Salt: bytes.Repeat([]byte{7}, 16), Blob: []byte("bundle")}
	exp, err := c.PutPairCode(ctx, pcID1, put)
	if err != nil || !exp.Equal(f.clk.now().Add(600*time.Second).Truncate(time.Second)) {
		t.Fatalf("put: %v %v", exp, err)
	}
	b := newPrincipal(2)
	f.register(b)
	cb := relayclient.New(f.ts.URL, b.priv)
	cb.Now = f.clk.now
	var re *relayclient.Error
	if _, err := cb.PutPairCode(ctx, pcID2, put); !errors.As(err, &re) || re.Code != CodeCodeTaken {
		t.Fatalf("collision: %v", err)
	}
	if err := c.DeletePairCode(ctx, pcID1); err != nil {
		t.Fatal(err)
	}
}

// Tags, code_macs, salts, blobs, claim ids and k_pc are never logged.
func TestPairCodeLogsCarryNoSecrets(t *testing.T) {
	var logs syncBuf
	f := newFixtureFull(t, func(c *config.Config) { withPairKey(c) }, &logs,
		func(*fixture) []Option { return []Option{WithPairCodeHold(pcHold)} })
	a, b := newPrincipal(1), newPrincipal(2)
	f.register(a)
	f.register(b)
	salt := f.salts()[0].SaltID
	tag, tag2 := bytes.Repeat([]byte{0xc3}, 32), bytes.Repeat([]byte{0xd4}, 32)
	blob := "CODE-BUNDLE-MARKER"
	f.do(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(salt, tag, blob), signer: &a})
	f.redeem(redeemBody(tagEntry(salt, tag2)))
	f.redeem([]byte("{not json " + blob))
	f.redeem(redeemBody(tagEntry(salt, tag)))
	f.do(req{method: "PUT", path: "/v1/pair-code/" + pcID2, body: putBody(salt, tag2, blob), signer: &a})
	f.do(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(salt, tag2, blob), signer: &b})
	f.do(req{method: "DELETE", path: "/v1/pair-code/" + pcID2, signer: &a})
	out := logs.String()
	if !strings.Contains(out, "/v1/pair-code/redeem") {
		t.Fatalf("no access log lines:\n%s", out)
	}
	for name, secret := range map[string]string{
		"tag b64":      base64.StdEncoding.EncodeToString(tag),
		"tag hex":      hex.EncodeToString(tag),
		"tag2 b64":     base64.StdEncoding.EncodeToString(tag2),
		"code_mac hex": hex.EncodeToString(paircode.MAC(testPairKey, tag)),
		"blob":         blob,
		"blob b64":     base64.StdEncoding.EncodeToString([]byte(blob)),
		"salt b64":     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)),
		"claim id":     pcID1,
		"claim id 2":   pcID2,
		"k_pc b64":     base64.StdEncoding.EncodeToString(testPairKey),
		"k_pc hex":     hex.EncodeToString(testPairKey),
	} {
		if strings.Contains(out, secret) {
			t.Errorf("logs contain the %s", name)
		}
	}
}

// The answer leaves within [hold, 2 x hold) of receipt.
func TestPairCodeHoldUpperBound(t *testing.T) {
	const hold = 100 * time.Millisecond
	f := pairCodeFixtureWith(t, nil, false, WithPairCodeHold(hold))
	salt := f.salts()[0].SaltID
	for range 5 {
		if _, _, d := f.redeem(redeemBody(tagEntry(salt, tagOf(9)))); d < hold || d >= 2*hold {
			t.Fatalf("answered after %v, want [%v, %v)", d, hold, 2*hold)
		}
	}
}

// The numbers the relay runs with (§6.9.1, §7.2 limit 14).
func TestPairCodeDefaults(t *testing.T) {
	if codeHold != 250*time.Millisecond || codeWindow != 10*time.Minute ||
		codeRedeemIPv4 != 20 || codeRedeem64 != 10 || codeRedeem48 != 200 || codeRedeem32 != 1000 {
		t.Fatal("the pair-code defaults changed")
	}
	f := newFixture(t, func(c *config.Config) { withPairKey(c) })
	if f.s.pc.hold != codeHold {
		t.Fatalf("hold %v", f.s.pc.hold)
	}
}

// A PUT's body is checked: a tag of 32 bytes, a salt of 16, a blob of 1
// to max_claim_bytes; a non-creator's DELETE leaves the claim.
func TestPairCodePutBodyAndDelete(t *testing.T) {
	f := pairCodeFixture(t, func(c *config.Config) { c.MaxClaimBytes = 64 })
	a, b := newPrincipal(1), newPrincipal(2)
	f.register(a)
	f.register(b)
	salt := f.salts()[0].SaltID
	for name, body := range map[string][]byte{
		"short tag":  putBody(salt, tagOf(1)[:31], "x"),
		"empty blob": putBody(salt, tagOf(1), ""),
		"big blob":   putBody(salt, tagOf(1), strings.Repeat("x", 65)),
		"not json":   []byte("{"),
	} {
		if code, b := f.do(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: body, signer: &a}); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(salt, tagOf(1), strings.Repeat("x", 64)), signer: &a}, http.StatusCreated, "")
	if code, _ := f.do(req{method: "DELETE", path: "/v1/pair-code/" + pcID1, signer: &b}); code != http.StatusNoContent {
		t.Fatal(code)
	}
	if code, _, _ := f.redeem(redeemBody(tagEntry(salt, tagOf(1)))); code != http.StatusOK {
		t.Fatalf("another mailbox's DELETE removed the claim: %d", code)
	}
}

// A code PUT is charged to limit 11 (the key's stored bytes), and a PUT
// that isn't stored gets its charge back.
func TestPairCodePutChargesStoredBytes(t *testing.T) {
	f := pairCodeFixture(t, func(c *config.Config) {
		c.RateKeyBytesPerSec, c.RateKeyBytesBurst = 1e-9, 100
	})
	a, b := newPrincipal(1), newPrincipal(2)
	f.register(a)
	f.register(b)
	salt := f.salts()[0].SaltID
	put := func(p principal, id string, tag byte, n int) int {
		code, _ := f.do(req{method: "PUT", path: "/v1/pair-code/" + id, body: putBody(salt, tagOf(tag), strings.Repeat("x", n)), signer: &p})
		return code
	}
	if c := put(a, pcID1, 1, 60); c != http.StatusCreated {
		t.Fatal(c)
	}
	// Not stored (the id is a's): refunded, so b's budget is whole.
	if c := put(b, pcID1, 2, 90); c != http.StatusBadRequest {
		t.Fatal(c)
	}
	if c := put(b, pcID2, 3, 100); c != http.StatusCreated {
		t.Fatalf("b's budget after a refunded PUT: %d", c)
	}
	// a has 40 left.
	if c := put(a, pcID1, 4, 41); c != http.StatusTooManyRequests {
		t.Fatalf("over the key's budget: %d", c)
	}
}

// The hold is counted from receipt: a body that arrives slowly is
// answered at the next step after receipt, not a hold after the work.
func TestPairCodeHoldCountsFromReceipt(t *testing.T) {
	const hold = 100 * time.Millisecond
	f := pairCodeFixtureWith(t, nil, false, WithPairCodeHold(hold))
	salt := f.salts()[0].SaltID
	body := redeemBody(tagEntry(salt, tagOf(9)))
	pr, pw := io.Pipe()
	hr := f.build(req{method: "POST", path: "/v1/pair-code/redeem", body: body})
	hr.Body, hr.ContentLength = pr, int64(len(body))
	go func() {
		time.Sleep(hold * 3 / 2) // the work ends at 1.5 holds
		pw.Write(body)
		pw.Close()
	}()
	start := time.Now()
	code, _, _ := f.send(hr)
	d := time.Since(start)
	// From receipt: the step at 2 holds. After the work: 2.5 holds.
	if code != http.StatusNotFound || d < 2*hold || d >= 2*hold+hold/2 {
		t.Fatalf("%d after %v, want [%v, %v)", code, d, 2*hold, 2*hold+hold/2)
	}
}

// A redeem body that doesn't arrive in time gets the same answer as any
// failure, at a hold step after the read deadline; it doesn't hang.
func TestPairCodeRedeemBodyDeadline(t *testing.T) {
	const hold = 50 * time.Millisecond
	f := pairCodeFixtureWith(t, nil, false, WithPairCodeHold(hold), WithSmallBodyTimeout(200*time.Millisecond))
	salt := f.salts()[0].SaltID
	body := redeemBody(tagEntry(salt, tagOf(9)))
	pr, pw := io.Pipe()
	defer pw.Close()
	hr := f.build(req{method: "POST", path: "/v1/pair-code/redeem", body: body})
	hr.Body, hr.ContentLength = pr, int64(len(body))
	done := make(chan int, 1)
	go func() {
		code, _, _ := f.send(hr)
		done <- code
	}()
	go pw.Write(body[:5]) // and then nothing
	select {
	case code := <-done:
		if code != http.StatusNotFound {
			t.Fatalf("a slow body: %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a slow body held the redeem past its deadline")
	}
}
