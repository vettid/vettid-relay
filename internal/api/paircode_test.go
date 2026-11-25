package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/paircode"
	"github.com/vettid/vettid-relay/relayclient"
)

// Code claims (§6.9.1).

var testPairKey = bytes.Repeat([]byte{0x5a}, 32)

// pcHour is a fixed hour for the tests: 2026-03-31T12:00:00Z (epoch 493044).
var pcHour = time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC)

const pcHold = 40 * time.Millisecond

func pairCodeFixture(t *testing.T, mut func(*config.Config)) *fixture {
	f := newFixtureWith(t, func(c *config.Config) {
		c.PairCodeKey = config.NewSecret(testPairKey)
		if mut != nil {
			mut(c)
		}
	}, func(*fixture) []Option { return []Option{WithPairCodeHold(pcHold)} })
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
			c.PairCodeKey = config.NewSecret(testPairKey)
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
	// A redeem may name the previous salt while it is listed.
	f.expectCode(req{method: "PUT", path: "/v1/pair-code/" + pcID1, body: putBody(l2[1].SaltID, tagOf(3), "x"), signer: &a}, http.StatusCreated, "")
	if code, _, _ := f.redeem(redeemBody(tagEntry(l2[0].SaltID, tagOf(9)), tagEntry(l2[1].SaltID, tagOf(3)))); code != http.StatusOK {
		t.Fatalf("redeem with two tags: %d", code)
	}
}

// Limit 14: 20 redeems per IPv4 address in 10 minutes; the 21st is
// answered like a miss and doesn't spend a live code.
func TestPairCodeRedeemLimitIPv4(t *testing.T) {
	f := pairCodeFixture(t, nil)
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
// together, and refused if any is empty.
func TestPairCodeRedeemLimitIPv6(t *testing.T) {
	f := pairCodeFixture(t, func(c *config.Config) { c.TrustProxy = true })
	from := func(ip string) http.Header { return http.Header{"X-Forwarded-For": {ip}} }
	refused := func(ip string) bool {
		t.Helper()
		ok := f.s.takeCodeRedeem(clientIP(f.build(req{method: "POST", path: "/", header: from(ip)}), true))
		return !ok
	}
	for range codeRedeem64 {
		if refused("2001:db8:1:1::1") {
			t.Fatal("refused within the /64's budget")
		}
	}
	if !refused("2001:db8:1:1::2") {
		t.Fatal("the /64 is not limited")
	}
	// Other /64s of the /48 have their own budgets, up to the /48's.
	n := codeRedeem64
	for i := 2; n < codeRedeem48; i++ {
		for range codeRedeem64 {
			if n == codeRedeem48 {
				break
			}
			if refused("2001:db8:1:" + itoaHex(i) + "::1") {
				t.Fatalf("refused at %d in the /48", n)
			}
			n++
		}
	}
	if !refused("2001:db8:1:ffff::1") {
		t.Fatal("the /48 is not limited")
	}
	// A refused request charged none of them: another /48 of the /32
	// still has its budget.
	if refused("2001:db8:2::1") {
		t.Fatal("a refusal charged the /32")
	}
}

func itoaHex(i int) string { return strconv.FormatInt(int64(i), 16) }

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
	f := newFixtureFull(t, func(c *config.Config) { c.PairCodeKey = config.NewSecret(testPairKey) }, &logs,
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
