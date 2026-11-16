package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
)

// registerAnswer registers p and returns the status and the answer.
func (f *fixture) registerAnswer(p principal) (int, map[string]any) {
	f.t.Helper()
	body, _ := json.Marshal(map[string]string{"pubkey": p.b64})
	code, b := f.do(req{method: "POST", path: "/v1/register", body: body, signer: &p})
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		f.t.Fatalf("register: %d %s", code, b)
	}
	return code, m
}

// tombField returns the answer's tokens_not_before, and whether it is there.
func tombField(m map[string]any) (string, bool) {
	v, ok := m["tokens_not_before"]
	s, _ := v.(string)
	return s, ok
}

// The registration answer reports the tombstone (§6.1, 0.12.0): the flag in
// limits always; tokens_not_before, rounded up to the whole second, in the
// 201 and the 200s while the tombstone is held, and never otherwise. A token
// with iat equal to the value reported is accepted; one a second before it
// is refused.
func TestRegisterReportsTombstones(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)

	code, m := f.registerAnswer(owner)
	if lim, _ := m["limits"].(map[string]any); code != http.StatusCreated || lim["reports_tombstones"] != true {
		t.Fatalf("first registration: %d %v", code, m)
	}
	if v, ok := tombField(m); ok {
		t.Fatalf("first registration has tokens_not_before %q", v)
	}
	if code, m := f.registerAnswer(owner); code != http.StatusOK {
		t.Fatalf("again: %d %v", code, m)
	} else if v, ok := tombField(m); ok {
		t.Fatalf("a mailbox never deleted has tokens_not_before %q", v)
	}

	// A deletion at a fractional second: the time reported is rounded up.
	f.clk.set(f.clk.now().Truncate(time.Second).Add(400 * time.Millisecond))
	deleted := f.clk.now()
	if code, b := f.deleteMailbox(owner); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	want := deleted.Add(auth.FreshnessWindow).Truncate(time.Second).Add(time.Second)
	wantS := want.UTC().Format(time.RFC3339)
	code, m = f.registerAnswer(owner)
	if v, _ := tombField(m); code != http.StatusCreated || v != wantS {
		t.Fatalf("re-registration: %d %v, want tokens_not_before %s", code, m, wantS)
	}
	if lim, _ := m["limits"].(map[string]any); lim["reports_tombstones"] != true {
		t.Fatalf("re-registration limits: %v", m)
	}
	code, m = f.registerAnswer(owner)
	if v, _ := tombField(m); code != http.StatusOK || v != wantS {
		t.Fatalf("another registration: %d %v, want %s", code, m, wantS)
	}

	// The value reported is the one compared.
	f.clk.set(want.Add(time.Second))
	before := f.mint(owner, sender, func(c *auth.Claims) { c.Iat = want.Add(-time.Second); c.Exp = want.Add(time.Hour); c.Jti = "before" })
	f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("x")), signer: &sender, token: before}, 403, CodeTokenRevoked)
	at := f.mint(owner, sender, func(c *auth.Claims) { c.Iat = want; c.Exp = want.Add(time.Hour); c.Jti = "at" })
	f.mustDeposit(owner, sender, at, []byte("x"))

	// Past the tombstone's retention. SQLite sweeps the tombstone, and the
	// field goes with it. DynamoDB keeps a re-registered mailbox's
	// tokens-not-before for good (deposits keep checking it), so the field
	// stays: the answer follows what deposits are checked against.
	f.clk.add(denylistRetention(f.cfg) + time.Hour)
	if _, err := f.st.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, m = f.registerAnswer(owner)
	v, ok := tombField(m)
	if os.Getenv("RELAY_TEST_API_STORE") == "dynamodb" {
		if code != http.StatusOK || v != wantS {
			t.Fatalf("past the retention (dynamodb): %d %v", code, m)
		}
	} else if code != http.StatusOK || ok {
		t.Fatalf("past the retention: %d %v", code, m)
	}
}

// A rotated-away mailbox removed at the end of its grace leaves a tombstone
// (§6.7): registering its key again reports it.
func TestRegisterReportsRotationTombstone(t *testing.T) {
	f := newFixture(t, nil)
	owner, next := newPrincipal(1), newPrincipal(4)
	f.register(owner)
	proof := ed25519.Sign(next.priv, []byte(owner.mbx))
	body, _ := json.Marshal(map[string]any{"new_pubkey": next.b64, "new_key_proof": proof})
	if code, b := f.do(req{method: "POST", path: "/v1/mailbox/rotate", body: body, signer: &owner}); code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, b)
	}
	f.clk.add(f.cfg.RotationGrace + time.Minute)
	removed := f.clk.now() // the registration below removes it (as the sweep would)
	code, m := f.registerAnswer(owner)
	want := wholeSecondUp(removed.Add(auth.FreshnessWindow)).UTC().Format(time.RFC3339)
	if v, _ := tombField(m); code != http.StatusCreated || v != want {
		t.Fatalf("after the grace: %d %v, want %s", code, m, want)
	}
	// The successor, never deleted, has none.
	if code, m := f.registerAnswer(next); code != http.StatusOK {
		t.Fatalf("successor: %d %v", code, m)
	} else if v, ok := tombField(m); ok {
		t.Fatalf("successor has tokens_not_before %q", v)
	}
}

// rotateAnswer rotates from's mailbox onto to's key and returns the status
// and the answer.
func (f *fixture) rotateAnswer(from, to principal) (int, map[string]any) {
	f.t.Helper()
	proof := ed25519.Sign(to.priv, []byte(from.mbx))
	body, _ := json.Marshal(map[string]any{"new_pubkey": to.b64, "new_key_proof": proof})
	code, b := f.do(req{method: "POST", path: "/v1/mailbox/rotate", body: body, signer: &from})
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		f.t.Fatalf("rotate: %d %s", code, b)
	}
	return code, m
}

// The rotate answer reports the successor's tombstone (§6.7, 0.13.0): the
// marker in every 200; tokens_not_before, as at registration, while a
// tombstone for the successor's id is held, and never otherwise; a repeat
// answers the same. Each case is checked against the registration answer
// for the same key, and the value against the deposit check.
func TestRotateReportsTombstones(t *testing.T) {
	f := newFixture(t, nil)
	sender := newPrincipal(20)
	// rotated rotates and checks the marker, and that the field matches a
	// registration of the successor's key just after.
	rotated := func(what string, from, to principal) (string, bool) {
		t.Helper()
		code, m := f.rotateAnswer(from, to)
		if code != http.StatusOK || m["mailbox_id"] != to.mbx || m["reports_tombstones_at_rotation"] != true {
			t.Fatalf("%s: %d %v", what, code, m)
		}
		v, ok := tombField(m)
		rcode, rm := f.registerAnswer(to)
		if rv, rok := tombField(rm); rcode != http.StatusOK || rv != v || rok != ok {
			t.Fatalf("%s: rotate said %q %v, registration %d %v", what, v, ok, rcode, rm)
		}
		return v, ok
	}
	// accepted checks the deposit check against a reported value.
	accepted := func(what string, owner principal, v string) {
		t.Helper()
		want, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t.Fatalf("%s: %q: %v", what, v, err)
		}
		if f.clk.now().Before(want.Add(time.Second)) {
			f.clk.set(want.Add(time.Second))
		}
		before := f.mint(owner, sender, func(c *auth.Claims) {
			c.Iat = want.Add(-time.Second)
			c.Exp = want.Add(time.Hour)
			c.Jti = what + "-before"
		})
		f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("x")), signer: &sender, token: before}, 403, CodeTokenRevoked)
		at := f.mint(owner, sender, func(c *auth.Claims) { c.Iat = want; c.Exp = want.Add(time.Hour); c.Jti = what + "-at" })
		f.mustDeposit(owner, sender, at, []byte("x"))
	}

	// A fresh key: no field, also on a repeat.
	a, b := newPrincipal(1), newPrincipal(2)
	f.register(a)
	if v, ok := rotated("a fresh key", a, b); ok {
		t.Fatalf("a fresh key: tokens_not_before %q", v)
	}
	if v, ok := rotated("a repeat onto a fresh key", a, b); ok {
		t.Fatalf("a repeat onto a fresh key: tokens_not_before %q", v)
	}

	// A deleted key, at a fractional second: rounded up; a repeat answers
	// the same.
	d, e := newPrincipal(3), newPrincipal(4)
	f.register(d)
	f.clk.set(f.clk.now().Truncate(time.Second).Add(400 * time.Millisecond))
	deleted := f.clk.now()
	if code, b := f.deleteMailbox(d); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	f.register(e)
	want := wholeSecondUp(deleted.Add(auth.FreshnessWindow)).UTC().Format(time.RFC3339)
	if v, _ := rotated("a deleted key", e, d); v != want {
		t.Fatalf("a deleted key: %q, want %q", v, want)
	}
	f.clk.add(time.Minute)
	if v, _ := rotated("a repeat onto a deleted key", e, d); v != want {
		t.Fatalf("a repeat onto a deleted key: %q, want %q", v, want)
	}
	accepted("deleted", d, want)

	// A tombstone written before 0.12.0, at a fractional second (the store
	// directly; the api rounds it up when it deletes): reported rounded up,
	// and that is the value deposits compare with.
	o, o2 := newPrincipal(10), newPrincipal(11)
	f.register(o)
	onb := f.clk.now().Truncate(time.Second).Add(90*time.Second + 400*time.Millisecond)
	if _, err := f.st.DeleteMailbox(context.Background(), o.mbx, o.pub, onb, onb.Add(denylistRetention(f.cfg))); err != nil {
		t.Fatal(err)
	}
	f.register(o2)
	owant := wholeSecondUp(onb).UTC().Format(time.RFC3339)
	if v, _ := rotated("a fractional tombstone", o2, o); v != owant {
		t.Fatalf("a fractional tombstone: %q, want %q", v, owant)
	}
	accepted("fractional", o, owant)

	// A live key that carries an older tombstone.
	g, h := newPrincipal(5), newPrincipal(6)
	f.register(g)
	gdel := f.clk.now()
	if code, b := f.deleteMailbox(g); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	f.clk.add(time.Hour)
	f.register(g)
	f.register(h)
	gwant := wholeSecondUp(gdel.Add(auth.FreshnessWindow)).UTC().Format(time.RFC3339)
	if v, _ := rotated("a live key with an older tombstone", h, g); v != gwant {
		t.Fatalf("a live key with an older tombstone: %q, want %q", v, gwant)
	}
	accepted("live", g, gwant)

	// A key rotated away whose grace has ended, not swept yet: the rotate
	// removes its mailbox first (vettid-relay #29) and reports the
	// removal's tombstone.
	p, q, r := newPrincipal(7), newPrincipal(8), newPrincipal(9)
	f.register(p)
	if code, m := f.rotateAnswer(p, q); code != http.StatusOK {
		t.Fatalf("rotate away: %d %v", code, m)
	}
	f.clk.add(f.cfg.RotationGrace + time.Minute)
	removed := f.clk.now()
	f.register(r)
	pwant := wholeSecondUp(removed.Add(auth.FreshnessWindow)).UTC().Format(time.RFC3339)
	if v, _ := rotated("a key past its grace", r, p); v != pwant {
		t.Fatalf("a key past its grace: %q, want %q", v, pwant)
	}
	accepted("removed", p, pwant)
}

func TestWholeSecondUp(t *testing.T) {
	at := time.Date(2026, 11, 14, 15, 0, 0, 0, time.UTC)
	for in, want := range map[time.Duration]time.Duration{0: 0, time.Millisecond: time.Second, 999 * time.Millisecond: time.Second, time.Second: time.Second} {
		if got := wholeSecondUp(at.Add(in)); !got.Equal(at.Add(want)) {
			t.Errorf("%v: %v", in, got)
		}
	}
}

// A token whose iat has a fractional second after the tombstone's time but
// before the whole second reported is refused: iat is compared with the
// value reported (§6.1), whatever its format.
func TestFractionalIatAgainstReportedTombstone(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	f.clk.set(f.clk.now().Truncate(time.Second).Add(400 * time.Millisecond))
	nb := f.clk.now().Add(auth.FreshnessWindow)
	if code, b := f.deleteMailbox(owner); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	_, m := f.registerAnswer(owner)
	v, _ := tombField(m)
	reported, err := time.Parse(time.RFC3339, v)
	if err != nil || !reported.Equal(wholeSecondUp(nb)) {
		t.Fatalf("reported %q: %v", v, err)
	}
	f.clk.set(reported.Add(5 * time.Second))
	token := func(jti string, iat time.Time) string {
		claims := fmt.Sprintf(`{"iss":%q,"sub":%q,"aud":%q,"iat":%q,"exp":%q,"jti":%q,"scope":"deposit"}`,
			owner.mbx, sender.b64, testAud, iat.UTC().Format(time.RFC3339Nano), iat.Add(time.Hour).UTC().Format(time.RFC3339), jti)
		return auth.SignToken(owner.priv, []byte(claims))
	}
	for i, iat := range []time.Time{nb.Add(300 * time.Millisecond), reported.Add(-time.Millisecond)} {
		f.expectCode(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: depositBody([]byte("x")), signer: &sender, token: token(fmt.Sprint("frac", i), iat)}, 403, CodeTokenRevoked)
	}
	f.mustDeposit(owner, sender, token("whole", reported.Add(500*time.Millisecond)), []byte("x"))
}
