package relayclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/api"
	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
	client "github.com/vettid/vettid-relay/relayclient"
)

// startRelay runs the real relay handler in-process on a loopback
// httptest server with a SQLite file in the test's temp dir.
func startRelay(t *testing.T) string {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	cfg := config.Defaults()
	cfg.BaseURL = ts.URL // tokens are minted for this exact audience
	srv := api.New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New())
	ts.Config.Handler = srv.Handler()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Drain(ctx)
		ts.Close()
		srv.Close()
		st.Close()
	})
	return ts.URL
}

// testKey derives a fixed key from name, so runs are reproducible.
func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("relayclient test key: " + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func newClient(url, name string) *client.Client { return client.New(url, testKey(name)) }

func parse(t *testing.T, c *client.Client, tok string) auth.Claims {
	t.Helper()
	cl, err := auth.ParseToken(tok, c.PublicKey())
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return cl
}

func TestRegister(t *testing.T) {
	url := startRelay(t)
	ctx := context.Background()
	c := newClient(url, "vault")
	reg, err := c.Register(ctx)
	if err != nil || !reg.Created || reg.MailboxID != c.MailboxID() {
		t.Fatalf("register: %+v %v", reg, err)
	}
	d := config.Defaults()
	if reg.Limits.MaxPayloadBytes != d.MaxPayloadBytes ||
		reg.Limits.OpenTokenMaxLifetimeSeconds != int64(d.OpenTokenMaxLifetime/time.Second) ||
		reg.Limits.MaxClaimBytes != d.MaxClaimBytes {
		t.Fatalf("limits: %+v", reg.Limits)
	}
	again, err := c.Register(ctx)
	if err != nil || again.Created || again.MailboxID != c.MailboxID() {
		t.Fatalf("re-register must be idempotent: %+v %v", again, err)
	}
}

func TestMintTokenClaims(t *testing.T) {
	c := newClient("https://relay.example", "vault")
	now := time.Date(2026, 6, 10, 12, 0, 0, 500, time.UTC)
	c.Now = func() time.Time { return now }
	sender := testKey("app").Public().(ed25519.PublicKey)
	senderB64 := auth.EncodeKey(sender)

	tok, err := c.MintToken(senderB64, "https://relay.example", client.TokenOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cl := parse(t, c, tok)
	if cl.Scope != auth.ScopeDeposit || cl.Sub != senderB64 || cl.Aud != "https://relay.example" ||
		cl.Iss != c.MailboxID() || cl.Open() || cl.OwnerDevice {
		t.Fatalf("claims: %+v", cl)
	}
	// iat is backdated 60 s (RELAY-PROTOCOL §5.2); the lifetime is the TTL.
	if want := now.Truncate(time.Second).Add(-time.Minute); !cl.Iat.Equal(want) {
		t.Fatalf("iat %v, want %v", cl.Iat, want)
	}
	if got := cl.Exp.Sub(cl.Iat); got != time.Hour {
		t.Fatalf("exp-iat %v", got)
	}

	// Defaults: 30 days, random jti; explicit jti and owner_device kept.
	tok, err = c.MintToken(senderB64, "https://relay.example", client.TokenOptions{JTI: "conn-1", OwnerDevice: true})
	if err != nil {
		t.Fatal(err)
	}
	cl = parse(t, c, tok)
	if cl.Jti != "conn-1" || !cl.OwnerDevice || cl.Exp.Sub(cl.Iat) != 30*24*time.Hour {
		t.Fatalf("claims: %+v", cl)
	}
}

func TestMintOpenTokenClaims(t *testing.T) {
	c := newClient("https://relay.example", "vault")
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	for _, tc := range []struct {
		ttl, lifetime, backdate time.Duration
	}{
		{0, 5 * time.Minute, time.Minute}, // default
		{10 * time.Minute, 10 * time.Minute, time.Minute},
		{time.Minute, time.Minute, 30 * time.Second}, // backdated by at most half the TTL
	} {
		tok, err := c.MintOpenToken("https://relay.example", tc.ttl, "")
		if err != nil {
			t.Fatal(err)
		}
		cl := parse(t, c, tok)
		if cl.Scope != auth.ScopeDepositOpen || cl.Sub != auth.OpenSub || !cl.Open() ||
			cl.Aud != "https://relay.example" || cl.Iss != c.MailboxID() || cl.Jti == "" {
			t.Fatalf("ttl %v: claims %+v", tc.ttl, cl)
		}
		if got := cl.Exp.Sub(cl.Iat); got != tc.lifetime {
			t.Fatalf("ttl %v: exp-iat %v, want %v", tc.ttl, got, tc.lifetime)
		}
		if got := now.Sub(cl.Iat); got != tc.backdate {
			t.Fatalf("ttl %v: iat backdated %v, want %v", tc.ttl, got, tc.backdate)
		}
	}
	tok, _ := c.MintOpenToken("https://relay.example", 0, "invite-7")
	if cl := parse(t, c, tok); cl.Jti != "invite-7" {
		t.Fatalf("jti %q", cl.Jti)
	}
}

// Default jtis are 26 Crockford base32 characters and never repeat.
func TestDefaultJTIsUnique(t *testing.T) {
	c := newClient("https://relay.example", "vault")
	sub := auth.EncodeKey(testKey("app").Public().(ed25519.PublicKey))
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	seen := map[string]bool{}
	for i := range 2000 {
		var tok string
		var err error
		if i%2 == 0 {
			tok, err = c.MintToken(sub, "https://relay.example", client.TokenOptions{})
		} else {
			tok, err = c.MintOpenToken("https://relay.example", 0, "")
		}
		if err != nil {
			t.Fatal(err)
		}
		jti := parse(t, c, tok).Jti
		if len(jti) != 26 || strings.Trim(jti, alphabet) != "" {
			t.Fatalf("jti %q is not 26 Crockford base32 characters", jti)
		}
		if seen[jti] {
			t.Fatalf("jti %q repeated after %d mints", jti, i)
		}
		seen[jti] = true
	}
}

func TestDepositCollectAck(t *testing.T) {
	url := startRelay(t)
	ctx := context.Background()
	vault, app := newClient(url, "vault"), newClient(url, "app")
	if _, err := vault.Register(ctx); err != nil {
		t.Fatal(err)
	}
	tok, err := vault.MintToken(app.PublicKeyB64(), url, client.TokenOptions{TTL: time.Hour, JTI: "conn-app"})
	if err != nil {
		t.Fatal(err)
	}
	msgID, err := app.Deposit(ctx, vault.MailboxID(), tok, []byte("ciphertext"))
	if err != nil || msgID == "" {
		t.Fatalf("deposit: %q %v", msgID, err)
	}
	msgs, err := vault.Collect(ctx, 0, 10)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("collect: %+v %v", msgs, err)
	}
	m := msgs[0]
	if m.MsgID != msgID || string(m.Payload) != "ciphertext" || m.Sender != app.PublicKeyB64() || m.JTI != "conn-app" || m.DepositedAt == "" {
		t.Fatalf("message: %+v", m)
	}
	if err := vault.Ack(ctx, msgID); err != nil {
		t.Fatal(err)
	}
	if err := vault.Ack(ctx, msgID); err != nil {
		t.Fatalf("ack must be idempotent: %v", err)
	}
	if msgs, err := vault.Collect(ctx, 0, 10); err != nil || len(msgs) != 0 {
		t.Fatalf("after ack: %+v %v", msgs, err)
	}
}

// An open token permits exactly one deposit; the second is 409 token_used
// (RELAY-PROTOCOL §5.6) and is not retried.
func TestOpenTokenUsedTwice(t *testing.T) {
	url := startRelay(t)
	ctx := context.Background()
	vault, stranger := newClient(url, "vault"), newClient(url, "stranger")
	if _, err := vault.Register(ctx); err != nil {
		t.Fatal(err)
	}
	open, err := vault.MintOpenToken(url, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.Deposit(ctx, vault.MailboxID(), open, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, err = stranger.Deposit(ctx, vault.MailboxID(), open, []byte("hello again"))
	var e *client.Error
	if !client.IsCode(err, "token_used") || !errors.As(err, &e) || e.Status != http.StatusConflict {
		t.Fatalf("second deposit: %v", err)
	}
	msgs, err := vault.Collect(ctx, 0, 10)
	if err != nil || len(msgs) != 1 || msgs[0].Sender != stranger.PublicKeyB64() {
		t.Fatalf("collect: %+v %v", msgs, err)
	}
}

func TestClaimSingleFetch(t *testing.T) {
	url := startRelay(t)
	ctx := context.Background()
	owner, stranger := newClient(url, "vault"), newClient(url, "stranger")
	if _, err := owner.Register(ctx); err != nil {
		t.Fatal(err)
	}
	id, exp, err := owner.PutClaim(ctx, []byte("bundle"), 2*time.Minute)
	if err != nil || id == "" {
		t.Fatalf("put claim: %q %v", id, err)
	}
	if d := time.Until(exp); d <= time.Minute || d > 2*time.Minute+5*time.Second {
		t.Fatalf("claim expires in %v", d)
	}
	got, err := stranger.GetClaim(ctx, id)
	if err != nil || string(got) != "bundle" {
		t.Fatalf("get claim: %q %v", got, err)
	}
	if _, err := stranger.GetClaim(ctx, id); !client.IsCode(err, "claim_unknown") {
		t.Fatalf("claim must be single-fetch: %v", err)
	}
}

// fakeRelay answers each request with the next of replies (the last one
// repeats) and counts the requests.
type fakeRelay struct {
	calls   atomic.Int32
	replies []reply
}

type reply struct {
	status int
	body   string
}

func (f *fakeRelay) start(t *testing.T) *client.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(f.calls.Add(1)) - 1
		rp := f.replies[min(n, len(f.replies)-1)]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rp.status)
		io.WriteString(w, rp.body)
	}))
	t.Cleanup(ts.Close)
	c := newClient(ts.URL, "vault")
	c.MaxAttempts = 3
	return c
}

const okDeposit = `{"msg_id":"m1"}`

func TestRetry(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		replies []reply
		calls   int
		code    string        // expected error code; "" for success
		minWait time.Duration // the retries must take at least this long
	}{
		{"429 honours retry_after", []reply{
			{429, `{"code":"rate_limited","message":"slow down","retry_after":1}`},
			{200, okDeposit}}, 2, "", time.Second},
		{"503 then success", []reply{{503, `{"code":"unavailable","message":"x"}`}, {200, okDeposit}}, 2, "", 0},
		{"5xx up to MaxAttempts", []reply{{500, `{"code":"internal","message":"x"}`}}, 3, "internal", 0},
		{"non-JSON 502", []reply{{502, "bad gateway"}}, 3, "http_502", 0},
		{"4xx not retried", []reply{{403, `{"code":"token_revoked","message":"x"}`}}, 1, "token_revoked", 0},
		{"409 not retried", []reply{{409, `{"code":"token_used","message":"x"}`}}, 1, "token_used", 0},
		{"quota 429 not retried", []reply{{429, `{"code":"quota_exceeded","message":"x","quota":"token","retry_after":1}`}}, 1, "quota_exceeded", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeRelay{replies: tc.replies}
			c := f.start(t)
			start := time.Now()
			id, err := c.Deposit(ctx, "mbx", "tok", []byte("x"))
			took := time.Since(start)
			if got := int(f.calls.Load()); got != tc.calls {
				t.Fatalf("%d requests, want %d (err %v)", got, tc.calls, err)
			}
			if tc.code == "" {
				if err != nil || id != "m1" {
					t.Fatalf("deposit: %q %v", id, err)
				}
			} else if !client.IsCode(err, tc.code) {
				t.Fatalf("error %v, want %s", err, tc.code)
			}
			if took < tc.minWait {
				t.Fatalf("retried after %v, before retry_after", took)
			}
		})
	}
}

func TestRetryStopsOnContextCancel(t *testing.T) {
	f := &fakeRelay{replies: []reply{{429, `{"code":"rate_limited","message":"x","retry_after":30}`}}}
	c := f.start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.Deposit(ctx, "mbx", "tok", []byte("x")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("%d requests", n)
	}
}

// A claim fetch deletes the claim, so a lost response must not be retried.
func TestGetClaimNotRetried(t *testing.T) {
	f := &fakeRelay{replies: []reply{{503, `{"code":"unavailable","message":"x","retry_after":1}`}}}
	c := f.start(t)
	if _, err := c.GetClaim(context.Background(), "claim"); !client.IsCode(err, "unavailable") {
		t.Fatalf("err %v", err)
	}
	if n := f.calls.Load(); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
}
