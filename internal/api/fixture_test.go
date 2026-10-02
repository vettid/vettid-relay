package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
)

const testAud = "https://relay.test.vettid.org"

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fixture struct {
	seq    atomic.Int64 // per-request signature timestamp offset (µs)
	logw   io.Writer
	dbPath string
	t      *testing.T
	cfg    config.Config
	clk    *testClock
	st     *store.Store
	s      *Server
	ts     *httptest.Server
	reg    *metrics.Registry
}

// newFixture starts a relay on an httptest server. Server and store share a
// controllable clock (starting at real time); requests are signed with
// f.clk.now().
func newFixture(t *testing.T, mut func(*config.Config)) *fixture {
	t.Helper()
	return newFixtureLog(t, mut, io.Discard)
}

// newFixtureLog is newFixture with the relay's JSON logs written to logw.
func newFixtureLog(t *testing.T, mut func(*config.Config), logw io.Writer) *fixture {
	t.Helper()
	cfg := config.Defaults()
	cfg.BaseURL = testAud
	cfg.RateIPPerSec, cfg.RateIPBurst = 1000, 1000
	cfg.RateSenderPerSec, cfg.RateSenderBurst = 1000, 1000
	cfg.RateClaimPerSec, cfg.RateClaimBurst = 1000, 1000
	if mut != nil {
		mut(&cfg)
	}
	clk := &testClock{t: time.Now().UTC().Truncate(time.Second)}
	f := &fixture{t: t, cfg: cfg, clk: clk, logw: logw, dbPath: filepath.Join(t.TempDir(), "relay.db")}
	f.start()
	t.Cleanup(f.stop)
	return f
}

// start opens the store and serves a fresh relay instance on f.dbPath.
func (f *fixture) start() {
	f.t.Helper()
	st, err := store.Open(context.Background(), f.dbPath, store.WithClock(f.clk.now))
	if err != nil {
		f.t.Fatal(err)
	}
	f.st = st
	f.reg = metrics.New()
	f.s = New(f.cfg, st, slog.New(slog.NewJSONHandler(f.logw, &slog.HandlerOptions{Level: slog.LevelDebug})), f.reg, WithClock(f.clk.now))
	f.ts = httptest.NewServer(f.s.Handler())
}

// stop drains and shuts the relay down and closes the store.
func (f *fixture) stop() {
	if f.s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f.s.Drain(ctx)
	f.ts.Close()
	f.s.Close()
	f.st.Close()
	f.s = nil
}

// restart simulates a process restart on the same database file (in-memory
// state such as the replay cache and rate limiters is lost).
func (f *fixture) restart() {
	f.t.Helper()
	f.stop()
	f.start()
}

type principal struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	b64  string
	mbx  string
}

func newPrincipal(seed byte) principal {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	pub := priv.Public().(ed25519.PublicKey)
	return principal{priv: priv, pub: pub, b64: auth.EncodeKey(pub), mbx: auth.MailboxID(pub)}
}

// req describes one HTTP call.
type req struct {
	method, path string
	body         []byte
	signer       *principal // nil: unsigned
	token        string
	at           time.Time // signature timestamp; zero → clock now
	header       http.Header
}

func (f *fixture) build(r req) *http.Request {
	f.t.Helper()
	hr, err := http.NewRequest(r.method, f.ts.URL+r.path, bytes.NewReader(r.body))
	if err != nil {
		f.t.Fatal(err)
	}
	if r.body == nil {
		hr.Body = http.NoBody
		hr.ContentLength = 0
	}
	if r.signer != nil {
		at := r.at
		if at.IsZero() {
			at = f.sigTime()
		}
		auth.SetHeaders(hr.Header, r.signer.priv, r.method, hr.URL.EscapedPath(), at, auth.BodyHash(r.body))
	}
	if r.token != "" {
		hr.Header.Set("Authorization", "VettID-Deposit "+r.token)
	}
	for k, v := range r.header {
		hr.Header[k] = v
	}
	return hr
}

// sigTime returns the clock time plus a unique microsecond offset, so
// otherwise identical requests carry distinct signatures (as real clients'
// sub-second timestamps do).
func (f *fixture) sigTime() time.Time {
	return f.clk.now().Add(time.Duration(f.seq.Add(1)) * time.Microsecond)
}

func (f *fixture) send(hr *http.Request) (int, []byte, http.Header) {
	f.t.Helper()
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func (f *fixture) do(r req) (int, []byte) {
	f.t.Helper()
	code, b, _ := f.send(f.build(r))
	return code, b
}

// expectCode asserts an error response with the given canonical code.
func (f *fixture) expectCode(r req, status int, code string) []byte {
	f.t.Helper()
	got, b := f.do(r)
	var e errorBody
	json.Unmarshal(b, &e)
	if got != status || e.Code != code {
		f.t.Fatalf("%s %s: got %d %s, want %d %s", r.method, r.path, got, b, status, code)
	}
	return b
}

func (f *fixture) register(p principal) {
	f.t.Helper()
	body, _ := json.Marshal(map[string]string{"pubkey": p.b64})
	code, b := f.do(req{method: "POST", path: "/v1/register", body: body, signer: &p})
	if code != http.StatusCreated && code != http.StatusOK {
		f.t.Fatalf("register: %d %s", code, b)
	}
}

// mintOpen issues a one-shot open token (spec §5.6) for owner's mailbox.
func (f *fixture) mintOpen(owner principal, jti string, lifetime time.Duration) string {
	f.t.Helper()
	now := f.clk.now()
	tok, err := auth.MintToken(owner.priv, auth.Claims{Iss: owner.mbx, Sub: auth.OpenSub, Aud: testAud,
		Iat: now.Add(-time.Second), Exp: now.Add(-time.Second + lifetime), Jti: jti, Scope: auth.ScopeDepositOpen})
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// mint issues a deposit token from owner to sender.
func (f *fixture) mint(owner, sender principal, mut func(*auth.Claims)) string {
	f.t.Helper()
	now := f.clk.now()
	c := auth.Claims{Iss: owner.mbx, Sub: sender.b64, Aud: testAud, Iat: now.Add(-time.Minute),
		Exp: now.Add(24 * time.Hour), Jti: "tok-" + sender.mbx[:8]}
	if mut != nil {
		mut(&c)
	}
	tok, err := auth.MintToken(owner.priv, c)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func depositBody(payload []byte) []byte {
	b, _ := json.Marshal(map[string][]byte{"payload": payload})
	return b
}
