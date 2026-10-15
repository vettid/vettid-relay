package api

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func depositReq(to, signer principal, tok, payload string) req {
	return req{method: "POST", path: "/v1/mailbox/" + to.mbx, body: depositBody([]byte(payload)), signer: &signer, token: tok}
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
// they come from, and nobody else's are: many keys behind one address (a
// vault host) are not one bucket.
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
		t.Fatalf("%d %q retry_after %d, header %q", code, e.Code, e.RetryAfter, h.Get("Retry-After"))
	}
	// Another key behind the same address is untouched.
	f.expectFrom(hostA, collectReq(b), 200, "")
	// Every owner route, registration and deletion draw on it.
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
	f.expectFrom(hostB, depositReq(a, stranger, tok, "x"), 201, "")
}

// The flood guard: per client network, before anything is parsed; IPv6
// clients are one network per /64. It is the only limit keyed on a network
// that an authenticated request for an existing mailbox can meet.
func TestFloodGuard(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateIPPerSec, c.RateIPBurst = 2, 3 })
	a := newPrincipal(1)
	f.register(a)
	for i := 0; i < 3; i++ {
		f.expectFrom("2001:db8:1:2::"+strconv.Itoa(i+1), collectReq(a), 200, "")
	}
	e := f.expectFrom("2001:db8:1:2::9", collectReq(a), 429, CodeRateLimited)
	if e.RetryAfter != 1 {
		t.Fatalf("retry_after %d", e.RetryAfter)
	}
	f.expectFrom("2001:db8:1:3::1", collectReq(a), 200, "") // the next /64
	f.expectFrom(hostA, req{method: "POST", path: "/v1/whatever", body: []byte("x")}, 404, CodeNotFound)
	if got := f.s.rl.refused.With(limAddress).Value(); got != 1 {
		t.Fatalf("refused counter %d", got)
	}
}

// countingGuard counts replay records.
type countingGuard struct {
	ReplayGuard
	n atomic.Int64
}

func (g *countingGuard) Check(sr auth.SignedRequest, now time.Time) error {
	g.n.Add(1)
	return g.ReplayGuard.Check(sr, now)
}

// The flood guard comes before everything a request can cost: signature
// checks, replay records, store reads. A request it refuses writes no
// replay record.
func TestFloodGuardBoundsReplayRecords(t *testing.T) {
	g := &countingGuard{ReplayGuard: auth.NewReplayCache(100_000)}
	f := newFixtureWith(t, func(c *config.Config) { c.RateIPPerSec, c.RateIPBurst = 0.01, 5 },
		func(*fixture) []Option { return []Option{WithReplayGuard(g)} })
	limited := 0
	for i := byte(0); i < 50; i++ { // properly signed registrations, each of a fresh key
		if code, _, _ := f.from(hostA, registerReq(newPrincipal(100+i))); code == 429 {
			limited++
		}
	}
	if g.n.Load() != 5 || limited != 45 {
		t.Fatalf("replay records written: %d (flood guard burst 5); refused: %d", g.n.Load(), limited)
	}
}

// New mailboxes are limited per address; registering an existing one again
// (every vault does at unlock) is not, however many do it at once.
func TestRegistrationBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateRegisterPerSec, c.RateRegisterBurst = 0.5, 2 })
	a, b, c, d := newPrincipal(1), newPrincipal(2), newPrincipal(3), newPrincipal(4)
	f.expectFrom(hostA, registerReq(a), 201, "")
	f.expectFrom(hostA, registerReq(b), 201, "")
	e := f.expectFrom(hostA, registerReq(c), 429, CodeRateLimited)
	if e.RetryAfter != 2 {
		t.Fatalf("retry_after %d", e.RetryAfter)
	}
	for i := 0; i < 20; i++ { // re-registration of an existing mailbox: free
		f.expectFrom(hostA, registerReq(a), 200, "")
		f.expectFrom(hostA, registerReq(b), 200, "")
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
	for i := 0; i < 5; i++ {
		f.expectFrom(hostB, depositReq(owner, thief, tok, "stolen"), 401, CodeSignatureInvalid)
	}
	f.expectFrom(hostA, depositReq(owner, sender, tok, "1"), 201, "")
	f.expectFrom(hostA, depositReq(owner, sender, tok, "2"), 201, "")
	f.expectFrom(hostA, depositReq(owner, sender, tok, "3"), 429, CodeRateLimited)
}

// countingBody counts what the relay reads of a body.
type countingBody struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// A deposit's body is read only once its token has verified (§5.3 steps
// 1–6 need only headers): an unauthorized deposit is refused unread, and
// the connection is closed rather than waited on.
func TestDepositBodyNotReadBeforeHeaderChecks(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender, nobody := newPrincipal(1), newPrincipal(2), newPrincipal(8)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	send := func(r req) (int, int64, string) {
		hr := f.build(r)
		body := &countingBody{r: hr.Body}
		hr.Body = io.NopCloser(body)
		hr.RemoteAddr = hostA + ":40000"
		rec := httptest.NewRecorder()
		f.s.Handler().ServeHTTP(rec, hr)
		return rec.Code, body.n.Load(), rec.Header().Get("Connection")
	}
	payload := depositBody(make([]byte, 100_000))
	for name, r := range map[string]req{
		"no credentials, unknown mailbox":  {method: "POST", path: "/v1/mailbox/" + nobody.mbx, body: payload},
		"no credentials, existing mailbox": {method: "POST", path: "/v1/mailbox/" + owner.mbx, body: payload},
		"signed, unknown mailbox":          {method: "POST", path: "/v1/mailbox/" + nobody.mbx, body: payload, signer: &sender, token: tok},
		"signed, bad token":                {method: "POST", path: "/v1/mailbox/" + owner.mbx, body: payload, signer: &sender, token: "garbage"},
	} {
		if code, read, conn := send(r); code < 400 || read != 0 || conn != "close" {
			t.Errorf("%s: %d, %d body bytes read, Connection %q", name, code, read, conn)
		}
	}
	// A declared length over the limit is refused unread.
	big := f.build(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: payload})
	big.ContentLength = f.s.depositBodyLimit() + 1
	rec := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(rec, big)
	if rec.Code != http.StatusRequestEntityTooLarge || rec.Header().Get("Connection") != "close" {
		t.Fatalf("oversized declared length: %d, Connection %q", rec.Code, rec.Header().Get("Connection"))
	}
	// An authorized one is read and stored, on a connection that stays open.
	if code, read, conn := send(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: payload, signer: &sender, token: tok}); code != 201 || read != int64(len(payload)) || conn != "" {
		t.Fatalf("valid deposit: %d, %d body bytes read, Connection %q", code, read, conn)
	}
}

// A refused request whose body never comes is answered at once (over a
// real connection): the relay does not wait for the body it will not read.
func TestRefusedUnreadRequestIsAnsweredAtOnce(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateIPPerSec, c.RateIPBurst = 0.01, 2 })
	nobody := newPrincipal(8)
	ask := func(what string) {
		t.Helper()
		c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// Announces a deposit body and sends none of it. 100 KiB: under the
		// 256 KiB above which net/http closes the connection by itself,
		// so that it is this relay's Connection: close that is tested.
		fmt.Fprintf(c, "POST /v1/mailbox/%s HTTP/1.1\r\nHost: relay\r\nContent-Length: %d\r\n\r\n", nobody.mbx, 100<<10)
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		began := time.Now()
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("%s: no answer within 3 s: %v", what, err)
		}
		if time.Since(began) > time.Second || !resp.Close {
			t.Fatalf("%s: answered after %v, connection closed: %v", what, time.Since(began), resp.Close)
		}
		if want := map[string]int{"header checks": 404, "flood guard": 429}[what]; resp.StatusCode != want {
			t.Fatalf("%s: %d", what, resp.StatusCode)
		}
	}
	ask("header checks")
	ask("header checks")
	ask("flood guard") // the third from this address
}

// The measurement the limits are sized from: per limiter, what was allowed
// and refused and how full the busiest bucket got; the busiest network's
// and the busiest key's requests in the minute; collectors. No client is
// named anywhere.
func TestLimiterMetricsAndReport(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 4 }, &logs)
	a, b := newPrincipal(1), newPrincipal(2)
	f.register(a)
	f.register(b)
	for i := 0; i < 5; i++ {
		f.from(hostA, collectReq(a)) // three served, two refused by a's bucket
	}
	f.expectFrom(hostA, collectReq(b), 200, "")
	f.expectFrom(hostB, collectReq(b), 200, "")
	f.s.reportLimits()
	var out strings.Builder
	f.reg.WriteTo(&out)
	for _, want := range []string{
		`relay_ratelimit_allowed_total{limiter="key"} 7`,
		`relay_ratelimit_refused_total{limiter="key"} 2`,
		`relay_ratelimit_peak_permille{limiter="key"} 1000`,
		`relay_ratelimit_allowed_total{limiter="address"} 9`,
		`relay_ratelimit_refused_total{limiter="address"} 0`,
		`relay_ratelimit_refused_total{limiter="register"} 0`,
		`relay_ratelimit_busiest_per_minute{limiter="address"} 6`,
		`relay_ratelimit_busiest_per_minute{limiter="key"} 6`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	line := lastLine(t, logs.String(), `"msg":"rate limits"`)
	for _, want := range []string{`"level":"INFO"`, `"key_refused":2`, `"key_peak":1000`, `"address_refused":0`, `"address_busiest_per_min":6`,
		`"addresses_seen":3`, `"keys_seen":2`, `"key_busiest_per_min":6`, `"addresses_refused":0`, `"register_refused":0`, `"collectors":0`, `"parked":0`, `"ws_sessions":0`} {
		if !strings.Contains(line, want) {
			t.Errorf("report line lacks %s: %s", want, line)
		}
	}
	for _, leak := range []string{hostA, hostB, a.b64, a.mbx, b.b64} {
		if strings.Contains(out.String(), leak) || strings.Contains(line, leak) {
			t.Fatalf("metrics or report name a client: %q", leak)
		}
	}
	// The tallies are per minute.
	f.s.reportLimits()
	if line := lastLine(t, logs.String(), `"msg":"rate limits"`); !strings.Contains(line, `"address_busiest_per_min":0`) || !strings.Contains(line, `"key_refused":0`) {
		t.Fatalf("second minute: %s", line)
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

// An unlock storm at the conservative flood guard (100/s, burst 300). A
// vault that is unlocked sends three requests: it registers its (existing)
// key, starts collecting, and deposits to a device. 100 vaults of one host
// can do that in the same instant; the 101st is refused with a 429 and
// retry_after, and gets through when it comes back as told (relayclient
// waits retry_after and tries again, three times in all).
func TestUnlockStormAtTheFloodGuard(t *testing.T) {
	skipOnOtherStores(t)
	f := newFixture(t, newLimits)
	h := f.s.Handler()
	do := func(r req) (int, int) {
		hr := f.build(r)
		hr.RemoteAddr = simHost + ":40000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, hr)
		var e errorBody
		json.Unmarshal(rec.Body.Bytes(), &e)
		return rec.Code, e.RetryAfter
	}
	const n = 150
	vaults := make([]principal, n)
	for i := range vaults {
		vaults[i] = simPrincipal("vault", i)
		if _, err := f.st.Register(t.Context(), vaults[i].mbx, vaults[i].pub); err != nil {
			t.Fatal(err)
		}
	}
	unlock := func(i int) (served int, retryAfter int) {
		tok := f.mint(vaults[(i+1)%n], vaults[i], nil)
		for _, r := range []req{registerReq(vaults[i]), collectReq(vaults[i]), depositReq(vaults[(i+1)%n], vaults[i], tok, "unlocked")} {
			code, ra := do(r)
			if code == 429 {
				return served, ra
			}
			if code >= 400 {
				t.Fatalf("vault %d: %d", i, code)
			}
			served++
		}
		return served, 0
	}
	whole, firstRefused, retryAfter := 0, -1, 0
	for i := 0; i < n; i++ { // the clock does not move: one instant
		served, ra := unlock(i)
		if served == 3 {
			whole++
		} else if firstRefused < 0 {
			firstRefused, retryAfter = i, ra
		}
	}
	burst := config.Defaults().RateIPBurst
	t.Logf("%d vaults unlocking in one instant behind one address: %d completed (burst %d / 3 requests); the first refused got 429 with retry_after %d", n, whole, burst, retryAfter)
	if whole != burst/3 || firstRefused != burst/3 || retryAfter != 1 {
		t.Fatalf("completed %d (want %d), first refused %d, retry_after %d", whole, burst/3, firstRefused, retryAfter)
	}
	if v := f.s.rl.refused.With(limRegister).Value(); v != 0 {
		t.Fatalf("re-registering existing mailboxes drew on the new-mailbox budget: %d refused", v)
	}
	// One second later 100 more requests fit: the refused vault's retry succeeds.
	f.clk.add(time.Second)
	if served, _ := unlock(firstRefused); served != 3 {
		t.Fatalf("the refused vault's retry after retry_after: %d of 3 served", served)
	}
}

// Small bodies (register, rotate, denylist, claim) are read before the
// request can be authenticated, so they have a deadline: one that is
// announced and then stalls is released, with the connection closed,
// instead of holding it until the server's read timeout.
func TestStalledSmallBodyIsReleased(t *testing.T) {
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithSmallBodyTimeout(300 * time.Millisecond)} })
	before := runtime.NumGoroutine()
	const n = 50
	var conns []net.Conn
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// A registration that announces 1,000 bytes and sends one.
		fmt.Fprint(c, "POST /v1/register HTTP/1.1\r\nHost: relay\r\nContent-Length: 1000\r\n\r\n{")
		conns = append(conns, c)
	}
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		began := time.Now()
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != http.StatusBadRequest || !resp.Close {
			t.Fatalf("stalled small body: %v %v", resp, err)
		}
		if time.Since(began) > 2*time.Second {
			t.Fatalf("released after %v", time.Since(began))
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+5 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines: %d before, %d after the stalled bodies were released", before, runtime.NumGoroutine())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if smallBodyTimeout != 10*time.Second {
		t.Fatalf("default deadline %v", smallBodyTimeout)
	}
}

// The deadline is cleared once a small body has been read: an honest
// client's keep-alive connection is good for the next request, also after
// longer than the deadline.
func TestSmallBodyDeadlineLeavesKeepAliveConnectionsAlone(t *testing.T) {
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithSmallBodyTimeout(200 * time.Millisecond)} })
	p := newPrincipal(1)
	c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	for i, want := range []int{201, 200, 200} {
		hr := f.build(registerReq(p))
		if err := hr.Write(c); err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(br, hr)
		if err != nil || resp.StatusCode != want || resp.Close {
			t.Fatalf("registration %d on one connection: %v %v", i+1, resp, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(350 * time.Millisecond) // longer than the body deadline
	}
	// A long-poll on the same connection is not cut short by it either.
	hr := f.build(req{method: "GET", path: "/v1/mailbox?wait=1", signer: &p})
	if err := hr.Write(c); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err := http.ReadResponse(br, hr); err != nil || resp.StatusCode != 200 {
		t.Fatalf("long-poll after registrations on the same connection: %v %v", resp, err)
	}
}
