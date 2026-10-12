package api

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Regression tests for the review of the rate-limit change (findings F1–F9).

// countingBody fails nothing; it counts what the relay reads of a body.
type countingBody struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// F1: a deposit's body is not read before the header-only checks of §5.3
// (steps 1–6): an unauthorized deposit is refused without it.
func TestDepositBodyNotReadBeforeHeaderChecks(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender, nobody := newPrincipal(1), newPrincipal(2), newPrincipal(8)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	send := func(r req) (int, int64) {
		hr := f.build(r)
		body := &countingBody{r: hr.Body}
		hr.Body = io.NopCloser(body)
		hr.RemoteAddr = hostA + ":40000"
		rec := httptest.NewRecorder()
		f.s.Handler().ServeHTTP(rec, hr)
		return rec.Code, body.n.Load()
	}
	payload := depositBody(make([]byte, 100_000))
	// No credentials at all, to a mailbox that does not exist and to one that does.
	for _, mbx := range []string{nobody.mbx, owner.mbx} {
		if code, read := send(req{method: "POST", path: "/v1/mailbox/" + mbx, body: payload}); code < 400 || read != 0 {
			t.Fatalf("unauthenticated deposit to %s: %d, %d body bytes read", mbx, code, read)
		}
	}
	// A key named, nothing signed.
	if code, read := send(req{method: "POST", path: "/v1/mailbox/" + nobody.mbx, body: payload, header: keyHeader(sender)}); code != 404 || read != 0 {
		t.Fatalf("deposit naming a key: %d, %d body bytes read", code, read)
	}
	// A declared length over the limit is refused unread.
	big := f.build(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: payload})
	big.ContentLength = f.s.depositBodyLimit() + 1
	rec := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(rec, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized declared length: %d", rec.Code)
	}
	// An authorized one is read and stored.
	if code, read := send(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: payload, signer: &sender, token: tok}); code != 201 || read != int64(len(payload)) {
		t.Fatalf("valid deposit: %d, %d body bytes read", code, read)
	}
}

// F1: bodies that are announced and then stall are capped per network and
// per process, and have to arrive within a deadline.
func TestStalledBodiesAreCapped(t *testing.T) {
	const each = 10_000
	f := newFixtureWith(t, func(c *config.Config) { c.MaxBodyBytesPerNetwork, c.MaxBodyBytes = 5*each, 1<<20 },
		func(*fixture) []Option { return []Option{WithBodyTimeout(1500 * time.Millisecond)} })
	inFlight := func() int64 {
		f.s.bodies.mu.Lock()
		defer f.s.bodies.mu.Unlock()
		return f.s.bodies.total
	}
	open := func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		// A signed-looking registration whose body never comes.
		fmt.Fprintf(c, "POST /v1/register HTTP/1.1\r\nHost: relay\r\nContent-Length: %d\r\n\r\n{", each)
		return c, bufio.NewReader(c)
	}
	var stalled []*bufio.Reader
	for i := 0; i < 5; i++ {
		_, r := open()
		stalled = append(stalled, r)
	}
	deadline := time.Now().Add(2 * time.Second)
	for inFlight() != 5*each && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// The sixth is over this network's cap: refused at once, unread.
	c, r := open()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	began := time.Now()
	resp, err := http.ReadResponse(r, nil)
	if time.Since(began) > 3*time.Second {
		t.Fatalf("the refusal took %v to arrive", time.Since(began))
	}
	if err != nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("sixth stalled body: %v %v", resp, err)
	}
	if v := f.s.rl.refused.With(limBodies).Value(); v != 1 {
		t.Fatalf("refused counter %d", v)
	}
	// The stalled ones end at the deadline and give their bytes back.
	for _, r := range stalled {
		resp, err := http.ReadResponse(r, nil)
		if err != nil || resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("stalled body after the deadline: %v %v", resp, err)
		}
	}
	f.s.bodies.mu.Lock()
	total, nets := f.s.bodies.total, len(f.s.bodies.perNet)
	f.s.bodies.mu.Unlock()
	if total != 0 || nets != 0 {
		t.Fatalf("body bytes still counted: %d (%d networks)", total, nets)
	}
	// The per-process cap, across networks.
	g := newFixture(t, func(c *config.Config) { c.MaxBodyBytesPerNetwork, c.MaxBodyBytes = 1<<20, 15_000 })
	rel, e := g.s.reserveBody(httptest.NewRecorder(), each)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := g.s.reserveBody(httptest.NewRecorder(), each); e == nil || e.code != CodeRateLimited {
		t.Fatal("process cap not enforced")
	}
	rel()
	if _, e := g.s.reserveBody(httptest.NewRecorder(), each); e != nil {
		t.Fatal("bytes not given back")
	}
}

// F2: a hold on a key does not outlive its registration on another relay
// process: before refusing, the store is asked again (every holdRecheck).
func TestHoldEndsWhenKeyRegistersOnAnotherProcess(t *testing.T) {
	opts := func() []Option {
		return []Option{WithNoMailboxHold(time.Second), WithRetryJitter(func() int { return 0 })}
	}
	f := newFixtureWith(t, func(c *config.Config) { c.AuthFailMaxPenalty = 10 * time.Minute }, func(*fixture) []Option { return opts() })
	sB := New(f.cfg, f.st, slog.New(slog.NewJSONHandler(io.Discard, nil)), metrics.New(), append(opts(), WithClock(f.clk.now))...)
	defer sB.Close()
	on := func(h http.Handler, r req) int {
		hr := f.build(r)
		hr.RemoteAddr = hostA + ":40000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, hr)
		return rec.Code
	}
	a, b := f.s.Handler(), sB.Handler()
	orphan := newPrincipal(7)
	// An orphan asks both processes every second for half an hour: both hold it, for minutes by now.
	for i := 0; i < 1800; i++ {
		on(a, collectReq(orphan))
		on(b, collectReq(orphan))
		f.clk.add(time.Second)
	}
	if on(b, collectReq(orphan)) != 429 || sB.orphans.Wait(orphan.b64, f.clk.now()) < time.Minute {
		t.Fatal("the orphan is not held on process B")
	}
	if code := on(a, registerReq(orphan)); code != 201 {
		t.Fatalf("register on A: %d", code)
	}
	if code := on(a, collectReq(orphan)); code != 200 {
		t.Fatalf("collect on A after registering: %d", code)
	}
	refused := 0
	for on(b, collectReq(orphan)) != 200 {
		if refused++; refused > int(holdRecheck/time.Second) {
			t.Fatalf("still refused on process B %d s after registering on A", refused)
		}
		f.clk.add(time.Second)
	}
	if sB.orphans.Len() != 0 {
		t.Fatal("hold not cleared on process B")
	}
	// A key that still has no mailbox costs one store lookup per recheck, not per request.
	other := newPrincipal(8)
	for i := 0; i < 20; i++ {
		on(b, collectReq(other))
	}
	if on(b, collectReq(other)) != 429 {
		t.Fatal("a key without a mailbox is no longer held")
	}
}

type countingGuard struct {
	ReplayGuard
	n atomic.Int64
}

func (g *countingGuard) Check(sr auth.SignedRequest, now time.Time) error {
	g.n.Add(1)
	return g.ReplayGuard.Check(sr, now)
}

// F3: on a penalised network the flood guard comes between the signature
// check and the replay record: what one network can write to the replay
// store is bounded by its flood guard, penalised or not.
func TestReplayRecordsBoundedByFloodGuard(t *testing.T) {
	g := &countingGuard{ReplayGuard: auth.NewReplayCache(100_000)}
	f := newFixtureWith(t, func(c *config.Config) {
		failBudget(1)(c)
		c.RateIPPerSec, c.RateIPBurst = 0.01, 5
	}, func(*fixture) []Option { return []Option{WithReplayGuard(g)} })
	f.expectFrom(hostA, req{method: "GET", path: "/v1/mailbox"}, 401, CodeSignatureInvalid) // penalised; one flood token used
	g.n.Store(0)
	limited := 0
	for i := byte(0); i < 50; i++ { // properly signed, each under a fresh key
		if code, _, _ := f.from(hostA, collectReq(newPrincipal(100+i))); code == 429 {
			limited++
		}
	}
	if g.n.Load() != 4 || limited != 46 {
		t.Fatalf("replay records written: %d (flood guard had 4 left); refused: %d", g.n.Load(), limited)
	}
}

// F4: a client that sends each request twice (a retry bug) is one unit to
// its address, not one per replay; the address stays in budget and new
// mailboxes, rotations and claim fetches of its neighbours go on.
func TestReplayingClientCostsItsAddressOneUnit(t *testing.T) {
	f := newFixture(t, failBudget(3))
	vault := newPrincipal(1)
	f.register(vault)
	for i := 0; i < 200; i++ {
		r := collectReq(vault)
		r.at = f.sigTime()
		f.expectFrom(hostA, r, 200, "")
		f.expectFrom(hostA, r, 401, CodeReplayDetected)
		f.clk.add(500 * time.Millisecond)
	}
	if f.s.rl.charged.Value() != 2 || f.s.fails.Exhausted(f.clk.now()) != 0 { // 100 s: two windows of a minute
		t.Fatalf("200 replays by one key: %d units charged, penalised networks %d", f.s.rl.charged.Value(), f.s.fails.Exhausted(f.clk.now()))
	}
	f.expectFrom(hostA, registerReq(newPrincipal(30)), 201, "")
	f.expectFrom(hostA, req{method: "GET", path: "/v1/claim/aaaaaaaaaaaaaaaaaaaaaaaaaa"}, 404, CodeClaimUnknown)
}

// F4: a burst of failures does not hold an address for long: by default
// the debt is capped at one minute.
func TestPenaltyEndsAMinuteAfterTheLastFailure(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		d := config.Defaults()
		c.RateAuthFailPerSec, c.RateAuthFailBurst, c.AuthFailMaxPenalty = d.RateAuthFailPerSec, d.RateAuthFailBurst, d.AuthFailMaxPenalty
		c.RateTricklePerSec, c.RateTrickleBurst = d.RateTricklePerSec, d.RateTrickleBurst
	})
	for i := 0; i < 700; i++ {
		f.from(hostA, req{method: "GET", path: "/v1/mailbox", header: keyHeader(newPrincipal(9))})
	}
	if f.s.fails.Wait(hostA, f.clk.now()) != time.Minute {
		t.Fatalf("after 700 failures: out of budget for %v", f.s.fails.Wait(hostA, f.clk.now()))
	}
	// Meanwhile new mailboxes still get through, at the trickle (3, then one per 10 s).
	served := 0
	for i := byte(0); i < 12; i++ {
		if code, _, _ := f.from(hostA, registerReq(newPrincipal(60+i))); code == 201 {
			served++
		}
		f.clk.add(5 * time.Second)
	}
	if served < 8 || served > 9 {
		t.Fatalf("new mailboxes on a penalised address in a minute: %d", served)
	}
	f.clk.add(time.Second)
	if f.s.fails.Wait(hostA, f.clk.now()) != 0 {
		t.Fatal("still penalised 61 s after the last failure")
	}
}

// fakeTimers stands in for the long-poll deadline timers: they fire when
// the test says so.
type fakeTimers struct {
	mu sync.Mutex
	ch []chan time.Time
}

func (ft *fakeTimers) timer(time.Duration) (<-chan time.Time, func()) {
	c := make(chan time.Time, 1)
	ft.mu.Lock()
	ft.ch = append(ft.ch, c)
	ft.mu.Unlock()
	return c, func() {}
}

func (ft *fakeTimers) fire() {
	ft.mu.Lock()
	for _, c := range ft.ch {
		select {
		case c <- time.Time{}:
		default:
		}
	}
	ft.ch = nil
	ft.mu.Unlock()
}

// F5: parked collects (real ones: wait=25, held open) are capped per
// network and per process, and a refused one is told to come back.
func TestParkedCollectorsAreCapped(t *testing.T) {
	ft := &fakeTimers{}
	f := newFixtureWith(t, func(c *config.Config) { c.MaxCollectorsPerNetwork, c.MaxCollectors = 3, 5 },
		func(*fixture) []Option {
			return []Option{WithTimer(ft.timer), WithRetryJitter(func() int { return 2 })}
		})
	vaults := make([]principal, 8)
	for i := range vaults {
		vaults[i] = newPrincipal(byte(10 + i))
		f.register(vaults[i])
	}
	park := func(p principal) req { return req{method: "GET", path: "/v1/mailbox?wait=25", signer: &p} }
	var wg sync.WaitGroup
	codes := make([]int, len(vaults))
	parkFrom := func(i int, addr string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _, _ = f.from(addr, park(vaults[i]))
		}()
	}
	waitParked := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for f.s.hub.collectors() != n {
			if time.Now().After(deadline) {
				t.Fatalf("parked collectors: %d, want %d", f.s.hub.collectors(), n)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	for i := 0; i < 3; i++ {
		parkFrom(i, hostA)
	}
	waitParked(3)
	// The fourth from the same network is over its cap.
	_, e, h := f.from(hostA, park(vaults[3]))
	if e.Code != CodeRateLimited || e.RetryAfter != 1+2 || h.Get("Retry-After") != "3" {
		t.Fatalf("over the network cap: %+v", e)
	}
	// Another network still has room, up to the process cap.
	parkFrom(4, hostB)
	parkFrom(5, hostB)
	waitParked(5)
	if _, e, _ := f.from("203.0.113.30", park(vaults[6])); e.Code != CodeRateLimited {
		t.Fatalf("over the process cap: %+v", e)
	}
	if v := f.s.rl.refused.With(limCollectors).Value(); v != 2 {
		t.Fatalf("refused counter %d", v)
	}
	// A deposit wakes its collector; the deadline ends the others; the slots come back.
	tok := f.mint(vaults[0], vaults[7], nil)
	f.expectFrom(hostB, depositReq(vaults[0], vaults[7], tok, "wake"), 201, "")
	waitParked(4)
	ft.fire()
	wg.Wait()
	for i, c := range codes[:6] {
		if i != 3 && c != 200 {
			t.Fatalf("parked collect %d ended with %d", i, c)
		}
	}
	waitParked(0)
	f.expectFrom(hostA, collectReq(vaults[3]), 200, "")
}

// F6: a full table of held keys charges nobody: an orphan it has no room
// for is not held, and its repeats are not charged to its network.
func TestFullTablesChargeNobody(t *testing.T) {
	f := newFixture(t, failBudget(3))
	f.s.orphans = ratelimit.NewHold(time.Second, time.Minute, 1)
	f.s.onceSeen = ratelimit.NewRecent(time.Minute, 1)
	first, second := newPrincipal(7), newPrincipal(8)
	f.expectFrom(hostB, collectReq(first), 404, CodeMailboxUnknown) // fills the table; one unit to hostB
	for i := 0; i < 10; i++ {
		f.expectFrom(hostA, collectReq(second), 404, CodeMailboxUnknown)
	}
	// Same for the table of keys charged once (stale timestamps, replays).
	vaults := []principal{newPrincipal(20), newPrincipal(21)}
	for _, v := range vaults {
		f.register(v)
	}
	for i := 0; i < 10; i++ {
		for _, v := range vaults {
			r := collectReq(v)
			r.at = f.sigTime().Add(-5 * time.Minute)
			f.expectFrom(hostA, r, 401, CodeTimestampStale)
		}
	}
	if f.s.fails.Exhausted(f.clk.now()) != 0 || f.s.rl.charged.Value() != 2 { // first orphan; the first stale key
		t.Fatalf("untracked keys were charged to their network: %d units, %d penalised", f.s.rl.charged.Value(), f.s.fails.Exhausted(f.clk.now()))
	}
}

// F7, F8: one peer that is gone does not stop a sender's deposits to its
// other peers; the refusal for the gone one is told only to the sender;
// and a failing deposit cannot be re-sent by someone else to run the
// sender's budget up.
func TestRefusedDepositsArePerPeerAndForTheSenderOnly(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		d := config.Defaults()
		c.RateKeyFailPerSec, c.RateKeyFailBurst = d.RateKeyFailPerSec, d.RateKeyFailBurst
		failBudget(3)(c)
	}, func(*fixture) []Option { return []Option{WithPairFailBudget(pairFailRate, pairFailBurst)} })
	owner, vault, gone := newPrincipal(1), newPrincipal(2), newPrincipal(8)
	f.register(owner)
	f.register(vault)
	tok := f.mint(owner, vault, nil)
	for i := 0; i < pairFailBurst; i++ {
		f.expectFrom(hostA, depositReq(gone, vault, tok, "x"), 404, CodeMailboxUnknown)
	}
	e := f.expectFrom(hostA, depositReq(gone, vault, tok, "x"), 429, CodeRateLimited)
	if e.RetryAfter != 10 {
		t.Fatalf("retry_after %d", e.RetryAfter)
	}
	// The healthy peer is not affected (the unlock-time deposit per device is sent once).
	f.expectFrom(hostA, depositReq(owner, vault, tok, "y"), 201, "")
	// Someone naming the sender's key without its signature learns nothing:
	// the answer is what any unsigned deposit there gets.
	f.expectFrom(hostB, req{method: "POST", path: "/v1/mailbox/" + gone.mbx, body: depositBody([]byte("x")), header: keyHeader(vault)}, 404, CodeMailboxUnknown)
	h := http.Header{}
	auth.SetHeaders(h, vault.priv, "POST", "/v1/elsewhere", f.sigTime(), auth.BodyHash(nil))
	f.expectFrom(hostB, req{method: "POST", path: "/v1/mailbox/" + gone.mbx, body: depositBody([]byte("x")), header: h, token: tok}, 404, CodeMailboxUnknown)
	// A captured failing deposit, sent again: a replay, charged to nobody's key.
	f.clk.add(time.Minute)
	captured := depositReq(gone, vault, tok, "captured")
	captured.at = f.sigTime()
	f.expectFrom(hostA, captured, 404, CodeMailboxUnknown)
	before := f.s.pairFails.Wait(pairKey(vault.b64, gone.mbx), f.clk.now().Add(-time.Hour))
	for i := 0; i < 20; i++ {
		f.expectFrom(hostB, captured, 404, CodeMailboxUnknown)
	}
	if after := f.s.pairFails.Wait(pairKey(vault.b64, gone.mbx), f.clk.now().Add(-time.Hour)); after != before {
		t.Fatalf("replays of a captured deposit ran the sender's budget up: %v -> %v", before, after)
	}
	f.expectFrom(hostA, depositReq(gone, vault, tok, "x"), 404, CodeMailboxUnknown) // still within its budget
}

// The burst of the flood guard: every long-poll of a 1,000-vault host
// re-issued in the same instant, twice over, with nothing refilled in
// between; and a 1,000-vault host unlocking all at once (register, collect
// and one deposit each: 3,000 requests in one instant).
func TestFloodGuardBurstCarriesAHostAtOnce(t *testing.T) {
	skipOnOtherStores(t)
	if raceEnabled || testing.Short() {
		t.Skip("4,000 signed requests: not under the race detector")
	}
	s := newSim(t, newLimits, 9, true)
	f := s.f
	const n = 1000
	vaults := make([]principal, n)
	for i := range vaults {
		vaults[i] = simPrincipal("vault", i)
		if _, err := f.st.Register(t.Context(), vaults[i].mbx, vaults[i].pub); err != nil {
			t.Fatal(err)
		}
	}
	refused := 0
	for round := 0; round < 2; round++ { // the clock does not move
		for i := range vaults {
			if code, _, _ := s.do(simHost, collectReq(vaults[i])); code != 200 {
				refused++
			}
		}
	}
	if refused != 0 {
		t.Fatalf("2,000 polls in one instant: %d refused", refused)
	}
	f.clk.add(25 * time.Second) // one long-poll period: the bucket is full again (200/s)
	for i := range vaults {
		tok := f.mint(vaults[(i+1)%n], vaults[i], nil)
		for _, r := range []req{registerReq(vaults[i]), collectReq(vaults[i]), depositReq(vaults[(i+1)%n], vaults[i], tok, "unlocked")} {
			if code, _, _ := s.do(simHost, r); code >= 400 {
				refused++
			}
		}
	}
	if refused != 0 {
		t.Fatalf("1,000 vaults unlocking in one instant (3,000 requests): %d refused", refused)
	}
	if code, _, _ := s.do(simHost, collectReq(vaults[0])); code == 200 {
		// 4,000 is the burst: 3,000 used, so this one still fits.
	} else {
		t.Fatalf("after the mass unlock: %d", code)
	}
}
