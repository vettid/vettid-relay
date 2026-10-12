package api

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
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

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	"github.com/vettid/vettid-relay/internal/store"
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

// N1/F1: a body counts against the caps as it arrives, never by what it
// announces; it has to keep arriving; and the pools are separate, so that
// stalled unauthenticated bodies cannot take the place of authenticated
// ones.
func TestBodiesCountAsTheyArriveAndStalledOnesEnd(t *testing.T) {
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithBodyPace(300*time.Millisecond, time.Second)} })
	open := func(path string, announce, send int) (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: relay\r\nContent-Length: %d\r\n\r\n", path, announce)
		c.Write(make([]byte, send))
		return c, bufio.NewReader(c)
	}
	// 100 registrations announce 16 KiB each (1.6 MiB in all) and send one byte.
	var stalled []*bufio.Reader
	for i := 0; i < 100; i++ {
		_, r := open("/v1/register", smallBodyLimit, 1)
		stalled = append(stalled, r)
	}
	deadline := time.Now().Add(2 * time.Second)
	var held int64
	for time.Now().Before(deadline) {
		if held, _ = f.s.smallBodies.inFlight(); held >= 100*bodyChunk {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if held != 100*bodyChunk {
		t.Fatalf("100 stalled bodies announcing %d bytes each hold %d bytes (want at most one chunk each)", smallBodyLimit, held)
	}
	// They end when nothing arrives, and give their bytes back.
	for _, r := range stalled {
		resp, err := http.ReadResponse(r, nil)
		if err != nil || resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("stalled body: %v %v", resp, err)
		}
	}
	if total, nets := f.s.smallBodies.inFlight(); total != 0 || nets != 0 {
		t.Fatalf("body bytes still counted: %d (%d networks)", total, nets)
	}
	// A body that keeps arriving, slowly, is read: the pace is about progress.
	c, r := open("/v1/register", 600, 0)
	for i := 0; i < 6; i++ {
		c.Write(make([]byte, 100))
		time.Sleep(100 * time.Millisecond)
	}
	if resp, err := http.ReadResponse(r, nil); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("slow but steady body: %v %v", resp, err) // read whole, then: not signed
	}
}

func TestBodyPools(t *testing.T) {
	p := newBodyPool(100, 40)
	reader := func(net string) *bodyRead {
		b := &bodyRead{net: net}
		if !p.enter(b) {
			t.Fatal("enter")
		}
		return b
	}
	a, a2, b, c := reader("a"), reader("a"), reader("b"), reader("c")
	if !p.grow(a, 30) || !p.grow(a2, 10) || p.grow(a, 1) {
		t.Fatal("a network's own share")
	}
	if !p.grow(b, 40) || !p.grow(c, 20) {
		t.Fatal("room for the others")
	}
	// The pool is full (100). A newcomer from a fourth network is not
	// refused: the heaviest network's largest body is ended instead.
	ended := false
	a.cancel = func() { ended = true }
	d := reader("d")
	if !p.grow(d, 10) || !ended || !a.shed || a.held != 0 {
		t.Fatalf("newcomer refused, or nobody shed (ended %v)", ended)
	}
	if total, readers := p.inFlight(); total != 10+40+20+10 || readers != 5 {
		t.Fatalf("after the shed: %d bytes, %d readers", total, readers)
	}
	// The heaviest network itself gets no such favour.
	if p.grow(b, 30) {
		t.Fatal("the heaviest network grew past the pool's cap by shedding others")
	}
	for _, r := range []*bodyRead{a, a2, b, c, d} {
		p.leave(r)
	}
	if total, readers := p.inFlight(); total != 0 || readers != 0 || len(p.nets) != 0 {
		t.Fatalf("after all left: %d bytes, %d readers", total, readers)
	}
	if p.takePeak() != 1000 || p.takePeak() != 0 {
		t.Fatal("peak")
	}
	// One network cannot have more than maxBodyReaders bodies in the reading.
	for i := 0; i < maxBodyReaders; i++ {
		reader("x")
	}
	if p.enter(&bodyRead{net: "x"}) || !p.enter(&bodyRead{net: "y"}) {
		t.Fatal("readers per network")
	}
	// The relay's pools are separate: deposits being read before
	// authentication, deposits whose token has verified, small bodies.
	f := newFixture(t, nil)
	if f.s.openBodies == f.s.keyedBodies || f.s.smallBodies == f.s.openBodies {
		t.Fatal("pools are shared")
	}
	d0 := config.Defaults()
	if d0.MaxOpenBodyBytesPerNetwork*8 > d0.MaxOpenBodyBytes || d0.MaxOpenBodyBytes+d0.MaxBodyBytes+smallBodyPool > 36<<20 {
		t.Fatalf("body budget: open %d (per network %d), keyed %d", d0.MaxOpenBodyBytes, d0.MaxOpenBodyBytesPerNetwork, d0.MaxBodyBytes)
	}
}

// N1: when the pool for small bodies is full of stalled ones, an honest
// registration from another network is still read: a stalled body of the
// network holding the most is ended (429) to make room.
func TestFullBodyPoolShedsTheHeaviestNetwork(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) { c.TrustProxy = true },
		func(*fixture) []Option { return []Option{WithDrainTimeout(200 * time.Millisecond)} })
	f.s.smallBodies = newBodyPool(3*bodyChunk, 2*bodyChunk)
	stall := func(from string) *bufio.Reader {
		c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		fmt.Fprintf(c, "POST /v1/register HTTP/1.1\r\nHost: relay\r\nX-Forwarded-For: %s\r\nContent-Length: %d\r\n\r\n{", from, smallBodyLimit)
		return bufio.NewReader(c)
	}
	heavy := []*bufio.Reader{stall("198.51.100.1"), stall("198.51.100.1")}
	stall("198.51.100.2")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if total, _ := f.s.smallBodies.inFlight(); total == 3*bodyChunk {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the pool did not fill")
		}
		time.Sleep(5 * time.Millisecond)
	}
	honest := newPrincipal(1)
	r := registerReq(honest)
	r.header = http.Header{"X-Forwarded-For": {"203.0.113.9"}}
	if code, b := f.do(r); code != 201 {
		t.Fatalf("honest registration with the pool full: %d %s", code, b)
	}
	// One of the heaviest network's stalled bodies was ended, at once.
	got := make(chan int, 2)
	for _, h := range heavy {
		go func() {
			if resp, err := http.ReadResponse(h, nil); err == nil {
				got <- resp.StatusCode
			}
		}()
	}
	select {
	case code := <-got:
		if code != http.StatusTooManyRequests {
			t.Fatalf("the shed body was answered %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no body of the heaviest network was ended")
	}
}

// F2: a hold on a key does not outlive its registration on another relay
// process: before refusing, the store is asked again (every quarter of the
// hold: at most 15 s with the default cap of a minute).
func TestHoldEndsWhenKeyRegistersOnAnotherProcess(t *testing.T) {
	opts := func() []Option {
		return []Option{WithNoMailboxHold(time.Second), WithRetryJitter(func() int { return 0 })}
	}
	f := newFixtureWith(t, nil, func(*fixture) []Option { return opts() })
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
	on(b, collectReq(orphan)) // if a hold had just ended, this starts the next (a minute)
	if on(b, collectReq(orphan)) != 429 {
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
		if refused++; refused > 15 {
			t.Fatalf("still refused on process B %d s after registering on A", refused)
		}
		f.clk.add(time.Second)
	}
	if sB.orphans.Wait(orphan.b64, f.clk.now()) != 0 {
		t.Fatal("still held on process B")
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

// parkedFixture is a relay whose long-poll deadlines fire when the test
// says so, with small collector caps.
type parkedFixture struct {
	*fixture
	ft    *fakeTimers
	wg    sync.WaitGroup
	mu    sync.Mutex
	codes map[string]int // by mailbox id
}

func newParkedFixture(t *testing.T, perNetwork, inAll int) *parkedFixture {
	pf := &parkedFixture{ft: &fakeTimers{}, codes: map[string]int{}}
	pf.fixture = newFixtureWith(t, func(c *config.Config) { c.MaxCollectorsPerNetwork, c.MaxCollectors = perNetwork, inAll },
		func(*fixture) []Option {
			return []Option{WithTimer(pf.ft.timer), WithRetryJitter(func() int { return 2 })}
		})
	return pf
}

func parkReq(p principal) req { return req{method: "GET", path: "/v1/mailbox?wait=25", signer: &p} }

// park issues a long-poll that stays open, in the background.
func (pf *parkedFixture) park(addr string, p principal) {
	pf.wg.Add(1)
	go func() {
		defer pf.wg.Done()
		code, _, _ := pf.from(addr, parkReq(p))
		pf.mu.Lock()
		pf.codes[p.mbx] = code
		pf.mu.Unlock()
	}()
}

func (pf *parkedFixture) waitParked(n int) {
	pf.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for pf.s.hub.collectors() != n {
		if time.Now().After(deadline) {
			pf.t.Fatalf("parked collectors: %d, want %d", pf.s.hub.collectors(), n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (pf *parkedFixture) code(p principal) int {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	return pf.codes[p.mbx]
}

// F5/N2: parked collects (real ones: wait=25, held open) are capped per
// network and per process, but nobody can use the caps to shut a mailbox
// out: a mailbox's first collector is always admitted (room is made by
// shedding one of the heaviest network's), and a collect that does not
// park is never refused by them.
func TestParkedCollectorsAreCappedWithoutLockingAnyoneOut(t *testing.T) {
	pf := newParkedFixture(t, 4, 6)
	f := pf.fixture
	vaults := make([]principal, 10)
	for i := range vaults {
		vaults[i] = newPrincipal(byte(10 + i))
		f.register(vaults[i])
	}
	// Two addresses fill the process: four mailboxes from one, two from another.
	for i := 0; i < 4; i++ {
		pf.park(hostA, vaults[i])
	}
	pf.waitParked(4)
	_, e, h := f.from(hostA, parkReq(vaults[4]))
	if e.Code != CodeRateLimited || e.RetryAfter != 1+2 || h.Get("Retry-After") != "3" {
		t.Fatalf("a fifth from a network at its cap of four: %+v", e)
	}
	pf.park(hostB, vaults[4])
	pf.park(hostB, vaults[5])
	pf.waitParked(6)
	// The process is full. An honest vault from a third address:
	honest := "203.0.113.30"
	f.expectFrom(honest, collectReq(vaults[6]), 200, "") // wait=0 is never refused by a parked-collector cap
	pf.park(honest, vaults[6])                           // its long-poll is admitted too ...
	deadline := time.Now().Add(5 * time.Second)
	for f.s.m.shed.Value() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("nobody was shed to make room for a mailbox without a collector")
		}
		time.Sleep(2 * time.Millisecond)
	}
	pf.waitParked(6) // ... and one of the heaviest network's (hostA) was sent home with an empty answer
	shed := 0
	for i := 0; i < 4; i++ {
		if pf.code(vaults[i]) == 200 {
			shed++
		}
	}
	if shed != 1 || pf.code(vaults[4]) != 0 || pf.code(vaults[5]) != 0 {
		t.Fatalf("shed from the heaviest network: %d (want 1); the lighter network's must stay parked", shed)
	}
	// What the process cap does refuse: a second collector of a mailbox
	// that has one, and more from the network that already holds the most.
	if _, e, _ := f.from(honest, parkReq(vaults[6])); e.Code != CodeRateLimited {
		t.Fatalf("second collector of a mailbox, process full: %+v", e)
	}
	if _, e, _ := f.from(hostA, parkReq(vaults[7])); e.Code != CodeRateLimited {
		t.Fatalf("newcomer of the heaviest network, process full: %+v", e)
	}
	if v := f.s.rl.refused.With(limCollectors).Value(); v != 3 {
		t.Fatalf("refused counter %d", v)
	}
	// A deposit still wakes its collector; the deadline ends the others; the slots come back.
	tok := f.mint(vaults[6], vaults[9], nil)
	f.expectFrom(hostB, depositReq(vaults[6], vaults[9], tok, "wake"), 201, "")
	pf.waitParked(5)
	pf.ft.fire()
	pf.wg.Wait()
	pf.waitParked(0)
	for i := 0; i < 7; i++ {
		if pf.code(vaults[i]) != 200 {
			t.Fatalf("parked collect %d ended with %d", i, pf.code(vaults[i]))
		}
	}
}

// N2: WebSocket sessions do not live for ever.
func TestWebSocketSessionHasAMaximumLifetime(t *testing.T) {
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithWebSocketLifetime(200 * time.Millisecond)} })
	owner := newPrincipal(1)
	f.register(owner)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := c.Read(ctx); websocket.CloseStatus(err) != websocket.StatusTryAgainLater {
		t.Fatalf("want close 1013 at the session's maximum lifetime, got %v", err)
	}
}

// F6: a full table of held keys charges nobody: an orphan it has no room
// for is not held, and its repeats are not charged to its network.
func TestFullTablesChargeNobody(t *testing.T) {
	f := newFixture(t, failBudget(3))
	f.s.orphans = ratelimit.NewHold(time.Second, time.Minute, 1, 0)
	f.s.onceSeen = ratelimit.NewRecent(time.Minute, 1, 0)
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

// ---- Second review (N1–N7), and the pools seen from an honest vault.

// honestVault checks that a registered vault, from its own address, gets
// everything it does served: registering its key again, collecting (with
// and without waiting), acking, depositing, rotating.
func honestVault(t *testing.T, pf *parkedFixture, addr string, seed byte) {
	t.Helper()
	f := pf.fixture
	v, peer, next := newPrincipal(seed), newPrincipal(seed+1), newPrincipal(seed+2)
	if _, err := f.st.Register(t.Context(), v.mbx, v.pub); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Register(t.Context(), peer.mbx, peer.pub); err != nil {
		t.Fatal(err)
	}
	f.expectFrom(addr, registerReq(v), 200, "")
	tok := f.mint(peer, v, nil)
	f.expectFrom(addr, depositReq(peer, v, tok, "from the honest vault"), 201, "")
	big := req{method: "POST", path: "/v1/mailbox/" + peer.mbx, body: depositBody(make([]byte, 200_000)), signer: &v, token: tok}
	f.expectFrom(addr, big, 201, "")
	f.expectFrom(addr, collectReq(v), 200, "") // wait=0
	f.expectFrom(addr, req{method: "DELETE", path: "/v1/mailbox/01ARZ3NDEKTSV4RRFFQ69G5FAV", signer: &v}, 204, "")
	before := f.s.hub.collectors()
	pf.park(addr, v) // wait=25
	deadline := time.Now().Add(5 * time.Second)
	for f.s.m.parked.Value() == 0 || (f.s.hub.collectors() == before && f.s.m.shed.Value() == 0) {
		if time.Now().After(deadline) {
			t.Fatalf("the honest vault's long-poll was not admitted (collectors %d)", f.s.hub.collectors())
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Its long-poll is woken by a deposit, like anyone's.
	back := f.mint(v, peer, nil)
	f.expectFrom(addr, depositReq(v, peer, back, "wake"), 201, "")
	deadline = time.Now().Add(5 * time.Second)
	for pf.code(v) != 200 {
		if time.Now().After(deadline) {
			t.Fatal("the honest vault's long-poll did not return its message")
		}
		time.Sleep(2 * time.Millisecond)
	}
	proof := ed25519.Sign(next.priv, []byte(v.mbx))
	body, _ := json.Marshal(map[string]any{"new_pubkey": next.b64, "new_key_proof": proof})
	f.expectFrom(addr, req{method: "POST", path: "/v1/mailbox/rotate", body: body, signer: &v}, 200, "")
}

// N1: addresses with no credentials cannot hold the memory for request
// bodies: announcing bodies reserves nothing, sending them fills only the
// attackers' own share of the pool for unauthenticated bodies, and never
// the pools an honest vault's requests are read from.
func TestBodyPoolsCannotBeHeldByUnauthenticatedAddresses(t *testing.T) {
	pf := newParkedFixture(t, 100, 100)
	f := pf.fixture
	target := newPrincipal(1)
	f.register(target)
	var conns []net.Conn
	t.Cleanup(func() {
		for _, c := range conns {
			c.Close()
		}
	})
	send := func(path string, header string, announce, bytes int) {
		c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: relay\r\n%sContent-Length: %d\r\n\r\n", path, header, announce)
		c.Write(make([]byte, bytes))
	}
	limit := int(f.s.depositBodyLimit())
	h := http.Header{}
	auth.SetHeaders(h, target.priv, "POST", "/v1/elsewhere", f.sigTime(), auth.BodyHash(nil))
	sig := fmt.Sprintf("X-VettID-Key: %s\r\nX-VettID-Timestamp: %s\r\nX-VettID-Sig: %s\r\nAuthorization: VettID-Deposit x\r\n", h.Get(auth.HeaderKey), h.Get(auth.HeaderTimestamp), h.Get(auth.HeaderSig))
	// (a) 100 deposits and 100 registrations that announce a full body and
	// send none; with well-formed signature headers naming a real key.
	for i := 0; i < 100; i++ {
		send("/v1/mailbox/"+target.mbx, sig, limit, 0)
		send("/v1/register", "", smallBodyLimit, 0)
	}
	time.Sleep(300 * time.Millisecond)
	open, _ := f.s.openBodies.inFlight()
	keyed, _ := f.s.keyedBodies.inFlight()
	small, _ := f.s.smallBodies.inFlight()
	t.Logf("200 requests announcing %d MiB in all, no body sent: bytes held: open %d, keyed %d, small %d", (100*limit+100*smallBodyLimit)>>20, open, keyed, small)
	if keyed != 0 || open != 0 || small != 0 {
		t.Fatalf("announced bodies hold memory: open %d, keyed %d, small %d", open, keyed, small)
	}
	// (b) The same deposits, now sending all but the last byte, to hold
	// what they can (the fixture's server sees them all from 127.0.0.1:
	// one network, so they are bounded by one network's share).
	for i := 0; i < 20; i++ {
		send("/v1/mailbox/"+target.mbx, sig, limit, limit-1)
	}
	time.Sleep(500 * time.Millisecond)
	open, _ = f.s.openBodies.inFlight()
	keyed, _ = f.s.keyedBodies.inFlight()
	t.Logf("20 stalled deposit bodies of %d KiB under a real key's name: bytes held: open %d (one network's share: %d), keyed %d", limit>>10, open, f.cfg.MaxOpenBodyBytesPerNetwork, keyed)
	if keyed != 0 || open > f.cfg.MaxOpenBodyBytesPerNetwork {
		t.Fatalf("stalled bodies: open %d (cap per network %d), keyed %d", open, f.cfg.MaxOpenBodyBytesPerNetwork, keyed)
	}
	// Meanwhile an honest vault, from another address, is served in full.
	honestVault(t, pf, hostB, 50)
}

// N2: addresses holding as many parked collectors as the process allows
// (WebSocket sessions and long-polls of mailboxes they registered) cannot
// shut out a vault's collect.
func TestCollectorCapCannotLockOutAVault(t *testing.T) {
	pf := newParkedFixture(t, 30, 60)
	f := pf.fixture
	// Two addresses, 30 registered mailboxes each: one holds WebSocket
	// sessions, the other long-polls. The process is full.
	for i := 0; i < 30; i++ {
		p := simPrincipal("squatter-ws", i)
		if _, err := f.st.Register(t.Context(), p.mbx, p.pub); err != nil {
			t.Fatal(err)
		}
		c, _, err := f.dialWS(p) // from 127.0.0.1
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.CloseNow() })
		q := simPrincipal("squatter-poll", i)
		if _, err := f.st.Register(t.Context(), q.mbx, q.pub); err != nil {
			t.Fatal(err)
		}
		pf.park(hostA, q)
	}
	pf.waitParked(60)
	for i := byte(0); i < 5; i++ { // five honest vaults, one after the other
		honestVault(t, pf, hostB, 100+10*i)
	}
	if f.s.hub.collectors() > 60 {
		t.Fatalf("parked collectors %d over the process cap", f.s.hub.collectors())
	}
	if f.s.m.shed.Value() < 1 {
		t.Fatal("nobody was shed: the squatters kept every place")
	}
	pf.ft.fire()
}

// N3: re-checking a held key's mailbox is a store read, so it comes after
// the flood guard: many held keys asking at once cost the store no more
// than the flood guard lets through.
func TestHoldRecheckIsBoundedByFloodGuard(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		failBudget(1)(c)
		c.RateIPPerSec, c.RateIPBurst = 0.01, 600
	}, func(*fixture) []Option { return []Option{WithNoMailboxHold(time.Minute)} })
	st := &countingStore{Backend: f.s.st}
	f.s.st = st
	keys := make([]principal, 500)
	for i := range keys {
		keys[i] = simPrincipal("held", i)
		f.expectFrom(hostA, collectReq(keys[i]), 404, CodeMailboxUnknown) // held now; hostA penalised
	}
	f.clk.add(20 * time.Second) // every hold is due a re-check; the flood guard has 100 tokens left
	st.mailbox.Store(0)
	refused := 0
	for round := 0; round < 3; round++ {
		for i := range keys {
			if code, _, _ := f.from(hostA, collectReq(keys[i])); code == 429 {
				refused++
			}
		}
	}
	if got := st.mailbox.Load(); got > 100 || refused != 1500 {
		t.Fatalf("1,500 requests by 500 held keys: %d store reads (flood guard had 100 tokens), %d refused", got, refused)
	}
}

type countingStore struct {
	store.Backend
	mailbox atomic.Int64
}

func (c *countingStore) Mailbox(ctx context.Context, id string) (store.Mailbox, error) {
	c.mailbox.Add(1)
	return c.Backend.Mailbox(ctx, id)
}

// N4: on a penalised address, someone fetching claims cannot take the
// trickle that properly signed new registrations and rotations get.
func TestClaimFetchesCannotStarveNewMailboxes(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		d := config.Defaults()
		failBudget(1)(c)
		c.RateAuthFailPerSec = 0.001
		c.RateTricklePerSec, c.RateTrickleBurst = d.RateTricklePerSec, d.RateTrickleBurst
	})
	f.expectFrom(hostA, req{method: "GET", path: "/v1/mailbox"}, 401, CodeSignatureInvalid) // penalised for the whole test
	fetched, enrolled, tried := 0, 0, 0
	for sec := 0; sec < 600; sec++ {
		if code, _, _ := f.from(hostA, req{method: "GET", path: "/v1/claim/aaaaaaaaaaaaaaaaaaaaaaaaaa"}); code == 404 {
			fetched++
		}
		if sec%15 == 0 { // a new member every 15 s
			tried++
			if code, _, _ := f.from(hostA, registerReq(simPrincipal("enrol", sec))); code == 201 {
				enrolled++
			}
		}
		f.clk.add(time.Second)
	}
	if enrolled != tried || fetched < 55 || fetched > 65 {
		t.Fatalf("10 min on a penalised address: claim fetches let through %d (their own trickle: about 60), new mailboxes %d of %d", fetched, enrolled, tried)
	}
}

// N6: a refused deposit by a signer that got in through the trickle and
// has no mailbox is charged to its network once a minute, not every time.
func TestMailboxlessSenderChargedOncePerMinute(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		failBudget(1)(c)
		c.RateAuthFailPerSec = 0.001
	})
	owner, passerby, gone := newPrincipal(1), newPrincipal(3), newPrincipal(8)
	f.register(owner)
	tok := f.mint(owner, passerby, nil)
	f.expectFrom(hostA, req{method: "GET", path: "/v1/mailbox"}, 401, CodeSignatureInvalid) // penalised
	before := f.s.rl.charged.Value()
	st := &countingStore{Backend: f.s.st}
	f.s.st = st
	for i := 0; i < 30; i++ {
		f.expectFrom(hostA, depositReq(gone, passerby, tok, "x"), 404, CodeMailboxUnknown)
		f.clk.add(time.Second)
	}
	if got := f.s.rl.charged.Value() - before; got != 1 {
		t.Fatalf("30 refused deposits in 30 s by one signer without a mailbox: %d units charged to its network", got)
	}
}

// N7: a deposit whose token has verified has minutes for its body, not
// seconds: a slow link is not refused.
func TestSlowDepositBodyIsReadOnceTheTokenVerified(t *testing.T) {
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithBodyPace(150*time.Millisecond, 400*time.Millisecond)} })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	body := depositBody(make([]byte, 3000))
	hr := f.build(req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: body, signer: &sender, token: tok})
	c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: relay\r\nContent-Length: %d\r\n", hr.URL.Path, len(body))
	for _, k := range []string{auth.HeaderKey, auth.HeaderTimestamp, auth.HeaderSig, "Authorization"} {
		fmt.Fprintf(c, "%s: %s\r\n", k, hr.Header.Get(k))
	}
	fmt.Fprint(c, "\r\n")
	// 1.2 s for the body, in ten pieces: three times the unauthenticated limit.
	for i := 0; i < 10; i++ {
		c.Write(body[i*len(body)/10 : (i+1)*len(body)/10])
		time.Sleep(120 * time.Millisecond)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("slow deposit with a valid token: %v %v", resp, err)
	}
	if paceKeyed.total < 5*time.Minute || paceKeyed.idle < 30*time.Second {
		t.Fatalf("pace for authenticated deposit bodies: %+v", paceKeyed)
	}
}
