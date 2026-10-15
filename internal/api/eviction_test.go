package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
)

// newUpload is an upload record for the slot accounting tests: started
// now on the fixture's clock, with a cut that counts.
func (f *fixture) newUpload(mailbox, sender string) *upload {
	return f.newUploadFrom("n", mailbox, sender)
}

func (f *fixture) newUploadFrom(network, mailbox, sender string) *upload {
	return &upload{mailbox: mailbox, sender: sender, network: network, start: f.clk.now(), now: f.clk.now, cut: func() {}}
}

// trickler is a client address of the tests (relayed in X-Forwarded-For).
const trickler = "198.51.100.66"

// rawBlobPutVia is rawBlobPut from the client address xff (the relay
// trusts X-Forwarded-For in these tests).
func rawBlobPutVia(t *testing.T, f *fixture, c net.Conn, xff string, owner, sender principal, data []byte, k int) {
	t.Helper()
	hr := f.build(req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: data, signer: &sender, token: f.mint(owner, sender, nil)})
	var b bytes.Buffer
	fmt.Fprintf(&b, "PUT %s HTTP/1.1\r\nHost: relay\r\nContent-Length: %d\r\nX-Forwarded-For: %s\r\n", hr.URL.EscapedPath(), len(data), xff)
	for name, vs := range hr.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	b.WriteString("\r\n")
	b.Write(data[:k])
	if _, err := c.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}
}

// uploadOf returns the upload in progress to mailbox (nil if none).
func (f *fixture) uploadOf(mailbox string) *upload {
	f.s.xfers.mu.Lock()
	defer f.s.xfers.mu.Unlock()
	for u := range f.s.xfers.uploads {
		if u.mailbox == mailbox {
			return u
		}
	}
	return nil
}

// readAnswer reads the relay's answer on c.
func readAnswer(t *testing.T, c net.Conn) (*http.Response, errorBody) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	var e errorBody
	json.NewDecoder(resp.Body).Decode(&e)
	return resp, e
}

// evictFixture: one upload slot in the process (2 transfers, 1 per
// mailbox), a pace window long enough that held uploads stay.
func evictFixture(t *testing.T, mut func(*config.Config)) *fixture {
	return newFixtureWith(t, func(c *config.Config) {
		c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 2, 1
		c.TrustProxy = true // rawBlobPutVia gives each client its network
		if mut != nil {
			mut(c)
		}
	}, func(*fixture) []Option { return []Option{WithBlobPaceWindow(5 * time.Second)} })
}

// A trickling upload that has run 30 s is cut off when a new upload finds
// no slot: the new one takes its slot and is stored; the trickle is
// answered 429 with retry_after, its connection closed, and its bytes
// stay charged.
func TestTrickleEvictedByARealUpload(t *testing.T) {
	f := evictFixture(t, func(c *config.Config) { c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 0.001, 1<<20 })
	a, b, s1, s2 := newPrincipal(1), newPrincipal(2), newPrincipal(11), newPrincipal(12)
	f.register(a)
	f.register(b)
	c := dial(t, f)
	rawBlobPutVia(t, f, c, trickler, a, s1, make([]byte, 64<<10), 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	f.clk.add(31 * time.Second)
	f.mustPutBlob(b, s2, f.mint(b, s2, nil), []byte("a real attachment")) // from another network
	resp, e := readAnswer(t, c)
	if resp.StatusCode != 429 || e.Code != CodeRateLimited || e.RetryAfter != 2 || !resp.Close {
		t.Fatalf("evicted upload: %d %+v close=%v", resp.StatusCode, e, resp.Close)
	}
	if n := f.counter(`relay_ratelimit_refused_total{limiter="blob_evicted"}`); n != 1 {
		t.Fatalf("evictions counted: %d", n)
	}
	waitFor(t, f.s.xfers.empty)
	// Charged to its network: the 1,000 bytes the trickle sent; the rest
	// of its declared 64 KiB was given back (once its handler ends).
	key := rateKey(netip.MustParseAddr(trickler))
	waitFor(t, func() bool {
		f.s.rl.mu.Lock()
		defer f.s.rl.mu.Unlock()
		return f.s.rl.count[limBlobBytes][key] == 1000
	})
	if ok, _ := f.s.blobByteLimit.AllowN(key, 1<<20-1000, f.clk.now()); !ok {
		t.Fatal("the unsent part of the evicted upload was not given back")
	}
	if ok, _ := f.s.blobByteLimit.AllowN(key, 1, f.clk.now()); ok {
		t.Fatal("the evicted upload's sent bytes were given back")
	}
	f.s.reportLimits()
}

// Nothing that has run less than RELAY_BLOB_EVICT_MIN_AGE is cut off: the
// new upload is refused as before.
func TestNoEvictionUnderMinAge(t *testing.T) {
	f := evictFixture(t, nil)
	a, b, s1, s2 := newPrincipal(1), newPrincipal(2), newPrincipal(11), newPrincipal(12)
	f.register(a)
	f.register(b)
	c := dial(t, f)
	rawBlobPutVia(t, f, c, trickler, a, s1, make([]byte, 64<<10), 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	f.clk.add(29 * time.Second)
	f.expectCode(req{method: "PUT", path: "/v1/blob/" + b.mbx, body: []byte("x"), signer: &s2, token: f.mint(b, s2, nil)}, 429, CodeRateLimited)
	if n := f.counter(`relay_ratelimit_refused_total{limiter="blob_evicted"}`); n != 0 {
		t.Fatalf("evicted under the minimum age: %d", n)
	}
	if f.s.xfers.inFlight() != 1 {
		t.Fatal("the held upload lost its slot")
	}
	if d := config.Defaults().BlobEvictMinAge; d != 30*time.Second {
		t.Fatalf("default minimum age %v", d)
	}
}

// The slowest goes first, by bytes received per second: a faster upload
// is not cut off ahead of a slower one, and a full mailbox gives up only
// its own uploads.
func TestSlowestUploadEvictedFirst(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 3, 1 // 2 uploads
		c.TrustProxy = true
	}, func(*fixture) []Option { return []Option{WithBlobPaceWindow(5 * time.Second)} })
	a, b, c3 := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	s1, s2, s3 := newPrincipal(11), newPrincipal(12), newPrincipal(13)
	for _, p := range []principal{a, b, c3} {
		f.register(p)
	}
	fast, slow := dial(t, f), dial(t, f)
	rawBlobPutVia(t, f, fast, "198.51.100.7", a, s1, make([]byte, 64<<10), 30_000)
	rawBlobPutVia(t, f, slow, "198.51.100.8", b, s2, make([]byte, 64<<10), 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 2 })
	f.clk.add(31 * time.Second)
	// Within the measuring window, the fast one keeps sending.
	if _, err := fast.Write(make([]byte, 20_000)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { u := f.uploadOf(a.mbx); return u != nil && u.rate(f.clk.now()) > 0 })
	f.mustPutBlob(c3, s3, f.mint(c3, s3, nil), []byte("new"))
	if resp, _ := readAnswer(t, slow); resp.StatusCode != 429 {
		t.Fatalf("the slow upload: %d", resp.StatusCode)
	}
	if f.s.xfers.inFlight() != 1 {
		t.Fatalf("in flight %d: the fast upload should still hold its slot", f.s.xfers.inFlight())
	}
	// Mailbox a is full with the fast upload; a newcomer to a cuts it off
	// (it is the only one there, and has run long enough).
	f.mustPutBlob(a, s3, f.mint(a, s3, nil), []byte("to a"))
	if resp, _ := readAnswer(t, fast); resp.StatusCode != 429 {
		t.Fatalf("the fast upload, its mailbox full: %d", resp.StatusCode)
	}
	waitFor(t, f.s.xfers.empty)
}

// The slot accounting stays right when uploads are cut off while others
// come and go concurrently (run with -race).
func TestEvictionAccountingConcurrent(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 6, 2 }) // 4 uploads
	s := f.s
	var cuts atomic.Int64
	rels := make([]func(), 4)
	for i := range rels {
		u := f.newUploadFrom("old", string(rune('a'+i)), "x")
		u.cut = func() { cuts.Add(1) }
		u.add(i)
		r, e := s.acquireUpload(u, nil)
		if e != nil {
			t.Fatal(e.code)
		}
		rels[i] = r
	}
	f.clk.add(time.Minute)
	var wg sync.WaitGroup
	var admitted atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := f.newUploadFrom("new", "n", string(rune('A'+i)))
			u.cut = func() { cuts.Add(1) }
			if r, e := s.acquireUpload(u, nil); e == nil {
				admitted.Add(1)
				r()
				r() // a second release is harmless
			}
		}(i)
	}
	for i := range rels { // the old uploads end too, evicted or not
		wg.Add(1)
		go func(i int) { defer wg.Done(); rels[i]() }(i)
	}
	wg.Wait()
	if !s.xfers.empty() {
		t.Fatal("slots left after everything ended")
	}
	if n := f.counter(`relay_ratelimit_refused_total{limiter="blob_evicted"}`); cuts.Load() != n {
		t.Fatalf("cuts %d, counted %d", cuts.Load(), n)
	}
	if admitted.Load() == 0 {
		t.Fatal("no newcomer admitted")
	}
}

// Eviction and completion race for an upload: exactly one wins. If the
// upload finished reading first, it keeps its slot and the newcomer is
// refused; if it was evicted first, it cannot go on to finish.
func TestEvictionRacesCompletion(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 2, 1 }) // 1 upload
	s := f.s
	for i := 0; i < 300; i++ {
		old := f.newUpload("a", "x")
		relOld, e := s.acquireUpload(old, nil)
		if e != nil {
			t.Fatal(e.code)
		}
		f.clk.add(time.Minute)
		var finished atomic.Bool
		var relNew func()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); finished.Store(old.state.CompareAndSwap(upReading, upDone)) }()
		go func() { defer wg.Done(); relNew, _ = s.acquireUpload(f.newUploadFrom("m", "b", "y"), nil) }()
		wg.Wait()
		switch {
		case finished.Load() && relNew != nil:
			t.Fatal("the upload finished and was evicted too")
		case !finished.Load() && (relNew == nil || old.state.Load() != upEvicted):
			t.Fatal("neither finished nor evicted")
		}
		if relNew != nil {
			relNew()
		}
		relOld()
		if !s.xfers.empty() {
			t.Fatal("slots left")
		}
	}
}

// An address cannot keep the upload slots by replacing old uploads with
// new ones: once its network has held a slot without a break for
// RELAY_BLOB_EVICT_MIN_AGE, any of its uploads may be cut off, however
// young.
func TestRotationDoesNotKeepNewcomersOut(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 3, 1 // 2 uploads
		c.TrustProxy = true
	}, func(*fixture) []Option { return []Option{WithBlobPaceWindow(5 * time.Second)} })
	var mb []principal
	for i := 0; i < 4; i++ {
		mb = append(mb, newPrincipal(byte(1+i)))
		f.register(mb[i])
	}
	data := make([]byte, 64<<10)
	const attacker, honest = "198.51.100.7", "203.0.113.50"
	u1 := dial(t, f)
	rawBlobPutVia(t, f, u1, attacker, mb[0], newPrincipal(21), data, 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	f.clk.add(20 * time.Second)
	u2 := dial(t, f)
	rawBlobPutVia(t, f, u2, attacker, mb[1], newPrincipal(22), data, 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 2 })
	u1.Close() // replaced: the attacker's network still holds a slot
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	f.clk.add(15 * time.Second) // u2 is 15 s old; the attacker's network has held a slot for 35 s
	u3 := dial(t, f)
	rawBlobPutVia(t, f, u3, attacker, mb[2], newPrincipal(23), data, 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 2 })
	h := dial(t, f)
	rawBlobPutVia(t, f, h, honest, mb[3], newPrincipal(24), []byte("an honest attachment"), len("an honest attachment"))
	if resp, _ := readAnswer(t, h); resp.StatusCode != 201 {
		t.Fatalf("the honest newcomer: %d", resp.StatusCode)
	}
	if resp, e := readAnswer(t, u2); resp.StatusCode != 429 || e.RetryAfter != 2 {
		t.Fatalf("the attacker's slowest upload (nothing in the last 10 s): %d %+v", resp.StatusCode, e)
	}
}

// Speed is measured over the last 10 s: an upload that bursts and then
// trickles is cut off before a steady one, though its average since it
// began is higher.
func TestBurstThenTrickleEvictedBeforeSteady(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 3, 1 // 2 uploads
		c.TrustProxy = true
	}, func(*fixture) []Option { return []Option{WithBlobPaceWindow(5 * time.Second)} })
	a, b, c := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	for _, p := range []principal{a, b, c} {
		f.register(p)
	}
	data := make([]byte, 128<<10)
	burst, steady := dial(t, f), dial(t, f)
	rawBlobPutVia(t, f, burst, "198.51.100.7", a, newPrincipal(21), data, 60_000)
	rawBlobPutVia(t, f, steady, "203.0.113.50", b, newPrincipal(22), data, 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 2 })
	waitFor(t, func() bool { u := f.uploadOf(a.mbx); return u != nil && u.rate(f.clk.now()) >= 60_000/5 }) // measured over at least 5 s
	f.clk.add(31 * time.Second)
	if _, err := steady.Write(make([]byte, 5000)); err != nil { // steady keeps sending; burst has stopped
		t.Fatal(err)
	}
	waitFor(t, func() bool { u := f.uploadOf(b.mbx); return u != nil && u.rate(f.clk.now()) > 0 })
	f.mustPutBlob(c, newPrincipal(23), f.mint(c, newPrincipal(23), nil), []byte("new"))
	if resp, _ := readAnswer(t, burst); resp.StatusCode != 429 {
		t.Fatalf("burst then trickle: %d", resp.StatusCode)
	}
	if f.uploadOf(b.mbx) == nil {
		t.Fatal("the steady upload was cut off")
	}
}

// Every upload is protected for its first seconds, whatever its network:
// newcomers from two busy networks (vault hosts) do not cut each other
// off before they get going, and a network never cuts off its own.
func TestBusyNetworksNewcomersComplete(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 3, 1 // 2 uploads
		c.TrustProxy = true
	}, func(*fixture) []Option { return []Option{WithBlobPaceWindow(5 * time.Second)} })
	const hostX, hostY = "198.51.100.10", "198.51.100.20"
	var mb []principal
	for i := 0; i < 6; i++ {
		mb = append(mb, newPrincipal(byte(1+i)))
		f.register(mb[i])
	}
	big := make([]byte, 64<<10)
	ox, oy := dial(t, f), dial(t, f) // both networks busy for 40 s
	rawBlobPutVia(t, f, ox, hostX, mb[0], newPrincipal(31), big, 1000)
	rawBlobPutVia(t, f, oy, hostY, mb[1], newPrincipal(32), big, 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 2 })
	f.clk.add(40 * time.Second)
	body := bytes.Repeat([]byte("n"), 40_000)
	// A newcomer from X cuts off Y's old upload (a network never cuts off
	// its own); one from Y then cuts off X's old one.
	n1, n2 := dial(t, f), dial(t, f)
	rawBlobPutVia(t, f, n1, hostX, mb[2], newPrincipal(33), body, 20_000)
	if resp, _ := readAnswer(t, oy); resp.StatusCode != 429 {
		t.Fatalf("Y's old upload: %d", resp.StatusCode)
	}
	rawBlobPutVia(t, f, n2, hostY, mb[3], newPrincipal(34), body, 20_000)
	if resp, _ := readAnswer(t, ox); resp.StatusCode != 429 {
		t.Fatalf("X's old upload: %d", resp.StatusCode)
	}
	// Further newcomers from either find only uploads under 5 s old: they
	// are refused, and cut off nobody.
	f.clk.add(2 * time.Second)
	for i, host := range []string{hostX, hostY} {
		c := dial(t, f)
		rawBlobPutVia(t, f, c, host, mb[4+i], newPrincipal(byte(35+i)), body, 20_000)
		if resp, _ := readAnswer(t, c); resp.StatusCode != 429 {
			t.Fatalf("a newcomer while both are young: %d", resp.StatusCode)
		}
	}
	// The protected newcomers complete.
	for _, c := range []net.Conn{n1, n2} {
		if _, err := c.Write(body[20_000:]); err != nil {
			t.Fatal(err)
		}
		if resp, _ := readAnswer(t, c); resp.StatusCode != 201 {
			t.Fatalf("a protected newcomer: %d", resp.StatusCode)
		}
	}
	if n := f.counter(`relay_ratelimit_refused_total{limiter="blob_evicted"}`); n != 2 {
		t.Fatalf("evictions: %d", n)
	}
}

// A network keeps its clock when it gives up its last slot and comes back
// within RELAY_BLOB_EVICT_MIN_AGE: aborting at 29 s and reconnecting does
// not make its uploads young again.
func TestReconnectKeepsTheNetworkClock(t *testing.T) {
	f := evictFixture(t, nil)
	a, b, c := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	for _, p := range []principal{a, b, c} {
		f.register(p)
	}
	big := make([]byte, 64<<10)
	u1 := dial(t, f)
	rawBlobPutVia(t, f, u1, trickler, a, newPrincipal(21), big, 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	f.clk.add(29 * time.Second)
	u1.Close()
	waitFor(t, f.s.xfers.empty)
	u2 := dial(t, f)
	rawBlobPutVia(t, f, u2, trickler, b, newPrincipal(22), big, 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	f.clk.add(6 * time.Second) // u2 is 6 s old; its network's clock says 35 s
	f.mustPutBlob(c, newPrincipal(23), f.mint(c, newPrincipal(23), nil), []byte("honest"))
	if resp, _ := readAnswer(t, u2); resp.StatusCode != 429 {
		t.Fatalf("the reconnected upload: %d", resp.StatusCode)
	}
}

// The eviction clock is kept per IPv4 address or IPv6 /48.
func TestEvictionNetwork(t *testing.T) {
	x, y := evictionNetwork(netip.MustParseAddr("2001:db8:1:1::1")), evictionNetwork(netip.MustParseAddr("2001:db8:1:ffff::2"))
	if x != y || x != "2001:db8:1::/48" {
		t.Fatalf("%s %s", x, y)
	}
	if evictionNetwork(netip.MustParseAddr("2001:db8:2::1")) == x {
		t.Fatal("another /48")
	}
	if n := evictionNetwork(netip.MustParseAddr("203.0.113.9")); n != "203.0.113.9" {
		t.Fatal(n)
	}
}

// Clocks of networks that have held no upload slot for the minimum age
// are dropped by the periodic janitor; a network still holding one, or
// gone for less, keeps its clock.
func TestNetClocksPruned(t *testing.T) {
	f := newFixture(t, nil)
	s := f.s
	gone, back, busy := f.newUploadFrom("gone", "a", "x"), f.newUploadFrom("back", "b", "x"), f.newUploadFrom("busy", "c", "x")
	var rels []func()
	for _, u := range []*upload{gone, back, busy} {
		r, e := s.acquireUpload(u, nil)
		if e != nil {
			t.Fatal(e.code)
		}
		rels = append(rels, r)
	}
	rels[0]()
	f.clk.add(20 * time.Second)
	rels[1]()
	f.clk.add(15 * time.Second) // "gone" left 35 s ago, "back" 15 s ago
	s.pruneNetClocks(f.clk.now())
	s.xfers.mu.Lock()
	_, g := s.xfers.netSince["gone"]
	_, bk := s.xfers.netSince["back"]
	_, bs := s.xfers.netSince["busy"]
	s.xfers.mu.Unlock()
	if g || !bk || !bs {
		t.Fatalf("clocks kept: gone %v, back %v, busy %v", g, bk, bs)
	}
	rels[2]()
}
