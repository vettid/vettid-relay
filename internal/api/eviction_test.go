package api

import (
	"bufio"
	"encoding/json"
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
	return &upload{mailbox: mailbox, sender: sender, start: f.clk.now(), cut: func() {}}
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
	rawBlobPut(t, f, c, a, s1, f.mint(a, s1, nil), make([]byte, 64<<10), 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	f.clk.add(31 * time.Second)
	f.mustPutBlob(b, s2, f.mint(b, s2, nil), []byte("a real attachment"))
	resp, e := readAnswer(t, c)
	if resp.StatusCode != 429 || e.Code != CodeRateLimited || e.RetryAfter != 2 || !resp.Close {
		t.Fatalf("evicted upload: %d %+v close=%v", resp.StatusCode, e, resp.Close)
	}
	if n := f.counter(`relay_ratelimit_refused_total{limiter="blob_evicted"}`); n != 1 {
		t.Fatalf("evictions counted: %d", n)
	}
	waitFor(t, f.s.xfers.empty)
	// Charged: the 1,000 bytes the trickle sent and the 17 stored; the
	// rest of its declared 64 KiB was given back (once its handler ends).
	key := rateKey(netip.MustParseAddr("127.0.0.1"))
	waitFor(t, func() bool {
		f.s.rl.mu.Lock()
		defer f.s.rl.mu.Unlock()
		return f.s.rl.count[limBlobBytes][key] == 1017
	})
	if ok, _ := f.s.blobByteLimit.AllowN(key, 1<<20-1017, f.clk.now()); !ok {
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
	rawBlobPut(t, f, c, a, s1, f.mint(a, s1, nil), make([]byte, 64<<10), 1000)
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
	f := newFixtureWith(t, func(c *config.Config) { c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 3, 1 }, // 2 uploads
		func(*fixture) []Option { return []Option{WithBlobPaceWindow(5 * time.Second)} })
	a, b, c3 := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	s1, s2, s3 := newPrincipal(11), newPrincipal(12), newPrincipal(13)
	for _, p := range []principal{a, b, c3} {
		f.register(p)
	}
	fast, slow := dial(t, f), dial(t, f)
	rawBlobPut(t, f, fast, a, s1, f.mint(a, s1, nil), make([]byte, 64<<10), 30_000)
	rawBlobPut(t, f, slow, b, s2, f.mint(b, s2, nil), make([]byte, 64<<10), 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 2 })
	waitFor(t, func() bool { // the fast one's bytes have all been read
		f.s.xfers.mu.Lock()
		defer f.s.xfers.mu.Unlock()
		var got int64
		for u := range f.s.xfers.uploads {
			got += u.received.Load()
		}
		return got == 31_000
	})
	f.clk.add(31 * time.Second)
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
	old := make([]*upload, 4)
	rels := make([]func(), 4)
	for i := range old {
		old[i] = &upload{mailbox: string(rune('a' + i)), sender: "x", start: f.clk.now(), cut: func() { cuts.Add(1) }}
		old[i].received.Store(int64(i))
		r, e := s.acquireUpload(old[i])
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
			u := &upload{mailbox: "n", sender: string(rune('A' + i)), start: f.clk.now(), cut: func() { cuts.Add(1) }}
			if r, e := s.acquireUpload(u); e == nil {
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
		t.Fatalf("slots left after everything ended: %+v", s.xfers)
	}
	for i, u := range old {
		if u.evicted.Load() && u.received.Load() != int64(i) {
			t.Fatal("bookkeeping changed a record")
		}
	}
	if cuts.Load() != f.counter(`relay_ratelimit_refused_total{limiter="blob_evicted"}`) {
		t.Fatalf("cuts %d, counted %d", cuts.Load(), f.counter(`relay_ratelimit_refused_total{limiter="blob_evicted"}`))
	}
	if admitted.Load() == 0 {
		t.Fatal("no newcomer admitted")
	}
}
