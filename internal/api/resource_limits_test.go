package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/logbudget"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Deposits draw on their network's byte budget with their declared length,
// after the token verified and before the body is read. A deposit it
// refuses is answered 429 rate_limited with retry_after, unread, with the
// connection closed. Unauthorized deposits cost nothing; another network
// is not affected; the budget refills.
func TestDepositByteBudget(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, func(c *config.Config) { c.RateIPBytesPerSec, c.RateIPBytesBurst = 1000, 3000 }, &logs)
	owner, sender, nobody := newPrincipal(1), newPrincipal(2), newPrincipal(9)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	payload := strings.Repeat("x", 1000) // a body of about 1,350 bytes
	for i := 0; i < 5; i++ {
		f.expectFrom(hostA, depositReq(owner, sender, "garbage", payload), 401, CodeTokenInvalid)
		f.expectFrom(hostA, depositReq(nobody, sender, tok, payload), 404, CodeMailboxUnknown)
	}
	f.expectFrom(hostA, depositReq(owner, sender, tok, payload), 201, "")
	f.expectFrom(hostA, depositReq(owner, sender, tok, payload), 201, "")

	hr := f.build(depositReq(owner, sender, tok, payload))
	body := &countingBody{r: hr.Body}
	hr.Body = io.NopCloser(body)
	hr.RemoteAddr = hostA + ":40000"
	rec := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(rec, hr)
	var eb errorBody
	json.Unmarshal(rec.Body.Bytes(), &eb)
	if rec.Code != 429 || eb.Code != CodeRateLimited || eb.RetryAfter != 2 ||
		rec.Header().Get("Retry-After") != "2" || body.n.Load() != 0 || rec.Header().Get("Connection") != "close" {
		t.Fatalf("over the byte budget: %d %s Retry-After %q, %d body bytes read, Connection %q",
			rec.Code, rec.Body, rec.Header().Get("Retry-After"), body.n.Load(), rec.Header().Get("Connection"))
	}
	f.expectFrom(hostB, depositReq(owner, sender, tok, payload), 201, "") // another network
	f.clk.add(2 * time.Second)
	f.expectFrom(hostA, depositReq(owner, sender, tok, payload), 201, "")
	if a, r := f.counter(`relay_ratelimit_allowed_total{limiter="bytes"}`), f.counter(`relay_ratelimit_refused_total{limiter="bytes"}`); a != 4 || r != 1 {
		t.Fatalf("bytes limiter: %d allowed, %d refused", a, r)
	}
	// Refusals are logged at debug (they are counted per minute).
	if line := lastLine(t, logs.String(), `"status":429`); !strings.Contains(line, `"level":"DEBUG"`) {
		t.Fatalf("refusal logged above debug: %s", line)
	}
}

// Claims are stored too: they draw on the same budget as deposits, with
// their length, once the claim is authenticated.
func TestClaimByteBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateIPBytesPerSec, c.RateIPBytesBurst = 1, 3000 })
	owner, sender, stranger := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	claim := func(p principal) req {
		return req{method: "PUT", path: "/v1/claim", body: make([]byte, 1000), signer: &p}
	}
	f.expectFrom(hostA, claim(stranger), 404, CodeMailboxUnknown) // no mailbox: not charged
	f.expectFrom(hostA, claim(owner), 201, "")
	f.expectFrom(hostA, claim(owner), 201, "")
	f.expectFrom(hostA, depositReq(owner, sender, tok, strings.Repeat("x", 1000)), 429, CodeRateLimited)
	f.expectFrom(hostA, claim(owner), 201, "") // 1,000 bytes still fit
	f.expectFrom(hostA, claim(owner), 429, CodeRateLimited)
}

// The mailbox's stored-bytes cap (RELAY_MAILBOX_MAX_BYTES, 32 MiB by
// default). A mailbox already above a lowered cap keeps what it holds: it
// is collected as before, and deposits are refused with quota_exceeded
// until acks bring it under the cap.
func TestMailboxByteCap(t *testing.T) {
	if d := config.Defaults().MailboxMaxBytes; d != 32<<20 {
		t.Fatalf("default mailbox cap %d", d)
	}
	f := newFixture(t, func(c *config.Config) { c.MaxPayloadBytes, c.MailboxMaxBytes = 1000, 2500 })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	payload := strings.Repeat("x", 1000)
	f.expectCode(depositReq(owner, sender, tok, payload), 201, "")
	f.expectCode(depositReq(owner, sender, tok, payload), 201, "")
	f.expectCode(depositReq(owner, sender, tok, payload), 429, CodeQuotaExceeded)

	f.cfg.MailboxMaxBytes = 1500 // lowered: the mailbox holds 2,000
	f.restart()
	got := f.collect(owner, "")
	if len(got.Messages) != 2 {
		t.Fatalf("a mailbox above the lowered cap lost messages: %d", len(got.Messages))
	}
	f.expectCode(depositReq(owner, sender, tok, "small"), 429, CodeQuotaExceeded)
	if code, b := f.ack(owner, got.Messages[0].MsgID); code != http.StatusNoContent {
		t.Fatalf("ack: %d %s", code, b)
	}
	f.expectCode(depositReq(owner, sender, tok, strings.Repeat("y", 400)), 201, "") // 1,400 of 1,500
}

// On owner routes the mailbox is looked up before the replay record is
// written: signed requests under keys without a mailbox write none.
func TestOwnerRouteReplayRecordAfterMailboxLookup(t *testing.T) {
	g := &countingGuard{ReplayGuard: auth.NewReplayCache(100_000)}
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithReplayGuard(g)} })
	owner := newPrincipal(1)
	f.register(owner)
	before := g.n.Load()
	for i := byte(0); i < 20; i++ {
		f.expectFrom(hostA, collectReq(newPrincipal(100+i)), 404, CodeMailboxUnknown)
		p := newPrincipal(100 + i)
		f.expectFrom(hostA, req{method: "PUT", path: "/v1/claim", body: []byte("c"), signer: &p}, 404, CodeMailboxUnknown)
	}
	if n := g.n.Load() - before; n != 0 {
		t.Fatalf("%d replay records written for keys without a mailbox", n)
	}
	// The owner's requests are recorded, and a replay is still refused.
	r := f.build(collectReq(owner))
	again := r.Clone(context.Background())
	if code, _, _ := f.send(r); code != 200 {
		t.Fatalf("collect: %d", code)
	}
	again.Body = http.NoBody
	if code, b, _ := f.send(again); code != 401 || !strings.Contains(string(b), CodeReplayDetected) {
		t.Fatalf("replayed collect: %d %s", code, b)
	}
	if n := g.n.Load() - before; n != 2 {
		t.Fatalf("replay records for the owner: %d", n)
	}
}

// Blob uploads and downloads draw on the network's blob byte budget:
// uploads with their declared length before the body is read, downloads
// with the blob's size.
func TestBlobByteBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.MaxBlobBytes = 1000
		c.MaxSenderBlobBytes = 1 << 20 // the byte budget, not the share (§6.8)
		c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 1, 2500
	})
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	put := func() req {
		return req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: make([]byte, 1000), signer: &sender, token: tok}
	}
	got := func(addr, id string) (int, errorBody) {
		code, e, _ := f.from(addr, req{method: "GET", path: "/v1/blob/" + id, signer: &owner})
		return code, e
	}
	_, e, _ := f.from(hostA, put())
	if e.Code != "" {
		t.Fatalf("first upload: %q", e.Code)
	}
	id := f.mustPutBlob(owner, sender, tok, make([]byte, 1000)) // over loopback: another network
	if code, _ := got(hostA, id); code != 200 {                 // 2,000 of 2,500
		t.Fatalf("download: %d", code)
	}
	if code, e := got(hostA, id); code != 429 || e.Code != CodeRateLimited || e.RetryAfter < 1 {
		t.Fatalf("download over the budget: %d %+v", code, e)
	}
	f.expectFrom(hostA, put(), 429, CodeRateLimited)
	f.expectFrom(hostB, put(), 201, "")
	if r := f.counter(`relay_ratelimit_refused_total{limiter="blob_bytes"}`); r != 2 {
		t.Fatalf("blob_bytes refused %d", r)
	}
}

// rawBlobPut writes a signed blob upload of data to c, but only its first
// k bytes of body.
func rawBlobPut(t *testing.T, f *fixture, c net.Conn, owner, sender principal, tok string, data []byte, k int) {
	t.Helper()
	hr := f.build(req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: data, signer: &sender, token: tok})
	var b bytes.Buffer
	fmt.Fprintf(&b, "PUT %s HTTP/1.1\r\nHost: relay\r\nContent-Length: %d\r\n", hr.URL.EscapedPath(), len(data))
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

func dial(t *testing.T, f *fixture) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// An upload that has announced its body and sent none holds no transfer
// slot, and one that stalls is dropped within the pace window, its
// connection closed.
func TestBlobSlotTakenOnlyOnceTheBodyArrives(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) { c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 2, 1 }, // one upload
		func(*fixture) []Option { return []Option{WithBlobPaceWindow(400 * time.Millisecond)} })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	data := make([]byte, 64<<10)
	var silent []net.Conn
	for i := 0; i < 5; i++ { // headers only
		c := dial(t, f)
		rawBlobPut(t, f, c, owner, sender, tok, data, 0)
		silent = append(silent, c)
	}
	time.Sleep(100 * time.Millisecond)
	f.mustPutBlob(owner, sender, tok, []byte("not blocked by the silent uploads"))
	for _, c := range silent {
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != 400 || !resp.Close {
			t.Fatalf("silent upload: %v %v", resp, err)
		}
	}

	// One that sends a little and stalls holds the slot until the pace
	// window ends, then is dropped and frees it.
	c := dial(t, f)
	rawBlobPut(t, f, c, owner, sender, tok, data, 1000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	began := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 400 || !resp.Close || time.Since(began) > 2*time.Second {
		t.Fatalf("stalled upload: %v %v after %v", resp, err, time.Since(began))
	}
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 0 })
	f.mustPutBlob(owner, sender, tok, []byte("slot free again"))
}

// A body that keeps its pace is not dropped, however long it takes within
// the transfer maximum.
func TestBlobPaceKeptIsServed(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) { c.BlobPaceBytes = 1000 },
		func(*fixture) []Option { return []Option{WithBlobPaceWindow(300 * time.Millisecond)} })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	data := bytes.Repeat([]byte("z"), 6000)
	c := dial(t, f)
	rawBlobPut(t, f, c, owner, sender, tok, data, 1000)
	for off := 1000; off < len(data); off += 1000 { // 1,000 bytes every 150 ms: 1.2 s in all
		time.Sleep(150 * time.Millisecond)
		if _, err := c.Write(data[off : off+1000]); err != nil {
			t.Fatal(err)
		}
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 201 {
		t.Fatalf("paced upload: %v %v", resp, err)
	}
}

// Upload slots: one per (mailbox, sender), RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX
// per mailbox, and the process's RELAY_MAX_CONCURRENT_BLOB_TRANSFERS less
// one mailbox's worth, which uploads never take: senders holding every
// upload slot cannot keep the owner from its blobs. Beyond any of them,
// 429 rate_limited with retry_after 2, counted.
func TestBlobUploadSlots(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) { c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 4, 2 },
		func(*fixture) []Option { return []Option{WithBlobPaceWindow(3 * time.Second)} })
	a, b := newPrincipal(1), newPrincipal(2)
	s1, s2, s3 := newPrincipal(11), newPrincipal(12), newPrincipal(13)
	f.register(a)
	f.register(b)
	stored := f.mustPutBlob(a, s3, f.mint(a, s3, nil), []byte("for the owner"))
	data := make([]byte, 64<<10)
	var held []net.Conn
	hold := func(owner, sender principal) {
		c := dial(t, f)
		rawBlobPut(t, f, c, owner, sender, f.mint(owner, sender, nil), data, 1000)
		held = append(held, c)
	}
	put := func(owner, sender principal) req {
		return req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: []byte("x"), signer: &sender, token: f.mint(owner, sender, nil)}
	}
	hold(a, s1)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	e := f.expectCode(put(a, s1), 429, CodeRateLimited) // s1 already uploads to a
	if !strings.Contains(string(e), `"retry_after":2`) {
		t.Fatalf("sender busy: %s", e)
	}
	hold(a, s2)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 2 })
	f.expectCode(put(a, s3), 429, CodeRateLimited) // a has its 2 uploads
	f.expectCode(put(b, s3), 429, CodeRateLimited) // the process has its 4 − 2 uploads
	// The owner still gets its blob: downloads have slots uploads cannot take.
	if code, got := f.do(req{method: "GET", path: "/v1/blob/" + stored, signer: &a}); code != 200 || string(got) != "for the owner" {
		t.Fatalf("owner's download while uploads hold every upload slot: %d %q", code, got)
	}
	for limiter, want := range map[string]int64{"blob_sender_slots": 1, "blob_mailbox_slots": 1, "blob_slots": 1} {
		if n := f.counter(`relay_ratelimit_refused_total{limiter="` + limiter + `"}`); n != want {
			t.Errorf("%s refused %d, want %d", limiter, n, want)
		}
	}
	for _, c := range held {
		c.Close()
	}
	waitFor(t, f.s.xfers.empty)
}

// The slot accounting: downloads per mailbox and in the process; uploads
// never take the slots kept for downloads; releases give everything back.
func TestBlobTransferAccounting(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 4, 2 })
	s := f.s
	var rel []func()
	ok := func(r func(), e *apiError) {
		t.Helper()
		if e != nil {
			t.Fatalf("refused: %v", e.code)
		}
		rel = append(rel, r)
	}
	busy := func(_ func(), e *apiError) {
		t.Helper()
		if e == nil {
			t.Fatal("admitted beyond a limit")
		}
	}
	ok(s.acquireDownload("a"))
	ok(s.acquireDownload("a"))
	busy(s.acquireDownload("a")) // 2 per mailbox
	ok(s.acquireUpload(f.newUpload("b", "x")))
	ok(s.acquireUpload(f.newUpload("c", "x"))) // one per (mailbox, sender), not per sender
	busy(s.acquireDownload("b"))               // 4 in the process
	for _, r := range rel {
		r()
	}
	rel = nil
	ok(s.acquireUpload(f.newUpload("b", "x")))
	ok(s.acquireUpload(f.newUpload("b", "y")))
	busy(s.acquireUpload(f.newUpload("c", "z"))) // uploads: at most 4 − 2
	ok(s.acquireDownload("b"))
	ok(s.acquireDownload("c"))
	for _, r := range rel {
		r()
	}
	if !s.xfers.empty() {
		t.Fatal("slots not given back")
	}
}

// deadlineRecorder records the write deadlines a pacedWriter sets.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

// A download moves its write deadline forward by one window for every pace
// bytes written, so a reader that stops reading is dropped; never past the
// transfer maximum.
func TestBlobDownloadPace(t *testing.T) {
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	p := newPacedWriter(rec, http.NewResponseController(rec), 1000, time.Second)
	if _, err := p.Write(make([]byte, 3500)); err != nil {
		t.Fatal(err)
	}
	if len(rec.deadlines) != 4 { // armed at the start, then after each 1,000 bytes
		t.Fatalf("%d deadlines set", len(rec.deadlines))
	}
	for _, d := range rec.deadlines {
		if until := time.Until(d); until <= 0 || until > time.Second {
			t.Fatalf("deadline %v away", until)
		}
	}
	p.until = time.Now().Add(10 * time.Millisecond)
	p.arm()
	if d := rec.deadlines[len(rec.deadlines)-1]; d.After(p.until) {
		t.Fatal("deadline past the transfer maximum")
	}
	if rec.Body.Len() != 3500 {
		t.Fatalf("wrote %d", rec.Body.Len())
	}
}

// The "rate limits" line keeps every field it had and adds the byte
// budgets, the blob slots and, with a log budget, the log counts; the
// metrics add series and families, none removed.
func TestResourceLimitsReport(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, nil, &logs)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	f.expectFrom(hostA, depositReq(owner, sender, tok, "hello"), 201, "")
	f.expectFrom(hostA, req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: make([]byte, 700), signer: &sender, token: tok}, 201, "")
	f.s.reportLimits()
	line := lastLine(t, logs.String(), `"msg":"rate limits"`)
	dep := len(depositBody([]byte("hello")))
	want := fmt.Sprintf(`"ws_sessions_refused":0,"ws_network_refused":0,"ws_network_hard_refused":0,"bytes_peak":0,"bytes_refused":0,"bytes_busiest_per_min":%d,"blob_bytes_peak":0,"blob_bytes_refused":0,"blob_bytes_busiest_per_min":700,"blob_key_bytes_peak":0,"blob_key_bytes_refused":0,"blob_key_bytes_busiest_per_min":700,"key_bytes_peak":0,"key_bytes_refused":0,"key_bytes_busiest_per_min":%d,"blob_slots_refused":0,"blob_mailbox_slots_refused":0,"blob_sender_slots_refused":0,"blob_evicted":0}`, dep, dep)
	if !strings.Contains(line, want) {
		t.Fatalf("rate limits line:\n%s\nwant it to end with\n%s", line, want)
	}
	for _, field := range []string{"address_peak", "address_refused", "key_peak", "key_refused", "sender_peak", "register_refused", "claim_refused", "web_refused",
		"address_busiest_per_min", "addresses_seen", "key_busiest_per_min", "keys_seen", "addresses_refused", "collectors", "parked", "ws_sessions"} {
		if !strings.Contains(line, `"`+field+`":`) {
			t.Errorf("rate limits line lost %s", field)
		}
	}
	var out strings.Builder
	f.reg.WriteTo(&out)
	for _, w := range []string{
		fmt.Sprintf(`relay_ratelimit_busiest_bytes_per_minute{limiter="bytes"} %d`, dep),
		`relay_ratelimit_busiest_bytes_per_minute{limiter="blob_bytes"} 700`,
		`relay_ratelimit_allowed_total{limiter="bytes"} 1`,
		`relay_ratelimit_allowed_total{limiter="blob_bytes"} 1`,
		`relay_ratelimit_peak_permille{limiter="bytes"} 0`,
		`relay_ratelimit_refused_total{limiter="blob_slots"} 0`,
		`relay_ratelimit_refused_total{limiter="blob_mailbox_slots"} 0`,
		`relay_ratelimit_refused_total{limiter="blob_sender_slots"} 0`,
		`relay_ratelimit_refused_total{limiter="blob_evicted"} 0`,
		`relay_ratelimit_busiest_per_minute{limiter="address"}`,
	} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("metrics lack %q", w)
		}
	}
	if strings.Contains(out.String(), hostA) || strings.Contains(line, hostA) {
		t.Fatal("a client network is named")
	}
}

// With a log budget, the report carries the lines it dropped and
// suppressed in the minute, and gets through itself however full the
// budget is.
func TestLogBudgetReported(t *testing.T) {
	cfg := config.Defaults()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var logs syncBuf
	reg := metrics.New()
	s := New(cfg, st, slog.New(logbudget.New(slog.NewJSONHandler(&logs, nil), 0.001, 3)), reg)
	defer s.Close()
	for i := 0; i < 10; i++ {
		s.log.Info("request")
		s.log.Warn("replay cache full or unavailable; shedding load")
	}
	s.reportLimits()
	line := lastLine(t, logs.String(), `"msg":"rate limits"`)
	if !strings.Contains(line, `"log_dropped":7,"log_suppressed":9,"blob_evicted":0}`) {
		t.Fatalf("rate limits line: %s", line)
	}
	if n := strings.Count(logs.String(), `"msg":"request"`); n != 3 {
		t.Fatalf("%d info lines written (budget 3)", n)
	}
	var out strings.Builder
	reg.WriteTo(&out)
	if !strings.Contains(out.String(), "relay_log_lines_dropped_total 7") || !strings.Contains(out.String(), "relay_log_lines_suppressed_total 9") {
		t.Fatalf("metrics:\n%s", out.String())
	}
	s.reportLimits() // per minute
	if line := lastLine(t, logs.String(), `"msg":"rate limits"`); !strings.Contains(line, `"log_dropped":0,"log_suppressed":0,"blob_evicted":0}`) {
		t.Fatalf("second minute: %s", line)
	}
}

// A charge is given back when nothing is stored: a deposit refused after
// the charge (quota, signature, bad body), a claim the store refuses. A
// sender retrying against a full mailbox does not drain its network's
// budget. A blob upload refused after its body arrived keeps what it sent.
func TestByteChargesRefundedWhenNothingIsStored(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RateIPBytesPerSec, c.RateIPBytesBurst = 0.001, 3000
		c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 0.001, 2500
		c.MaxBlobBytes, c.MailboxMaxBlobBytes = 1000, 3000 // the claim below counts too; 1,000 kept for the owner's devices
		c.MailboxMaxMessages = 1
	})
	owner, sender, thief := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	payload := strings.Repeat("x", 1000) // a body of 1,349 bytes
	f.expectFrom(hostA, depositReq(owner, sender, tok, payload), 201, "")
	for i := 0; i < 20; i++ { // the mailbox is full: refused, refunded
		f.expectFrom(hostA, depositReq(owner, sender, tok, payload), 429, CodeQuotaExceeded)
		f.expectFrom(hostA, depositReq(owner, thief, tok, payload), 401, CodeSignatureInvalid)
		f.expectFrom(hostA, req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: []byte("not json"), signer: &sender, token: tok}, 400, CodeBadRequest)
	}
	// 1,651 bytes left of 3,000: a 1,000-byte claim fits, then nothing more.
	f.expectFrom(hostA, req{method: "PUT", path: "/v1/claim", body: make([]byte, 1000), signer: &owner}, 201, "")
	f.expectFrom(hostA, req{method: "PUT", path: "/v1/claim", body: make([]byte, 1000), signer: &owner}, 429, CodeRateLimited)

	// Blobs: one stored (1,000 of 2,500). An upload refused over the
	// mailbox's blob storage is refused before its body (0.9.2, §6.8) and
	// charged nothing. An upload refused after its body arrived (here its
	// signature) keeps the bytes it sent charged: a trickle that ends in a
	// refusal is not free.
	blob := func(signer principal) req {
		return req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: make([]byte, 1000), signer: &signer, token: tok}
	}
	f.expectFrom(hostA, blob(sender), 201, "")
	for i := 0; i < 5; i++ {
		if e := f.expectFrom(hostA, blob(sender), 429, CodeQuotaExceeded); e.Quota != "mailbox_blobs" {
			t.Fatalf("quota %q", e.Quota)
		}
	}
	other := newPrincipal(4) // a mailbox with room
	f.register(other)
	toOther := func(signer principal) req {
		return req{method: "PUT", path: "/v1/blob/" + other.mbx, body: make([]byte, 1000), signer: &signer, token: f.mint(other, sender, nil)}
	}
	f.expectFrom(hostA, toOther(thief), 401, CodeSignatureInvalid)
	f.expectFrom(hostA, toOther(sender), 429, CodeRateLimited) // 500 left
	key := rateKey(netip.MustParseAddr(hostA))
	if ok, _ := f.s.blobByteLimit.AllowN(key, 500, f.clk.now()); !ok {
		t.Fatal("the budget-refused upload was charged")
	}
	if ok, _ := f.s.blobByteLimit.AllowN(key, 1, f.clk.now()); ok {
		t.Fatal("the quota-refused upload's bytes were given back")
	}
}

// A download is charged at most the burst (a blob stored under a larger
// budget can still be fetched), and a network whose blob budget is empty
// is refused before the store is read.
func TestBlobDownloadCharge(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.MaxBlobBytes = 3000
		c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 0.001, 1<<30
	})
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	id := f.mustPutBlob(owner, sender, f.mint(owner, sender, nil), make([]byte, 3000))
	f.cfg.RateBlobBytesBurst = 2000 // lowered below the blob's size
	f.restart()
	get := req{method: "GET", path: "/v1/blob/" + id, signer: &owner}
	if code, _, _ := f.from(hostA, get); code != 200 {
		t.Fatalf("a blob larger than the burst: %d", code)
	}
	opens := &countingBlobs{BlobStore: f.s.blobs}
	f.s.blobs = opens
	f.expectFrom(hostA, get, 429, CodeRateLimited)
	if opens.n != 0 {
		t.Fatalf("an empty budget still read the store %d times", opens.n)
	}
}

type countingBlobs struct {
	store.BlobStore
	n int
}

func (c *countingBlobs) OpenBlob(ctx context.Context, mailbox, id string) (store.BlobInfo, io.ReadCloser, error) {
	c.n++
	return c.BlobStore.OpenBlob(ctx, mailbox, id)
}

// Within the log budget, the lines of successful requests that change a
// mailbox's state draw on a bucket of their own: a flood of other requests,
// failed registrations included, does not crowd them out.
func TestAuditLinesHaveTheirOwnBudget(t *testing.T) {
	var logs syncBuf
	f := newFixtureFull(t, nil, &logs, nil)
	f.s.log = slog.New(logbudget.New(slog.NewJSONHandler(&logs, nil), 0.001, 5))
	owner := newPrincipal(1)
	f.register(owner) // audit
	for i := 0; i < 20; i++ {
		f.do(req{method: "GET", path: "/v1/claim/" + strings.Repeat("a", 26)}) // 404s at info
	}
	for i := 0; i < 10; i++ { // failed registrations (anyone can send them) stay on the ordinary budget
		f.do(req{method: "POST", path: "/v1/register", body: []byte("{}")})
	}
	for i := byte(0); i < 3; i++ {
		f.register(newPrincipal(50 + i))
	}
	if n := strings.Count(logs.String(), `"route":"POST /v1/register"`); n != 4 {
		t.Fatalf("%d registration lines written, want the 4 that succeeded", n)
	}
	if n := strings.Count(logs.String(), `"route":"GET /v1/claim/{claim_id}"`); n != 5 {
		t.Fatalf("%d other lines written (budget 5)", n)
	}
}

// An upload whose body stalls keeps charged the bytes it sent (holding a
// slot with a trickle is not free); the rest of its declared length is
// given back.
func TestStalledUploadKeepsWhatItSent(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) { c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 0.001, 100_000 },
		func(*fixture) []Option { return []Option{WithBlobPaceWindow(300 * time.Millisecond)} })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	c := dial(t, f)
	rawBlobPut(t, f, c, owner, sender, f.mint(owner, sender, nil), make([]byte, 64<<10), 1000)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != 400 {
		t.Fatalf("stalled upload: %v %v", resp, err)
	}
	waitFor(t, f.s.xfers.empty)
	key := rateKey(netip.MustParseAddr("127.0.0.1"))
	if ok, _ := f.s.blobByteLimit.AllowN(key, 99_000, f.clk.now()); !ok {
		t.Fatal("the unsent part was not given back")
	}
	if ok, _ := f.s.blobByteLimit.AllowN(key, 1, f.clk.now()); ok {
		t.Fatal("the 1,000 bytes sent were given back too")
	}
}

// The blob byte budget is per authenticated key (the sender's for an
// upload, the mailbox owner's for a download), with a ceiling per
// network: vaults behind one address each have their own budget, and the
// address as a whole has the ceiling.
func TestBlobKeyBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.MaxBlobBytes, c.MailboxMaxBlobBytes = 1000, 1<<20
		c.MaxSenderBlobBytes = 1 << 20 // these uploads test the byte budgets, not the share (§6.8)
		c.RateBlobKeyBytesPerSec, c.RateBlobKeyBytesBurst = 0.001, 2000
		c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 0.001, 5000
	})
	owner := newPrincipal(1)
	f.register(owner)
	s1, s2, s3 := newPrincipal(11), newPrincipal(12), newPrincipal(13)
	put := func(sender principal) req {
		return req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: make([]byte, 1000), signer: &sender, token: f.mint(owner, sender, nil)}
	}
	f.expectFrom(hostA, put(s1), 201, "")
	f.expectFrom(hostA, put(s1), 201, "")
	f.expectFrom(hostA, put(s1), 429, CodeRateLimited) // s1's 2,000
	f.expectFrom(hostA, put(s2), 201, "")              // another vault behind the same address
	f.expectFrom(hostA, put(s2), 201, "")
	f.expectFrom(hostA, put(s3), 201, "")              // 5,000: the network's ceiling
	f.expectFrom(hostA, put(s3), 429, CodeRateLimited) // s3 has 1,000 left, the network none
	f.expectFrom(hostB, put(s3), 201, "")              // another network: s3's last 1,000
	if k, n := f.counter(`relay_ratelimit_refused_total{limiter="blob_key_bytes"}`), f.counter(`relay_ratelimit_refused_total{limiter="blob_bytes"}`); k != 1 || n != 1 {
		t.Fatalf("refused: %d by the key budget, %d by the network ceiling", k, n)
	}
	// The ceiling's refusal gave s3's key charge back: it had 1,000 left
	// for hostB, which it used.
	// Downloads draw on the owner's key: it has 2,000.
	var id string
	{
		code, b := f.do(put(newPrincipal(14)))
		if code != 201 {
			t.Fatalf("upload over loopback: %d %s", code, b)
		}
		var out struct {
			BlobID string `json:"blob_id"`
		}
		json.Unmarshal(b, &out)
		id = out.BlobID
	}
	get := req{method: "GET", path: "/v1/blob/" + id, signer: &owner}
	f.expectFrom(hostB, get, 200, "")
	f.expectFrom(hostB, get, 200, "")
	f.expectFrom(hostB, get, 429, CodeRateLimited) // the owner's key is spent; hostB's ceiling is not
}

// The token's sub is written by the mailbox owner; the sender's key is
// proved only by the signature after the body. So an upload is charged to
// its sub's key budget only once that signature has verified: nobody can
// drain a vault's budget by minting tokens that name its key.
func TestForgedSubCannotDrainAKeyBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.MaxBlobBytes, c.MailboxMaxBlobBytes = 1000, 1<<20
		c.MaxSenderBlobBytes = 1 << 20 // these uploads test the byte budgets, not the share (§6.8)
		c.RateBlobKeyBytesPerSec, c.RateBlobKeyBytesBurst = 0.001, 2000
	})
	mallory, victim, friend := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(mallory)
	f.register(friend)
	forged := f.mint(mallory, victim, nil) // sub = the victim's key, signed by mallory's mailbox
	for i := 0; i < 10; i++ {
		f.expectFrom(hostA, req{method: "PUT", path: "/v1/blob/" + mallory.mbx, body: make([]byte, 1000), signer: &mallory, token: forged}, 401, CodeSignatureInvalid)
	}
	tok := f.mint(friend, victim, nil)
	up := req{method: "PUT", path: "/v1/blob/" + friend.mbx, body: make([]byte, 1000), signer: &victim, token: tok}
	f.expectFrom(hostB, up, 201, "")
	f.expectFrom(hostB, up, 201, "")
	f.expectFrom(hostB, up, 429, CodeRateLimited) // now the victim's own 2,000 are spent
}

// Blob uploads draw on the per-sender limit only after the signature, as
// deposits do: tokens that name another's key cannot empty that key's
// sender budget, which its deposits share.
func TestForgedSubCannotDrainASenderBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateSenderPerSec, c.RateSenderBurst = 0.001, 2 })
	mallory, victim, friend := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(mallory)
	f.register(friend)
	forged := f.mint(mallory, victim, nil)
	for i := 0; i < 10; i++ {
		f.expectFrom(hostA, req{method: "PUT", path: "/v1/blob/" + mallory.mbx, body: []byte("x"), signer: &mallory, token: forged}, 401, CodeSignatureInvalid)
	}
	tok := f.mint(friend, victim, nil)
	f.expectFrom(hostB, depositReq(friend, victim, tok, "1"), 201, "")
	f.expectFrom(hostB, req{method: "PUT", path: "/v1/blob/" + friend.mbx, body: []byte("2"), signer: &victim, token: tok}, 201, "")
	f.expectFrom(hostB, depositReq(friend, victim, tok, "3"), 429, CodeRateLimited) // now its own 2 are spent
}

// A key in debt is told how long its debt takes to pay off.
func TestBlobKeyDebtRetryAfter(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.MaxBlobBytes, c.MailboxMaxBlobBytes = 1000, 1<<20
		c.MaxSenderBlobBytes = 1 << 20 // these uploads test the byte budgets, not the share (§6.8)
		c.RateBlobKeyBytesPerSec, c.RateBlobKeyBytesBurst = 100, 1500
	})
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	up := req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: make([]byte, 1000), signer: &sender, token: f.mint(owner, sender, nil)}
	f.expectFrom(hostA, up, 201, "") // 500 left
	f.expectFrom(hostA, up, 201, "") // charged after the fact: 500 in debt
	if e := f.expectFrom(hostA, up, 429, CodeRateLimited); e.RetryAfter != 6 {
		t.Fatalf("retry_after %d, want 6 (501 bytes at 100 a second)", e.RetryAfter)
	}
}

// The deposit and claim byte budget is per key (the depositor's, once its
// signature verified; a claim's creator), with a ceiling per network:
// vaults behind one address each have their own budget, the address as a
// whole the ceiling. A key is charged after the fact (it may go into
// debt), and looked at before the body: an empty one is refused unread.
func TestDepositKeyBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RateKeyBytesPerSec, c.RateKeyBytesBurst = 0.001, 3000
		c.RateIPBytesPerSec, c.RateIPBytesBurst = 0.001, 6000
	})
	owner, s1, s2, s3 := newPrincipal(1), newPrincipal(11), newPrincipal(12), newPrincipal(13)
	f.register(owner)
	dep := func(sender principal) req {
		return depositReq(owner, sender, f.mint(owner, sender, nil), strings.Repeat("x", 1000)) // a body of 1,349 bytes
	}
	f.expectFrom(hostA, dep(s1), 201, "")
	f.expectFrom(hostA, dep(s1), 201, "")
	f.expectFrom(hostA, dep(s1), 201, "")              // 302 left: let through, charged into debt
	f.expectFrom(hostA, dep(s1), 429, CodeRateLimited) // s1's key is in debt: refused unread
	f.expectFrom(hostA, dep(s2), 201, "")              // another vault behind the same address: 5,396 of the network's 6,000
	f.expectFrom(hostA, dep(s2), 429, CodeRateLimited) // the network's ceiling
	f.expectFrom(hostB, dep(s3), 201, "")              // another network
	if k, n := f.counter(`relay_ratelimit_refused_total{limiter="key_bytes"}`), f.counter(`relay_ratelimit_refused_total{limiter="bytes"}`); k != 1 || n != 1 {
		t.Fatalf("refused: %d by the key budget, %d by the network ceiling", k, n)
	}
	// Claims are charged to their creator's key.
	f.expectFrom(hostB, req{method: "PUT", path: "/v1/claim", body: make([]byte, 2000), signer: &owner}, 201, "")
	f.expectFrom(hostB, req{method: "PUT", path: "/v1/claim", body: make([]byte, 2000), signer: &owner}, 429, CodeRateLimited)
}

// The token's sub is written by the mailbox owner: a deposit is charged
// to its sender's key only once the signature has proved it, so tokens
// naming another's key cannot drain that key's deposit budget.
func TestForgedSubCannotDrainADepositBudget(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateKeyBytesPerSec, c.RateKeyBytesBurst = 0.001, 3000 })
	mallory, victim, friend := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(mallory)
	f.register(friend)
	forged := f.mint(mallory, victim, nil)
	for i := 0; i < 10; i++ {
		f.expectFrom(hostA, depositReq(mallory, mallory, forged, strings.Repeat("x", 1000)), 401, CodeSignatureInvalid)
	}
	tok := f.mint(friend, victim, nil)
	f.expectFrom(hostB, depositReq(friend, victim, tok, strings.Repeat("x", 1000)), 201, "")
	f.expectFrom(hostB, depositReq(friend, victim, tok, strings.Repeat("x", 1000)), 201, "")
	// A deposit that is then not stored gives its key charge back.
	f.expectFrom(hostB, req{method: "POST", path: "/v1/mailbox/" + friend.mbx, body: []byte("not json"), signer: &victim, token: tok}, 400, CodeBadRequest)
	f.expectFrom(hostB, depositReq(friend, victim, tok, strings.Repeat("x", 100)), 201, "")
}
