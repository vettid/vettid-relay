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
	f := newFixtureWith(t, func(c *config.Config) { c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 1, 1 },
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
	waitFor(t, func() bool { return len(f.s.blobSlots) == 1 })
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	began := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 400 || !resp.Close || time.Since(began) > 2*time.Second {
		t.Fatalf("stalled upload: %v %v after %v", resp, err, time.Since(began))
	}
	waitFor(t, func() bool { return len(f.s.blobSlots) == 0 })
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

// At most RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX transfers per mailbox and
// RELAY_MAX_CONCURRENT_BLOB_TRANSFERS per process; beyond either, 429
// rate_limited with retry_after 2, counted.
func TestBlobSlotsPerMailboxAndProcess(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) { c.MaxConcurrentBlobTransfers, c.MaxBlobTransfersPerMailbox = 3, 2 },
		func(*fixture) []Option { return []Option{WithBlobPaceWindow(3 * time.Second)} })
	a, b, sender := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(a)
	f.register(b)
	ta, tb := f.mint(a, sender, nil), f.mint(b, sender, nil)
	data := make([]byte, 64<<10)
	var held []net.Conn
	hold := func(owner principal, tok string) {
		c := dial(t, f)
		rawBlobPut(t, f, c, owner, sender, tok, data, 1000)
		held = append(held, c)
	}
	hold(a, ta)
	hold(a, ta)
	waitFor(t, func() bool { return len(f.s.blobSlots) == 2 })
	e := f.expectCode(req{method: "PUT", path: "/v1/blob/" + a.mbx, body: []byte("third"), signer: &sender, token: ta}, 429, CodeRateLimited)
	if e := string(e); !strings.Contains(e, `"retry_after":2`) {
		t.Fatalf("mailbox full: %s", e)
	}
	f.mustPutBlob(b, sender, tb, []byte("another mailbox")) // 3 of 3 for a moment
	hold(b, tb)
	waitFor(t, func() bool { return len(f.s.blobSlots) == 3 })
	f.expectCode(req{method: "PUT", path: "/v1/blob/" + b.mbx, body: []byte("full"), signer: &sender, token: tb}, 429, CodeRateLimited)
	// A download takes a slot of its owner's mailbox too.
	f.expectCode(req{method: "GET", path: "/v1/blob/" + strings.Repeat("0", 26), signer: &a}, 429, CodeRateLimited)
	if m, p := f.counter(`relay_ratelimit_refused_total{limiter="blob_mailbox_slots"}`), f.counter(`relay_ratelimit_refused_total{limiter="blob_slots"}`); m != 2 || p != 1 {
		t.Fatalf("refusals: %d mailbox, %d process", m, p)
	}
	for _, c := range held {
		c.Close()
	}
	waitFor(t, func() bool { return len(f.s.blobSlots) == 0 })
	f.blobMailboxesEmpty(t)
}

func (f *fixture) blobMailboxesEmpty(t *testing.T) {
	t.Helper()
	waitFor(t, func() bool {
		f.s.blobMu.Lock()
		defer f.s.blobMu.Unlock()
		return len(f.s.blobMbx) == 0
	})
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
	want := fmt.Sprintf(`"ws_sessions_refused":0,"ws_network_refused":0,"ws_network_hard_refused":0,"bytes_peak":0,"bytes_refused":0,"bytes_busiest_per_min":%d,"blob_bytes_peak":0,"blob_bytes_refused":0,"blob_bytes_busiest_per_min":700,"blob_slots_refused":0,"blob_mailbox_slots_refused":0}`, dep)
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
	if !strings.Contains(line, `"log_dropped":7,"log_suppressed":9}`) {
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
	if line := lastLine(t, logs.String(), `"msg":"rate limits"`); !strings.Contains(line, `"log_dropped":0,"log_suppressed":0}`) {
		t.Fatalf("second minute: %s", line)
	}
}
