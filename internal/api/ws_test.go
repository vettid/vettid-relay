package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

func (f *fixture) dialWS(owner principal) (*websocket.Conn, *http.Response, error) {
	return f.dialWSFrom(owner, "")
}

// dialWSFrom dials as the client address addr (the relay must trust the
// proxy header); "" is the test's own address.
func (f *fixture) dialWSFrom(owner principal, addr string) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
	if addr != "" {
		h.Set("X-Forwarded-For", addr)
	}
	auth.SetHeaders(h, owner.priv, "GET", "/v1/mailbox/ws", f.sigTime(), auth.BodyHash(nil))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.ts.URL, "http")+"/v1/mailbox/ws", &websocket.DialOptions{HTTPHeader: h})
}

func readFrame(t *testing.T, c *websocket.Conn, within time.Duration) wireMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	typ, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var m wireMessage
	if typ != websocket.MessageText || json.Unmarshal(data, &m) != nil || m.MsgID == "" {
		t.Fatalf("bad frame %q", data)
	}
	return m
}

func TestWebSocketCollect(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	early := f.mustDeposit(owner, sender, tok, []byte("before connect"))

	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	if m := readFrame(t, c, 2*time.Second); m.MsgID != early || string(m.Payload) != "before connect" || m.Sender != sender.b64 {
		t.Fatalf("backlog frame %+v", m)
	}
	// Live push: deposit → frame in well under a second.
	start := time.Now()
	live := f.mustDeposit(owner, sender, tok, []byte("live"))
	m := readFrame(t, c, 2*time.Second)
	if m.MsgID != live || time.Since(start) >= time.Second {
		t.Fatalf("live frame %+v after %v", m, time.Since(start))
	}
	t.Logf("ws deposit→frame latency: %v", time.Since(start))

	// Ack over the socket deletes both.
	ctx := context.Background()
	for _, id := range []string{early, live} {
		if err := c.Write(ctx, websocket.MessageText, []byte(`{"ack":"`+id+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	// Acks are processed asynchronously: past every lease, the mailbox must
	// become (and stay) empty — an unacked message would keep coming back.
	waitFor(t, func() bool {
		f.clk.add(2 * f.cfg.VisibilityTimeout)
		got := f.collect(owner, "")
		return len(got.Messages) == 0
	})
	f.clk.add(2 * f.cfg.VisibilityTimeout)
	if got := f.collect(owner, ""); len(got.Messages) != 0 {
		t.Fatalf("acked messages came back: %+v", got)
	}
}

func TestWebSocketRedeliversUnacked(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	id := f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("x"))
	if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
		t.Fatal("first delivery")
	}
	// Not acked: after the visibility timeout the session pushes it again.
	f.clk.add(f.cfg.VisibilityTimeout + time.Second)
	f.s.hub.notify(owner.mbx) // the lease timer runs on wall time; nudge the loop
	if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
		t.Fatal("unacked message not redelivered")
	}
}

func TestWebSocketAuthAndDrain(t *testing.T) {
	f := newFixture(t, nil)
	owner, stranger := newPrincipal(1), newPrincipal(2)
	f.register(owner)

	// Unregistered key: HTTP error before upgrade.
	if _, resp, err := f.dialWS(stranger); err == nil || resp == nil || resp.StatusCode != 404 {
		t.Fatalf("stranger upgrade: %v %v", resp, err)
	}
	// Unsigned upgrade.
	ctx := context.Background()
	if _, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.ts.URL, "http")+"/v1/mailbox/ws", nil); err == nil || resp.StatusCode != 401 {
		t.Fatalf("unsigned upgrade: %v", err)
	}

	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	waitFor(t, func() bool { return f.s.m.wsSessions.Value() == 1 })
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	errc := make(chan error, 1)
	go func() { _, _, err := c.Read(ctx); errc <- err }()
	if err := f.s.Drain(dctx); err != nil {
		t.Fatalf("drain did not finish: %v", err)
	}
	select {
	case err := <-errc:
		var ce websocket.CloseError
		if !errors.As(err, &ce) || ce.Code != websocket.StatusGoingAway {
			t.Fatalf("want going-away close, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client not closed on drain")
	}
}

func TestWebSocketBadFrame(t *testing.T) {
	f := newFixture(t, nil)
	owner := newPrincipal(1)
	f.register(owner)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	ctx := context.Background()
	c.Write(ctx, websocket.MessageText, []byte(`{"hello":1}`))
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _, err = c.Read(rctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.StatusPolicyViolation {
		t.Fatalf("want policy violation, got %v", err)
	}
}

// countingStore counts the calls that a caller-supplied message or blob id
// can cause.
type countingStore struct {
	store.Backend
	acks, blobOpens, blobDeletes atomic.Int64
	pings                        atomic.Int64
	collects, ranges             atomic.Int64  // Collect; CollectRange with a bound
	shortRange                   atomic.Int64  // > 0: a bounded CollectRange returns at most this many of what it leased
	down                         atomic.Bool   // Ping fails
	hang                         atomic.Bool   // Ping does not answer until its context ends
	slowPing                     time.Duration // Ping takes this long (set before use)
}

func (c *countingStore) Ping(ctx context.Context) error {
	c.pings.Add(1)
	time.Sleep(c.slowPing)
	if c.hang.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	if c.down.Load() {
		return errors.New("store down")
	}
	return c.Backend.Ping(ctx)
}

func (c *countingStore) Ack(ctx context.Context, mailbox, msgID string) (bool, error) {
	c.acks.Add(1)
	return c.Backend.Ack(ctx, mailbox, msgID)
}

func (c *countingStore) Collect(ctx context.Context, mailbox string, max int, visibility time.Duration) ([]store.Message, time.Time, error) {
	c.collects.Add(1)
	return c.Backend.Collect(ctx, mailbox, max, visibility)
}

// CollectRange can lose part of a bounded batch, as a collector does whose
// candidates another collector leased first: those stay leased, unsent.
func (c *countingStore) CollectRange(ctx context.Context, mailbox, after, upTo string, max int, visibility time.Duration) ([]store.Message, time.Time, error) {
	c.ranges.Add(1)
	msgs, next, err := c.Backend.CollectRange(ctx, mailbox, after, upTo, max, visibility)
	if n := int(c.shortRange.Load()); n > 0 && upTo != "" && len(msgs) > n {
		msgs = msgs[:n]
	}
	return msgs, next, err
}

func (c *countingStore) OpenBlob(ctx context.Context, mailbox, id string) (store.BlobInfo, io.ReadCloser, error) {
	c.blobOpens.Add(1)
	return c.Backend.OpenBlob(ctx, mailbox, id)
}

func (c *countingStore) DeleteBlob(ctx context.Context, mailbox, id string) error {
	c.blobDeletes.Add(1)
	return c.Backend.DeleteBlob(ctx, mailbox, id)
}

// countStore restarts the relay on a store that counts those calls (the
// in-memory limiters start full again).
func (f *fixture) countStore() *countingStore {
	f.t.Helper()
	cs, inner := &countingStore{}, f.newSt
	f.newSt = func() store.Backend { cs.Backend = inner(); return cs }
	f.restart()
	return cs
}

// unknownID returns the i-th of a series of well-formed ids that name no
// message.
func unknownID(i int) string { return fmt.Sprintf("01J00000000000000000000%03d", i) }

func sendAck(c *websocket.Conn, id string) error {
	return c.Write(context.Background(), websocket.MessageText, []byte(`{"ack":"`+id+`"}`))
}

// expectWSClose reads until the relay closes the session and checks the
// close code and reason.
func expectWSClose(t *testing.T, c *websocket.Conn, code websocket.StatusCode, reason string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		if _, _, err := c.Read(ctx); err != nil {
			var ce websocket.CloseError
			if !errors.As(err, &ce) || ce.Code != code || ce.Reason != reason {
				t.Fatalf("want close %d %q, got %v", code, reason, err)
			}
			return
		}
	}
}

// Ack frames the relay did not ask for (no message was sent on the session)
// are charged like DELETE /v1/mailbox/{msg_id}: the key's bucket and the
// network's flood guard. When one is empty the session ends with 1013 "try
// again later" (1008 is for frames that are malformed), and nothing more
// reaches the store.
func TestWebSocketUnsolicitedAcksAreRateLimited(t *testing.T) {
	for name, mut := range map[string]func(*config.Config){
		"per key":     func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 5 },
		"flood guard": func(c *config.Config) { c.RateIPPerSec, c.RateIPBurst = 0.001, 5 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, mut)
			cs := f.countStore()
			owner := newPrincipal(1)
			f.register(owner) // one token
			c, _, err := f.dialWS(owner)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()
			// The upgrade took the second token: three are left.
			for i := 0; i < 50; i++ {
				if sendAck(c, unknownID(i)) != nil {
					break // closed
				}
			}
			expectWSClose(t, c, websocket.StatusTryAgainLater, CodeRateLimited)
			if n := cs.acks.Load(); n != 3 {
				t.Fatalf("%d acks reached the store, want 3", n)
			}
		})
	}
}

// A client that acks what it is sent is never limited, however little is
// left of its key's bucket and however fast it drains a backlog: every
// message sent on the session pays for its ack. The credit is used up by
// exactly those acks.
func TestWebSocketAcksOfDeliveredMessagesAreNotLimited(t *testing.T) {
	// Two tokens: the registration and the upgrade. No refill.
	f := newFixture(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 2 })
	cs := f.countStore()
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	const backlog = 2*wsBatch + 6
	for i := 0; i < backlog; i++ {
		f.mustDeposit(owner, sender, tok, []byte("x"))
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	for i := 0; i < backlog; i++ {
		if err := sendAck(c, readFrame(t, c, 2*time.Second).MsgID); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return f.s.m.acks.Value() == backlog })
	// Still open, and live messages are acked the same way.
	live := f.mustDeposit(owner, sender, tok, []byte("live"))
	if m := readFrame(t, c, 2*time.Second); m.MsgID != live {
		t.Fatalf("live frame %+v", m)
	}
	if err := sendAck(c, live); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return f.s.m.acks.Value() == backlog+1 })
	// One ack more than was delivered needs a token, and there is none.
	sendAck(c, unknownID(0))
	expectWSClose(t, c, websocket.StatusTryAgainLater, CodeRateLimited)
	if n := cs.acks.Load(); n != backlog+1 {
		t.Fatalf("%d acks reached the store, want %d", n, backlog+1)
	}
}

// An ack frame whose id is not a message id as the relay issues them ends
// the session before the store is asked.
func TestWebSocketMalformedAckID(t *testing.T) {
	f := newFixture(t, nil)
	cs := f.countStore()
	owner := newPrincipal(1)
	f.register(owner)
	for _, id := range malformedIDs {
		if len(id) > wsReadLimit/2 {
			continue // refused by the frame size limit before it is parsed
		}
		c, _, err := f.dialWS(owner)
		if err != nil {
			t.Fatal(err)
		}
		sendAck(c, id)
		expectWSClose(t, c, websocket.StatusPolicyViolation, `expected {"ack":"<msg_id>"}`)
		c.CloseNow()
		waitFor(t, func() bool { return f.s.hub.collectors() == 0 })
	}
	if n := cs.acks.Load(); n != 0 {
		t.Fatalf("%d malformed acks reached the store", n)
	}
}

// A relay process carries at most RELAY_MAX_WS_SESSIONS sessions; long-poll
// is not affected, and a slot is free again when a session ends.
func TestWebSocketSessionCap(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, func(c *config.Config) { c.MaxWebSocketSessions = 2 }, &logs)
	a, b, late := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	for _, p := range []principal{a, b, late} {
		f.register(p)
	}
	ca, _, err := f.dialWS(a)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.CloseNow()
	cb, _, err := f.dialWS(b)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.CloseNow()
	_, resp, err := f.dialWS(late)
	if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "5" {
		t.Fatalf("upgrade beyond the maximum: %v %v", resp, err)
	}
	if got := f.collect(late, ""); len(got.Messages) != 0 {
		t.Fatalf("long-poll at the session maximum: %+v", got)
	}
	// The refusal is counted with the limiters' (its own label) and
	// reported in the `rate limits` line, per minute like the others.
	if n := f.counter(`relay_ratelimit_refused_total{limiter="ws_sessions"}`); n != 1 {
		t.Fatalf("refused counter %d, want 1", n)
	}
	f.s.reportLimits()
	f.s.reportLimits()
	if out := logs.String(); !strings.Contains(out, `"ws_sessions_refused":1`) || !strings.Contains(out, `"ws_sessions_refused":0`) {
		t.Fatalf("rate limits lines lack the refusals of full processes:\n%s", out)
	}
	ca.CloseNow()
	waitFor(t, func() bool { return f.s.wsOpen.Load() == 1 })
	cl, _, err := f.dialWS(late)
	if err != nil {
		t.Fatalf("upgrade after a session ended: %v", err)
	}
	cl.CloseNow()
}

// A failed upgrade gives its session slot and its collector slot back.
func TestWebSocketFailedUpgradeReleasesSlot(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxWebSocketSessions, c.MaxCollectorsPerMailbox = 1, 1 })
	owner := newPrincipal(1)
	f.register(owner)
	for i := 0; i < 3; i++ {
		// Properly signed, but not a WebSocket handshake: Accept refuses it.
		if code, b := f.do(req{method: "GET", path: "/v1/mailbox/ws", signer: &owner}); code < 400 || code == http.StatusTooManyRequests {
			t.Fatalf("plain GET %d: %d %s", i, code, b)
		}
	}
	if n, c := f.s.wsOpen.Load(), f.s.hub.collectors(); n != 0 || c != 0 {
		t.Fatalf("slots held after failed upgrades: %d sessions, %d collectors", n, c)
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatalf("upgrade after failed upgrades: %v", err)
	}
	c.CloseNow()
}

// A session that does not ack is sent a window of messages and then no
// more: the relay takes no further leases for it until it acks or the
// leases end, and then again only a window.
func TestWebSocketWindow(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	const stored = wsWindow + 2*wsBatch + 8
	for i := 0; i < stored; i++ {
		f.mustDeposit(owner, sender, tok, []byte("x"))
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	sentStays := func(want int64) {
		t.Helper()
		waitFor(t, func() bool { return f.s.m.collected.Value() >= want })
		time.Sleep(200 * time.Millisecond)
		if n := f.s.m.collected.Value(); n != want {
			t.Fatalf("%d messages sent, want %d", n, want)
		}
	}
	sentStays(wsWindow)
	var got []string
	for i := 0; i < wsWindow; i++ {
		got = append(got, readFrame(t, c, 2*time.Second).MsgID)
	}
	// More deposits do not make it lease.
	f.mustDeposit(owner, sender, tok, []byte("x"))
	sentStays(wsWindow)
	// Acks short of a batch make no room; a whole batch does, for a batch.
	for _, id := range got[:wsBatch-1] {
		sendAck(c, id)
	}
	waitFor(t, func() bool { return f.s.m.acks.Value() == wsBatch-1 })
	sentStays(wsWindow)
	sendAck(c, got[wsBatch-1])
	sentStays(wsWindow + wsBatch)
	for i := 0; i < wsBatch; i++ {
		readFrame(t, c, 2*time.Second)
	}
	// The leases end: everything unacked is anyone's again. The session is
	// sent the messages it has not been sent yet (the 40 that did not fit
	// and the one deposited since), and of the unacked ones again as many
	// as leave a batch of the window free.
	f.clk.add(f.cfg.VisibilityTimeout + time.Second)
	f.s.hub.notify(owner.mbx)
	const unsent = stored - wsWindow - wsBatch + 1
	sentStays(wsWindow + wsBatch + unsent + (wsWindow - wsBatch - unsent))
}

// Sending a message again after its lease ended does not add to what the
// session may ack without charge: after any number of rounds it is owed
// one ack per message, by id.
func TestWebSocketRedeliveryGrantsNoExtraAcks(t *testing.T) {
	// Two tokens: the registration and the upgrade. No refill.
	f := newFixture(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 2 })
	cs := f.countStore()
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	const stored, rounds = 11, 6
	ids := map[string]bool{}
	for i := 0; i < stored; i++ {
		ids[f.mustDeposit(owner, sender, tok, []byte("x"))] = true
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	for r := 0; r < rounds; r++ {
		if r > 0 {
			f.clk.add(f.cfg.VisibilityTimeout + time.Second)
			f.s.hub.notify(owner.mbx)
		}
		for i := 0; i < stored; i++ {
			if m := readFrame(t, c, 2*time.Second); !ids[m.MsgID] {
				t.Fatalf("round %d: unexpected frame %+v", r, m)
			}
		}
	}
	// One ack for each message is owed, and nothing else.
	for id := range ids {
		sendAck(c, id)
	}
	waitFor(t, func() bool { return f.s.m.acks.Value() == stored })
	for i := 0; i < stored*(rounds-1); i++ {
		if sendAck(c, unknownID(i)) != nil {
			break
		}
	}
	expectWSClose(t, c, websocket.StatusTryAgainLater, CodeRateLimited)
	if n := cs.acks.Load(); n != stored {
		t.Fatalf("%d acks reached the store, want %d", n, stored)
	}
}

// An ack for a message that was sent on another session is a request like
// any other: it needs a token.
func TestWebSocketCrossSessionAckIsCharged(t *testing.T) {
	// Three tokens: the registration and two upgrades.
	f := newFixture(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 3 })
	cs := f.countStore()
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	a, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer a.CloseNow()
	id := f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("x"))
	if m := readFrame(t, a, 2*time.Second); m.MsgID != id {
		t.Fatalf("frame %+v", m)
	}
	b, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer b.CloseNow()
	sendAck(b, id)
	expectWSClose(t, b, websocket.StatusTryAgainLater, CodeRateLimited)
	if n := cs.acks.Load(); n != 0 {
		t.Fatalf("%d acks reached the store from the other session", n)
	}
	// The session it was sent on acks it without a token.
	sendAck(a, id)
	waitFor(t, func() bool { return f.s.m.acks.Value() == 1 })
}

// The window does not depend on the mailbox quota: a relay without one
// (RELAY_MAILBOX_MAX_MESSAGES=0) still owes a session the acks of what it
// was sent.
func TestWebSocketAcksWithoutMailboxQuota(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.MailboxMaxMessages = 0
		c.RateKeyPerSec, c.RateKeyBurst = 0.001, 2
	})
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	for i := int64(1); i <= 3; i++ {
		id := f.mustDeposit(owner, sender, tok, []byte("x"))
		if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
			t.Fatalf("frame %+v", m)
		}
		sendAck(c, id)
		waitFor(t, func() bool { return f.s.m.acks.Value() == i })
	}
}

// refusing is a limiter that admits its first n requests and then none:
// what a limiter answers when it cannot admit (the shared one unreachable
// and the per-process fallback full or empty).
type refusing struct{ left atomic.Int64 }

func (l *refusing) Allow(string, time.Time) (bool, time.Duration) {
	return l.left.Add(-1) >= 0, time.Second
}

// When the limiter cannot admit, a session keeps what it is owed (acks of
// what it was sent need no limiter) and loses everything else: closed.
func TestWebSocketAcksWhenLimiterRefuses(t *testing.T) {
	lim := &refusing{}
	lim.left.Store(2) // the registration and the upgrade
	f := newFixtureWith(t, nil, func(*fixture) []Option { return []Option{WithRateLimiters(Limiters{Key: lim})} })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	id := f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("x"))
	if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
		t.Fatalf("frame %+v", m)
	}
	sendAck(c, id)
	waitFor(t, func() bool { return f.s.m.acks.Value() == 1 })
	sendAck(c, unknownID(0))
	expectWSClose(t, c, websocket.StatusTryAgainLater, CodeRateLimited)
}

func TestAckWindow(t *testing.T) {
	var w ackWindow
	t0 := time.Unix(1_800_000_000, 0)
	until := t0.Add(time.Minute)
	for i := 0; i < wsWindow; i++ {
		if fits, _, _ := w.room(t0); fits != (i <= wsWindow-wsBatch) {
			t.Fatalf("room with %d outstanding: %v", i, fits)
		}
		if w.sent(unknownID(i), until.Add(time.Duration(i)*time.Second)) {
			t.Fatal("first sending reported as a second")
		}
		if !w.sent(unknownID(i), until.Add(time.Duration(i)*time.Second)) { // again: nothing added
			t.Fatal("second sending not reported")
		}
	}
	if fits, next, lapsed := w.room(t0); fits || !next.Equal(until) || lapsed != 0 || len(w.out) != wsWindow {
		t.Fatalf("full window: fits=%v next=%v lapsed=%d n=%d", fits, next, lapsed, len(w.out))
	}
	if owed, _ := w.acked(unknownID(wsWindow)); owed {
		t.Fatal("ack owed for a message that was not sent")
	}
	for i := 0; i < wsBatch; i++ {
		owed, freed := w.acked(unknownID(i))
		if !owed || freed != (i == wsBatch-1) {
			t.Fatalf("ack %d: owed=%v freed=%v", i, owed, freed)
		}
	}
	if owed, _ := w.acked(unknownID(0)); owed {
		t.Fatal("ack owed twice")
	}
	// Leases that ended are forgotten, with their acks.
	if fits, _, lapsed := w.room(until.Add(time.Duration(wsBatch+9) * time.Second)); !fits || lapsed != 10 || len(w.out) != wsWindow-wsBatch-10 {
		t.Fatalf("after 10 more leases ended: fits=%v lapsed=%d n=%d", fits, lapsed, len(w.out))
	}
	if owed, _ := w.acked(unknownID(wsBatch)); owed {
		t.Fatal("ack owed for a message whose lease ended")
	}
}

// A network holds at most RELAY_MAX_WS_SESSIONS_PER_NETWORK sessions on a
// process, except that the first session of a mailbox is always admitted:
// whoever uses up a shared network's allowance keeps no other mailbox
// behind it from collecting. Other networks are not affected, and the
// process maximum holds for everyone.
func TestWebSocketNetworkCap(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, func(c *config.Config) {
		c.TrustProxy = true
		c.MaxWebSocketSessionsPerNetwork = 2
		c.MaxWebSocketSessions = 5
	}, &logs)
	const host, other = "203.0.113.7", "203.0.113.8"
	a, b, c := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	for _, p := range []principal{a, b, c} {
		f.register(p)
	}
	open := func(p principal, addr string) *websocket.Conn {
		t.Helper()
		conn, _, err := f.dialWSFrom(p, addr)
		if err != nil {
			t.Fatalf("upgrade from %s: %v", addr, err)
		}
		t.Cleanup(func() { conn.CloseNow() })
		return conn
	}
	refused := func(p principal, addr, label string, want int64) {
		t.Helper()
		_, resp, err := f.dialWSFrom(p, addr)
		if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "5" {
			t.Fatalf("upgrade from %s: %v %v, want 429 with Retry-After 5", addr, resp, err)
		}
		if n := f.counter(`relay_ratelimit_refused_total{limiter="` + label + `"}`); n != want {
			t.Fatalf("refused under %s: %d, want %d", label, n, want)
		}
	}
	a1 := open(a, host)
	open(a, host) // the network is at its maximum
	refused(a, host, "ws_network", 1)
	open(a, other)                    // another network is not: 3 sessions
	open(b, host)                     // a mailbox's first session is admitted at the maximum: 4
	refused(b, host, "ws_network", 2) // its second is not
	// An IPv6 network is its /64.
	open(c, "2001:db8:aa:bb::1") // 5: the process is full
	refused(b, "2001:db8:aa:bb::2", "ws_sessions", 1)
	if n := f.counter(`relay_ratelimit_refused_total{limiter="ws_network"}`); n != 2 {
		t.Fatalf("a full process counted as a full network: %d", n)
	}
	// A session that ends gives its network the place back.
	a1.CloseNow()
	waitFor(t, func() bool { return f.s.wsOpen.Load() == 4 })
	refused(a, host, "ws_network", 3) // host still holds 2: a's other session and b's
	open(a, other)                    // 5 again
	f.s.reportLimits()
	if out := logs.String(); !strings.Contains(out, `"ws_sessions_refused":1,"ws_network_refused":3,"ws_network_hard_refused":0}`) {
		t.Fatalf("rate limits line does not end with the session refusals:\n%s", out)
	}
	f.s.hub.mu.Lock()
	nets := fmt.Sprint(f.s.hub.nets)
	f.s.hub.mu.Unlock()
	if nets != "map[2001:db8:aa:bb::/64:1 203.0.113.7:2 203.0.113.8:2]" {
		t.Fatalf("sessions per network: %s", nets)
	}
}

// The per-network count is given back however a session ends, and an
// empty network is forgotten.
func TestWebSocketNetworkCountReleased(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.TrustProxy = true; c.MaxWebSocketSessionsPerNetwork = 1 })
	owner := newPrincipal(1)
	f.register(owner)
	for i := 0; i < 3; i++ {
		// Admitted (and counted), then the handshake fails.
		hr := f.build(req{method: "GET", path: "/v1/mailbox/ws", signer: &owner, header: http.Header{"X-Forwarded-For": {"203.0.113.7"}}})
		if code, _, _ := f.send(hr); code < 400 || code == http.StatusTooManyRequests {
			t.Fatalf("plain GET: %d", code)
		}
		c, _, err := f.dialWSFrom(owner, "203.0.113.7")
		if err != nil {
			t.Fatal(err)
		}
		c.CloseNow()
		waitFor(t, func() bool { return f.s.hub.collectors() == 0 })
	}
	f.s.hub.mu.Lock()
	defer f.s.hub.mu.Unlock()
	if len(f.s.hub.nets) != 0 || len(f.s.hub.boxes) != 0 {
		t.Fatalf("left behind: %v, %d mailboxes", f.s.hub.nets, len(f.s.hub.boxes))
	}
}

// A full window opens again when the leases of what was sent end, with no
// ack, no deposit and no ping: the session is woken by the end of the
// first lease it is waiting for.
func TestWebSocketWindowResumesAtLeaseEnd(t *testing.T) {
	const lease = 400 * time.Millisecond
	f := newFixture(t, func(c *config.Config) { c.VisibilityTimeout = lease })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	for i := 0; i < wsWindow+wsBatch; i++ {
		f.mustDeposit(owner, sender, tok, []byte("x"))
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	waitFor(t, func() bool { return f.s.m.collected.Value() == wsWindow })
	// The session now waits `lease` (of real time) for the first lease to
	// end. Let the leases end on the relay's clock and do nothing else.
	// It is sent the batch it had not been sent yet, and of the unacked
	// messages again as many as leave a batch of the window free.
	f.clk.add(lease + time.Millisecond)
	waitFor(t, func() bool { return f.s.m.collected.Value() == wsWindow+wsBatch+(wsWindow-2*wsBatch) })
}

// No network holds more than RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD
// sessions on a process, whatever mailboxes they are for: the first
// session of a mailbox is admitted beyond the per-network maximum only up
// to there. Other networks are not affected, and the process maximum holds.
func TestWebSocketNetworkCeiling(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, func(c *config.Config) {
		c.TrustProxy = true
		c.MaxWebSocketSessionsPerNetwork = 1
		c.MaxWebSocketSessionsPerNetworkHard = 3
		c.MaxWebSocketSessions = 5
	}, &logs)
	const host, other = "203.0.113.7", "203.0.113.8"
	var p []principal
	for i := byte(1); i <= 6; i++ {
		p = append(p, newPrincipal(i))
		f.register(p[i-1])
	}
	open := func(who principal, addr string) {
		t.Helper()
		conn, _, err := f.dialWSFrom(who, addr)
		if err != nil {
			t.Fatalf("upgrade from %s: %v", addr, err)
		}
		t.Cleanup(func() { conn.CloseNow() })
	}
	refused := func(who principal, addr, label string, want int64) {
		t.Helper()
		_, resp, err := f.dialWSFrom(who, addr)
		if err == nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "5" {
			t.Fatalf("upgrade from %s: %v %v, want 429 with Retry-After 5", addr, resp, err)
		}
		if n := f.counter(`relay_ratelimit_refused_total{limiter="` + label + `"}`); n != want {
			t.Fatalf("refused under %s: %d, want %d", label, n, want)
		}
	}
	open(p[0], host)
	refused(p[0], host, "ws_network", 1)      // the per-network maximum: not a first session
	open(p[1], host)                          // first sessions pass it
	open(p[2], host)                          // ... up to the ceiling: 3
	refused(p[3], host, "ws_network_hard", 1) // a first session, and still refused
	refused(p[0], host, "ws_network_hard", 2)
	open(p[3], other) // another network is not affected
	open(p[4], other) // 5: the process is full
	refused(p[5], other, "ws_sessions", 1)
	f.s.reportLimits()
	if out := logs.String(); !strings.Contains(out, `"ws_sessions_refused":1,"ws_network_refused":1,"ws_network_hard_refused":2}`) {
		t.Fatalf("rate limits line does not end with the session refusals:\n%s", out)
	}
}

// lapse lets every lease end on the relay's clock and wakes the session
// (its timers run on real time).
func (f *fixture) lapse(mailbox string) {
	f.clk.add(f.cfg.VisibilityTimeout + time.Second)
	f.s.hub.notify(mailbox)
}

// sent waits until the relay has sent want messages in all, and checks it
// sends no more.
func (f *fixture) sent(want int64) {
	f.t.Helper()
	waitFor(f.t, func() bool { return f.s.m.collected.Value() >= want })
	time.Sleep(150 * time.Millisecond)
	if n := f.s.m.collected.Value(); n != want {
		f.t.Fatalf("%d messages sent, want %d", n, want)
	}
}

func readFrames(t *testing.T, c *websocket.Conn, n int) []string {
	t.Helper()
	ids := make([]string, n)
	for i := range ids {
		ids[i] = readFrame(t, c, 2*time.Second).MsgID
	}
	return ids
}

// A session that leaves a full window unacked is not sent the same
// messages ahead of newer ones for ever. Until the first leases end the
// window holds everything back; from then on a message that arrived
// meanwhile is sent first, and what was left unacked is sent again in
// passes: as much per visibility timeout as leaves a batch of the window
// free, and the late message with the others once it is unacked too.
func TestWebSocketUnackedDoNotBlockNewer(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	var old []string
	for i := 0; i < wsWindow; i++ {
		old = append(old, f.mustDeposit(owner, sender, tok, []byte("x")))
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	if got := readFrames(t, c, wsWindow); !slices.Equal(got, old) {
		t.Fatal("first delivery out of order")
	}
	late := f.mustDeposit(owner, sender, tok, []byte("late"))
	f.sent(wsWindow) // the window is full: not before the first lease ends

	// The leases end: the late one first, then the oldest again, leaving
	// a batch of the window free.
	const first = wsWindow - wsBatch - 1
	f.lapse(owner.mbx)
	f.sent(wsWindow + 1 + first)
	if got := readFrames(t, c, 1+first); !slices.Equal(got, append([]string{late}, old[:first]...)) {
		t.Fatalf("after the first leases ended: late message first: %v", got[0] == late)
	}
	// The rest of the pass, which ends with the late message: it was the
	// newest the session had been sent when the pass began.
	f.lapse(owner.mbx)
	f.sent(2*wsWindow + 2)
	if got := readFrames(t, c, wsWindow-first+1); !slices.Equal(got, append(slices.Clone(old[first:]), late)) {
		t.Fatal("second batch is not the rest of the pass")
	}
	// The next pass starts over, and acks still work by id.
	f.lapse(owner.mbx)
	f.sent(2*wsWindow + 2 + wsWindow - wsBatch)
	got := readFrames(t, c, wsWindow-wsBatch)
	if !slices.Equal(got, old[:wsWindow-wsBatch]) {
		t.Fatal("the next pass did not start with the oldest")
	}
	for _, id := range got {
		sendAck(c, id)
	}
	waitFor(t, func() bool { return f.s.m.acks.Value() == wsWindow-wsBatch })
}

// With messages left unacked and new ones arriving all the time, neither
// kind waits for the other: new messages are sent as they arrive (the
// re-sent ones leave a batch of the window free), and the unacked ones
// are still sent again, pass after pass.
func TestWebSocketUnackedAndSteadyTraffic(t *testing.T) {
	// Two tokens: the registration and the upgrade. Every ack below must
	// be one the session is owed.
	f := newFixture(t, func(c *config.Config) { c.RateKeyPerSec, c.RateKeyBurst = 0.001, 2 })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	var stuck []string
	for i := 0; i < wsWindow; i++ {
		stuck = append(stuck, f.mustDeposit(owner, sender, tok, []byte("x")))
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	readFrames(t, c, wsWindow)
	var acked int64
	const most = wsWindow - wsBatch
	for round, want := range [][]string{stuck[:most], stuck[most:], stuck[:most], stuck[most:]} {
		f.lapse(owner.mbx)
		if got := readFrames(t, c, len(want)); !slices.Equal(got, want) {
			t.Fatalf("round %d: not the next batch of unacked messages", round)
		}
		// New messages arrive and are acked while those are outstanding.
		for i := 0; i < 5; i++ {
			id := f.mustDeposit(owner, sender, tok, []byte("new"))
			if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
				t.Fatalf("round %d: new message held up (got %s)", round, m.MsgID)
			}
			sendAck(c, id)
			acked++
			waitFor(t, func() bool { return f.s.m.acks.Value() == acked })
		}
	}
}

// drain reads the frames the relay has sent and the test has not read
// yet, once it has stopped sending.
func (f *fixture) drain(c *websocket.Conn, read *int64) []string {
	f.t.Helper()
	for last := int64(-1); ; {
		time.Sleep(100 * time.Millisecond)
		n := f.s.m.collected.Value()
		if n == last {
			break
		}
		last = n
	}
	ids := readFrames(f.t, c, int(f.s.m.collected.Value()-*read))
	*read += int64(len(ids))
	return ids
}

// A pass over the unacked messages ends where the session's newest
// message was when the pass began. New messages that the client acks late
// (after their lease) join the next pass; they cannot keep this one from
// ever ending, so an old unacked message keeps coming back however much
// arrives after it.
func TestWebSocketPassEndsDespiteNewTraffic(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	stuck := f.mustDeposit(owner, sender, tok, []byte("never acked"))
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	var read int64
	var late []string // what arrived in the round before: acked one lease late
	const rounds = 10
	var seen []int
	for round := 0; round < rounds; round++ {
		for i := 0; i < 40; i++ {
			f.mustDeposit(owner, sender, tok, []byte("x"))
		}
		got := f.drain(c, &read)
		f.lapse(owner.mbx)
		got = append(got, f.drain(c, &read)...)
		if slices.Contains(got, stuck) {
			seen = append(seen, round)
		}
		for _, id := range late {
			sendAck(c, id)
		}
		late = late[:0]
		for _, id := range got {
			if id != stuck {
				late = append(late, id)
			}
		}
	}
	// It comes back in every pass; a pass is a round or two here.
	if len(seen) < rounds/2 || seen[len(seen)-1] < rounds-2 {
		t.Fatalf("the unacked message was sent in rounds %v of %d", seen, rounds)
	}
}

// A batch that comes back short (another collector took part of it) does
// not end the pass: the next batch goes on after it, not from the oldest.
func TestWebSocketShortBatchDoesNotEndPass(t *testing.T) {
	f := newFixture(t, nil)
	cs := f.countStore()
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	var old []string
	for i := 0; i < wsWindow; i++ {
		old = append(old, f.mustDeposit(owner, sender, tok, []byte("x")))
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	readFrames(t, c, wsWindow)
	cs.shortRange.Store(20) // of each bounded collect, the session wins 20
	for round := 0; round < 3; round++ {
		f.lapse(owner.mbx)
		f.sent(int64(wsWindow + 20*(round+1)))
		if got := readFrames(t, c, 20); !slices.Equal(got, old[20*round:20*(round+1)]) {
			t.Fatalf("round %d: the pass did not go on after the short batch (first %s)", round, got[0])
		}
	}
}

// When a whole pass finds nothing to send again, the session collects as
// a session that never let a lease end: one Collect, no ranges.
func TestWebSocketBackToPlainCollect(t *testing.T) {
	f := newFixture(t, nil)
	cs := f.countStore()
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	id := f.mustDeposit(owner, sender, tok, []byte("x"))
	readFrame(t, c, 2*time.Second)
	if n := cs.ranges.Load(); n != 0 {
		t.Fatalf("%d ranged collects for a session that let no lease end", n)
	}
	// Unacked: sent again, and from the second time on (at the latest:
	// the first may be a collect that was already under way) by ranges.
	for i := 0; i < 2; i++ {
		f.lapse(owner.mbx)
		if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
			t.Fatalf("re-send: %s", m.MsgID)
		}
	}
	if cs.ranges.Load() == 0 {
		t.Fatal("no ranged collect for a session that let leases end")
	}
	sendAck(c, id)
	waitFor(t, func() bool { return f.s.m.acks.Value() == 1 })
	// The next pass finds nothing: back to plain collects.
	f.lapse(owner.mbx)
	var ranges int64
	waitFor(t, func() bool {
		ranges = cs.ranges.Load()
		time.Sleep(50 * time.Millisecond)
		return ranges == cs.ranges.Load()
	})
	plain := cs.collects.Load()
	for i := 0; i < 5; i++ {
		id := f.mustDeposit(owner, sender, tok, []byte("x"))
		if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
			t.Fatalf("got %s", m.MsgID)
		}
		sendAck(c, id)
	}
	waitFor(t, func() bool { return f.s.m.acks.Value() == 6 })
	if n := cs.ranges.Load(); n != ranges || cs.collects.Load() <= plain {
		t.Fatalf("after an empty pass: %d more ranged collects, %d plain", n-ranges, cs.collects.Load()-plain)
	}
	// And a lease that ends later starts the passes again, from the oldest.
	id = f.mustDeposit(owner, sender, tok, []byte("x"))
	readFrame(t, c, 2*time.Second)
	for i := 0; i < 2; i++ {
		f.lapse(owner.mbx)
		if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
			t.Fatalf("later lapse: %s", m.MsgID)
		}
	}
	if cs.ranges.Load() == ranges {
		t.Fatal("no ranged collect after a later lease ended")
	}
}

// A mailbox's session count goes down when a session ends, also while a
// long-poll keeps the mailbox known to the process: its next session is a
// first session again and admitted at the network's maximum.
func TestWebSocketFirstSessionAfterOneEnded(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.TrustProxy = true; c.MaxWebSocketSessionsPerNetwork = 1 })
	const host = "203.0.113.7"
	a, b := newPrincipal(1), newPrincipal(2)
	f.register(a)
	f.register(b)
	ca, _, err := f.dialWSFrom(a, host)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.CloseNow()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); f.collect(b, "?wait=3") }()
	waitFor(t, func() bool { return f.s.m.parked.Value() == 1 })
	for i := 0; i < 2; i++ {
		cb, _, err := f.dialWSFrom(b, host)
		if err != nil {
			t.Fatalf("session %d of a mailbox with none open: %v", i+1, err)
		}
		cb.CloseNow()
		waitFor(t, func() bool { return f.s.wsOpen.Load() == 1 })
	}
	wg.Wait()
}

// What one session lets expire, another session on the same mailbox
// collects as before; the first is then back to plain oldest-first.
func TestWebSocketUnackedGoToAnotherSession(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	var old []string
	for i := 0; i < wsWindow; i++ {
		old = append(old, f.mustDeposit(owner, sender, tok, []byte("x")))
	}
	a, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer a.CloseNow()
	readFrames(t, a, wsWindow)
	f.clk.add(f.cfg.VisibilityTimeout + time.Second) // a is not woken
	b, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer b.CloseNow()
	if got := readFrames(t, b, wsWindow); !slices.Equal(got, old) {
		t.Fatal("the second session was not sent what the first let expire, oldest first")
	}
	for _, id := range old {
		sendAck(b, id)
	}
	waitFor(t, func() bool { return f.s.m.acks.Value() == wsWindow })
	// a finds nothing to send again and goes on with new messages.
	f.s.hub.notify(owner.mbx)
	b.CloseNow()
	waitFor(t, func() bool { return f.s.hub.collectors() == 1 })
	id := f.mustDeposit(owner, sender, tok, []byte("new"))
	if m := readFrame(t, a, 2*time.Second); m.MsgID != id {
		t.Fatalf("first session after the other took over: %+v", m)
	}
}

// A message deposited after the relay's clock was set back still gets an
// id above the earlier ones, so a session that is rationing re-sends
// takes it for the new message it is and sends it at once.
func TestWebSocketNewMessageAfterClockSetBack(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	var old []string
	for i := 0; i < wsWindow; i++ {
		old = append(old, f.mustDeposit(owner, sender, tok, []byte("x")))
	}
	c, _, err := f.dialWS(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	readFrames(t, c, wsWindow)
	f.lapse(owner.mbx)
	readFrames(t, c, wsWindow-wsBatch)
	f.clk.add(-10 * time.Minute)
	id := f.mustDeposit(owner, sender, f.mint(owner, sender, nil), []byte("late"))
	if id <= old[wsWindow-1] {
		t.Fatalf("id %s issued after %s is not above it", id, old[wsWindow-1])
	}
	if m := readFrame(t, c, 2*time.Second); m.MsgID != id {
		t.Fatalf("got %s, want the new message", m.MsgID)
	}
}
