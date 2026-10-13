package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

func (f *fixture) dialWS(owner principal) (*websocket.Conn, *http.Response, error) {
	h := http.Header{}
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
}

func (c *countingStore) Ack(ctx context.Context, mailbox, msgID string) (bool, error) {
	c.acks.Add(1)
	return c.Backend.Ack(ctx, mailbox, msgID)
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
// network's flood guard. When one is empty the session ends, and nothing
// more reaches the store.
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
			expectWSClose(t, c, websocket.StatusPolicyViolation, CodeRateLimited)
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
	expectWSClose(t, c, websocket.StatusPolicyViolation, CodeRateLimited)
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
	// The leases end: everything unacked is anyone's again, and the
	// session is sent one window of it.
	f.clk.add(f.cfg.VisibilityTimeout + time.Second)
	f.s.hub.notify(owner.mbx)
	sentStays(2*wsWindow + wsBatch)
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
	expectWSClose(t, c, websocket.StatusPolicyViolation, CodeRateLimited)
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
	expectWSClose(t, b, websocket.StatusPolicyViolation, CodeRateLimited)
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
	expectWSClose(t, c, websocket.StatusPolicyViolation, CodeRateLimited)
}

func TestAckWindow(t *testing.T) {
	var w ackWindow
	t0 := time.Unix(1_800_000_000, 0)
	until := t0.Add(time.Minute)
	for i := 0; i < wsWindow; i++ {
		if fits, _ := w.room(t0); fits != (i <= wsWindow-wsBatch) {
			t.Fatalf("room with %d outstanding: %v", i, fits)
		}
		w.sent(unknownID(i), until.Add(time.Duration(i)*time.Second))
		w.sent(unknownID(i), until.Add(time.Duration(i)*time.Second)) // again: nothing added
	}
	if fits, next := w.room(t0); fits || !next.Equal(until) || len(w.out) != wsWindow {
		t.Fatalf("full window: fits=%v next=%v n=%d", fits, next, len(w.out))
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
	if fits, _ := w.room(until.Add(time.Duration(wsBatch+9) * time.Second)); !fits || len(w.out) != wsWindow-wsBatch-10 {
		t.Fatalf("after 10 more leases ended: fits=%v n=%d", fits, len(w.out))
	}
	if owed, _ := w.acked(unknownID(wsBatch)); owed {
		t.Fatal("ack owed for a message whose lease ended")
	}
}
