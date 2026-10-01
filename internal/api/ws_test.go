package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/auth"
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

	if m := readFrame(t, c, 2*time.Second); m.MsgID != early || string(m.Payload) != "before connect" {
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
	waitFor(t, func() bool {
		f.clk.add(time.Millisecond)
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
