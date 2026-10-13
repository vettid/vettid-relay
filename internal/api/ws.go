package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	auth "github.com/vettid/vettid-relay/relayauth"
)

const (
	wsBatch        = 32
	wsWriteTimeout = 15 * time.Second
	wsPingInterval = 30 * time.Second
	wsReadLimit    = 1024 // client frames are tiny {"ack":"<ulid>"}

	// wsFullRetryAfter is the retry_after of an upgrade refused because
	// this process carries its maximum of sessions: longer than a busy
	// mailbox's 1 s, since a slot frees only when some session ends.
	wsFullRetryAfter = 5
)

// ackCredit counts the ack frames a WebSocket session may still send
// without being charged: one per message the relay sent on it. It is the
// session's own (not shared between processes, gone when the session
// ends): acks for messages received elsewhere are charged.
type ackCredit struct{ n atomic.Int64 }

// grant adds the credit for one delivered message. Credit never exceeds
// max, the number of messages a mailbox can hold: a session that does not
// ack is sent the same messages again after every lease, and must not save
// up more acks than there can be messages to acknowledge.
func (c *ackCredit) grant(max int64) {
	if c.n.Load() < max { // the session's writer is the only granter
		c.n.Add(1)
	}
}

// take uses one credit; false if there is none.
func (c *ackCredit) take() bool {
	for {
		n := c.n.Load()
		if n <= 0 {
			return false
		}
		if c.n.CompareAndSwap(n, n-1) {
			return true
		}
	}
}

// GET /v1/mailbox/ws (spec §6.4). Owner-signed at upgrade. Server frames are
// {msg_id, deposited_at, payload} under the same lease semantics as
// long-poll; client frames are {"ack": "<msg_id>"}.
//
// The limits of §7.2 are applied to the upgrade request; what a session
// does afterwards is bounded here:
//
//   - A process carries at most cfg.MaxWebSocketSessions sessions.
//   - Every message the relay sends on a session entitles the session to
//     one ack frame (ackCredit). A client that acks what it is sent
//     never needs more, however fast it drains a backlog, so these acks
//     are not rate limited: there are never more of them than deliveries.
//   - Any further ack frame is charged like the DELETE /v1/mailbox/{msg_id}
//     it stands for: one token of the flood guard of the session's network
//     and one of the key's bucket. When either is empty the session is
//     closed (the client reconnects under the ordinary limits).
//   - A frame that is not an ack of a well-formed id closes the session.
//
// So every client frame is either paid for by a delivery, paid for from
// the shared buckets, or the session's last.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	body, e := s.readBody(w, r, smallBodyLimit)
	if e != nil {
		s.writeError(w, e)
		return
	}
	mb, e := s.authorizeOwner(r.Context(), r, auth.BodyHash(body))
	if e != nil {
		s.writeError(w, e)
		return
	}
	if !s.hub.acquire(mb.ID, s.cfg.MaxCollectorsPerMailbox) {
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: 1})
		return
	}
	defer s.hub.release(mb.ID)
	if s.wsOpen.Add(1) > int64(s.cfg.MaxWebSocketSessions) { // this process is full
		s.wsOpen.Add(-1)
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: wsFullRetryAfter})
		return
	}
	defer s.wsOpen.Add(-1)
	gone := s.hub.goneCh(mb.ID)
	if !s.stillRegistered(r.Context(), mb.ID) {
		s.writeError(w, fail(CodeMailboxUnknown)) // deleted since authorization
		return
	}
	network := rateKey(clientIP(r, s.cfg.TrustProxy))
	if !s.beginStream() { // shutting down: tell the client to come back
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: 1})
		return
	}
	defer s.streams.Done()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Payloads are ciphertext (incompressible); compression also invites
		// length side channels.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return // Accept already wrote an HTTP error
	}
	defer conn.CloseNow()
	conn.SetReadLimit(wsReadLimit)
	s.m.wsSessions.Inc()
	defer s.m.wsSessions.Dec()

	// A hijacked connection's request context is not cancelled by
	// http.Server.Shutdown, so the session lives on its own context that
	// ends on drain, read error, or write error.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-s.drainCtx.Done():
			conn.Close(websocket.StatusGoingAway, "relay shutting down")
			cancel()
		case <-ctx.Done():
		}
	}()

	// Reader: ack frames.
	var credit ackCredit
	go func() {
		defer cancel()
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var f struct {
				Ack *string `json:"ack"`
			}
			if typ != websocket.MessageText || !decodeJSON(data, &f) || f.Ack == nil || !validID(*f.Ack) {
				conn.Close(websocket.StatusPolicyViolation, "expected {\"ack\":\"<msg_id>\"}")
				return
			}
			// Before the store: an ack the relay did not ask for is a
			// request, and is limited like one.
			if !credit.take() {
				e := s.take(limAddress, s.ipLimit, network)
				if e == nil {
					e = s.allowKey(mb.PubKey)
				}
				if e != nil {
					s.m.errors.With(e.code).Inc()
					conn.Close(websocket.StatusPolicyViolation, e.code)
					return
				}
			}
			if e := s.ack(ctx, mb.ID, *f.Ack); e != nil {
				s.m.errors.With(e.code).Inc()
				if e.code == CodeInternal {
					conn.Close(websocket.StatusInternalError, "internal error")
					return
				}
			}
		}
	}()

	ping := time.NewTicker(wsPingInterval)
	defer ping.Stop()
	gen := s.forceGen.Load()
	for {
		wake := s.hub.wait(mb.ID) // before leasing: no lost wakeups
		g := s.forceGen.Load()
		msgs, next, err := s.collectOnce(ctx, mb.ID, wsBatch, g != gen)
		gen = g
		if err != nil {
			if ctx.Err() == nil {
				s.log.Error("ws lease failed", "err", err)
				conn.Close(websocket.StatusInternalError, "internal error")
			}
			return
		}
		for _, m := range msgs {
			frame, _ := json.Marshal(toWire(m))
			credit.grant(s.cfg.MailboxMaxMessages) // before the write: the ack may come back at once
			wctx, wcancel := context.WithTimeout(ctx, wsWriteTimeout)
			err := conn.Write(wctx, websocket.MessageText, frame)
			wcancel()
			if err != nil {
				return // leased messages reappear after the visibility timeout
			}
			s.m.collected.Inc()
		}
		if len(msgs) > 0 {
			continue // more may be waiting; an empty Collect parks below
		}
		var leaseC <-chan time.Time
		var leaseT *time.Timer
		if !next.IsZero() {
			leaseT = time.NewTimer(max0(next.Sub(s.now())) + 5*time.Millisecond)
			leaseC = leaseT.C
		}
		var stop bool
		select {
		case <-wake:
		case <-leaseC:
		case <-ping.C: // also re-checks the store (covers a lost cross-process wake)
			pctx, pcancel := context.WithTimeout(ctx, wsWriteTimeout)
			err := conn.Ping(pctx)
			pcancel()
			stop = err != nil
		case <-gone: // the owner deleted the mailbox (§6.10)
			conn.Close(wsStatusMailboxUnknown, CodeMailboxUnknown)
			stop = true
		case <-ctx.Done():
			stop = true
		}
		if leaseT != nil {
			leaseT.Stop()
		}
		if stop {
			return
		}
	}
}
