package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

const (
	wsBatch        = 32
	wsWriteTimeout = 15 * time.Second
	wsPingInterval = 30 * time.Second
	wsReadLimit    = 1024 // client frames are tiny {"ack":"<ulid>"}

	// wsFullRetryAfter is the retry_after of an upgrade refused because
	// this process, or the caller's network on it, carries its maximum of
	// sessions: longer than a busy mailbox's 1 s, since a slot frees only
	// when some session ends.
	wsFullRetryAfter = 5
)

// wsWindow is how many messages a session may have been sent and not yet
// acked. The relay leases the next batch only while a whole batch still
// fits, so a session that does not ack is sent wsWindow messages and then
// nothing until it acks or their leases end. A client that acks as it
// receives never has a window's worth outstanding (the largest batch a
// client is known to hold before acking is one of wsBatch).
const wsWindow = 4 * wsBatch

// ackWindow is the set of messages sent on one WebSocket session and not
// yet acked there, each until its lease ends. It bounds what the session
// costs without a request: the leases taken for it (at most wsWindow per
// visibility timeout) and the ack frames it may send without being charged
// (one for each message in the set, by id). It is the session's own: not
// shared between processes, gone when the session ends.
type ackWindow struct {
	mu  sync.Mutex
	out map[string]time.Time // msg id → end of the lease it was sent under
}

// room forgets the messages whose lease has ended (they are anyone's to
// collect again, and an ack for them is no longer owed to this session)
// and reports whether another batch fits; if not, when the next lease ends.
func (a *ackWindow) room(now time.Time) (bool, time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var first time.Time
	for id, until := range a.out {
		if !until.After(now) {
			delete(a.out, id)
		} else if first.IsZero() || until.Before(first) {
			first = until
		}
	}
	return len(a.out) <= wsWindow-wsBatch, first
}

// sent records a message about to be sent, leased until the given time.
// Sending a message again that is still in the set adds nothing.
func (a *ackWindow) sent(id string, until time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.out == nil {
		a.out = make(map[string]time.Time, wsBatch)
	}
	a.out[id] = until
}

// acked removes id. owed is false if the session was not sent that message
// (or its lease has ended, or it was acked before): such an ack is charged.
// freed reports that this ack made room for a batch again.
func (a *ackWindow) acked(id string) (owed, freed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.out[id]; !ok {
		return false, false
	}
	delete(a.out, id)
	return true, len(a.out) == wsWindow-wsBatch
}

// GET /v1/mailbox/ws (spec §6.4). Owner-signed at upgrade. Server frames are
// {msg_id, deposited_at, payload} under the same lease semantics as
// long-poll; client frames are {"ack": "<msg_id>"}.
//
// The limits of §7.2 are applied to the upgrade request; what a session
// does afterwards is bounded here:
//
//   - A process carries at most cfg.MaxWebSocketSessions sessions, and at
//     most cfg.MaxWebSocketSessionsPerNetwork of one client network, not
//     counting the first session of a mailbox (hub.acquireWS).
//   - A session has at most wsWindow messages sent and not yet acked
//     (ackWindow); the relay leases no more for it until it acks or their
//     leases end. So a session that does not ack costs at most wsWindow
//     leases per visibility timeout, not its whole mailbox again and again.
//   - An ack frame for one of those messages is not rate limited: the
//     relay asked for it, and there is one per message, by id. A client
//     that acks what it is sent never needs another kind, however fast it
//     drains a backlog.
//   - Any other ack frame (a message received elsewhere, an id acked
//     before, an id that names nothing) is charged like the DELETE /v1/mailbox/{msg_id}
//     it stands for: one token of the flood guard of the session's network
//     and one of the key's bucket. When either is empty the session is
//     closed with 1013 "try again later" and the reason rate_limited (the
//     client reconnects under the ordinary limits).
//   - A frame that is not an ack of a well-formed id closes the session
//     with 1008.
//
// So every client frame either answers a message in the window, is paid
// for from the shared buckets, or is the session's last.
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
	network := rateKey(clientIP(r, s.cfg.TrustProxy))
	if s.wsOpen.Add(1) > int64(s.cfg.MaxWebSocketSessions) { // this process is full
		s.wsOpen.Add(-1)
		s.rl.refused.With(limWSSessions).Inc()
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: wsFullRetryAfter})
		return
	}
	defer s.wsOpen.Add(-1)
	switch s.hub.acquireWS(mb.ID, s.cfg.MaxCollectorsPerMailbox, network, s.cfg.MaxWebSocketSessionsPerNetwork) {
	case wsMailboxFull:
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: 1})
		return
	case wsNetworkFull:
		s.rl.refused.With(limWSNetwork).Inc()
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: wsFullRetryAfter})
		return
	}
	defer s.hub.releaseWS(mb.ID, network)
	gone := s.hub.goneCh(mb.ID)
	if !s.stillRegistered(r.Context(), mb.ID) {
		s.writeError(w, fail(CodeMailboxUnknown)) // deleted since authorization
		return
	}
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
	var win ackWindow
	room := make(chan struct{}, 1) // an ack made room for a batch again
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
			owed, freed := win.acked(*f.Ack)
			if freed {
				select {
				case room <- struct{}{}:
				default:
				}
			}
			if !owed {
				e := s.take(limAddress, s.ipLimit, network)
				if e == nil {
					e = s.allowKey(mb.PubKey)
				}
				if e != nil {
					s.m.errors.With(e.code).Inc()
					conn.Close(websocket.StatusTryAgainLater, e.code)
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
		var msgs []store.Message
		fits, next := win.room(s.now()) // if not: wait for acks, or for the next lease to end
		if fits {
			g := s.forceGen.Load()
			var err error
			msgs, next, err = s.collectOnce(ctx, mb.ID, wsBatch, g != gen)
			gen = g
			if err != nil {
				if ctx.Err() == nil {
					s.log.Error("ws lease failed", "err", err)
					conn.Close(websocket.StatusInternalError, "internal error")
				}
				return
			}
		}
		for _, m := range msgs {
			frame, _ := json.Marshal(toWire(m))
			// Before the write: the ack may come back at once. The lease
			// was taken a moment ago, so this is never earlier than its end.
			win.sent(m.ID, s.now().Add(s.cfg.VisibilityTimeout))
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
		case <-room:
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
