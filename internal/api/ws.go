package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/auth"
)

const (
	wsBatch        = 32
	wsWriteTimeout = 15 * time.Second
	wsPingInterval = 30 * time.Second
	wsReadLimit    = 1024 // client frames are tiny {"ack":"<ulid>"}
)

// GET /v1/mailbox/ws (spec §6.4). Owner-signed at upgrade. Server frames are
// {msg_id, deposited_at, payload} under the same lease semantics as
// long-poll; client frames are {"ack": "<msg_id>"}.
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
			if typ != websocket.MessageText || !decodeJSON(data, &f) || f.Ack == nil {
				conn.Close(websocket.StatusPolicyViolation, "expected {\"ack\":\"<msg_id>\"}")
				return
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
	for {
		wake := s.hub.wait(mb.ID) // before leasing: no lost wakeups
		msgs, err := s.st.Lease(ctx, mb.ID, wsBatch, s.cfg.VisibilityTimeout)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Error("ws lease failed", "err", err)
				conn.Close(websocket.StatusInternalError, "internal error")
			}
			return
		}
		for _, m := range msgs {
			frame, _ := json.Marshal(toWire(m))
			wctx, wcancel := context.WithTimeout(ctx, wsWriteTimeout)
			err := conn.Write(wctx, websocket.MessageText, frame)
			wcancel()
			if err != nil {
				return // leased messages reappear after the visibility timeout
			}
			s.m.collected.Inc()
		}
		if len(msgs) == wsBatch {
			continue // more may be waiting
		}
		var leaseC <-chan time.Time
		var leaseT *time.Timer
		if next, ok, err := s.st.NextLeaseExpiry(ctx, mb.ID); err == nil && ok {
			leaseT = time.NewTimer(max0(next.Sub(s.now())) + 5*time.Millisecond)
			leaseC = leaseT.C
		}
		var stop bool
		select {
		case <-wake:
		case <-leaseC:
		case <-ping.C:
			pctx, pcancel := context.WithTimeout(ctx, wsWriteTimeout)
			err := conn.Ping(pctx)
			pcancel()
			stop = err != nil
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
