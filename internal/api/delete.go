package api

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"

	auth "github.com/vettid/vettid-relay/relayauth"
)

// wsStatusMailboxUnknown closes a WebSocket collect session whose mailbox
// was deleted (spec §6.10): 4404, reason "mailbox_unknown".
const wsStatusMailboxUnknown = websocket.StatusCode(4404)

// deleteTimeout bounds one deletion. It runs detached from the request:
// a client that disconnects mid-way must not leave it half done.
const deleteTimeout = time.Minute

// DELETE /v1/mailbox (spec §6.10, 0.5.0). Owner-signed and bodiless; the
// mailbox is the signer's. Idempotent: 204 whether or not the mailbox
// existed.
func (s *Server) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	body, e := s.readBody(w, r, smallBodyLimit)
	if e != nil {
		s.writeError(w, e)
		return
	}
	sr, e := s.authorizeSigner(r, auth.BodyHash(body))
	if e != nil {
		s.writeError(w, e)
		return
	}
	if len(body) != 0 {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	// Tokens minted before the deletion stay refused if the key registers
	// again: iat must be at least notBefore. The freshness window covers an
	// owner clock running ahead of ours (this request's timestamp was
	// within it). The tombstone lives until every such token has expired.
	notBefore := s.now().Add(auth.FreshnessWindow)
	keepUntil := notBefore.Add(s.denylistRetention())
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), deleteTimeout)
	defer cancel()
	ids, err := s.st.DeleteMailbox(ctx, auth.MailboxID(sr.Key), sr.Key, notBefore, keepUntil)
	for _, id := range ids {
		s.mailboxDeleted(ctx, id)
	}
	if err != nil {
		s.log.Error("mailbox delete failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	s.m.deletions.Add(int64(len(ids)))
	setLog(w, "count", len(ids))
	w.WriteHeader(http.StatusNoContent)
}

// mailboxDeleted ends what this and other processes hold for a deleted
// mailbox: the empty hint is invalidated (a version bump: a later
// registration of the key never inherits a stale "empty"), collectors
// parked here get mailbox_unknown, and other processes are told to do the
// same and to drop their cached copy.
func (s *Server) mailboxDeleted(ctx context.Context, mailbox string) {
	if s.hints != nil {
		if err := s.hints.Bump(ctx, mailbox); err != nil {
			s.log.Warn("empty-hint bump after delete failed", "err", err)
		}
	}
	s.hub.kill(mailbox)
	if b, ok := s.bus.(GoneBus); ok {
		b.PublishGone(mailbox)
	}
}

// MailboxGone is called for a deletion signalled by another relay process:
// the cached mailbox is dropped (so this process stops resolving it now,
// not when its cache entry expires) and parked collectors get
// mailbox_unknown. A lost signal only delays this until the cache entry
// expires; writes are refused by the store regardless.
func (s *Server) MailboxGone(mailbox string) {
	if f, ok := s.st.(interface{ Forget(ids ...string) }); ok {
		f.Forget(mailbox)
	}
	s.hub.kill(mailbox)
}

// stillRegistered re-checks, after a collector registered with the hub,
// that its mailbox was not deleted in between (a deletion after this point
// closes the collector's gone channel instead).
func (s *Server) stillRegistered(ctx context.Context, mailbox string) bool {
	_, err := s.st.Mailbox(ctx, mailbox)
	return err == nil
}
