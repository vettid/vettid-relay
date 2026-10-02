package api

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strconv"

	auth "github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/internal/store"
)

// Blob transfer (spec §6.8). Blob bodies are opaque ciphertext: never parsed,
// never logged. Only ids and sizes reach logs and metrics.

// tryBlobSlot bounds concurrent blob transfers (each may hold up to
// max_blob_bytes in memory).
func (s *Server) tryBlobSlot() bool {
	select {
	case s.blobSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseBlobSlot() { <-s.blobSlots }

// PUT /v1/blob/{mailbox_id}
func (s *Server) handleBlobPut(w http.ResponseWriter, r *http.Request) {
	limit := s.cfg.MaxBlobBytes
	// Size limit before any verification (spec §8.5); a declared length over
	// the limit is refused without reading.
	if r.ContentLength > limit {
		s.writeError(w, fail(CodePayloadTooLarge))
		return
	}
	mailboxID := r.PathValue("mailbox_id")
	// §5.3 steps 1–6 need only headers: unauthorized uploads are refused
	// before their body is read.
	da, e := s.authorizeDepositToken(r.Context(), r, mailboxID)
	if e != nil {
		s.writeError(w, e)
		return
	}
	// One-shot open tokens permit exactly one *message* deposit (§5.6); they
	// are not accepted for blob uploads (see README interpretation notes).
	if da.claims.Open() {
		s.writeError(w, fail(CodeTokenInvalid))
		return
	}
	if e := s.allowSender(da.claims.Sub); e != nil {
		s.writeError(w, e)
		return
	}
	if !s.tryBlobSlot() {
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: 2})
		return
	}
	defer s.releaseBlobSlot()

	// Stream the body, hashing as we go; MaxBytesReader stops after
	// limit+1 bytes, so at most limit bytes are ever buffered.
	var buf bytes.Buffer
	if r.ContentLength > 0 {
		buf.Grow(int(r.ContentLength))
	}
	h := sha256.New()
	_, err := io.Copy(io.MultiWriter(&buf, h), http.MaxBytesReader(w, r.Body, limit))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		s.writeError(w, fail(CodePayloadTooLarge))
		return
	case err != nil:
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	var bodyHash [32]byte
	h.Sum(bodyHash[:0])
	sender, e := s.verifySender(r, da, bodyHash) // step 7
	if e != nil {
		s.writeError(w, e)
		return
	}
	size := int64(buf.Len())
	info, err := s.blobs.PutBlob(r.Context(), store.BlobPut{
		Mailbox:   mailboxID,
		SenderSub: sender,
		Size:      size,
		TTL:       s.cfg.BlobTTL,
		Limits:    s.limitsFor(da, true), // step 8: token bytes + mailbox blob cap
	}, &buf)
	switch {
	case errors.Is(err, store.ErrQuota):
		s.writeError(w, fail(CodeQuotaExceeded))
		return
	case err != nil:
		s.log.Error("blob put failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	s.m.blobPuts.Inc()
	s.m.blobBytes.Add(size)
	setLog(w, "blob_id", info.ID)
	setLog(w, "size", size)
	writeJSON(w, http.StatusCreated, map[string]string{
		"blob_id":    info.ID,
		"expires_at": info.ExpiresAt.UTC().Format(timeFormat),
	})
}

// GET /v1/blob/{blob_id} — owner of the recipient mailbox only.
func (s *Server) handleBlobGet(w http.ResponseWriter, r *http.Request) {
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
	id := r.PathValue("blob_id")
	if len(id) != 26 {
		s.writeError(w, fail(CodeBlobUnknown))
		return
	}
	if !s.tryBlobSlot() {
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: 2})
		return
	}
	defer s.releaseBlobSlot()
	info, rc, err := s.blobs.OpenBlob(r.Context(), mb.ID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Unknown, expired and other-mailbox blobs are indistinguishable.
		s.writeError(w, fail(CodeBlobUnknown))
		return
	case err != nil:
		s.log.Error("blob get failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	defer rc.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, rc)
	s.m.blobGets.Inc()
	setLog(w, "blob_id", id)
	setLog(w, "size", info.Size)
}

// DELETE /v1/blob/{blob_id} — idempotent.
func (s *Server) handleBlobDelete(w http.ResponseWriter, r *http.Request) {
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
	id := r.PathValue("blob_id")
	if len(id) == 26 {
		if err := s.blobs.DeleteBlob(r.Context(), mb.ID, id); err != nil {
			s.log.Error("blob delete failed", "err", err)
			s.writeError(w, fail(CodeInternal))
			return
		}
	}
	s.m.blobDeletes.Inc()
	setLog(w, "blob_id", id)
	w.WriteHeader(http.StatusNoContent)
}
