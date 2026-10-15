package api

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-relay/internal/ratelimit"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Blob transfer (spec §6.8). Blob bodies are opaque ciphertext: never parsed,
// never logged. Only ids and sizes reach logs and metrics.

// Transfer slots. A blob body is held in memory while it moves (up to
// max_blob_bytes), so transfers are bounded per process
// (cfg.MaxConcurrentBlobTransfers, P) and per mailbox
// (cfg.MaxBlobTransfersPerMailbox, M), with uploads and downloads counted
// apart so that senders can never keep an owner from its blobs:
//
//   - uploads: at most M to one mailbox, at most one per (mailbox, sender
//     key), and at most P − M in the process, so M process slots are
//     always left for downloads;
//   - downloads: at most M per mailbox (the owner's), and the process's
//     P in all.
//
// A slot is held only while the body moves: an upload takes one when its
// first bytes have arrived, and every transfer must keep a pace of
// cfg.BlobPaceBytes in every config.BlobPaceWindow (s.blobPaceWindow), or
// it is dropped and its slot freed; and no transfer takes longer than
// blobTransferMax.

// blobTransferMax bounds one blob body's transfer, either way (the
// server's read timeout, which the pace's deadlines replace). An 8 MiB
// blob needs 28 KiB/s to make it.
const blobTransferMax = 5 * time.Minute

// blobTransfers counts the transfers in progress in this process.
type blobTransfers struct {
	mu       sync.Mutex
	up, down int
	upMbx    map[string]int // uploads, by recipient mailbox
	downMbx  map[string]int // downloads, by owner mailbox
	upSender map[string]int // uploads, by recipient mailbox and sender key
	uploads  map[*upload]struct{}
}

func newBlobTransfers() *blobTransfers {
	return &blobTransfers{upMbx: map[string]int{}, downMbx: map[string]int{}, upSender: map[string]int{}, uploads: map[*upload]struct{}{}}
}

func (b *blobTransfers) inFlight() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.up + b.down
}

func (b *blobTransfers) empty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.up+b.down == 0 && len(b.upMbx)+len(b.downMbx)+len(b.upSender)+len(b.uploads) == 0
}

func decr(m map[string]int, k string) {
	if m[k]--; m[k] <= 0 {
		delete(m, k)
	}
}

// slotBusy is the answer to a transfer refused for want of a slot.
func (s *Server) slotBusy(limiter string) *apiError {
	s.rl.refused.With(limiter).Inc()
	return &apiError{code: CodeRateLimited, retryAfter: 2}
}

// errEvicted ends the body read of an upload whose slot was given to a
// newer one.
var errEvicted = errors.New("blob upload evicted for a newer one")

// upload is one blob upload, from the moment its body begins to be read.
type upload struct {
	mailbox, sender string
	start           time.Time    // when its body began to be read (server clock)
	received        atomic.Int64 // body bytes received so far
	done            atomic.Bool  // its body has been read whole
	evicted         atomic.Bool  // its slot was given to a newer upload
	cut             func()       // interrupts its body read (a read deadline in the past)
	released        bool         // its slot is given up (under blobTransfers.mu)
}

func (u *upload) senderKey() string { return u.mailbox + "\x00" + u.sender }

// rate is u's bytes received per second since its body began.
func (u *upload) rate(now time.Time) float64 {
	el := now.Sub(u.start).Seconds()
	if el <= 0 {
		return math.Inf(1)
	}
	return float64(u.received.Load()) / el
}

// removeLocked gives up u's slot (b.mu held).
func (b *blobTransfers) removeLocked(u *upload) {
	if u.released {
		return
	}
	u.released = true
	b.up--
	decr(b.upMbx, u.mailbox)
	decr(b.upSender, u.senderKey())
	delete(b.uploads, u)
}

// victimLocked is the upload to cut off for a newcomer to mailbox when the
// mailbox (inMailbox) or the process has no upload slot free: the slowest,
// by bytes received per second so far, of those still reading their body
// that have run at least cfg.BlobEvictMinAge (and are uploads to mailbox,
// if the mailbox is full). Nil if none qualifies.
func (s *Server) victimLocked(mailbox string, inMailbox bool) *upload {
	now := s.now()
	var victim *upload
	slowest := math.Inf(1)
	for u := range s.xfers.uploads {
		if (inMailbox && u.mailbox != mailbox) || u.done.Load() || now.Sub(u.start) < s.cfg.BlobEvictMinAge {
			continue
		}
		if r := u.rate(now); victim == nil || r < slowest {
			victim, slowest = u, r
		}
	}
	return victim
}

// acquireUpload takes an upload slot for u, or returns the 429. When the
// mailbox or the process has none free, the slowest upload that has run at
// least cfg.BlobEvictMinAge is cut off and u takes its slot (it is answered
// 429 with retry_after; see handleBlobPut). One sender's own upload to the
// mailbox is never cut off for it. release frees the slot (nothing, if it
// was taken away).
func (s *Server) acquireUpload(u *upload) (release func(), e *apiError) {
	b, per, all := s.xfers, s.cfg.MaxBlobTransfersPerMailbox, s.cfg.MaxConcurrentBlobTransfers
	ks := u.senderKey()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.upSender[ks] >= 1 {
		return nil, s.slotBusy(limBlobSenderSlots)
	}
	mailboxFull := b.upMbx[u.mailbox] >= per
	if mailboxFull || b.up >= all-per || b.up+b.down >= all {
		v := s.victimLocked(u.mailbox, mailboxFull)
		switch {
		case v != nil:
			b.removeLocked(v) // frees a slot of the mailbox (if it was full) and of the process
			v.evicted.Store(true)
			v.cut()
			s.rl.refused.With(limBlobEvicted).Inc()
		case mailboxFull:
			return nil, s.slotBusy(limBlobMailboxSlots)
		default:
			return nil, s.slotBusy(limBlobSlots)
		}
	}
	b.up++
	b.upMbx[u.mailbox]++
	b.upSender[ks]++
	b.uploads[u] = struct{}{}
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.removeLocked(u)
	}, nil
}

// acquireDownload takes a download slot of mailbox (the owner's), or
// returns the 429. release frees it.
func (s *Server) acquireDownload(mailbox string) (release func(), e *apiError) {
	b := s.xfers
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case b.downMbx[mailbox] >= s.cfg.MaxBlobTransfersPerMailbox:
		return nil, s.slotBusy(limBlobMailboxSlots)
	case b.up+b.down >= s.cfg.MaxConcurrentBlobTransfers:
		return nil, s.slotBusy(limBlobSlots)
	}
	b.down++
	b.downMbx[mailbox]++
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.down--
		decr(b.downMbx, mailbox)
	}, nil
}

// pacedBody reads a request body that must keep up a pace: the read
// deadline is moved forward by one window each time pace bytes have
// arrived, so a body that stalls (or trickles below the pace) fails with
// a timeout within a window.
type pacedBody struct {
	r      io.Reader
	rc     *http.ResponseController
	pace   int64
	window time.Duration
	until  time.Time // the deadline never passes this
	got    int64
	u      *upload // counts what arrives; once evicted, reads end
}

func newPacedBody(r io.Reader, rc *http.ResponseController, pace int64, window time.Duration) *pacedBody {
	p := &pacedBody{r: r, rc: rc, pace: pace, window: window, until: time.Now().Add(blobTransferMax)}
	p.arm()
	return p
}

func (p *pacedBody) arm() {
	if p.u != nil && p.u.evicted.Load() {
		return // its deadline is in the past: leave it there
	}
	p.rc.SetReadDeadline(paceDeadline(p.window, p.until))
}

func paceDeadline(window time.Duration, until time.Time) time.Time {
	d := time.Now().Add(window)
	if d.After(until) {
		return until
	}
	return d
}

func (p *pacedBody) Read(b []byte) (int, error) {
	if p.u != nil && p.u.evicted.Load() {
		return 0, errEvicted
	}
	n, err := p.r.Read(b)
	if p.u != nil {
		p.u.received.Add(int64(n))
		if p.u.evicted.Load() {
			return n, errEvicted
		}
	}
	if p.got += int64(n); p.got >= p.pace {
		p.got = 0
		p.arm()
	}
	return n, err
}

// pacedWriter is pacedBody for a response: the write deadline moves forward
// by one window each time pace bytes have been written, so a reader that
// stops reading frees the transfer within a window (plus what the socket
// buffers hold).
type pacedWriter struct {
	w      io.Writer
	rc     *http.ResponseController
	pace   int64
	window time.Duration
	until  time.Time
	put    int64
}

func newPacedWriter(w io.Writer, rc *http.ResponseController, pace int64, window time.Duration) *pacedWriter {
	p := &pacedWriter{w: w, rc: rc, pace: pace, window: window, until: time.Now().Add(blobTransferMax)}
	p.arm()
	return p
}

func (p *pacedWriter) arm() { p.rc.SetWriteDeadline(paceDeadline(p.window, p.until)) }

func (p *pacedWriter) Write(b []byte) (int, error) {
	var total int
	for len(b) > 0 { // in pieces of at most pace, so each gets its window
		chunk := b[:min(int64(len(b)), p.pace)]
		n, err := p.w.Write(chunk)
		total += n
		if p.put += int64(n); p.put >= p.pace {
			p.put = 0
			p.arm()
		}
		if err != nil {
			return total, err
		}
		b = b[n:]
	}
	return total, nil
}

// PUT /v1/blob/{mailbox_id}
func (s *Server) handleBlobPut(w http.ResponseWriter, r *http.Request) {
	limit := s.cfg.MaxBlobBytes
	// Size limit before any verification (spec §8.5); a declared length over
	// the limit is refused without reading.
	if r.ContentLength > limit {
		s.refuseUnread(w, r, fail(CodePayloadTooLarge))
		return
	}
	mailboxID := r.PathValue("mailbox_id")
	// §5.3 steps 1–6 need only headers: unauthorized uploads are refused
	// before their body is read.
	da, e := s.authorizeDepositToken(r.Context(), r, mailboxID)
	if e != nil {
		s.refuseUnread(w, r, e)
		return
	}
	// One-shot open tokens permit exactly one *message* deposit (§5.6); they
	// are not accepted for blob uploads (see README interpretation notes).
	if da.claims.Open() {
		s.refuseUnread(w, r, fail(CodeTokenInvalid))
		return
	}
	// The per-sender limit comes after the signature (step 7), as for
	// deposits: the token's sub is written by the mailbox owner, so a
	// token naming someone else's key must not spend that key's budget.
	// The blob byte budgets. The token's sub names the sender's key, but
	// the mailbox owner wrote the token: the sender is proved only by the
	// request signature (step 7), after the body. So before the body only
	// the network's ceiling is charged, with the declared length; the
	// key's budget is only looked at (an empty one is refused unread) and
	// charged once the signature has verified, with what arrived. Nobody
	// can spend another key's budget by naming it in a token.
	//
	// An upload that stores nothing gets back the part of the network
	// charge it never sent; every byte that reached the relay stays
	// charged, whatever refuses the upload (body failure, signature,
	// quota, store), so holding a transfer slot with a trickle is never
	// free. Only an upload refused a slot gets everything back: it held
	// none.
	network, charged := s.network(r), declaredLength(r, limit)
	if ok, wait := s.blobKeyLimit.Ready(da.claims.Sub, s.now()); !ok {
		s.rl.refused.With(limBlobKeyBytes).Inc()
		s.refuseUnread(w, r, &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)})
		return
	}
	if e := s.takeBytes(limBlobBytes, s.blobByteLimit, network, charged); e != nil {
		s.refuseUnread(w, r, e)
		return
	}
	var buf bytes.Buffer // the body as received
	var sent int64       // its length once read whole (the store drains buf)
	stored, held := false, false
	defer func() {
		kept := int64(0)
		if held {
			kept = max(sent, int64(buf.Len()))
		}
		if !stored && charged > kept {
			s.refundBytes(limBlobBytes, s.blobByteLimit, network, charged-kept)
		}
	}()

	// Stream the body, hashing as we go; MaxBytesReader stops after
	// limit+1 bytes, so at most limit bytes are ever buffered. The body
	// must keep its pace from the start.
	rc := http.NewResponseController(w)
	up := &upload{mailbox: mailboxID, sender: da.claims.Sub, start: s.now(),
		cut: func() { rc.SetReadDeadline(time.Unix(1, 0)) }}
	body := newPacedBody(http.MaxBytesReader(w, r.Body, limit), rc, s.cfg.BlobPaceBytes, s.blobPaceWindow)
	body.u = up
	defer rc.SetReadDeadline(time.Time{}) // the connection may serve another request
	// The slot is taken once the body has begun to arrive: a client that
	// announces an upload and sends nothing holds no slot.
	first := make([]byte, 32<<10)
	n, err := io.ReadAtLeast(body, first, 1)
	if e := blobReadError(w, err); e != nil {
		s.writeError(w, e)
		return
	}
	release, e := s.acquireUpload(up)
	if e != nil {
		s.refuseUnread(w, r, e)
		return
	}
	defer release()
	held = true
	if r.ContentLength > 0 {
		buf.Grow(int(r.ContentLength))
	}
	h := sha256.New()
	buf.Write(first[:n])
	h.Write(first[:n])
	if n > 0 {
		_, err = io.Copy(io.MultiWriter(&buf, h), body)
	}
	up.done.Store(true)
	if up.evicted.Load() {
		// Its slot went to a newer upload (it was the slowest): try
		// again later. The bytes it sent stay charged.
		w.Header().Set("Connection", "close")
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: 2})
		return
	}
	if e := blobReadError(w, err); e != nil {
		s.writeError(w, e)
		return
	}
	sent = int64(buf.Len())
	var bodyHash [32]byte
	h.Sum(bodyHash[:0])
	// Step 7. The sender is authenticated but not stored with a blob:
	// nothing reads it.
	if _, e := s.verifySender(r, da, bodyHash); e != nil {
		s.writeError(w, e)
		return
	}
	if e := s.allowSender(da.claims.Sub); e != nil {
		s.writeError(w, e)
		return
	}
	size := int64(buf.Len())
	// The sender is proved: its key's budget pays for what arrived,
	// whatever the store then says (into debt if need be; never refused
	// here).
	s.chargeBlobKey(da.claims.Sub, size)
	info, err := s.blobs.PutBlob(r.Context(), store.BlobPut{
		Mailbox: mailboxID,
		Size:    size,
		TTL:     s.cfg.BlobTTL,
		Limits:  s.limitsFor(da, true), // step 8: token bytes + mailbox blob cap
	}, &buf)
	switch {
	case errors.Is(err, store.ErrQuota):
		s.writeError(w, fail(CodeQuotaExceeded))
		return
	case errors.Is(err, store.ErrRevoked):
		s.writeError(w, fail(CodeTokenRevoked))
		return
	case errors.Is(err, store.ErrNotFound): // deleted mid-request
		s.writeError(w, fail(CodeMailboxUnknown))
		return
	case err != nil:
		s.log.Error("blob put failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	stored = true
	s.m.blobPuts.Inc()
	s.m.blobBytes.Add(size)
	setLog(w, "blob_id", info.ID)
	setLog(w, "size", size)
	writeJSON(w, http.StatusCreated, map[string]string{
		"blob_id":    info.ID,
		"expires_at": info.ExpiresAt.UTC().Format(timeFormat),
	})
}

// blobReadError maps a blob body read error to its answer (nil: the body
// was read, io.EOF included). A body that failed part-way is not coming:
// the connection is closed with the answer.
func blobReadError(w http.ResponseWriter, err error) *apiError {
	var mbe *http.MaxBytesError
	switch {
	case err == nil, errors.Is(err, io.EOF):
		return nil
	case errors.As(err, &mbe):
		return fail(CodePayloadTooLarge)
	default:
		w.Header().Set("Connection", "close")
		return fail(CodeBadRequest)
	}
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
	if !validID(id) {
		s.writeError(w, fail(CodeBlobUnknown))
		return
	}
	// An owner whose blob budget is empty, or whose network's is, is
	// refused before the store is read (the exact charge needs the blob's
	// size, which the read gives).
	network, owner := s.network(r), auth.EncodeKey(mb.PubKey)
	for _, b := range []struct {
		name string
		l    ByteLimiter
		key  string
	}{{limBlobKeyBytes, s.blobKeyLimit, owner}, {limBlobBytes, s.blobByteLimit, network}} {
		if ok, wait := b.l.Ready(b.key, s.now()); !ok {
			s.rl.refused.With(b.name).Inc()
			s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)})
			return
		}
	}
	release, e := s.acquireDownload(mb.ID)
	if e != nil {
		s.writeError(w, e)
		return
	}
	defer release()
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
	// The owner's blob byte budget and its network's ceiling, with the
	// blob's size (at most a key's burst: a blob stored under a larger
	// budget can still be fetched). Only the owner gets this far, so the
	// answer tells nobody else anything.
	if e := s.takeBlobBytes(owner, network, min(info.Size, s.blobKeyLimit.Burst(), s.blobByteLimit.Burst())); e != nil {
		s.writeError(w, e)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	ctl := http.NewResponseController(w)
	io.Copy(newPacedWriter(w, ctl, s.cfg.BlobPaceBytes, s.blobPaceWindow), rc)
	ctl.SetWriteDeadline(time.Time{})
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
	if validID(id) {
		if err := s.blobs.DeleteBlob(r.Context(), mb.ID, id); err != nil {
			s.log.Error("blob delete failed", "err", err)
			s.writeError(w, fail(CodeInternal))
			return
		}
	}
	s.m.blobDeletes.Inc()
	setLog(w, "blob_id", logID(id))
	w.WriteHeader(http.StatusNoContent)
}
