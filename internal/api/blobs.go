package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Blob transfer (spec §6.8). Blob bodies are opaque ciphertext: never parsed,
// never logged. Only ids and sizes reach logs and metrics.

// Transfer slots. An upload streams to the store and holds a buffer of
// its body; a download streams from S3, or holds its blob when the SQLite
// store serves it. Transfers share the process's bandwidth, and slow ones
// compete for slots (eviction, below), so they are bounded per process
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
	netUp    map[string]int       // uploads, by eviction network (evictionNetwork)
	netSince map[string]time.Time // since when each has held an upload slot (gaps under the minimum age not counted)
	netLeft  map[string]time.Time // when each last gave up its last upload slot
}

func newBlobTransfers() *blobTransfers {
	return &blobTransfers{upMbx: map[string]int{}, downMbx: map[string]int{}, upSender: map[string]int{}, uploads: map[*upload]struct{}{},
		netUp: map[string]int{}, netSince: map[string]time.Time{}, netLeft: map[string]time.Time{}}
}

func (b *blobTransfers) inFlight() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.up + b.down
}

func (b *blobTransfers) empty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.up+b.down == 0 && len(b.upMbx)+len(b.downMbx)+len(b.upSender)+len(b.uploads)+len(b.netUp) == 0
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

// An upload's state moves once, from reading to done (its body read whole)
// or to evicted (its slot given to a newer upload), by CompareAndSwap: the
// handler and the evictor cannot both win.
const (
	upReading int32 = iota
	upDone
	upEvicted
)

// rateWindow is how far back an upload's speed is measured: what it
// received in the last rateWindow seconds (an upload that bursts and then
// trickles is judged on the trickle).
const rateWindow = 10

// evictGrace protects every upload, whatever its network, for its first
// seconds: one pace window (config.BlobPaceWindow), by the end of which it
// has had to send cfg.BlobPaceBytes or be dropped, so it has a speed to
// be judged on. Without it, newcomers from busy networks (vault hosts)
// would cut each other off before any got going.
const evictGrace = config.BlobPaceWindow

// evictionNetwork is what the eviction clock is kept for: the IPv4
// address, or the IPv6 /48 (wider than the /64 of the per-network limits,
// so that whoever holds a larger prefix cannot take turns with its /64s).
func evictionNetwork(a netip.Addr) string {
	if a.Is6() && !a.Is4In6() {
		p, _ := a.Prefix(48)
		return p.String()
	}
	return rateKey(a)
}

// nearlyEqual is how close two speeds are to count as the same when the
// victim is chosen: then the upload of the network holding the most
// upload slots goes.
func nearlyEqual(a, b float64) bool { return math.Abs(a-b) <= max(0.1*min(a, b), 1024) }

// upload is one blob upload, from the moment its body begins to be read.
type upload struct {
	mailbox, sender, network string
	start                    time.Time // when its body began to be read (server clock)
	now                      func() time.Time
	state                    atomic.Int32
	cut                      func()       // interrupts its body read (a read deadline in the past)
	released                 bool         // its slot is given up (under blobTransfers.mu)
	res                      *reservation // its reserved length (blobquota.go; under blobReservations.mu), dropped with its slot

	mu   sync.Mutex
	secs [rateWindow]struct{ sec, n int64 } // bytes received, by second (a ring)
}

func (u *upload) senderKey() string { return u.mailbox + "\x00" + u.sender }

func (u *upload) evicted() bool { return u.state.Load() == upEvicted }

// add counts n bytes received now.
func (u *upload) add(n int) {
	if n <= 0 {
		return
	}
	sec := u.now().Unix()
	u.mu.Lock()
	b := &u.secs[sec%rateWindow]
	if b.sec != sec {
		b.sec, b.n = sec, 0
	}
	b.n += int64(n)
	u.mu.Unlock()
}

// rate is u's bytes received per second over the last rateWindow seconds
// (over its actual age, at least evictGrace, if it is younger).
func (u *upload) rate(now time.Time) float64 {
	sec := now.Unix()
	var n int64
	u.mu.Lock()
	for _, b := range u.secs {
		if b.sec > sec-rateWindow && b.sec <= sec {
			n += b.n
		}
	}
	u.mu.Unlock()
	span := min(max(now.Sub(u.start).Seconds(), evictGrace.Seconds()), rateWindow)
	return float64(n) / span
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
	if b.netUp[u.network]--; b.netUp[u.network] <= 0 {
		delete(b.netUp, u.network)
		b.netLeft[u.network] = u.now() // its clock is kept: see takeNetLocked
	}
}

// takeNetLocked records that u's network takes an upload slot. A network
// that comes back within cfg.BlobEvictMinAge of giving up its last slot
// keeps its clock: aborting and reconnecting does not reset it. Clocks of
// networks gone longer are dropped by pruneNetClocks.
func (s *Server) takeNetLocked(u *upload, now time.Time) {
	b := s.xfers
	if b.netUp[u.network]++; b.netUp[u.network] > 1 {
		return
	}
	if left, ok := b.netLeft[u.network]; !ok || now.Sub(left) >= s.cfg.BlobEvictMinAge {
		b.netSince[u.network] = now
	}
	delete(b.netLeft, u.network)
}

// pruneNetClocks drops the clocks of networks that have held no upload
// slot for cfg.BlobEvictMinAge (they would start afresh anyway). Run by
// the server's periodic janitor, not on every upload.
func (s *Server) pruneNetClocks(now time.Time) {
	b := s.xfers
	b.mu.Lock()
	defer b.mu.Unlock()
	for n, left := range b.netLeft {
		if now.Sub(left) >= s.cfg.BlobEvictMinAge {
			delete(b.netLeft, n)
			delete(b.netSince, n)
		}
	}
}

// evictableLocked reports whether u may be cut off now for a newcomer
// from network: u has run evictGrace, comes from another network, and has
// run cfg.BlobEvictMinAge or its network has held upload slots that long
// (gaps shorter than that not counting). Tying it to the network means an
// address cannot keep slots by replacing old uploads with new ones; not
// letting a network cut off its own means it cannot replace them without
// first giving a slot up.
func (s *Server) evictableLocked(u *upload, network string, now time.Time) bool {
	age, minAge := now.Sub(u.start), s.cfg.BlobEvictMinAge
	return age >= evictGrace && u.network != network &&
		(age >= minAge || now.Sub(s.xfers.netSince[u.network]) >= minAge)
}

// victimLocked is the upload to cut off for newcomer when its mailbox
// (inMailbox) or the process has no upload slot free: the slowest, by
// bytes received in the last rateWindow seconds, of the evictable uploads
// still reading their body (uploads to that mailbox, if it is full); of
// nearly equal speeds, the one whose network holds the most upload slots.
// Nil if none qualifies.
func (s *Server) victimLocked(newcomer *upload, inMailbox bool) *upload {
	now := s.now()
	type cand struct {
		u    *upload
		rate float64
	}
	var cands []cand
	slowest := math.Inf(1)
	for u := range s.xfers.uploads {
		if (inMailbox && u.mailbox != newcomer.mailbox) || u.state.Load() != upReading || !s.evictableLocked(u, newcomer.network, now) {
			continue
		}
		r := u.rate(now)
		cands = append(cands, cand{u, r})
		slowest = min(slowest, r)
	}
	var victim *upload
	var vr float64
	for _, c := range cands {
		if !nearlyEqual(c.rate, slowest) {
			continue
		}
		if victim == nil || s.xfers.netUp[c.u.network] > s.xfers.netUp[victim.network] ||
			(s.xfers.netUp[c.u.network] == s.xfers.netUp[victim.network] && c.rate < vr) {
			victim, vr = c.u, c.rate
		}
	}
	return victim
}

// acquireUpload takes an upload slot for u, or returns the 429. When the
// mailbox or the process has none free, the slowest evictable upload is
// cut off and u takes its slot (it is answered 429 with retry_after; see
// handleBlobPut). A sender's own upload to the mailbox is never cut off
// for its next one to that mailbox.
//
// With c (blobquota.go), u also reserves its declared length, re-checked
// now: if only other uploads' reservations stand in its way, the fewest
// evictable uploads to its mailbox, slowest first, are cut off to make
// room, their reservations dropped at once; if that cannot make room,
// u is refused rate_limited (quota_exceeded over what is stored) and
// nobody is cut off. release frees the slot and the reservation (nothing,
// if they were taken away).
func (s *Server) acquireUpload(u *upload, c *blobCheck) (release func(), e *apiError) {
	b, per, all := s.xfers, s.cfg.MaxBlobTransfersPerMailbox, s.cfg.MaxConcurrentBlobTransfers
	ks := u.senderKey()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.upSender[ks] >= 1 {
		return nil, s.slotBusy(limBlobSenderSlots)
	}
	res := s.blobRes
	res.mu.Lock()
	defer res.mu.Unlock()
	for {
		var planned []*upload
		mailboxFull := b.upMbx[u.mailbox] >= per
		if mailboxFull || b.up >= all-per || b.up+b.down >= all {
			v := s.victimLocked(u, mailboxFull)
			if v == nil {
				if mailboxFull {
					return nil, s.slotBusy(limBlobMailboxSlots)
				}
				return nil, s.slotBusy(limBlobSlots)
			}
			planned = append(planned, v)
		}
		if c != nil {
			if planned, e = s.planLocked(c, planned); e != nil {
				return nil, e
			}
		}
		raced := false
		for _, v := range planned {
			if !v.state.CompareAndSwap(upReading, upEvicted) {
				raced = true // it has just finished reading: plan again
				continue
			}
			b.removeLocked(v) // frees its slot (of the mailbox, and of the process)
			res.dropLocked(v.res)
			v.cut()
			s.rl.refused.With(limBlobEvicted).Inc()
		}
		if !raced {
			break
		}
	}
	b.up++
	b.upMbx[u.mailbox]++
	b.upSender[ks]++
	b.uploads[u] = struct{}{}
	s.takeNetLocked(u, s.now())
	if c != nil {
		u.res = res.addLocked(c)
	}
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.removeLocked(u)
		res.mu.Lock()
		res.dropLocked(u.res)
		res.mu.Unlock()
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
	if p.u != nil && p.u.evicted() {
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
	if p.u != nil && p.u.evicted() {
		return 0, errEvicted
	}
	n, err := p.r.Read(b)
	if p.u != nil {
		p.u.add(n)
		if p.u.evicted() {
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

// bodyReader is an upload's body as the store reads it: hashed and
// counted as it passes, with the first error the body itself gave (the
// store may wrap or replace it).
type bodyReader struct {
	r   io.Reader
	h   hash.Hash
	n   int64
	err error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.h.Write(p[:n])
	b.n += int64(n)
	if err != nil && err != io.EOF && b.err == nil {
		b.err = err
	}
	return n, err
}

// PUT /v1/blob/{mailbox_id}
//
// The body is streamed to the store as it arrives (staged, invisible and
// uncounted), hashed on the way; once it is whole the request signature
// is verified over that hash (step 7) and only then is the blob committed
// with the quota checks. An upload refused or failed after its body
// began leaves nothing stored: the staged body is discarded.
func (s *Server) handleBlobPut(w http.ResponseWriter, r *http.Request) {
	limit := s.cfg.MaxBlobBytes
	// Size limit before any verification (spec §8.5); a declared length over
	// the limit is refused without reading. (0.9.2) An upload must declare
	// its length: the quota checks below are made on it before the body.
	if r.ContentLength > limit {
		s.refuseUnread(w, r, fail(CodePayloadTooLarge))
		return
	}
	if r.ContentLength < 0 {
		s.refuseUnread(w, r, fail(CodeBadRequest))
		return
	}
	size := r.ContentLength
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
	// Step 8 before the body (0.9.2, §6.8): the mailbox's blob storage
	// (less the owner's devices' room), the sender's share and the token's
	// byte quota, on the declared length. Checked only: the length is
	// reserved once the upload holds a transfer slot (blobquota.go). The
	// store checks again at the commit, after the signature.
	check, e := s.checkBlob(r.Context(), da, size, evictionNetwork(clientIP(r, s.cfg.TrustProxy)))
	if e != nil {
		s.refuseUnread(w, r, e)
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
	network, charged := s.network(r), size
	if ok, wait := s.blobKeyLimit.Ready(da.claims.Sub, s.now()); !ok {
		s.rl.refused.With(limBlobKeyBytes).Inc()
		s.refuseUnread(w, r, &apiError{code: CodeRateLimited, retryAfter: ratelimit.RetryAfterSeconds(wait)})
		return
	}
	src, e := s.takeBytes(limBlobBytes, s.blobByteLimit, network, charged)
	if e != nil {
		s.refuseUnread(w, r, e)
		return
	}
	body := &bodyReader{h: sha256.New()} // the body as received
	var staged store.StagedBlob
	stored, held, firstN := false, false, 0
	defer func() {
		if staged != nil && !stored {
			// Nothing may stay behind: the staged body goes.
			if err := staged.Discard(context.WithoutCancel(r.Context())); err != nil {
				s.log.Error("staged blob discard failed", "err", err)
			}
		}
		kept := int64(0)
		if held { // every byte received stays charged, the first read's included
			kept = max(body.n, int64(firstN))
		}
		if !stored && charged > kept {
			s.refundBytes(limBlobBytes, s.blobByteLimit, network, charged-kept, src)
		}
	}()

	// The body must keep its pace from the start; MaxBytesReader stops it
	// past limit (which Content-Length already bounds).
	rc := http.NewResponseController(w)
	up := &upload{mailbox: mailboxID, sender: da.claims.Sub, network: evictionNetwork(clientIP(r, s.cfg.TrustProxy)), start: s.now(), now: s.now,
		cut: func() { rc.SetReadDeadline(time.Unix(1, 0)) }}
	paced := newPacedBody(http.MaxBytesReader(w, r.Body, limit), rc, s.cfg.BlobPaceBytes, s.blobPaceWindow)
	paced.u = up
	defer rc.SetReadDeadline(time.Time{}) // the connection may serve another request
	// The slot is taken once the body has begun to arrive: a client that
	// announces an upload and sends nothing holds no slot. (This first
	// read, at most blobFirstRead bytes, and the store's copy buffer are
	// what an upload holds in memory.)
	first := make([]byte, min(blobFirstRead, max(size, 1)))
	n := 0
	if size > 0 {
		var err error
		n, err = io.ReadAtLeast(paced, first, 1)
		firstN = n
		if e := blobReadError(w, err); e != nil {
			s.writeError(w, e)
			return
		}
	}
	// The slot, and with it the reservation of its declared length,
	// re-checked against the uploads that reserved meanwhile.
	release, e := s.acquireUpload(up, check)
	if e != nil { // it took no slot: charged nothing
		s.refuseUnread(w, r, e)
		return
	}
	defer release()
	held = true
	body.r = io.MultiReader(bytes.NewReader(first[:n]), paced)
	st, err := s.blobs.StageBlob(r.Context(), mailboxID, size, body)
	if err == nil {
		staged = st
	}
	if !up.state.CompareAndSwap(upReading, upDone) {
		// Its slot went to a newer upload (it was the slowest): try
		// again later. The bytes it sent stay charged.
		w.Header().Set("Connection", "close")
		s.writeError(w, &apiError{code: CodeRateLimited, retryAfter: 2})
		return
	}
	switch {
	case body.err != nil || errors.Is(err, store.ErrBlobSize):
		// The body failed (stalled, cut off, short or long): not coming.
		bodyErr := body.err
		if bodyErr == nil {
			bodyErr = io.ErrUnexpectedEOF
		}
		s.writeError(w, blobReadError(w, bodyErr))
		return
	case err != nil:
		s.log.Error("blob stage failed", "err", err)
		w.Header().Set("Connection", "close")
		s.writeError(w, fail(CodeInternal))
		return
	}
	var bodyHash [32]byte
	body.h.Sum(bodyHash[:0])
	// Step 7: the sender's key is proved, and is kept with the blob (its
	// share is counted by it).
	sender, e := s.verifySender(r, da, bodyHash)
	if e != nil {
		s.writeError(w, e)
		return
	}
	if e := s.allowSender(sender); e != nil {
		s.writeError(w, e)
		return
	}
	// The sender is proved: its key's budget pays for what arrived,
	// whatever the store then says (into debt if need be; never refused
	// here).
	s.chargeBlobKey(sender, size)
	// Step 8, again, atomically. The commit is not cut short by the client
	// going away: one cancelled mid-write could leave a counted blob whose
	// body the deferred discard then deletes.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), s.blobCommitWait)
	defer cancel()
	info, err := staged.Commit(cctx, s.blobPut(da, sender, size))
	if err != nil && !errors.Is(err, store.ErrQuota) && !errors.Is(err, store.ErrRevoked) && !errors.Is(err, store.ErrNotFound) {
		// Not a definite refusal: the commit may have been applied after
		// all (a timeout, say). Deleting the blob by its id undoes it if so
		// (idempotent), on a context of its own: the commit's may be what
		// ran out. If that fails too, the body is kept (no discard): it may
		// back a committed blob, and the bucket's lifecycle rule removes it
		// if nothing does.
		if id := staged.ID(); id != "" {
			dctx, dcancel := context.WithTimeout(context.WithoutCancel(r.Context()), s.blobCommitWait)
			if derr := s.blobs.DeleteBlob(dctx, mailboxID, id); derr != nil {
				s.log.Error("blob cleanup after a failed commit failed; its body is kept", "err", derr)
				staged = nil
			}
			dcancel()
		}
	}
	switch {
	case errors.Is(err, store.ErrQuota):
		s.writeError(w, quotaFail(err))
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

// blobCommitTimeout bounds an upload's commit, which runs on after its
// client has gone.
const blobCommitTimeout = 30 * time.Second

// blobFirstRead bounds the first read of an upload's body, which is made
// before the transfer slot is taken.
const blobFirstRead = 32 << 10

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

// The owner's list of its mailbox's blobs (0.9.2, §6.8).
const (
	blobListBodyLimit = 1 << 10 // its signed body: {after?, max?}
	blobListDefault   = 100
	blobListMax       = 500
)

type wireBlob struct {
	BlobID    string `json:"blob_id"`
	Size      int64  `json:"size"`
	Sender    string `json:"sender,omitempty"` // the uploading key (absent for blobs stored before 0.9.2)
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

type blobListResponse struct {
	Blobs     []wireBlob `json:"blobs"`
	Next      string     `json:"next,omitempty"`
	UsedBytes int64      `json:"used_bytes"`
	MaxBytes  int64      `json:"max_bytes"`
}

// POST /v1/blobs — owner-signed. The paging parameters are in the signed
// body, not the query string, which the signature does not cover: two
// page requests then never share a signature (replay_detected), and
// nobody can change them in transit.
func (s *Server) handleBlobList(w http.ResponseWriter, r *http.Request) {
	body, e := s.readBody(w, r, blobListBodyLimit) // under the small-body deadline
	if e != nil {
		s.writeError(w, e)
		return
	}
	mb, e := s.authorizeOwner(r.Context(), r, auth.BodyHash(body))
	if e != nil {
		s.writeError(w, e)
		return
	}
	var req struct {
		After *string          `json:"after"`
		Max   *json.RawMessage `json:"max"`
	}
	if len(bytes.TrimSpace(body)) > 0 && !decodeJSON(body, &req) {
		s.writeError(w, fail(CodeBadRequest))
		return
	}
	after, max := "", blobListDefault
	if req.After != nil {
		if after = *req.After; !validID(after) {
			s.writeError(w, fail(CodeBadRequest))
			return
		}
	}
	if req.Max != nil {
		// An integer in [1, 500], never clamped.
		n, err := strconv.Atoi(string(*req.Max))
		if err != nil || n < 1 || n > blobListMax || strconv.Itoa(n) != string(*req.Max) {
			s.writeError(w, fail(CodeBadRequest))
			return
		}
		max = n
	}
	blobs, next, used, err := s.blobs.ListBlobs(r.Context(), mb.ID, after, max)
	if err != nil {
		s.log.Error("blob list failed", "err", err)
		s.writeError(w, fail(CodeInternal))
		return
	}
	out := blobListResponse{Blobs: make([]wireBlob, 0, len(blobs)), Next: next, UsedBytes: used, MaxBytes: s.cfg.MailboxMaxBlobBytes}
	for _, b := range blobs {
		out.Blobs = append(out.Blobs, wireBlob{BlobID: b.ID, Size: b.Size, Sender: b.Sender,
			CreatedAt: b.CreatedAt.UTC().Format(timeFormat), ExpiresAt: b.ExpiresAt.UTC().Format(timeFormat)})
	}
	setLog(w, "count", len(out.Blobs))
	writeJSON(w, http.StatusOK, out)
}
