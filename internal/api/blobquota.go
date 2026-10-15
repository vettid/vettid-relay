package api

import (
	"context"
	"sort"
	"sync"

	"github.com/vettid/vettid-relay/internal/store"
)

// The mailbox's blob storage is shared (0.9.2, §6.8): every depositor and
// the claims the mailbox created. So that one sender cannot fill it for
// all the others, an upload is checked before its body is read, on its
// declared length (Content-Length, which an upload must carry), against
//
//   - the mailbox's cap, less the room of one maximum blob kept for
//     uploads under the owner's device tokens (owner_device, §5.2): any
//     other upload is refused when it would leave less free; a device
//     token's upload may use the whole cap;
//   - the sender's share: at most cfg.SenderBlobBytes() in at most
//     cfg.MaxSenderBlobs blobs per sender key and mailbox;
//   - the token's byte quota.
//
// What the store holds decides: over it, the upload is refused
// quota_exceeded (final until something is deleted or expires, or a
// token renewed). Uploads in progress on this process count too, with
// their declared lengths, but only those that hold a transfer slot (13):
// an upload reserves its length when it takes its slot, after its body
// has begun to arrive, re-checked then, and gives it back when it ends.
// So reservations are bounded by the slots and their pace, and an upload
// announced but never sent reserves nothing. Reservations do not keep
// others out either: the reservation of an upload that a newcomer could
// cut off for its slot (evictable, blobs.go) does not refuse the newcomer
// before its body, and when it takes its slot the fewest such uploads to
// its mailbox, slowest first, are cut off and their reservations dropped
// at once (nobody, if that would not make room). An upload that fits what
// is stored but not with the reservations of uploads it cannot cut off is
// told to retry (rate_limited, retry_after), since those may yet fail. The
// store checks again, atomically with the commit, what was actually
// stored (and is what holds across processes).
//
// Before the body the sender is the token's sub: the mailbox owner wrote
// it, and only the request signature (step 7, after the body) proves the
// uploader holds that key. A token naming another key can therefore make
// this check look at that key's share (refusing itself) and, while its
// body moves, hold a reservation on it, as it holds that key's transfer
// slot (13); it can never store a blob under that key: the commit is made
// only after step 7, under the key that signed.

// blobRetryAfter is the retry_after of an upload refused for other
// uploads' reservations (as for want of a transfer slot).
const blobRetryAfter = 2

// blobReservations are the uploads of this process that hold a transfer
// slot.
type blobReservations struct {
	mu      sync.Mutex
	mailbox map[string]int64    // bytes, by mailbox
	sender  map[string][2]int64 // blobs and bytes, by mailbox and sender key
	token   map[string]int64    // bytes, by mailbox and token jti
}

func newBlobReservations() *blobReservations {
	return &blobReservations{mailbox: map[string]int64{}, sender: map[string][2]int64{}, token: map[string]int64{}}
}

func (b *blobReservations) empty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.mailbox)+len(b.sender)+len(b.token) == 0
}

// blobRoom is what an upload may fill of a mailbox's blob storage: the
// whole cap under an owner_device token, the cap less one maximum blob
// (kept for those) otherwise.
func (s *Server) blobRoom(da *depositAuth) int64 {
	if da.claims.OwnerDevice {
		return s.cfg.MailboxMaxBlobBytes
	}
	return s.cfg.MailboxMaxBlobBytes - s.cfg.MaxBlobBytes
}

// blobCheck is an upload's pre-body check: what the store held when it was
// made, for the re-check when the upload takes its slot.
type blobCheck struct {
	da      *depositAuth
	size    int64
	usage   store.BlobUsage
	jti     string // the token's jti if it has a byte quota, else ""
	network string // the upload's eviction network (evictionNetwork)
}

func (c *blobCheck) keys() (mbx, sk, tk string) {
	return c.da.mailbox.ID, c.da.mailbox.ID + "\x00" + c.da.claims.Sub, c.da.mailbox.ID + "\x00" + c.da.claims.Jti
}

// reservation is what one upload holding a slot has reserved (its
// upload's res, under blobReservations.mu).
type reservation struct {
	mbx, sk, tk string
	size        int64
	token       bool // the token's bytes are reserved too
	dropped     bool
}

// addLocked reserves c's size (b.mu held).
func (b *blobReservations) addLocked(c *blobCheck) *reservation {
	mbx, sk, tk := c.keys()
	r := &reservation{mbx: mbx, sk: sk, tk: tk, size: c.size, token: c.jti != ""}
	b.mailbox[mbx] += r.size
	b.sender[sk] = [2]int64{b.sender[sk][0] + 1, b.sender[sk][1] + r.size}
	if r.token {
		b.token[tk] += r.size
	}
	return r
}

// dropLocked gives a reservation back (b.mu held); idempotent.
func (b *blobReservations) dropLocked(r *reservation) {
	if r == nil || r.dropped {
		return
	}
	r.dropped = true
	if b.mailbox[r.mbx] -= r.size; b.mailbox[r.mbx] <= 0 {
		delete(b.mailbox, r.mbx)
	}
	if v := [2]int64{b.sender[r.sk][0] - 1, b.sender[r.sk][1] - r.size}; v[0] <= 0 {
		delete(b.sender, r.sk)
	} else {
		b.sender[r.sk] = v
	}
	if r.token {
		if b.token[r.tk] -= r.size; b.token[r.tk] <= 0 {
			delete(b.token, r.tk)
		}
	}
}

// overLocked is the quota an upload of c.size would exceed given the
// stored usage and, with res, the reservations less those of the uploads
// in without (blobReservations.mu held); "" if none. The order is the
// store's.
func (s *Server) overLocked(c *blobCheck, res bool, without []*upload) store.QuotaKind {
	b, da, u := s.blobRes, c.da, c.usage
	var rm, rt int64
	var rs [2]int64
	if res {
		mbx, sk, tk := c.keys()
		rm, rs, rt = b.mailbox[mbx], b.sender[sk], b.token[tk]
		for _, w := range without {
			if r := w.res; r != nil && !r.dropped {
				if r.mbx == mbx {
					rm -= r.size
				}
				if r.sk == sk {
					rs[0], rs[1] = rs[0]-1, rs[1]-r.size
				}
				if r.token && r.tk == tk {
					rt -= r.size
				}
			}
		}
	}
	switch {
	case u.MailboxBytes+rm+c.size > s.blobRoom(da):
		return store.QuotaMailboxBlobs
	case u.SenderBytes+rs[1]+c.size > s.cfg.SenderBlobBytes() || u.SenderBlobs+rs[0]+1 > s.cfg.MaxSenderBlobs:
		return store.QuotaSenderBlobs
	case c.jti != "" && u.TokenBytes+rt+c.size > *da.claims.Quota.Bytes:
		return store.QuotaToken
	}
	return ""
}

// judgeLocked is the answer to c given the reservations less those of
// without (blobReservations.mu held): nil if it fits; quota_exceeded if
// what is stored refuses it; rate_limited if only reservations do.
func (s *Server) judgeLocked(c *blobCheck, without []*upload) *apiError {
	if kind := s.overLocked(c, false, nil); kind != "" {
		return &apiError{code: CodeQuotaExceeded, quota: kind}
	}
	if s.overLocked(c, true, without) != "" {
		return &apiError{code: CodeRateLimited, retryAfter: blobRetryAfter}
	}
	return nil
}

// reservingVictimsLocked are the uploads to c's mailbox whose reservation
// a newcomer from c's network may take by cutting them off: evictable
// (evictableLocked), still reading, holding a reservation, not in skip;
// the slowest first (s.xfers.mu and s.blobRes.mu held).
func (s *Server) reservingVictimsLocked(c *blobCheck, skip []*upload) []*upload {
	now := s.now()
	type cand struct {
		u    *upload
		rate float64
	}
	var cs []cand
next:
	for u := range s.xfers.uploads {
		if u.mailbox != c.da.mailbox.ID || u.res == nil || u.res.dropped || u.state.Load() != upReading || !s.evictableLocked(u, c.network, now) {
			continue
		}
		for _, k := range skip {
			if k == u {
				continue next
			}
		}
		cs = append(cs, cand{u, u.rate(now)})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].rate < cs[j].rate })
	out := make([]*upload, len(cs))
	for i, c := range cs {
		out[i] = c.u
	}
	return out
}

// planLocked adds to planned (the uploads a newcomer will cut off) the
// fewest reserving victims, slowest first, that make c fit, and returns
// the answer with them left out (s.xfers.mu and s.blobRes.mu held).
func (s *Server) planLocked(c *blobCheck, planned []*upload) ([]*upload, *apiError) {
	e := s.judgeLocked(c, planned)
	if e == nil || e.code != CodeRateLimited {
		return planned, e
	}
	cands := s.reservingVictimsLocked(c, planned)
	if s.judgeLocked(c, append(append([]*upload(nil), planned...), cands...)) != nil {
		return planned, e // even cutting them all off would not do
	}
	for _, v := range cands {
		planned = append(planned, v)
		if s.judgeLocked(c, planned) == nil {
			break
		}
	}
	return planned, nil
}

// checkBlob is §5.3 step 8 for a blob upload before its body is read (see
// above): nothing is reserved yet, and the reservations of uploads this
// one could cut off when it takes its slot do not refuse it.
func (s *Server) checkBlob(ctx context.Context, da *depositAuth, size int64, network string) (*blobCheck, *apiError) {
	c := &blobCheck{da: da, size: size, network: network}
	if da.claims.Quota != nil && da.claims.Quota.Bytes != nil {
		c.jti = da.claims.Jti
	}
	var e *apiError
	for _, fresh := range []bool{false, true} { // a counter that runs high is recomputed once
		u, err := s.blobs.BlobUsage(ctx, da.mailbox.ID, da.claims.Sub, c.jti, fresh)
		if err != nil {
			s.log.Error("blob usage lookup failed", "err", err)
			return nil, fail(CodeInternal)
		}
		c.usage = u
		s.xfers.mu.Lock()
		s.blobRes.mu.Lock()
		_, e = s.planLocked(c, nil)
		s.blobRes.mu.Unlock()
		s.xfers.mu.Unlock()
		if e == nil || e.code != CodeQuotaExceeded {
			break
		}
	}
	return c, e
}

// blobPut is the commit's store.BlobPut for an upload authorized by da and
// signed by sender.
func (s *Server) blobPut(da *depositAuth, sender string, size int64) store.BlobPut {
	lim := s.limitsFor(da, true)
	lim.MailboxMaxBytes = s.blobRoom(da)
	return store.BlobPut{
		Mailbox: da.mailbox.ID, Sender: sender, Size: size, TTL: s.cfg.BlobTTL, Limits: lim,
		SenderMaxBytes: s.cfg.SenderBlobBytes(), SenderMaxBlobs: s.cfg.MaxSenderBlobs,
	}
}
