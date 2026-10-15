package api

import (
	"context"
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
// announced but never sent reserves nothing. An upload that fits what is
// stored but not with the reservations of others is told to retry
// (rate_limited, retry_after), since those uploads may yet fail. The
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
// made, for the re-check when the upload reserves.
type blobCheck struct {
	da    *depositAuth
	size  int64
	usage store.BlobUsage
	jti   string // the token's jti if it has a byte quota, else ""
}

// overLocked is the quota an upload of c.size would exceed given the
// stored usage and, with res, the reservations (b.mu held); "" if none.
// The order is the store's.
func (s *Server) overLocked(c *blobCheck, res bool) store.QuotaKind {
	b, da, u := s.blobRes, c.da, c.usage
	var rm, rt int64
	var rs [2]int64
	if res {
		rm, rs, rt = b.mailbox[da.mailbox.ID], b.sender[da.mailbox.ID+"\x00"+da.claims.Sub], b.token[da.mailbox.ID+"\x00"+da.claims.Jti]
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

// judgeLocked is the answer to c given the reservations (b.mu held): nil
// if it fits; quota_exceeded if what is stored refuses it; rate_limited
// if only other uploads' reservations do.
func (s *Server) judgeLocked(c *blobCheck) *apiError {
	if kind := s.overLocked(c, false); kind != "" {
		return &apiError{code: CodeQuotaExceeded, quota: kind}
	}
	if s.overLocked(c, true) != "" {
		return &apiError{code: CodeRateLimited, retryAfter: blobRetryAfter}
	}
	return nil
}

// checkBlob is §5.3 step 8 for a blob upload before its body is read (see
// above): nothing is reserved yet.
func (s *Server) checkBlob(ctx context.Context, da *depositAuth, size int64) (*blobCheck, *apiError) {
	c := &blobCheck{da: da, size: size}
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
		s.blobRes.mu.Lock()
		e = s.judgeLocked(c)
		s.blobRes.mu.Unlock()
		if e == nil || e.code != CodeQuotaExceeded {
			break
		}
	}
	return c, e
}

// reserve re-checks c against the reservations and reserves its size, once
// the upload holds its transfer slot; release gives it back.
func (s *Server) reserve(c *blobCheck) (release func(), e *apiError) {
	b := s.blobRes
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := s.judgeLocked(c); e != nil {
		return nil, e
	}
	mbx, sk, tk := c.da.mailbox.ID, c.da.mailbox.ID+"\x00"+c.da.claims.Sub, c.da.mailbox.ID+"\x00"+c.da.claims.Jti
	size, jti := c.size, c.jti
	b.mailbox[mbx] += size
	b.sender[sk] = [2]int64{b.sender[sk][0] + 1, b.sender[sk][1] + size}
	if jti != "" {
		b.token[tk] += size
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.mailbox[mbx] -= size; b.mailbox[mbx] <= 0 {
				delete(b.mailbox, mbx)
			}
			if r := [2]int64{b.sender[sk][0] - 1, b.sender[sk][1] - size}; r[0] <= 0 {
				delete(b.sender, sk)
			} else {
				b.sender[sk] = r
			}
			if jti != "" {
				if b.token[tk] -= size; b.token[tk] <= 0 {
					delete(b.token, tk)
				}
			}
		})
	}, nil
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
