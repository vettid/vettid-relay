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
//   - the token's byte quota;
//
// counting, besides what the store holds, the uploads of this process
// still in progress, whose declared lengths are reserved until they end.
// The store checks again, atomically with the commit, what was actually
// stored (and is what holds across processes).
//
// Before the body the sender is the token's sub: the mailbox owner wrote
// it, and only the request signature (step 7, after the body) proves the
// uploader holds that key. A token naming another key can therefore make
// this check look at that key's share (refusing itself) and hold a
// reservation on it while its body is read, as it holds that key's
// transfer slot (13), but it can never store a blob under that key: the
// commit is made only after step 7, under the key that signed.

// blobReservations are the uploads of this process between their pre-body
// check and their end.
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

// overBlobQuota is the quota an upload of size would exceed, given u and
// the reservations (b.mu held); "" if none. The order is the store's.
func (s *Server) overBlobQuotaLocked(da *depositAuth, u store.BlobUsage, size int64) store.QuotaKind {
	b := s.blobRes
	mbx, sk, tk := da.mailbox.ID, da.mailbox.ID+"\x00"+da.claims.Sub, da.mailbox.ID+"\x00"+da.claims.Jti
	sr := b.sender[sk]
	switch {
	case u.MailboxBytes+b.mailbox[mbx]+size > s.blobRoom(da):
		return store.QuotaMailboxBlobs
	case u.SenderBytes+sr[1]+size > s.cfg.SenderBlobBytes() || u.SenderBlobs+sr[0]+1 > s.cfg.MaxSenderBlobs:
		return store.QuotaSenderBlobs
	case da.claims.Quota != nil && da.claims.Quota.Bytes != nil && u.TokenBytes+b.token[tk]+size > *da.claims.Quota.Bytes:
		return store.QuotaToken
	}
	return ""
}

// reserveBlob is §5.3 step 8 for a blob upload before its body is read
// (see above). On success the upload's declared size is reserved until
// release is called; otherwise the answer is quota_exceeded with its
// quota member (or internal).
func (s *Server) reserveBlob(ctx context.Context, da *depositAuth, size int64) (release func(), e *apiError) {
	jti := ""
	if da.claims.Quota != nil && da.claims.Quota.Bytes != nil {
		jti = da.claims.Jti
	}
	b := s.blobRes
	var kind store.QuotaKind
	for _, fresh := range []bool{false, true} { // a counter that runs high is recomputed once
		u, err := s.blobs.BlobUsage(ctx, da.mailbox.ID, da.claims.Sub, jti, fresh)
		if err != nil {
			s.log.Error("blob usage lookup failed", "err", err)
			return nil, fail(CodeInternal)
		}
		b.mu.Lock()
		if kind = s.overBlobQuotaLocked(da, u, size); kind == "" {
			break // b.mu still held
		}
		b.mu.Unlock()
	}
	if kind != "" {
		return nil, &apiError{code: CodeQuotaExceeded, quota: kind}
	}
	mbx, sk, tk := da.mailbox.ID, da.mailbox.ID+"\x00"+da.claims.Sub, da.mailbox.ID+"\x00"+da.claims.Jti
	b.mailbox[mbx] += size
	b.sender[sk] = [2]int64{b.sender[sk][0] + 1, b.sender[sk][1] + size}
	if jti != "" {
		b.token[tk] += size
	}
	b.mu.Unlock()
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
