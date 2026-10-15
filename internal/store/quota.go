package store

import "errors"

// QuotaKind says which quota refused a write (0.9.2: the `quota` member of
// a quota_exceeded error body, spec §7.1), so that a client can tell a
// token it may renew from storage only the mailbox owner can free.
type QuotaKind string

const (
	QuotaToken        QuotaKind = "token"         // the token's quota (msgs or bytes)
	QuotaMailbox      QuotaKind = "mailbox"       // the mailbox's message quota
	QuotaMailboxBlobs QuotaKind = "mailbox_blobs" // the mailbox's blob storage cap (blobs and claims)
	QuotaSenderBlobs  QuotaKind = "sender_blobs"  // one sender key's share of it
)

type quotaError struct{ kind QuotaKind }

func (e *quotaError) Error() string { return "store: quota exceeded (" + string(e.kind) + ")" }

// Is makes every quota error match ErrQuota.
func (e *quotaError) Is(target error) bool { return target == ErrQuota }

// The quota errors by kind; each matches ErrQuota (errors.Is).
var (
	ErrQuotaToken        error = &quotaError{QuotaToken}
	ErrQuotaMailbox      error = &quotaError{QuotaMailbox}
	ErrQuotaMailboxBlobs error = &quotaError{QuotaMailboxBlobs}
	ErrQuotaSenderBlobs  error = &quotaError{QuotaSenderBlobs}
)

// QuotaOf returns the kind of a quota error ("" for a plain ErrQuota or
// any other error).
func QuotaOf(err error) QuotaKind {
	var q *quotaError
	if errors.As(err, &q) {
		return q.kind
	}
	return ""
}
