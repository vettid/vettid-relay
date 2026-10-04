package store

import (
	"context"
	"time"
)

// Backend is everything the API layer needs from relay persistence. Two
// implementations exist:
//
//   - *Store (this package): one SQLite file, single writer, one relay
//     process. The default, for development and small single-task relays.
//   - dynamo.Store (internal/store/dynamo): DynamoDB + S3, shared by any
//     number of relay processes (multi-task hosting).
//
// Every method that the SQLite store performs in one transaction is atomic in
// every implementation; the conformance suite (internal/store/storetest) runs
// against both.
type Backend interface {
	BlobStore

	// Ping verifies the backend is reachable (health checks).
	Ping(ctx context.Context) error
	// Close releases resources. Call after all handlers have finished.
	Close() error

	// Register creates the mailbox if absent; created is false when it
	// already existed with the same key.
	Register(ctx context.Context, id string, pub []byte) (created bool, err error)
	// Mailbox returns a live mailbox (not past its rotation grace period).
	Mailbox(ctx context.Context, id string) (Mailbox, error)
	// Rotate registers the successor (idempotent) and schedules the old
	// mailbox for deletion at deleteAfter (never later than an existing
	// schedule).
	Rotate(ctx context.Context, oldID, newID string, newPub []byte, deleteAfter time.Time) error
	// DeleteMailbox deletes mailbox id (registered with pub) and everything
	// it holds — messages, leases, denylist, token counters, consumed open
	// tokens, blobs (bodies included) and the claims it created — together
	// with every predecessor rotated into it, and returns the ids deleted
	// (none if id is not registered with pub: deletion is idempotent).
	// Deposits, blob puts and claim puts fail with ErrNotFound from the
	// moment it returns, on every process sharing the backend. Each id
	// keeps a tombstone until keepUntil: if its key registers again, the
	// new mailbox's TokensNotBefore is notBefore, so no token minted
	// before the deletion becomes valid again.
	DeleteMailbox(ctx context.Context, id string, pub []byte, notBefore, keepUntil time.Time) (deleted []string, err error)

	AddDenylist(ctx context.Context, mailbox string, entries []DenyEntry, expiresAt time.Time, maxEntries int64) error
	IsDenied(ctx context.Context, mailbox, jti, sub string) (bool, error)
	IsConsumed(ctx context.Context, mailbox, jti string) (bool, error)

	// Deposit stores a message, enforcing quotas and open-token
	// consumption atomically, and returns it with its ULID.
	Deposit(ctx context.Context, mailbox, senderSub string, payload []byte, ttl time.Duration, lim Limits) (Message, error)
	// Collect leases up to max of the oldest unexpired, unleased messages
	// for visibility. When it returns no messages, nextVisible is the
	// earliest time a currently leased message becomes collectable again
	// (zero if none), so a parked collector can wake for redelivery.
	Collect(ctx context.Context, mailbox string, max int, visibility time.Duration) (msgs []Message, nextVisible time.Time, err error)
	// Ack deletes msgID if it belongs to mailbox.
	Ack(ctx context.Context, mailbox, msgID string) (bool, error)

	PutClaim(ctx context.Context, mailbox string, data []byte, ttl time.Duration, maxStored int64) (string, time.Time, error)
	// TakeClaim atomically returns and deletes an unexpired claim: across
	// any number of concurrent callers (and processes) exactly one wins.
	TakeClaim(ctx context.Context, claimID string) ([]byte, error)
	DeleteClaim(ctx context.Context, mailbox, claimID string) error

	// Sweep removes what expiry alone does not (see each implementation).
	Sweep(ctx context.Context) (SweepStats, error)
}

var _ Backend = (*Store)(nil)

// TombstonePolicy is how a mailbox that ends without an explicit deletion
// — a rotated-away mailbox removed at the end of its grace (§6.7) — is
// tombstoned like a deleted one (§6.10): tokens issued before the removal
// time plus Margin are refused if its key registers again, and the
// tombstone is kept for Retention after that.
type TombstonePolicy struct {
	Margin    time.Duration // the freshness window (90 s)
	Retention time.Duration // the denylist retention (max token lifetime + margins)
}

// DefaultTombstonePolicy matches the relay's default limits (400-day
// token lifetime). The relay passes its configured policy
// (api.TombstonePolicy).
var DefaultTombstonePolicy = TombstonePolicy{Margin: 90 * time.Second, Retention: 400*24*time.Hour + 90*time.Second + time.Minute}

func (p TombstonePolicy) orDefault() TombstonePolicy {
	if p.Margin <= 0 || p.Retention <= 0 {
		return DefaultTombstonePolicy
	}
	return p
}

// Times returns the tombstone's not-before and expiry for a removal at now.
func (p TombstonePolicy) Times(now time.Time) (notBefore, keepUntil time.Time) {
	p = p.orDefault()
	nb := now.Add(p.Margin)
	return nb, nb.Add(p.Retention)
}

// Collect implements Backend for SQLite: Lease, and when nothing was leased,
// the next lease expiry.
func (s *Store) Collect(ctx context.Context, mailbox string, max int, visibility time.Duration) ([]Message, time.Time, error) {
	msgs, err := s.Lease(ctx, mailbox, max, visibility)
	if err != nil || len(msgs) > 0 {
		return msgs, time.Time{}, err
	}
	next, ok, err := s.NextLeaseExpiry(ctx, mailbox)
	if err != nil || !ok {
		return nil, time.Time{}, err
	}
	return nil, next, nil
}
