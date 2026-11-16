package store

import (
	"context"
	"errors"
	"fmt"
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
	// already existed with the same key. tokensNotBefore is the mailbox's
	// TokensNotBefore as deposits are checked against it, read within the
	// registration itself (never from a cache): zero when no tombstone
	// for the id is held (§6.1, §6.10).
	Register(ctx context.Context, id string, pub []byte) (created bool, tokensNotBefore time.Time, err error)
	// Mailbox returns a live mailbox (not past its rotation grace period).
	Mailbox(ctx context.Context, id string) (Mailbox, error)
	// Rotate registers the successor (idempotent) and schedules the old
	// mailbox for deletion at deleteAfter (never later than an existing
	// schedule). tokensNotBefore is the successor's TokensNotBefore as
	// the rotation committed it, the value deposits are checked against,
	// read within the rotation itself (never from a cache): zero when no
	// tombstone for its id is held (§6.7, §6.10).
	Rotate(ctx context.Context, oldID, newID string, newPub []byte, deleteAfter time.Time) (tokensNotBefore time.Time, err error)
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
	// CollectRange is Collect restricted to the messages whose id is
	// greater than after and, unless upTo is empty, not greater than
	// upTo: the oldest of those first, and nextVisible for those only.
	// With both empty it is Collect. Message ids order a mailbox's
	// messages by arrival, and a later deposit never gets a smaller id.
	CollectRange(ctx context.Context, mailbox, after, upTo string, max int, visibility time.Duration) (msgs []Message, nextVisible time.Time, err error)
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

// LifetimeMarker keeps the high-water mark of the token lifetimes the
// relay has advertised (RELAY-PROTOCOL 0.12.0 §6.10: tombstones are kept
// for the largest limits ever advertised; §5.5's denylist the same).
// RaiseLifetimeMark stores max(the mark, d) and returns the result; the
// mark never goes down, across restarts and processes.
type LifetimeMarker interface {
	RaiseLifetimeMark(ctx context.Context, d time.Duration) (time.Duration, error)
	// LifetimeMark reads the stored mark without raising it; one that
	// isn't stored (the relay always raises it at start) is an error, so a
	// caller fails closed.
	LifetimeMark(ctx context.Context) (time.Duration, error)
	// SetTombstones replaces the tombstone policy (before the store is in
	// use: openStore calls it once the mark is known).
	SetTombstones(p TombstonePolicy)
}

// MaxLifetimeMark is the largest lifetime mark a store reads as valid: 100
// years, the largest token lifetime limit the relay accepts
// (config.MaxTokenLifetimeLimit). Retention adds margins to the mark, and
// a larger one (stored before that limit existed, or edited by hand) could
// overflow into a negative retention: revocations and tombstones would
// expire at once.
const MaxLifetimeMark = 100 * 365 * 24 * time.Hour

// MarkFromMillis is the lifetime mark stored as ms. One below zero or over
// MaxLifetimeMark is an error, so whoever reads it fails closed: the relay
// doesn't start, and deletions and revocations are refused, until the mark
// is reset (README, "Resetting the mark").
func MarkFromMillis(ms int64) (time.Duration, error) {
	if ms < 0 || ms > MaxLifetimeMark.Milliseconds() {
		return 0, markError(fmt.Sprintf("store: the stored lifetime mark (%d ms) is outside 0 to %s: reset it (README, \"Resetting the mark\")", ms, MaxLifetimeMark))
	}
	return time.Duration(ms) * time.Millisecond, nil
}

// ErrMarkInvalid matches (errors.Is) the error for a stored lifetime mark
// that can't be used: out of range or not a whole number of ms.
var ErrMarkInvalid = errors.New("store: the stored lifetime mark is invalid")

// markError is an invalid-mark error with its own message.
type markError string

func (e markError) Error() string        { return string(e) }
func (e markError) Is(target error) bool { return target == ErrMarkInvalid }

// CheckRaise refuses to store a lifetime mark below zero or over
// MaxLifetimeMark: stored, it would be refused wherever it is read, and
// every relay on the store would stop until it is reset by hand. The
// stores call it before they write. It is the only bound the store
// enforces: the 400-day cap and RELAY_ALLOW_LONG_TOKEN_LIFETIME are the
// config's, checked at start before the store opens.
func CheckRaise(d time.Duration) error {
	if d < 0 || d > MaxLifetimeMark {
		return fmt.Errorf("store: a lifetime mark of %s is outside 0 to %s: not stored", d, MaxLifetimeMark)
	}
	return nil
}

// MarkUnreadable is the error for a stored lifetime mark that isn't a
// whole number of milliseconds in int64 (stored as text or a fraction, or
// too large, by hand): like one out of range, it must be reset.
func MarkUnreadable(stored string) error {
	return markError(fmt.Sprintf("store: the stored lifetime mark (%s) isn't a whole number of ms: reset it (README, \"Resetting the mark\")", stored))
}

// WithMark returns p with its retention at least what the lifetime mark
// asks: the mark plus the margin plus a minute, the api's denylist
// retention for that lifetime.
func (p TombstonePolicy) WithMark(mark time.Duration) TombstonePolicy {
	p = p.orDefault()
	p.Retention = max(p.Retention, mark+p.Margin+time.Minute)
	return p
}

// Times returns the tombstone's not-before and expiry for a removal at now.
// The not-before is rounded up to the whole second, so what the stores
// keep (milliseconds) and what registration reports (whole seconds, §6.1)
// are the same instant.
func (p TombstonePolicy) Times(now time.Time) (notBefore, keepUntil time.Time) {
	p = p.orDefault()
	nb := now.Add(p.Margin)
	if t := nb.Truncate(time.Second); !t.Equal(nb) {
		nb = t.Add(time.Second)
	}
	return nb, nb.Add(p.Retention)
}

// Collect implements Backend for SQLite: Lease, and when nothing was leased,
// the next lease expiry.
func (s *Store) Collect(ctx context.Context, mailbox string, max int, visibility time.Duration) ([]Message, time.Time, error) {
	return s.CollectRange(ctx, mailbox, "", "", max, visibility)
}

// CollectRange implements Backend for SQLite.
func (s *Store) CollectRange(ctx context.Context, mailbox, after, upTo string, max int, visibility time.Duration) ([]Message, time.Time, error) {
	msgs, err := s.leaseRange(ctx, mailbox, after, upTo, max, visibility)
	if err != nil || len(msgs) > 0 {
		return msgs, time.Time{}, err
	}
	next, ok, err := s.nextLeaseExpiry(ctx, mailbox, after, upTo)
	if err != nil || !ok {
		return nil, time.Time{}, err
	}
	return nil, next, nil
}
