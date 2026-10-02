// Package store is the relay's SQLite persistence layer.
//
// The whole relay state lives in ONE SQLite file (WAL mode): mailboxes,
// messages, denylists, token quota counters and blobs. That file is the unit
// of backup/replication (e.g. Litestream).
//
// SINGLE WRITER: exactly one relay process may open a given database file.
// All writes go through one connection (MaxOpenConns=1, BEGIN IMMEDIATE), which
// is what gives deposits their arrival-ordered ULIDs and makes quota checks
// atomic. Two relay instances sharing a file (e.g. via a network filesystem)
// is unsupported and will corrupt ordering/quota guarantees or the file itself.
package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite" // pure-Go SQLite driver, registers "sqlite"
)

var (
	// ErrNotFound is returned when a mailbox/blob does not exist (or is not
	// visible to the caller — callers must not distinguish the two).
	ErrNotFound = errors.New("store: not found")
	// ErrQuota is returned when a token or mailbox quota would be exceeded.
	ErrQuota = errors.New("store: quota exceeded")
)

// Store is the SQLite-backed relay store.
type Store struct {
	w   *sql.DB // single writer connection
	r   *sql.DB // read-only pool
	now func() time.Time

	idMu    sync.Mutex
	entropy io.Reader
}

// Option configures a Store.
type Option func(*Store)

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	} else {
		q.Add("_pragma", "journal_mode(WAL)")
		// FULL: a 201 for a deposit means the message is durable.
		q.Add("_pragma", "synchronous(FULL)")
		q.Set("_txlock", "immediate")
	}
	return "file:" + path + "?" + q.Encode()
}

// Open opens (creating if needed) the database at path, enables WAL and
// applies the schema. On return the file exists on disk in WAL mode.
func Open(ctx context.Context, path string, opts ...Option) (*Store, error) {
	w, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	w.SetConnMaxIdleTime(0)

	var mode string
	if err := w.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		w.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if mode != "wal" {
		w.Close()
		return nil, fmt.Errorf("open %s: journal_mode is %q, want wal", path, mode)
	}
	if err := migrate(ctx, w); err != nil {
		w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(8)
	s := &Store{w: w, r: r, now: time.Now, entropy: ulid.Monotonic(rand.Reader, 0)}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Close closes both pools. Call only after all request handlers have finished.
func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

// Ping verifies the database is reachable for reads and writes.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	if err := s.r.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return err
	}
	return s.w.PingContext(ctx)
}

// newID returns a fresh ULID. Called while holding the writer connection so
// IDs are issued in commit order (per-mailbox ULID order == arrival order).
func (s *Store) newID(t time.Time) string {
	s.idMu.Lock()
	defer s.idMu.Unlock()
	return ulid.MustNew(ulid.Timestamp(t), s.entropy).String()
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

// ---------------------------------------------------------------- mailboxes

// Mailbox is a registered mailbox.
type Mailbox struct {
	ID          string
	PubKey      []byte
	CreatedAt   time.Time
	DeleteAfter *time.Time // set when rotated away
}

// Register creates the mailbox if absent. created is false when it already
// existed with the same key (idempotent re-registration).
func (s *Store) Register(ctx context.Context, id string, pub []byte) (created bool, err error) {
	res, err := s.w.ExecContext(ctx,
		`INSERT INTO mailboxes(mailbox_id, pubkey, created_at) VALUES(?,?,?)
		 ON CONFLICT(mailbox_id) DO NOTHING`, id, pub, ms(s.now()))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		return true, nil
	}
	mb, err := s.mailbox(ctx, s.w, id, true)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(mb.PubKey, pub) != 1 {
		// 130-bit truncated hash collision; treat as a conflict.
		return false, fmt.Errorf("store: mailbox id collision")
	}
	return false, nil
}

// Mailbox returns a live mailbox (not past its rotation grace period).
func (s *Store) Mailbox(ctx context.Context, id string) (Mailbox, error) {
	return s.mailbox(ctx, s.r, id, false)
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) mailbox(ctx context.Context, q querier, id string, includeDead bool) (Mailbox, error) {
	var mb Mailbox
	var created int64
	var del sql.NullInt64
	err := q.QueryRowContext(ctx,
		`SELECT mailbox_id, pubkey, created_at, delete_after FROM mailboxes WHERE mailbox_id=?`, id).
		Scan(&mb.ID, &mb.PubKey, &created, &del)
	if errors.Is(err, sql.ErrNoRows) {
		return Mailbox{}, ErrNotFound
	}
	if err != nil {
		return Mailbox{}, err
	}
	mb.CreatedAt = fromMS(created)
	if del.Valid {
		t := fromMS(del.Int64)
		if !includeDead && !s.now().Before(t) {
			return Mailbox{}, ErrNotFound
		}
		mb.DeleteAfter = &t
	}
	return mb, nil
}

// Rotate registers the successor mailbox (idempotent) and schedules the old
// one for deletion at deleteAfter (never later than an existing schedule).
func (s *Store) Rotate(ctx context.Context, oldID, newID string, newPub []byte, deleteAfter time.Time) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now()
	if _, err := s.mailbox(ctx, tx, oldID, false); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO mailboxes(mailbox_id, pubkey, created_at) VALUES(?,?,?)
		 ON CONFLICT(mailbox_id) DO NOTHING`, newID, newPub, ms(now)); err != nil {
		return err
	}
	var existing []byte
	if err := tx.QueryRowContext(ctx, `SELECT pubkey FROM mailboxes WHERE mailbox_id=?`, newID).Scan(&existing); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(existing, newPub) != 1 {
		return fmt.Errorf("store: mailbox id collision")
	}
	// A successor that was itself scheduled for deletion is revived.
	if _, err := tx.ExecContext(ctx,
		`UPDATE mailboxes SET delete_after=NULL WHERE mailbox_id=?`, newID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE mailboxes SET delete_after=MIN(COALESCE(delete_after, ?1), ?1), successor_id=?2
		 WHERE mailbox_id=?3`, ms(deleteAfter), newID, oldID); err != nil {
		return err
	}
	return tx.Commit()
}

// ----------------------------------------------------------------- denylist

// DenyEntry is one revocation (kind "jti" or "sub").
type DenyEntry struct {
	Kind  string
	Value string
}

// AddDenylist inserts (or extends) entries for a mailbox, retained until
// expiresAt. Fails with ErrQuota if the mailbox would exceed maxEntries.
func (s *Store) AddDenylist(ctx context.Context, mailbox string, entries []DenyEntry, expiresAt time.Time, maxEntries int64) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range entries {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO denylist(mailbox_id, kind, value, expires_at) VALUES(?,?,?,?)
			 ON CONFLICT(mailbox_id, kind, value) DO UPDATE SET expires_at=MAX(expires_at, excluded.expires_at)`,
			mailbox, e.Kind, e.Value, ms(expiresAt)); err != nil {
			return err
		}
	}
	var n int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM denylist WHERE mailbox_id=? AND expires_at>?`, mailbox, ms(s.now())).Scan(&n); err != nil {
		return err
	}
	if maxEntries > 0 && n > maxEntries {
		return ErrQuota
	}
	return tx.Commit()
}

// IsDenied reports whether jti or sub is on the mailbox's live denylist.
func (s *Store) IsDenied(ctx context.Context, mailbox, jti, sub string) (bool, error) {
	var one int
	err := s.r.QueryRowContext(ctx,
		`SELECT 1 FROM denylist WHERE mailbox_id=? AND expires_at>? AND
		   ((kind='jti' AND value=?) OR (kind='sub' AND value=?)) LIMIT 1`,
		mailbox, ms(s.now()), jti, sub).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ---------------------------------------------------------------- messages

// Limits are the quota limits applied atomically with a deposit or blob put.
// Zero/negative mailbox limits mean "unlimited". Token quota fields are nil
// when the token carries no quota.
type Limits struct {
	MailboxMaxMsgs  int64
	MailboxMaxBytes int64 // messages: payload bytes; blobs: blob bytes

	TokenJTI        string
	TokenExpires    time.Time
	TokenQuotaMsgs  *int64
	TokenQuotaBytes *int64
}

// Message is a stored message.
type Message struct {
	ID          string
	Mailbox     string
	Payload     []byte
	DepositedAt time.Time
}

// Deposit stores a message, enforcing quotas atomically, and returns its ULID.
func (s *Store) Deposit(ctx context.Context, mailbox, senderSub string, payload []byte, ttl time.Duration, lim Limits) (Message, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return Message{}, err
	}
	defer tx.Rollback()
	now := s.now()
	size := int64(len(payload))

	if lim.MailboxMaxMsgs > 0 || lim.MailboxMaxBytes > 0 {
		var count, bytes int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*), COALESCE(SUM(size),0) FROM messages WHERE mailbox_id=? AND expires_at>?`,
			mailbox, ms(now)).Scan(&count, &bytes); err != nil {
			return Message{}, err
		}
		if (lim.MailboxMaxMsgs > 0 && count+1 > lim.MailboxMaxMsgs) ||
			(lim.MailboxMaxBytes > 0 && bytes+size > lim.MailboxMaxBytes) {
			return Message{}, ErrQuota
		}
	}
	if err := chargeToken(ctx, tx, mailbox, lim, 1, size); err != nil {
		return Message{}, err
	}
	m := Message{ID: s.newID(now), Mailbox: mailbox, Payload: payload, DepositedAt: now.UTC()}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO messages(msg_id, mailbox_id, size, deposited_at, expires_at, sender_sub, payload)
		 VALUES(?,?,?,?,?,?,?)`,
		m.ID, mailbox, size, ms(now), ms(now.Add(ttl)), senderSub, payload); err != nil {
		return Message{}, err
	}
	return m, tx.Commit()
}

// chargeToken adds usage to the token's counters and fails with ErrQuota if
// its quota would be exceeded. Without a token quota it is a no-op.
func chargeToken(ctx context.Context, tx *sql.Tx, mailbox string, lim Limits, msgs, bytes int64) error {
	if lim.TokenQuotaMsgs == nil && lim.TokenQuotaBytes == nil {
		return nil
	}
	var usedMsgs, usedBytes int64
	err := tx.QueryRowContext(ctx,
		`SELECT msgs, bytes FROM token_usage WHERE mailbox_id=? AND jti=?`, mailbox, lim.TokenJTI).
		Scan(&usedMsgs, &usedBytes)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if (lim.TokenQuotaMsgs != nil && usedMsgs+msgs > *lim.TokenQuotaMsgs) ||
		(lim.TokenQuotaBytes != nil && usedBytes+bytes > *lim.TokenQuotaBytes) {
		return ErrQuota
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO token_usage(mailbox_id, jti, msgs, bytes, expires_at) VALUES(?,?,?,?,?)
		 ON CONFLICT(mailbox_id, jti) DO UPDATE SET msgs=msgs+excluded.msgs, bytes=bytes+excluded.bytes,
		   expires_at=MAX(expires_at, excluded.expires_at)`,
		mailbox, lim.TokenJTI, msgs, bytes, ms(lim.TokenExpires))
	return err
}

// Lease returns up to max of the oldest unexpired, unleased messages and
// leases them until now+visibility.
func (s *Store) Lease(ctx context.Context, mailbox string, max int, visibility time.Duration) ([]Message, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := ms(s.now())
	rows, err := tx.QueryContext(ctx,
		`SELECT msg_id, deposited_at, payload FROM messages
		 WHERE mailbox_id=? AND expires_at>? AND (leased_until IS NULL OR leased_until<=?)
		 ORDER BY msg_id LIMIT ?`, mailbox, now, now, max)
	if err != nil {
		return nil, err
	}
	var out []Message
	for rows.Next() {
		var m Message
		var dep int64
		if err := rows.Scan(&m.ID, &dep, &m.Payload); err != nil {
			rows.Close()
			return nil, err
		}
		m.Mailbox = mailbox
		m.DepositedAt = fromMS(dep)
		out = append(out, m)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	until := now + visibility.Milliseconds()
	for _, m := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE messages SET leased_until=? WHERE msg_id=?`, until, m.ID); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, nil // nothing written; rollback is fine
	}
	return out, tx.Commit()
}

// NextLeaseExpiry returns the earliest time a currently leased, unexpired
// message of the mailbox becomes collectable again.
func (s *Store) NextLeaseExpiry(ctx context.Context, mailbox string) (time.Time, bool, error) {
	var v sql.NullInt64
	now := ms(s.now())
	err := s.r.QueryRowContext(ctx,
		`SELECT MIN(leased_until) FROM messages WHERE mailbox_id=? AND expires_at>? AND leased_until>?`,
		mailbox, now, now).Scan(&v)
	if err != nil || !v.Valid {
		return time.Time{}, false, err
	}
	return fromMS(v.Int64), true, nil
}

// Ack deletes msgID if it belongs to mailbox and reports whether a row was
// deleted. Another mailbox's message is never touched, and callers must not
// reveal the difference (spec §6.5).
func (s *Store) Ack(ctx context.Context, mailbox, msgID string) (bool, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM messages WHERE msg_id=? AND mailbox_id=?`, msgID, mailbox)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ------------------------------------------------------------------- sweep

// SweepStats counts what one sweep pass removed.
type SweepStats struct {
	Messages, Leases, Denylist, Blobs, TokenUsage, Mailboxes int64
}

// Sweep deletes expired messages, blobs, denylist rows, token counters and
// mailboxes past their rotation grace, and releases stale leases — in one
// transaction.
func (s *Store) Sweep(ctx context.Context) (SweepStats, error) {
	var st SweepStats
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return st, err
	}
	defer tx.Rollback()
	now := ms(s.now())
	steps := []struct {
		dst *int64
		sql string
	}{
		// Mailboxes first: ON DELETE CASCADE removes their messages/blobs/denylist.
		{&st.Mailboxes, `DELETE FROM mailboxes WHERE delete_after IS NOT NULL AND delete_after<=?`},
		{&st.Messages, `DELETE FROM messages WHERE expires_at<=?`},
		{&st.Leases, `UPDATE messages SET leased_until=NULL WHERE leased_until IS NOT NULL AND leased_until<=?`},
		{&st.Denylist, `DELETE FROM denylist WHERE expires_at<=?`},
		{&st.Blobs, `DELETE FROM blobs WHERE expires_at<=?`},
		{&st.TokenUsage, `DELETE FROM token_usage WHERE expires_at<=?`},
	}
	for _, step := range steps {
		res, err := tx.ExecContext(ctx, step.sql, now)
		if err != nil {
			return SweepStats{}, err
		}
		*step.dst, _ = res.RowsAffected()
	}
	return st, tx.Commit()
}
