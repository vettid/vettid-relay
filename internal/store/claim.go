package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
)

// Claims (spec §6.9) are small single-fetch blobs an owner leaves for someone
// without a token (e.g. the bootstrap bundle behind a QR code). They count,
// together with blobs, against the creating mailbox's storage cap.

// storedBytes is the live blob + claim storage attributed to a mailbox.
func storedBytes(ctx context.Context, tx *sql.Tx, mailbox string, now time.Time) (int64, error) {
	var used int64
	err := tx.QueryRowContext(ctx,
		`SELECT (SELECT COALESCE(SUM(size),0) FROM blobs  WHERE mailbox_id=?1 AND expires_at>?2)
		      + (SELECT COALESCE(SUM(size),0) FROM claims WHERE mailbox_id=?1 AND expires_at>?2)`,
		mailbox, ms(now)).Scan(&used)
	return used, err
}

// PutClaim stores data for creator mailbox under a fresh random claim id,
// failing with ErrQuota if the mailbox storage cap (maxStored > 0) would be
// exceeded.
func (s *Store) PutClaim(ctx context.Context, mailbox string, data []byte, ttl time.Duration, maxStored int64) (string, time.Time, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	now := s.now()
	if err := s.checkLive(ctx, tx, mailbox, Limits{}); err != nil {
		return "", time.Time{}, err
	}
	if maxStored > 0 {
		used, err := storedBytes(ctx, tx, mailbox, now)
		if err != nil {
			return "", time.Time{}, err
		}
		if used+int64(len(data)) > maxStored {
			return "", time.Time{}, ErrQuota
		}
	}
	id := auth.NewClaimID()
	exp := now.Add(ttl).UTC()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO claims(claim_id, mailbox_id, size, created_at, expires_at, data) VALUES(?,?,?,?,?,?)`,
		id, mailbox, len(data), ms(now), ms(exp), data); err != nil {
		return "", time.Time{}, err
	}
	return id, exp, tx.Commit()
}

// TakeClaim atomically returns and deletes an unexpired claim (single
// fetch). Unknown, expired and already-taken claims are all ErrNotFound.
func (s *Store) TakeClaim(ctx context.Context, claimID string) ([]byte, error) {
	var data []byte
	err := s.w.QueryRowContext(ctx,
		`DELETE FROM claims WHERE claim_id=? AND expires_at>? RETURNING data`, claimID, ms(s.now())).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return data, err
}

// DeleteClaim deletes a claim created by mailbox. Idempotent; other
// mailboxes' claims are untouched.
func (s *Store) DeleteClaim(ctx context.Context, mailbox, claimID string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM claims WHERE claim_id=? AND mailbox_id=?`, claimID, mailbox)
	return err
}
