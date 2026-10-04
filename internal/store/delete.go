package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

// DeleteMailbox implements Backend for SQLite in one transaction: it
// tombstones and deletes the mailbox and every predecessor rotated into it
// (ON DELETE CASCADE removes their messages, leases, denylists, token
// counters, consumed open tokens, blobs and claims).
func (s *Store) DeleteMailbox(ctx context.Context, id string, pub []byte, notBefore, keepUntil time.Time) ([]string, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var stored []byte
	err = tx.QueryRowContext(ctx, `SELECT pubkey FROM mailboxes WHERE mailbox_id=?`, id).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // never registered, already deleted, or purged
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(stored, pub) != 1 {
		return nil, nil // another key's mailbox (a hash collision): not the caller's
	}
	// The mailbox and its predecessors: mailboxes rotated away (delete_after
	// set) whose successor is in the set. UNION ends a rotation cycle.
	rows, err := tx.QueryContext(ctx, `
WITH RECURSIVE gone(mailbox_id) AS (
  SELECT ?1
  UNION
  SELECT m.mailbox_id FROM mailboxes m JOIN gone g ON m.successor_id = g.mailbox_id
  WHERE m.delete_after IS NOT NULL
)
SELECT mailbox_id FROM gone`, id)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, v)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, v := range ids {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO tombstones(mailbox_id, not_before, expires_at) VALUES(?,?,?)
			 ON CONFLICT(mailbox_id) DO UPDATE SET not_before=MAX(not_before, excluded.not_before),
			   expires_at=MAX(expires_at, excluded.expires_at)`,
			v, ms(notBefore), ms(keepUntil)); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM mailboxes WHERE mailbox_id=?`, v); err != nil {
			return nil, err
		}
	}
	return ids, tx.Commit()
}
