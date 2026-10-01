package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"
)

// BlobPut describes a blob upload that has already been authorized and whose
// body has already been bounded to Size bytes by the caller.
type BlobPut struct {
	Mailbox   string
	SenderSub string
	Size      int64
	TTL       time.Duration
	Limits    Limits // MailboxMaxBytes = per-mailbox blob storage cap
}

// BlobInfo is blob metadata visible to the API layer. Blob content metadata
// (filename, MIME type) never reaches the relay (spec §8.8).
type BlobInfo struct {
	ID        string
	Mailbox   string
	Size      int64
	ExpiresAt time.Time
}

// BlobStore stores opaque blob ciphertext (spec §6.8). The SQLite
// implementation keeps blobs in the same database file so that one file is
// the relay's entire state; a filesystem backend can implement the same
// interface later.
type BlobStore interface {
	// PutBlob stores exactly p.Size bytes read from r, enforcing the
	// mailbox blob cap and token byte quota atomically (ErrQuota).
	PutBlob(ctx context.Context, p BlobPut, r io.Reader) (BlobInfo, error)
	// OpenBlob returns the blob if it exists, is unexpired and belongs to
	// mailbox; otherwise ErrNotFound (no distinction — no existence oracle).
	OpenBlob(ctx context.Context, mailbox, blobID string) (BlobInfo, io.ReadCloser, error)
	// DeleteBlob deletes the blob if it belongs to mailbox. Idempotent.
	DeleteBlob(ctx context.Context, mailbox, blobID string) error
}

var _ BlobStore = (*Store)(nil)

// PutBlob implements BlobStore.
func (s *Store) PutBlob(ctx context.Context, p BlobPut, r io.Reader) (BlobInfo, error) {
	// The caller bounded the body; read at most Size+1 to detect a mismatch.
	data, err := io.ReadAll(io.LimitReader(r, p.Size+1))
	if err != nil {
		return BlobInfo{}, err
	}
	if int64(len(data)) != p.Size {
		return BlobInfo{}, fmt.Errorf("store: blob size mismatch")
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return BlobInfo{}, err
	}
	defer tx.Rollback()
	now := s.now()
	if p.Limits.MailboxMaxBytes > 0 {
		var used int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(size),0) FROM blobs WHERE mailbox_id=? AND expires_at>?`,
			p.Mailbox, ms(now)).Scan(&used); err != nil {
			return BlobInfo{}, err
		}
		if used+p.Size > p.Limits.MailboxMaxBytes {
			return BlobInfo{}, ErrQuota
		}
	}
	// Blobs count against the token's byte quota only (spec §6.8).
	if err := chargeToken(ctx, tx, p.Mailbox, p.Limits, 0, p.Size); err != nil {
		return BlobInfo{}, err
	}
	info := BlobInfo{ID: s.newID(now), Mailbox: p.Mailbox, Size: p.Size, ExpiresAt: now.Add(p.TTL).UTC()}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO blobs(blob_id, mailbox_id, size, created_at, expires_at, sender_sub, data)
		 VALUES(?,?,?,?,?,?,?)`,
		info.ID, p.Mailbox, p.Size, ms(now), ms(info.ExpiresAt), p.SenderSub, data); err != nil {
		return BlobInfo{}, err
	}
	return info, tx.Commit()
}

// OpenBlob implements BlobStore.
func (s *Store) OpenBlob(ctx context.Context, mailbox, blobID string) (BlobInfo, io.ReadCloser, error) {
	info := BlobInfo{ID: blobID, Mailbox: mailbox}
	var exp int64
	var data []byte
	err := s.r.QueryRowContext(ctx,
		`SELECT size, expires_at, data FROM blobs WHERE blob_id=? AND mailbox_id=? AND expires_at>?`,
		blobID, mailbox, ms(s.now())).Scan(&info.Size, &exp, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return BlobInfo{}, nil, ErrNotFound
	}
	if err != nil {
		return BlobInfo{}, nil, err
	}
	info.ExpiresAt = fromMS(exp)
	return info, io.NopCloser(bytes.NewReader(data)), nil
}

// DeleteBlob implements BlobStore.
func (s *Store) DeleteBlob(ctx context.Context, mailbox, blobID string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM blobs WHERE blob_id=? AND mailbox_id=?`, blobID, mailbox)
	return err
}
