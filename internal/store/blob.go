package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BlobPut describes a blob upload that has already been authorized and whose
// body has already been bounded to Size bytes by the caller.
type BlobPut struct {
	Mailbox string
	// Sender is the canonical base64 key that signed the upload (§5.3
	// step 7). It is kept with the blob for as long as the blob exists
	// (0.9.2, §6.8): the per-sender share is counted by it, and the
	// owner's list of its blobs returns it.
	Sender string
	Size   int64
	TTL    time.Duration
	// Limits.MailboxMaxBytes is the part of the mailbox's blob storage
	// (blobs and claims) this upload may fill: the whole cap for an
	// upload under an owner_device token, the cap less the room kept for
	// those for any other (the caller decides). Limits.Token* is the
	// token's byte quota.
	Limits Limits
	// The sender's share of the mailbox's blob storage: at most
	// SenderMaxBytes in at most SenderMaxBlobs blobs (0: no limit).
	SenderMaxBytes int64
	SenderMaxBlobs int64
}

// BlobInfo is blob metadata visible to the API layer. Blob content metadata
// (filename, MIME type) never reaches the relay (spec §8.8).
type BlobInfo struct {
	ID        string
	Mailbox   string
	Sender    string // the uploading key ('' for blobs stored by relays of protocol 0.9.0 and 0.9.1)
	Size      int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// BlobUsage is what a mailbox's blob storage holds, for the checks made
// before an upload's body is read (§6.8): the stored bytes (blobs and the
// claims the mailbox created), the given sender's blobs and bytes in it,
// and the bytes charged to the given token.
type BlobUsage struct {
	MailboxBytes int64
	SenderBytes  int64
	SenderBlobs  int64
	TokenBytes   int64
}

// StagedBlob is a blob body stored but not yet a blob: nobody can read
// it, and it counts against nothing, until Commit makes it one. Discard
// removes it; it is a no-op after a successful Commit, and idempotent.
type StagedBlob interface {
	// Commit makes the staged body a blob, checking atomically with the
	// write the mailbox's liveness, its blob storage cap, the sender's
	// share and the token's byte quota (ErrQuotaMailboxBlobs,
	// ErrQuotaSenderBlobs, ErrQuotaToken, in that order of precedence).
	// p.Mailbox and p.Size must be the staged ones. On error the body is
	// still staged: the caller discards it.
	Commit(ctx context.Context, p BlobPut) (BlobInfo, error)
	Discard(ctx context.Context) error
}

// BlobStore stores opaque blob ciphertext (spec §6.8). The SQLite
// implementation keeps blobs in the same database file so that one file is
// the relay's entire state; DynamoDB + S3 is the other (internal/store/dynamo).
type BlobStore interface {
	// StageBlob stores exactly size bytes read from r for mailbox as a
	// staged body (an error, and nothing left behind, if r ends early,
	// holds more, or fails). The body is streamed: the store holds only a
	// buffer of it at a time.
	StageBlob(ctx context.Context, mailbox string, size int64, r io.Reader) (StagedBlob, error)
	// PutBlob is StageBlob and Commit in one call (the staged body is
	// discarded if the commit fails).
	PutBlob(ctx context.Context, p BlobPut, r io.Reader) (BlobInfo, error)
	// BlobUsage reports what mailbox's blob storage holds, for sender and
	// token jti (TokenBytes is 0 for an empty jti). Counters a backend
	// keeps may run above the truth (expired blobs not yet removed);
	// fresh asks for them to be recomputed first, where a backend does
	// that.
	BlobUsage(ctx context.Context, mailbox, sender, jti string, fresh bool) (BlobUsage, error)
	// ListBlobs returns up to max of mailbox's unexpired blobs with ids
	// greater than after, in id order (oldest first); next is the last
	// id returned if more follow (else ""); used is the bytes the
	// mailbox's blob storage cap is checked against (blobs and claims).
	ListBlobs(ctx context.Context, mailbox, after string, max int) (blobs []BlobInfo, next string, used int64, err error)
	// OpenBlob returns the blob if it exists, is unexpired and belongs to
	// mailbox; otherwise ErrNotFound (no distinction — no existence oracle).
	OpenBlob(ctx context.Context, mailbox, blobID string) (BlobInfo, io.ReadCloser, error)
	// DeleteBlob deletes the blob if it belongs to mailbox. Idempotent.
	DeleteBlob(ctx context.Context, mailbox, blobID string) error
}

var _ BlobStore = (*Store)(nil)

// ErrBlobSize is returned by StageBlob when the body is not exactly the
// announced size.
var ErrBlobSize = errors.New("store: blob size mismatch")

// stagePrefix names the SQLite store's staged bodies: temporary files next
// to the database file, removed at commit or discard, and at Open (left by
// a process that stopped mid-upload).
const stagePrefix = ".relay-blob-staged-"

// removeStaged removes staged bodies left in dir by an earlier process.
func removeStaged(dir string) {
	names, _ := filepath.Glob(filepath.Join(dir, stagePrefix+"*"))
	for _, n := range names {
		os.Remove(n)
	}
}

// ExactReader reads exactly size bytes from r: it fails with ErrBlobSize
// if r ends early or holds more. (The more is detected by reading one
// byte past size, which for an HTTP request body bounded by its
// Content-Length is its EOF.)
func ExactReader(r io.Reader, size int64) io.Reader { return &exactReader{r: r, left: size} }

type exactReader struct {
	r    io.Reader
	left int64
	done bool
}

func (e *exactReader) Read(p []byte) (int, error) {
	if e.done {
		return 0, io.EOF
	}
	if e.left == 0 {
		var one [1]byte
		n, err := io.ReadFull(e.r, one[:])
		switch {
		case n > 0:
			return 0, ErrBlobSize
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			e.done = true
			return 0, io.EOF
		default:
			return 0, err
		}
	}
	if int64(len(p)) > e.left {
		p = p[:e.left]
	}
	n, err := e.r.Read(p)
	e.left -= int64(n)
	if err == io.EOF {
		if e.left > 0 {
			return n, ErrBlobSize
		}
		e.done = true
		if n > 0 {
			return n, nil
		}
	}
	return n, err
}

// sqliteStaged is a body staged in a temporary file.
type sqliteStaged struct {
	s       *Store
	mailbox string
	size    int64
	mu      sync.Mutex
	path    string // "" once committed or discarded
}

// StageBlob implements BlobStore: the body is written to a temporary file
// next to the database (an io.Copy buffer at a time).
func (s *Store) StageBlob(ctx context.Context, mailbox string, size int64, r io.Reader) (StagedBlob, error) {
	f, err := os.CreateTemp(s.stageDir, stagePrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("store: stage blob: %w", err)
	}
	_, err = io.Copy(f, ExactReader(r, size))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(f.Name())
		return nil, err
	}
	return &sqliteStaged{s: s, mailbox: mailbox, size: size, path: f.Name()}, nil
}

// Discard implements StagedBlob.
func (b *sqliteStaged) Discard(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.path == "" {
		return nil
	}
	err := os.Remove(b.path)
	b.path = ""
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Commit implements StagedBlob. The body is read from its file inside the
// write transaction: the store's single writer connection makes that one
// body in memory at a time, whatever the number of uploads.
func (b *sqliteStaged) Commit(ctx context.Context, p BlobPut) (BlobInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.path == "" || p.Mailbox != b.mailbox || p.Size != b.size {
		return BlobInfo{}, errors.New("store: commit of a blob not staged as such")
	}
	s := b.s
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return BlobInfo{}, err
	}
	defer tx.Rollback()
	now := s.now()
	if err := s.checkLive(ctx, tx, p.Mailbox, p.Limits); err != nil {
		return BlobInfo{}, err
	}
	if p.Limits.MailboxMaxBytes > 0 {
		used, err := storedBytes(ctx, tx, p.Mailbox, now)
		if err != nil {
			return BlobInfo{}, err
		}
		if used+p.Size > p.Limits.MailboxMaxBytes {
			return BlobInfo{}, ErrQuotaMailboxBlobs
		}
	}
	if p.Sender != "" && (p.SenderMaxBytes > 0 || p.SenderMaxBlobs > 0) {
		n, sum, err := senderUsage(ctx, tx, p.Mailbox, p.Sender, now)
		if err != nil {
			return BlobInfo{}, err
		}
		if (p.SenderMaxBytes > 0 && sum+p.Size > p.SenderMaxBytes) || (p.SenderMaxBlobs > 0 && n+1 > p.SenderMaxBlobs) {
			return BlobInfo{}, ErrQuotaSenderBlobs
		}
	}
	// Blobs count against the token's byte quota only (spec §6.8).
	if err := chargeToken(ctx, tx, p.Mailbox, p.Limits, 0, p.Size); err != nil {
		return BlobInfo{}, err
	}
	data, err := os.ReadFile(b.path)
	if err != nil {
		return BlobInfo{}, err
	}
	if int64(len(data)) != p.Size {
		return BlobInfo{}, ErrBlobSize
	}
	info := BlobInfo{ID: s.newID(now), Mailbox: p.Mailbox, Sender: p.Sender, Size: p.Size, CreatedAt: now.UTC(), ExpiresAt: now.Add(p.TTL).UTC()}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO blobs(blob_id, mailbox_id, size, created_at, expires_at, sender_sub, data)
		 VALUES(?,?,?,?,?,?,?)`,
		info.ID, p.Mailbox, p.Size, ms(now), ms(info.ExpiresAt), p.Sender, data); err != nil {
		return BlobInfo{}, err
	}
	if err := tx.Commit(); err != nil {
		return BlobInfo{}, err
	}
	os.Remove(b.path)
	b.path = ""
	return info, nil
}

// BlobNeverFits reports a blob that no state of the mailbox could take
// (larger than the cap, the share or the token's quota): a backend whose
// conditions cannot say "delta > quota" on a missing item refuses it
// before any write, with QuotaFor.
func BlobNeverFits(p BlobPut) bool {
	return (p.Limits.MailboxMaxBytes > 0 && p.Size > p.Limits.MailboxMaxBytes) ||
		(p.Sender != "" && p.SenderMaxBytes > 0 && p.Size > p.SenderMaxBytes) ||
		(p.Limits.TokenQuotaBytes != nil && p.Size > *p.Limits.TokenQuotaBytes)
}

// QuotaFor is the quota error a refused blob is answered with, given what
// the mailbox holds, in Commit's order of precedence; ErrQuotaToken if
// only the token's quota is left to blame.
func QuotaFor(p BlobPut, u BlobUsage) error {
	switch {
	case p.Limits.MailboxMaxBytes > 0 && u.MailboxBytes+p.Size > p.Limits.MailboxMaxBytes:
		return ErrQuotaMailboxBlobs
	case p.Sender != "" && ((p.SenderMaxBytes > 0 && u.SenderBytes+p.Size > p.SenderMaxBytes) || (p.SenderMaxBlobs > 0 && u.SenderBlobs+1 > p.SenderMaxBlobs)):
		return ErrQuotaSenderBlobs
	}
	return ErrQuotaToken
}

// senderUsage counts sender's unexpired blobs in mailbox and their bytes.
func senderUsage(ctx context.Context, q querier, mailbox, sender string, now time.Time) (n, sum int64, err error) {
	err = q.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(size),0) FROM blobs WHERE mailbox_id=? AND sender_sub=? AND expires_at>?`,
		mailbox, sender, ms(now)).Scan(&n, &sum)
	return n, sum, err
}

// PutBlob implements BlobStore.
func (s *Store) PutBlob(ctx context.Context, p BlobPut, r io.Reader) (BlobInfo, error) {
	return PutStaged(ctx, s, p, r)
}

// PutStaged is BlobStore.PutBlob on StageBlob and Commit.
func PutStaged(ctx context.Context, bs BlobStore, p BlobPut, r io.Reader) (BlobInfo, error) {
	st, err := bs.StageBlob(ctx, p.Mailbox, p.Size, r)
	if err != nil {
		return BlobInfo{}, err
	}
	info, err := st.Commit(ctx, p)
	if err != nil {
		st.Discard(context.WithoutCancel(ctx))
	}
	return info, err
}

// BlobUsage implements BlobStore (exact: fresh changes nothing).
func (s *Store) BlobUsage(ctx context.Context, mailbox, sender, jti string, _ bool) (BlobUsage, error) {
	var u BlobUsage
	now := s.now()
	var err error
	if u.MailboxBytes, err = storedBytes(ctx, s.r, mailbox, now); err != nil {
		return u, err
	}
	if sender != "" {
		if u.SenderBlobs, u.SenderBytes, err = senderUsage(ctx, s.r, mailbox, sender, now); err != nil {
			return u, err
		}
	}
	if jti != "" {
		err = s.r.QueryRowContext(ctx, `SELECT bytes FROM token_usage WHERE mailbox_id=? AND jti=?`, mailbox, jti).Scan(&u.TokenBytes)
		if errors.Is(err, sql.ErrNoRows) {
			err = nil
		}
	}
	return u, err
}

// ListBlobs implements BlobStore.
func (s *Store) ListBlobs(ctx context.Context, mailbox, after string, max int) ([]BlobInfo, string, int64, error) {
	now := s.now()
	rows, err := s.r.QueryContext(ctx,
		`SELECT blob_id, size, sender_sub, created_at, expires_at FROM blobs
		 WHERE mailbox_id=? AND blob_id>? AND expires_at>? ORDER BY blob_id LIMIT ?`,
		mailbox, after, ms(now), max+1)
	if err != nil {
		return nil, "", 0, err
	}
	defer rows.Close()
	var out []BlobInfo
	for rows.Next() {
		b := BlobInfo{Mailbox: mailbox}
		var created, exp int64
		if err := rows.Scan(&b.ID, &b.Size, &b.Sender, &created, &exp); err != nil {
			return nil, "", 0, err
		}
		b.CreatedAt, b.ExpiresAt = fromMS(created), fromMS(exp)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, "", 0, err
	}
	next := ""
	if len(out) > max {
		out = out[:max]
		next = out[max-1].ID
	}
	used, err := storedBytes(ctx, s.r, mailbox, now)
	return out, next, used, err
}

// OpenBlob implements BlobStore.
func (s *Store) OpenBlob(ctx context.Context, mailbox, blobID string) (BlobInfo, io.ReadCloser, error) {
	info := BlobInfo{ID: blobID, Mailbox: mailbox}
	var exp, created int64
	var data []byte
	err := s.r.QueryRowContext(ctx,
		`SELECT size, sender_sub, created_at, expires_at, data FROM blobs WHERE blob_id=? AND mailbox_id=? AND expires_at>?`,
		blobID, mailbox, ms(s.now())).Scan(&info.Size, &info.Sender, &created, &exp, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return BlobInfo{}, nil, ErrNotFound
	}
	if err != nil {
		return BlobInfo{}, nil, err
	}
	info.CreatedAt, info.ExpiresAt = fromMS(created), fromMS(exp)
	return info, io.NopCloser(bytes.NewReader(data)), nil
}

// DeleteBlob implements BlobStore.
func (s *Store) DeleteBlob(ctx context.Context, mailbox, blobID string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM blobs WHERE blob_id=? AND mailbox_id=?`, blobID, mailbox)
	return err
}
