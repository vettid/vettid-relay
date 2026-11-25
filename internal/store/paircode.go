package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Code claims (spec §6.9.1): a claim found by a short pairing code. The
// relay stores code_mac = HMAC-SHA-256(k_pc, tag), never the tag or the
// code; the API layer computes it. The store files each code claim under
// its key id (which k_pc made the mac), its salt_id and its bucket (the
// first 2 bytes of code_mac): a redeem looks up only its own key id's
// claims, so a rotated k_pc leaves every older claim unredeemable.

// CodeTTL is a code claim's fixed lifetime (§6.9.1: receipt plus 600 s).
const CodeTTL = 600 * time.Second

// CodeMaxMisses is how many unmatched redeems in its bucket cancel a code
// claim (§7.2 limit 15).
const CodeMaxMisses = 32

var (
	// ErrCodeTaken: the new code claim's code_mac matched a live one; both
	// are deleted (§6.9.1 step 4).
	ErrCodeTaken = errors.New("store: code taken")
	// ErrClaimIDTaken: the creator's claim id is in use by another live
	// code claim (§6.9.1 step 2).
	ErrClaimIDTaken = errors.New("store: claim id in use")
)

// CodePut is a code claim to store.
type CodePut struct {
	Mailbox string // the creating mailbox
	ClaimID string // chosen by the creator, canonical
	KeyID   string // which k_pc made CodeMAC
	SaltID  string
	CodeMAC []byte // 32 bytes
	Salt    []byte // the per-claim salt s_c, 16 bytes
	Blob    []byte
}

// CodeLookup is one tag of a redeem: its salt and its code_mac.
type CodeLookup struct {
	SaltID  string
	CodeMAC []byte
}

// CodeClaim is a redeemed code claim.
type CodeClaim struct {
	ClaimID   string
	Salt      []byte
	Blob      []byte
	ExpiresAt time.Time
}

// CodeBackend is the store's part of code claims. Both stores implement it.
type CodeBackend interface {
	// DeleteMailboxCode deletes the live code claim mailbox created, if
	// any (one live code claim per mailbox, §6.9.1 step 1).
	DeleteMailboxCode(ctx context.Context, mailbox string) error
	// PutCode stores a code claim for CodeTTL, in place of the mailbox's
	// live one (deleted in the same transaction). It fails with
	// ErrClaimIDTaken if the claim id names another live code claim, with
	// ErrCodeTaken (having deleted the live claim with the same code_mac)
	// on a collision, with ErrNotFound if the mailbox is not live, and
	// with ErrQuotaMailboxBlobs if the mailbox's storage cap (maxStored >
	// 0) would be exceeded. Like claims, it counts against that cap.
	PutCode(ctx context.Context, c CodePut, maxStored int64) (expiresAt time.Time, err error)
	// RedeemCode looks up each lookup's code_mac among the live code
	// claims of keyID and that lookup's salt. The first match is deleted
	// atomically, across all processes, and returned: only one caller
	// gets a given claim. With no match it returns ErrNotFound, and,
	// unless dry, adds one miss to each live code claim of each lookup's
	// salt in that lookup's bucket, deleting the claims that reach
	// CodeMaxMisses. A match that lost the race to another caller is
	// ErrNotFound with no misses added. A dry redeem (a refused or
	// malformed request's dummy work) does the same reads and never
	// deletes or adds a miss.
	RedeemCode(ctx context.Context, keyID string, lookups []CodeLookup, dry bool) (CodeClaim, error)
	// DeleteCode deletes code claim claimID if mailbox created it.
	// Idempotent.
	DeleteCode(ctx context.Context, mailbox, claimID string) error
	// PairCodeNonce returns the lookup salt nonce of epoch: the stored
	// one, or fresh, stored now, if there is none yet. Once returned, an
	// epoch's nonce never changes, on any process.
	PairCodeNonce(ctx context.Context, epoch int64, fresh []byte) ([]byte, error)
}

var _ CodeBackend = (*Store)(nil)

// codeBucket is a code_mac's bucket: its first 2 bytes, big-endian.
func codeBucket(mac []byte) int { return int(mac[0])<<8 | int(mac[1]) }

// CodeBucket is exported for the other store.
func CodeBucket(mac []byte) int { return codeBucket(mac) }

func (s *Store) DeleteMailboxCode(ctx context.Context, mailbox string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM code_claims WHERE mailbox_id=?`, mailbox)
	return err
}

func (s *Store) PutCode(ctx context.Context, c CodePut, maxStored int64) (time.Time, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	now := s.now()
	if err := s.checkLive(ctx, tx, c.Mailbox, Limits{}); err != nil {
		return time.Time{}, err
	}
	// One live code claim per mailbox, also against a PUT from the same
	// mailbox on another process (§6.9.1 step 1).
	if _, err := tx.ExecContext(ctx, `DELETE FROM code_claims WHERE mailbox_id=?`, c.Mailbox); err != nil {
		return time.Time{}, err
	}
	// Expired rows hold their claim id and code_mac until a sweep: they
	// stop counting here.
	if _, err := tx.ExecContext(ctx, `DELETE FROM code_claims WHERE (claim_id=? OR code_mac=?) AND expires_at<=?`,
		c.ClaimID, c.CodeMAC, ms(now)); err != nil {
		return time.Time{}, err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM code_claims WHERE claim_id=?`, c.ClaimID).Scan(&n); err != nil {
		return time.Time{}, err
	}
	if n > 0 {
		return time.Time{}, ErrClaimIDTaken
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM code_claims WHERE code_mac=?`, c.CodeMAC)
	if err != nil {
		return time.Time{}, err
	}
	if k, _ := res.RowsAffected(); k > 0 {
		// The other claim goes, and this one is never stored.
		if err := tx.Commit(); err != nil {
			return time.Time{}, err
		}
		return time.Time{}, ErrCodeTaken
	}
	if maxStored > 0 {
		used, err := storedBytes(ctx, tx, c.Mailbox, now)
		if err != nil {
			return time.Time{}, err
		}
		if used+int64(len(c.Blob)) > maxStored {
			return time.Time{}, ErrQuotaMailboxBlobs
		}
	}
	exp := now.Add(CodeTTL).UTC()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO code_claims(claim_id, mailbox_id, key_id, salt_id, bucket, code_mac, misses, size, expires_at, salt, blob)
		 VALUES(?,?,?,?,?,?,0,?,?,?,?)`,
		c.ClaimID, c.Mailbox, c.KeyID, c.SaltID, codeBucket(c.CodeMAC), c.CodeMAC, len(c.Blob), ms(exp), c.Salt, c.Blob); err != nil {
		return time.Time{}, err
	}
	return exp, tx.Commit()
}

func (s *Store) RedeemCode(ctx context.Context, keyID string, lookups []CodeLookup, dry bool) (CodeClaim, error) {
	now := ms(s.now())
	if dry {
		for _, l := range lookups {
			var n int
			if err := s.r.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM code_claims WHERE key_id=? AND salt_id=? AND bucket=? AND expires_at>?`,
				keyID, l.SaltID, codeBucket(l.CodeMAC), now).Scan(&n); err != nil {
				return CodeClaim{}, err
			}
		}
		return CodeClaim{}, ErrNotFound
	}
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return CodeClaim{}, err
	}
	defer tx.Rollback()
	for _, l := range lookups {
		var c CodeClaim
		var exp int64
		err := tx.QueryRowContext(ctx,
			`DELETE FROM code_claims WHERE key_id=? AND salt_id=? AND code_mac=? AND expires_at>?
			 RETURNING claim_id, salt, blob, expires_at`,
			keyID, l.SaltID, l.CodeMAC, now).Scan(&c.ClaimID, &c.Salt, &c.Blob, &exp)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return CodeClaim{}, err
		}
		c.ExpiresAt = time.UnixMilli(exp).UTC()
		return c, tx.Commit()
	}
	// No match: one miss for each live claim of each lookup's salt and
	// bucket (a claim is in one salt and bucket, so at most once per
	// request), then the cancelled ones go.
	for _, l := range lookups {
		if _, err := tx.ExecContext(ctx,
			`UPDATE code_claims SET misses=misses+1 WHERE key_id=? AND salt_id=? AND bucket=? AND expires_at>?`,
			keyID, l.SaltID, codeBucket(l.CodeMAC), now); err != nil {
			return CodeClaim{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM code_claims WHERE misses>=?`, CodeMaxMisses); err != nil {
		return CodeClaim{}, err
	}
	if err := tx.Commit(); err != nil {
		return CodeClaim{}, err
	}
	return CodeClaim{}, ErrNotFound
}

func (s *Store) DeleteCode(ctx context.Context, mailbox, claimID string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM code_claims WHERE claim_id=? AND mailbox_id=?`, claimID, mailbox)
	return err
}

func (s *Store) PairCodeNonce(ctx context.Context, epoch int64, fresh []byte) ([]byte, error) {
	if _, err := s.w.ExecContext(ctx, `INSERT INTO pair_code_nonces(epoch, nonce) VALUES(?,?) ON CONFLICT(epoch) DO NOTHING`,
		epoch, fresh); err != nil {
		return nil, err
	}
	var n []byte
	err := s.w.QueryRowContext(ctx, `SELECT nonce FROM pair_code_nonces WHERE epoch=?`, epoch).Scan(&n)
	return n, err
}
