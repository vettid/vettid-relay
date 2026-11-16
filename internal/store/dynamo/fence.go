package dynamo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/vettid-relay/internal/store"
)

// The purge fence. Emptying a dead mailbox's partition is many writes; if
// the mailbox's key registered again in the middle, the purge would delete
// the live mailbox's contents (its denylist and consumed one-shot tokens
// among them, so a revoked or used token would work again). So every purge
// of a dead mailbox first takes the fence: purging (when, ms) and
// purge_by (whose, a random token) on its account item, set by a
// conditional write that requires the mailbox still dead and no other
// purge holding it. A revive (Register, or Rotate onto a dead successor)
// takes the fence itself, purges, and commits only while it still holds
// it; the sweep's final write and a deletion's counters reset also
// require it. While one purge holds the fence, nothing revives the
// mailbox.
//
// The token is a true fencing token: each batch of a purge's deletes is
// one transaction with a check that the token still holds the fence. A
// holder that lost it (stalled past the lease, however long, whatever its
// clock says) deletes nothing more.
//
// A fence older than purgeLease belongs to a purge that died or stalled,
// and the next purge takes it over and carries on (purging is
// idempotent). A purge also gives up after its budget (purgeBudget), so a
// live holder normally finishes or lets go well inside the lease.
const (
	purgeLease = 5 * time.Minute
	// PurgeBudget is how long one purge may run (the API's deletion
	// timeout is longer).
	PurgeBudget = 2 * time.Minute
	// purgeBatch deletes go in one transaction with the fence's check
	// (DynamoDB allows 100 actions).
	purgeBatch = 99
)

// deadCond is the condition, on an account item, that the mailbox of key
// :p is dead at :now: deleted, or past its rotation grace (as dead()).
const deadCond = "pub = :p AND (attribute_exists(deleted) OR delete_after <= :now)"

// errPurging is a mailbox whose contents another purge is deleting: the
// caller (a registration, a rotation or a deletion) tries again later.
var errPurging = fmt.Errorf("dynamo: the mailbox is being purged: %w", store.ErrBusy)

// errFenceLost is a purge whose fence another purge took over.
var errFenceLost = errors.New("dynamo: the purge lost its fence")

// fence takes the purge fence on id's account item under cond, which must
// hold only while the mailbox is dead (vals are cond's values). ok false:
// cond fails, or another purge holds the fence.
func (s *Store) fence(ctx context.Context, id, cond string, vals item) (tok string, ok bool, err error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", false, err
	}
	tok = hex.EncodeToString(b[:])
	now := s.now()
	_, err = s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        &s.cfg.Table,
		Key:              key(mbPK(id), skAccount),
		UpdateExpression: aws.String("SET purging = :fnow, purge_by = :fby"),
		ConditionExpression: aws.String("attribute_exists(pk) AND (" + cond + ") AND " +
			"(attribute_not_exists(purge_by) OR purging <= :fstale)"),
		ExpressionAttributeValues: withVals(item{
			":fnow": avN(ms(now)), ":fby": avS(tok), ":fstale": avN(ms(now.Add(-purgeLease))),
		}, vals),
	})
	if isCCF(err) {
		return "", false, nil
	}
	if isTxConflict(err) {
		return "", false, nil // a purge's batch in flight: busy; nothing was written
	}
	if err != nil {
		// The write may have applied (a lost response, a cancelled
		// request): give it back rather than block the key for a lease.
		s.unfence(ctx, id, tok)
		return "", false, err
	}
	return tok, true, nil
}

// unfence gives the fence back, if tok still holds it. Best effort: a
// fence left behind ends with its lease.
func (s *Store) unfence(ctx context.Context, id, tok string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	for attempt := 0; attempt < 5; attempt++ {
		_, err := s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(id), skAccount),
			UpdateExpression:          aws.String("REMOVE purging, purge_by"),
			ConditionExpression:       aws.String("purge_by = :fby"),
			ExpressionAttributeValues: item{":fby": avS(tok)},
		})
		if !isTxConflict(err) || backoff(ctx, attempt) != nil {
			return
		}
	}
}

// fenceCheck is the transaction action that requires tok to hold id's
// fence.
func (s *Store) fenceCheck(id, tok string) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(id), skAccount),
		ConditionExpression:       aws.String("purge_by = :fby"),
		ExpressionAttributeValues: item{":fby": avS(tok)},
	}}
}

// purgeFenced empties a mailbox the caller holds the fence on (tok):
// messages, leases, denylist, token counters, consumed open tokens, blobs
// (with their bodies) and the claims it created; the account and counters
// items stay (a deletion's tombstone). Each batch of deletes requires the
// fence (errFenceLost when another purge took it over); a blob's body is
// deleted once its item is. It stops at the budget; a later purge carries
// on from what is left.
func (s *Store) purgeFenced(ctx context.Context, id, tok string) (msgs int64, err error) {
	budget := PurgeBudget
	if s.purgeBudget > 0 {
		budget = s.purgeBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if s.duringPurge != nil {
		s.duringPurge()
	}
	var keys []item
	err = s.queryAll(ctx, &dynamodb.QueryInput{
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: item{":pk": avS(mbPK(id))},
		ProjectionExpression:      aws.String("pk, sk"),
	}, func(it item) error {
		sk := getS(it, "sk")
		switch {
		case sk == skAccount || sk == skStats:
			return nil
		case strings.HasPrefix(sk, "M#"):
			msgs++
		case strings.HasPrefix(sk, "C#"):
			keys = append(keys, key(claimPK(sk[2:]), "CL"))
		}
		keys = append(keys, key(mbPK(id), sk))
		return nil
	})
	if err != nil {
		return 0, err
	}
	for len(keys) > 0 {
		n := min(purgeBatch, len(keys))
		if err := s.fencedDelete(ctx, id, tok, keys[:n]); err != nil {
			return 0, err
		}
		if s.cfg.S3 != nil {
			for _, k := range keys[:n] {
				if sk := getS(k, "sk"); getS(k, "pk") == mbPK(id) && strings.HasPrefix(sk, "B#") {
					if _, err := s.cfg.S3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.cfg.Bucket, Key: aws.String(blobKey(id, sk[2:]))}); err != nil {
						return 0, err
					}
				}
			}
		}
		keys = keys[n:]
	}
	if s.afterPurge != nil {
		s.afterPurge()
	}
	return msgs, nil
}

// fencedDelete deletes keys in one transaction that requires tok to hold
// id's fence, retrying conflicts.
func (s *Store) fencedDelete(ctx context.Context, id, tok string, keys []item) error {
	acts := []types.TransactWriteItem{s.fenceCheck(id, tok)}
	for _, k := range keys {
		acts = append(acts, types.TransactWriteItem{Delete: &types.Delete{TableName: &s.cfg.Table, Key: k}})
	}
	for attempt := 0; ; attempt++ {
		_, err := s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: acts})
		if err == nil {
			return nil
		}
		r := txReasons(err)
		if r != nil && reasonCode(r, 0) == "ConditionalCheckFailed" {
			return errFenceLost
		}
		if r == nil || !isConflict(r) || attempt >= maxTxAttempts {
			return fmt.Errorf("dynamo: purge: %w", err)
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
}
