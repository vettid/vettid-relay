package dynamo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// The purge fence. Emptying a dead mailbox's partition (purgeItems) is
// many writes, outside any transaction; if the mailbox's key registered
// again in the middle, the purge would delete the live mailbox's contents
// (its denylist and consumed one-shot tokens among them, so a revoked or
// used token would work again). So every purge of a dead mailbox first
// takes the fence: purging (when, ms) and purge_by (whose) on its account
// item, set by a conditional write that requires the mailbox still dead
// and no other purge holding it. A revive (Register, or Rotate onto a dead
// successor) takes the fence itself, purges, and commits only while it
// still holds it; the sweep's final write also requires it. While one
// purge holds the fence, nothing revives the mailbox.
//
// A purge runs for at most purgeBudget, well inside purgeLease: a fence
// older than the lease belongs to a purge that died (or gave up), and the
// next purge takes it over and carries on (purging is idempotent).
const (
	purgeLease  = 5 * time.Minute
	purgeBudget = 2 * time.Minute
)

// deadCond is the condition, on an account item, that the mailbox of key
// :p is dead at :now: deleted, or past its rotation grace (as dead()).
const deadCond = "pub = :p AND (attribute_exists(deleted) OR delete_after <= :now)"

// errPurging is a mailbox whose contents another purge is deleting: the
// caller (a registration or a rotation) tries again later.
var errPurging = errors.New("dynamo: the mailbox is being purged; try again")

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
	if err != nil {
		return "", false, err
	}
	return tok, true, nil
}

// unfence gives the fence back, if tok still holds it. Best effort: a
// fence left behind ends with its lease.
func (s *Store) unfence(ctx context.Context, id, tok string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_, _ = s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(id), skAccount),
		UpdateExpression:          aws.String("REMOVE purging, purge_by"),
		ConditionExpression:       aws.String("purge_by = :fby"),
		ExpressionAttributeValues: item{":fby": avS(tok)},
	})
}

// purgeFenced empties a mailbox the caller holds the fence on (as
// purgeContents), within purgeBudget: no delete of it is sent after its
// lease could have passed to another purge.
func (s *Store) purgeFenced(ctx context.Context, id string) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, purgeBudget)
	defer cancel()
	if s.duringPurge != nil {
		s.duringPurge()
	}
	return s.purgeContents(ctx, id)
}
