package dynamo

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DeleteMailbox implements store.Backend. Each mailbox (the one named and
// every predecessor rotated into it) is first tombstoned in one
// transaction — A marked deleted, S dead with nb — which is the moment
// every process starts refusing writes to it; then its contents are
// deleted and its counters zeroed. A crash after the transaction leaves
// contents that nothing can reach (the mailbox is dead) and that expire
// on their own; repeating the deletion, a re-registration (which purges
// before reviving) or the tombstone's final purge removes them.
func (s *Store) DeleteMailbox(ctx context.Context, id string, pub []byte, notBefore, keepUntil time.Time) ([]string, error) {
	type job struct{ id, successor string }
	todo := []job{{id: id}}
	seen := map[string]bool{}
	var deleted []string
	for len(todo) > 0 {
		j := todo[0]
		todo = todo[1:]
		if seen[j.id] {
			continue
		}
		seen[j.id] = true
		out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: &s.cfg.Table, Key: key(mbPK(j.id), skAccount), ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return deleted, err
		}
		it := out.Item
		if len(it) == 0 {
			continue
		}
		if j.successor == "" {
			if subtle.ConstantTimeCompare(getB(it, "pub"), pub) != 1 {
				return nil, nil // another key's mailbox (a hash collision)
			}
		} else if _, rotated := getN(it, "delete_after"); !rotated || getS(it, "successor") != j.successor {
			continue // not (or no longer) a predecessor of this mailbox
		}
		_, already := it["deleted"]
		if s.beforeMark != nil {
			s.beforeMark()
		}
		// A repeated deletion never shortens the tombstone (§6.10): its
		// expiry is the larger of the new one, the stored gsk (a rotated
		// mailbox's delete_after, or an earlier tombstone's) and tomb_keep
		// (an earlier tombstone's, kept when the key registered again).
		if err := s.tombstone(ctx, j.id, getB(it, "pub"), getN0(it, "nb"), notBefore, keepUntil, max(getN0(it, "gsk"), getN0(it, "tomb_keep"))); err != nil {
			return deleted, err
		}
		if !already { // a repeat finishes an interrupted purge but reports nothing new
			deleted = append(deleted, j.id)
		}
		if v, ok := it["preds"].(*types.AttributeValueMemberSS); ok {
			for _, p := range v.Value {
				todo = append(todo, job{id: p, successor: j.id})
			}
		}
	}
	return deleted, nil
}

// tombstone marks one mailbox deleted and empties it.
func (s *Store) tombstone(ctx context.Context, id string, pub []byte, prevNB int64, notBefore, keepUntil time.Time, prevKeep int64) error {
	defer s.forget(id)
	nb := max(ms(notBefore), prevNB)
	keepUntil = time.UnixMilli(max(ms(keepUntil), prevKeep))
	for attempt := 0; ; attempt++ {
		err := s.markDeleted(ctx, id, pub, nb, keepUntil)
		if err == nil {
			break
		}
		if r := txReasons(err); r == nil || !isConflict(r) || attempt >= maxTxAttempts {
			return fmt.Errorf("dynamo: delete mailbox: %w", err)
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
	// The contents go under the fence (fence.go). While another purge
	// holds it, wait: the deletion answers only once its mailbox is empty
	// (a holder may stop short of that). If the key registered again
	// since, or the sweep removed the tombstone, nothing of this
	// deletion's is left to empty.
	var tok string
	for attempt := 0; ; attempt++ {
		t, ok, err := s.fence(ctx, id, "pub = :p AND attribute_exists(deleted)", item{":p": avB(pub)})
		if err != nil {
			return err
		}
		if ok {
			tok = t
			break
		}
		it, err := s.getAccount(ctx, id)
		if err != nil {
			return err
		}
		if _, deleted := it["deleted"]; !deleted {
			return nil
		}
		if attempt >= maxTxAttempts {
			return fmt.Errorf("dynamo: delete mailbox: %w", errPurging)
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
	defer s.unfence(ctx, id, tok)
	if _, err := s.purgeFenced(ctx, id); err != nil {
		return err
	}
	// Zero the counters after the purge, so that acks racing it cannot
	// leave them negative for a later re-registration (which zeroes them
	// again anyway).
	// Only an existing counters item: one the sweep deleted (after a
	// takeover of the fence) isn't made again.
	_, err := s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(id), skStats),
		UpdateExpression:          aws.String("SET msgs = :z, bytes = :z, blob_bytes = :z, deny = :z"),
		ConditionExpression:       aws.String("attribute_exists(pk)"),
		ExpressionAttributeValues: item{":z": avN(0)},
	})
	if isCCF(err) {
		return nil
	}
	return err
}

// markDeleted is the tombstone transaction (A deleted, S dead).
func (s *Store) markDeleted(ctx context.Context, id string, pub []byte, nb int64, keepUntil time.Time) error {
	vals := item{":p": avB(pub), ":now": avN(ms(s.now())), ":nb": avN(nb), ":due": avS(dueValue), ":keep": avN(ms(keepUntil))}
	_, err := s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:        &s.cfg.Table,
			Key:              key(mbPK(id), skAccount),
			UpdateExpression: aws.String("SET deleted = :now, nb = :nb, gpk = :due, gsk = :keep REMOVE preds"),
			// gsk only grows: one raised since the read fails this, the
			// API answers 500, and the owner's retry reads it again.
			ConditionExpression:       aws.String("pub = :p AND (attribute_not_exists(gsk) OR gsk <= :keep) AND (attribute_not_exists(tomb_keep) OR tomb_keep <= :keep)"),
			ExpressionAttributeValues: vals,
		}},
		{Update: &types.Update{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(id), skStats),
			UpdateExpression:          aws.String("SET dead_at = :zero, nb = :nb"),
			ExpressionAttributeValues: item{":zero": avN(0), ":nb": avN(nb)},
		}},
	}})
	return err
}
