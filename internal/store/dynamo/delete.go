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
		if err := s.tombstone(ctx, j.id, getB(it, "pub"), getN0(it, "nb"), notBefore, keepUntil); err != nil {
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
func (s *Store) tombstone(ctx context.Context, id string, pub []byte, prevNB int64, notBefore, keepUntil time.Time) error {
	defer s.forget(id)
	nb := max(ms(notBefore), prevNB)
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
	if _, err := s.purgeContents(ctx, id); err != nil {
		return err
	}
	// Zero the counters after the purge, so that acks racing it cannot
	// leave them negative for a later re-registration (which zeroes them
	// again anyway).
	_, err := s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(id), skStats),
		UpdateExpression:          aws.String("SET msgs = :z, bytes = :z, blob_bytes = :z, deny = :z"),
		ExpressionAttributeValues: item{":z": avN(0)},
	})
	return err
}

// markDeleted is the tombstone transaction (A deleted, S dead).
func (s *Store) markDeleted(ctx context.Context, id string, pub []byte, nb int64, keepUntil time.Time) error {
	vals := item{":p": avB(pub), ":now": avN(ms(s.now())), ":nb": avN(nb), ":due": avS(dueValue), ":keep": avN(ms(keepUntil))}
	_, err := s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(id), skAccount),
			UpdateExpression:          aws.String("SET deleted = :now, nb = :nb, gpk = :due, gsk = :keep REMOVE preds"),
			ConditionExpression:       aws.String("pub = :p"),
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
