package dynamo

import (
	"context"
	"crypto/subtle"
	"errors"
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
	var errs []error // after a mark: the deletion goes on, and fails at the end
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
		marked, err := s.tombstone(ctx, j.id, getB(it, "pub"), getN0(it, "nb"), notBefore, keepUntil, max(getN0(it, "gsk"), getN0(it, "tomb_keep")))
		if !marked {
			return deleted, errors.Join(append(errs, err)...)
		}
		// Marked: the mailbox is dead, whether or not its purge finished.
		// It is reported, and its predecessors go too; a repeat finishes
		// the purge (the tombstone keeps preds for it).
		if !already { // a repeat finishes an interrupted purge but reports nothing new
			deleted = append(deleted, j.id)
		}
		if err != nil {
			errs = append(errs, err)
		}
		if v, ok := it["preds"].(*types.AttributeValueMemberSS); ok {
			for _, p := range v.Value {
				todo = append(todo, job{id: p, successor: j.id})
			}
		}
	}
	return deleted, errors.Join(errs...)
}

// tombstone marks one mailbox deleted and empties it. marked: the mark is
// written (the mailbox is dead), even if emptying it then failed.
func (s *Store) tombstone(ctx context.Context, id string, pub []byte, prevNB int64, notBefore, keepUntil time.Time, prevKeep int64) (marked bool, err error) {
	defer s.forget(id)
	nb := max(ms(notBefore), prevNB)
	keepUntil = time.UnixMilli(max(ms(keepUntil), prevKeep))
	for attempt := 0; ; attempt++ {
		err := s.markDeleted(ctx, id, pub, nb, keepUntil)
		if err == nil {
			break
		}
		if r := txReasons(err); r == nil || !isConflict(r) || attempt >= maxTxAttempts {
			return false, fmt.Errorf("dynamo: delete mailbox: %w", err)
		}
		if err := backoff(ctx, attempt); err != nil {
			return false, err
		}
	}
	if s.afterMark != nil {
		s.afterMark()
	}
	return true, s.emptyDeleted(ctx, id, pub)
}

// emptyDeleted purges a deleted mailbox under the fence (fence.go), then
// zeroes its counters. While another purge holds the fence, it waits: a
// deletion answers only once its mailbox is empty (a holder may stop
// short of that). If the key registered again since, or the sweep removed
// the tombstone, nothing of this deletion's is left to empty.
func (s *Store) emptyDeleted(ctx context.Context, id string, pub []byte) error {
	for attempt := 0; ; attempt++ {
		tok, ok, err := s.fence(ctx, id, "pub = :p AND attribute_exists(deleted)", item{":p": avB(pub)})
		if err != nil {
			return err
		}
		if ok {
			_, err := s.purgeFenced(ctx, id, tok)
			if err == nil {
				err = s.zeroCounters(ctx, id, tok)
			}
			s.unfence(ctx, id, tok)
			if !errors.Is(err, errFenceLost) {
				return err
			}
			// Taken over: look again.
		} else {
			it, err := s.getAccount(ctx, id)
			if err != nil {
				return err
			}
			if _, deleted := it["deleted"]; !deleted {
				return nil
			}
		}
		if attempt >= maxTxAttempts {
			return fmt.Errorf("dynamo: delete mailbox: %w", errPurging)
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
}

// zeroCounters zeroes a purged mailbox's counters, so that acks racing the
// purge cannot leave them negative for a later re-registration (which
// zeroes them again anyway). Only while tok holds the fence: never a
// revived mailbox's counters, nor a counters item the sweep removed.
func (s *Store) zeroCounters(ctx context.Context, id, tok string) error {
	for attempt := 0; ; attempt++ {
		_, err := s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
			s.fenceCheck(id, tok),
			{Update: &types.Update{
				TableName:                 &s.cfg.Table,
				Key:                       key(mbPK(id), skStats),
				UpdateExpression:          aws.String("SET msgs = :z, bytes = :z, blob_bytes = :z, deny = :z"),
				ConditionExpression:       aws.String("attribute_exists(pk)"),
				ExpressionAttributeValues: item{":z": avN(0)},
			}},
		}})
		if err == nil {
			return nil
		}
		r := txReasons(err)
		switch {
		case r != nil && reasonCode(r, 0) == "ConditionalCheckFailed":
			return errFenceLost
		case r != nil && reasonCode(r, 1) == "ConditionalCheckFailed":
			return nil // no counters item
		case r == nil || !isConflict(r) || attempt >= maxTxAttempts:
			return err
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
}

// markDeleted is the tombstone transaction (A deleted, S dead).
func (s *Store) markDeleted(ctx context.Context, id string, pub []byte, nb int64, keepUntil time.Time) error {
	vals := item{":p": avB(pub), ":now": avN(ms(s.now())), ":nb": avN(nb), ":due": avS(dueValue), ":keep": avN(ms(keepUntil))}
	_, err := s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName: &s.cfg.Table,
			Key:       key(mbPK(id), skAccount),
			// preds stay: a repeated deletion (after one that failed past
			// its mark) still reaches the predecessors.
			UpdateExpression: aws.String("SET deleted = :now, nb = :nb, gpk = :due, gsk = :keep"),
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
