package dynamo

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/vettid-relay/internal/store"
)

// AddDenylist implements store.Backend. It first reserves room for the
// entries that are new (or expired) against the mailbox's denylist counter —
// so an add refused for quota writes nothing — and then writes every entry
// with expiry max(existing, expiresAt). Entry writes are idempotent; if one
// fails the call fails and a retry completes it (revocation only ever errs
// toward revoking).
func (s *Store) AddDenylist(ctx context.Context, mailbox string, entries []store.DenyEntry, expiresAt time.Time, maxEntries int64) error {
	now := s.now()
	uniq := map[string]bool{}
	var keys []item
	for _, e := range entries {
		sk := denySK(e.Kind, e.Value)
		if !uniq[sk] {
			uniq[sk] = true
			keys = append(keys, key(mbPK(mailbox), sk))
		}
	}
	if len(keys) == 0 {
		return nil
	}
	existing, err := s.batchGet(ctx, keys)
	if err != nil {
		return err
	}
	var fresh int64
	for sk := range uniq {
		if exp, ok := existing[sk]; !ok || exp <= ms(now) {
			fresh++
		}
	}
	if fresh > 0 {
		reconciled := false
		for {
			q := newQuotaCond(now)
			q.room("deny", fresh, maxEntries)
			q.vals[":n"], q.vals[":one"] = avN(fresh), avN(1)
			_, err := s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
				TableName:                 &s.cfg.Table,
				Key:                       key(mbPK(mailbox), skStats),
				UpdateExpression:          aws.String("ADD deny :n, v :one"),
				ConditionExpression:       q.expr(),
				ExpressionAttributeValues: q.vals,
			})
			if err == nil {
				break
			}
			if !isCCF(err) {
				return err
			}
			if !reconciled {
				reconciled = true
				if ok, err := s.reconcile(ctx, mailbox, kindDeny); err != nil {
					return err
				} else if ok {
					continue
				}
			}
			return store.ErrQuota
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(uniq))
	sem := make(chan struct{}, 16)
	for sk := range uniq {
		if exp, ok := existing[sk]; ok && exp >= ms(expiresAt) {
			continue // already retained at least as long
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			_, err := s.cfg.DB.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: &s.cfg.Table,
				Item: item{
					"pk": avS(mbPK(mailbox)), "sk": avS(sk),
					"exp": avN(ms(expiresAt)), "ttl_s": avN(ttlSec(expiresAt)),
				},
				ConditionExpression:       aws.String("attribute_not_exists(sk) OR exp < :e"),
				ExpressionAttributeValues: item{":e": avN(ms(expiresAt))},
			})
			if err != nil && !isCCF(err) {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	return <-errs
}

// batchGet reads keys (≤ 100) with strong consistency and returns sk → exp.
func (s *Store) batchGet(ctx context.Context, keys []item) (map[string]int64, error) {
	out := map[string]int64{}
	req := map[string]types.KeysAndAttributes{s.cfg.Table: {Keys: keys, ConsistentRead: aws.Bool(true), ProjectionExpression: aws.String("sk, exp")}}
	for attempt := 0; len(req) > 0; attempt++ {
		res, err := s.cfg.DB.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: req})
		if err != nil {
			return nil, err
		}
		for _, it := range res.Responses[s.cfg.Table] {
			out[getS(it, "sk")] = getN0(it, "exp")
		}
		req = res.UnprocessedKeys
		if len(req) > 0 {
			if err := backoff(ctx, attempt); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// IsDenied implements store.Backend (strongly consistent: a revocation that
// returned 204 applies to the very next deposit on any process).
func (s *Store) IsDenied(ctx context.Context, mailbox, jti, sub string) (bool, error) {
	got, err := s.batchGet(ctx, []item{key(mbPK(mailbox), denySK("jti", jti)), key(mbPK(mailbox), denySK("sub", sub))})
	if err != nil {
		return false, err
	}
	now := ms(s.now())
	for _, exp := range got {
		if exp > now {
			return true, nil
		}
	}
	return false, nil
}

// IsConsumed implements store.Backend.
func (s *Store) IsConsumed(ctx context.Context, mailbox, jti string) (bool, error) {
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), consumedSK(jti)), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	return len(out.Item) > 0 && getN0(out.Item, "exp") > ms(s.now()), nil
}
