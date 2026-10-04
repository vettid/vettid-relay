package dynamo

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/vettid-relay/internal/store"
)

// quotaCond builds the counter conditions for one write: the mailbox must not
// be dead, and each capped counter must leave room for its delta.
type quotaCond struct {
	parts []string
	vals  item
}

func newQuotaCond(now time.Time) *quotaCond {
	return &quotaCond{
		parts: []string{"(attribute_not_exists(dead_at) OR dead_at > :now)"},
		vals:  item{":now": avN(ms(now))},
	}
}

// room requires attr + delta <= max (max > 0; otherwise unlimited).
func (q *quotaCond) room(attr string, delta, max int64) {
	if max <= 0 {
		return
	}
	ph := ":max_" + attr
	q.parts = append(q.parts, fmt.Sprintf("(attribute_not_exists(%s) OR %s <= %s)", attr, attr, ph))
	q.vals[ph] = avN(max - delta)
}

// issuedAt requires a token issued at iat to be no older than the
// mailbox's TokensNotBefore (nb on the counters item, set when a deletion
// tombstoned the id, §6.10). Zero iat: no token, no condition.
func (q *quotaCond) issuedAt(iat time.Time) {
	if iat.IsZero() {
		return
	}
	q.parts = append(q.parts, "(attribute_not_exists(nb) OR nb <= :iat)")
	q.vals[":iat"] = avN(ms(iat))
}

// deadOrRevoked explains a failed counters condition from the item's old
// image: ErrNotFound for a dead mailbox (rotated past its grace, or
// deleted), ErrRevoked for a token issued before nb; nil otherwise.
func deadOrRevoked(old item, now, iat time.Time) error {
	if d, ok := getN(old, "dead_at"); ok && d <= ms(now) {
		return store.ErrNotFound
	}
	if nb, ok := getN(old, "nb"); ok && !iat.IsZero() && ms(iat) < nb {
		return store.ErrRevoked
	}
	return nil
}

func (q *quotaCond) expr() *string { return aws.String(strings.Join(q.parts, " AND ")) }

// tokenCharge is the token-usage update for a deposit or blob (nil without a
// token quota, like the SQLite store).
func (s *Store) tokenCharge(mailbox string, lim store.Limits, msgs, bytes int64) *types.Update {
	if lim.TokenQuotaMsgs == nil && lim.TokenQuotaBytes == nil {
		return nil
	}
	var cond []string
	vals := item{":m": avN(msgs), ":b": avN(bytes), ":e": avN(ms(lim.TokenExpires)), ":t": avN(ttlSec(lim.TokenExpires))}
	if lim.TokenQuotaMsgs != nil {
		cond = append(cond, "(attribute_not_exists(msgs) OR msgs <= :qm)")
		vals[":qm"] = avN(*lim.TokenQuotaMsgs - msgs)
	}
	if lim.TokenQuotaBytes != nil {
		cond = append(cond, "(attribute_not_exists(bytes) OR bytes <= :qb)")
		vals[":qb"] = avN(*lim.TokenQuotaBytes - bytes)
	}
	return &types.Update{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(mailbox), tokenSK(lim.TokenJTI)),
		UpdateExpression:          aws.String("ADD msgs :m, bytes :b SET exp = :e, ttl_s = :t"),
		ConditionExpression:       aws.String(strings.Join(cond, " AND ")),
		ExpressionAttributeValues: vals,
	}
}

// overTokenQuota reports a charge that can never fit (checked before the
// transaction because a condition cannot express "delta > quota" on a
// missing item).
func overTokenQuota(lim store.Limits, msgs, bytes int64) bool {
	return (lim.TokenQuotaMsgs != nil && msgs > *lim.TokenQuotaMsgs) ||
		(lim.TokenQuotaBytes != nil && bytes > *lim.TokenQuotaBytes)
}

// Deposit implements store.Backend as one transaction: the counters item
// (mailbox live, quota room, ULID order), the message, the token's usage
// and, for an open token, its consumption record.
func (s *Store) Deposit(ctx context.Context, mailbox, senderSub string, payload []byte, ttl time.Duration, lim store.Limits) (store.Message, error) {
	size := int64(len(payload))
	// A delta that can never fit fails like the SQLite store would: a used
	// open token is reported first, then quota.
	if (lim.MailboxMaxMsgs > 0 && 1 > lim.MailboxMaxMsgs) || (lim.MailboxMaxBytes > 0 && size > lim.MailboxMaxBytes) || overTokenQuota(lim, 1, size) {
		if lim.ConsumeJTI {
			if used, err := s.IsConsumed(ctx, mailbox, lim.TokenJTI); err != nil {
				return store.Message{}, err
			} else if used {
				return store.Message{}, store.ErrTokenUsed
			}
		}
		return store.Message{}, store.ErrQuota
	}
	after := ""
	reconciled := false
	for attempt := 0; ; attempt++ {
		now := s.now()
		id := s.newID(now, after)
		q := newQuotaCond(now)
		q.issuedAt(lim.TokenIssuedAt)
		q.parts = append(q.parts, "(attribute_not_exists(last_id) OR last_id < :id)")
		q.vals[":id"] = avS(id)
		q.room("msgs", 1, lim.MailboxMaxMsgs)
		q.room("bytes", size, lim.MailboxMaxBytes)
		q.vals[":one"], q.vals[":size"] = avN(1), avN(size)
		exp := now.Add(ttl)
		items := []types.TransactWriteItem{
			{Update: &types.Update{
				TableName:                           &s.cfg.Table,
				Key:                                 key(mbPK(mailbox), skStats),
				UpdateExpression:                    aws.String("SET last_id = :id, v = if_not_exists(v, :zero) + :one ADD msgs :one, bytes :size"),
				ConditionExpression:                 q.expr(),
				ExpressionAttributeValues:           withZero(q.vals),
				ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
			}},
			{Put: &types.Put{
				TableName: &s.cfg.Table,
				Item: item{
					"pk": avS(mbPK(mailbox)), "sk": avS(msgSK(id)),
					"sz": avN(size), "dep": avN(ms(now)), "exp": avN(ms(exp)), "ttl_s": avN(ttlSec(exp)),
					"sender": avS(senderSub), "jti": avS(lim.TokenJTI), "payload": avB(payload),
				},
				ConditionExpression: aws.String("attribute_not_exists(sk)"),
			}},
		}
		tokIdx, useIdx := -1, -1
		if u := s.tokenCharge(mailbox, lim, 1, size); u != nil {
			tokIdx = len(items)
			items = append(items, types.TransactWriteItem{Update: u})
		}
		if lim.ConsumeJTI {
			useIdx = len(items)
			items = append(items, types.TransactWriteItem{Put: &types.Put{
				TableName: &s.cfg.Table,
				Item: item{
					"pk": avS(mbPK(mailbox)), "sk": avS(consumedSK(lim.TokenJTI)),
					"exp": avN(ms(lim.TokenExpires)), "ttl_s": avN(ttlSec(lim.TokenExpires)),
				},
				ConditionExpression:       aws.String("attribute_not_exists(sk) OR exp <= :now"),
				ExpressionAttributeValues: item{":now": avN(ms(now))},
			}})
		}
		_, err := s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
		if err == nil {
			return store.Message{ID: id, Mailbox: mailbox, Sender: senderSub, TokenJTI: lim.TokenJTI, Payload: payload, DepositedAt: now.UTC()}, nil
		}
		r := txReasons(err)
		if r == nil {
			return store.Message{}, err
		}
		const ccf = "ConditionalCheckFailed"
		switch {
		case reasonCode(r, useIdx) == ccf:
			return store.Message{}, store.ErrTokenUsed
		case reasonCode(r, tokIdx) == ccf:
			return store.Message{}, store.ErrQuota
		case reasonCode(r, 0) == ccf:
			old := r[0].Item
			if err := deadOrRevoked(old, now, lim.TokenIssuedAt); err != nil {
				return store.Message{}, err
			}
			if last := getS(old, "last_id"); last >= id {
				after = last // lost the ordering race: retry with a later ULID
				continue
			}
			// Quota. The counters may include acked-in-flight or expired
			// messages: recompute once, then decide.
			if !reconciled {
				reconciled = true
				if ok, err := s.reconcile(ctx, mailbox, kindMsgs); err != nil {
					return store.Message{}, err
				} else if ok {
					continue
				}
			}
			return store.Message{}, store.ErrQuota
		case reasonCode(r, 1) == ccf:
			after = id // ULID collision (practically impossible)
			continue
		}
		if !isConflict(r) || attempt >= maxTxAttempts {
			return store.Message{}, fmt.Errorf("dynamo: deposit: %w", err)
		}
		if err := backoff(ctx, attempt); err != nil {
			return store.Message{}, err
		}
	}
}

// Collect implements store.Backend. One strongly consistent query walks the
// mailbox's lease items (L#, which sort first) and then its messages (M#) in
// ULID order; each candidate is leased with a conditional write, so two
// collectors — on any processes — never hold the same message at once.
func (s *Store) Collect(ctx context.Context, mailbox string, max int, visibility time.Duration) ([]store.Message, time.Time, error) {
	now := s.now()
	nowMS := ms(now)
	leases := map[string]int64{}
	var candidates []store.Message
	var expired []string
	var next int64
	in := &dynamodb.QueryInput{
		TableName:                 &s.cfg.Table,
		ConsistentRead:            aws.Bool(true),
		KeyConditionExpression:    aws.String("pk = :pk AND sk BETWEEN :lo AND :hi"),
		ExpressionAttributeValues: item{":pk": avS(mbPK(mailbox)), ":lo": avS("L#"), ":hi": avS("M$")},
		Limit:                     aws.Int32(int32(max + 16)),
	}
	for len(candidates) < max {
		out, err := s.cfg.DB.Query(ctx, in)
		if err != nil {
			return nil, time.Time{}, err
		}
		for _, it := range out.Items {
			sk := getS(it, "sk")
			switch {
			case strings.HasPrefix(sk, "L#"):
				leases[sk[2:]] = getN0(it, "lease_until")
			case strings.HasPrefix(sk, "M#"):
				id := sk[2:]
				if getN0(it, "exp") <= nowMS {
					expired = append(expired, sk)
					continue
				}
				if until := leases[id]; until > nowMS {
					if next == 0 || until < next {
						next = until
					}
					continue
				}
				if len(candidates) < max {
					candidates = append(candidates, store.Message{
						ID: id, Mailbox: mailbox, Sender: getS(it, "sender"), TokenJTI: getS(it, "jti"),
						Payload: getB(it, "payload"), DepositedAt: fromMS(getN0(it, "dep")),
					})
				}
			}
		}
		if len(out.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
	s.dropExpiredMessages(ctx, mailbox, expired, now)

	until := now.Add(visibility)
	won := make([]bool, len(candidates))
	var firstErr error
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, m := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			_, err := s.cfg.DB.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: &s.cfg.Table,
				Item: item{
					"pk": avS(mbPK(mailbox)), "sk": avS(leaseSK(m.ID)),
					"lease_until": avN(ms(until)), "ttl_s": avN(ttlSec(until.Add(time.Hour))),
				},
				ConditionExpression:       aws.String("attribute_not_exists(sk) OR lease_until <= :now"),
				ExpressionAttributeValues: item{":now": avN(nowMS)},
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won[i] = true
			case isCCF(err): // another collector leased it first
			case firstErr == nil:
				firstErr = err
			}
		}()
	}
	wg.Wait()
	var msgs []store.Message
	for i, m := range candidates {
		if won[i] {
			msgs = append(msgs, m)
		}
	}
	if len(msgs) == 0 && firstErr != nil {
		return nil, time.Time{}, firstErr
	}
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].ID < msgs[j].ID })
	if len(msgs) > 0 {
		return msgs, time.Time{}, nil
	}
	// Candidates whose lease another collector won just now are leased
	// until about now+visibility (by the winner's clock): report that as
	// the next possible visibility, so a parked collector — and an empty
	// hint (api.EmptyHints) — never wait past it.
	if len(candidates) > 0 {
		lost := ms(until.Add(time.Second))
		if next == 0 || lost < next {
			next = lost
		}
	}
	if next == 0 {
		return nil, time.Time{}, nil
	}
	return nil, fromMS(next), nil
}

// dropExpiredMessages deletes expired messages met during a collect and
// releases their share of the mailbox counters (best effort: TTL would
// remove them eventually, and quota checks recompute if needed).
func (s *Store) dropExpiredMessages(ctx context.Context, mailbox string, sks []string, now time.Time) {
	if len(sks) > 25 {
		sks = sks[:25]
	}
	for _, sk := range sks {
		out, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(mailbox), sk),
			ConditionExpression:       aws.String("exp <= :now"),
			ExpressionAttributeValues: item{":now": avN(ms(now))},
			ReturnValues:              types.ReturnValueAllOld,
		})
		if err != nil || len(out.Attributes) == 0 {
			continue
		}
		_ = s.deleteKey(ctx, mbPK(mailbox), leaseSK(strings.TrimPrefix(sk, "M#")))
		_ = s.adjust(ctx, mailbox, map[string]int64{"msgs": -1, "bytes": -getN0(out.Attributes, "sz")})
	}
}

// Ack implements store.Backend. The delete is keyed by the mailbox, so
// another mailbox's message is never touched.
func (s *Store) Ack(ctx context.Context, mailbox, msgID string) (bool, error) {
	out, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    &s.cfg.Table,
		Key:          key(mbPK(mailbox), msgSK(msgID)),
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return false, err
	}
	if len(out.Attributes) == 0 {
		return false, nil
	}
	return true, errors.Join(
		s.deleteKey(ctx, mbPK(mailbox), leaseSK(msgID)),
		s.adjust(ctx, mailbox, map[string]int64{"msgs": -1, "bytes": -getN0(out.Attributes, "sz")}),
	)
}
