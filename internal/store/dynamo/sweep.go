package dynamo

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/vettid-relay/internal/store"
)

// Sweep implements store.Backend. Expiry needs no sweeping here: every read
// checks exp, Collect and quota recomputation delete expired items they
// meet, DynamoDB TTL reclaims the rest, and the S3 lifecycle rule expires
// blob bodies. What TTL cannot do is cascade: Sweep purges rotated mailboxes
// whose grace period ended at least PurgeDelay ago — every item in the
// mailbox, its blob bodies and its claims — the way the SQLite store's
// ON DELETE CASCADE does, and leaves a tombstone (§6.7, §6.10: the A and S
// items, as a deletion does) that it purges in turn when it expires. Any
// number of processes may sweep concurrently; purging is idempotent.
func (s *Store) Sweep(ctx context.Context) (store.SweepStats, error) {
	var st store.SweepStats
	cutoff := ms(s.now().Add(-s.cfg.PurgeDelay))
	var due []string
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		IndexName:                 aws.String(dueGSI),
		KeyConditionExpression:    aws.String("gpk = :due AND gsk <= :cut"),
		ExpressionAttributeValues: item{":due": avS(dueValue), ":cut": avN(cutoff)},
	}, func(it item) error {
		due = append(due, strings.TrimPrefix(getS(it, "pk"), "MB#"))
		return nil
	})
	if err != nil {
		return st, err
	}
	var errs []error
	for _, mb := range due {
		n, purged, err := s.purge(ctx, mb, cutoff)
		if err != nil {
			if ctx.Err() != nil {
				return st, err
			}
			// One mailbox's failure (a purge past its budget, say) doesn't
			// hold up the others; the next sweep comes back to it. The
			// error names no mailbox (RELAY-PROTOCOL §8: logs carry no
			// mailbox ids): the errors it joins are the store's own, whose
			// AWS errors are scrubbed (scrub.go).
			errs = append(errs, err)
			continue
		}
		st.Messages += n
		if purged {
			st.Mailboxes++
		}
	}
	if len(errs) > 0 {
		return st, fmt.Errorf("dynamo: sweep: %d of %d due mailboxes failed: %w", len(errs), len(due), joinDistinct(errs))
	}
	return st, nil
}

// joinDistinct joins errors with distinct texts, at most three.
func joinDistinct(errs []error) error {
	seen := map[string]bool{}
	var out []error
	for _, e := range errs {
		if t := e.Error(); !seen[t] && len(out) < 3 {
			seen[t] = true
			out = append(out, e)
		}
	}
	return errors.Join(out...)
}

// purge removes a due mailbox. A rotated-away one is emptied and turned
// into a tombstone; an expired tombstone is deleted with its whole
// partition. Both steps are conditional on the mailbox still being due
// (it may have been revived as a rotation successor or re-registered).
func (s *Store) purge(ctx context.Context, mailbox string, cutoff int64) (msgs int64, purged bool, err error) {
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), skAccount), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return 0, false, err
	}
	it := out.Item
	if len(it) == 0 || getS(it, "gpk") != dueValue || getN0(it, "gsk") > cutoff {
		return 0, false, nil
	}
	if s.beforePurge != nil {
		s.beforePurge()
	}
	if _, tomb := it["deleted"]; !tomb {
		return s.retire(ctx, mailbox, it, cutoff) // folds tomb_keep into the gsk it sets
	}
	// A tombstone isn't purged while a tomb_keep is still ahead: nothing of
	// the partition (its counters item included, which carries nb) goes
	// before the tombstone ends (§6.10).
	if getN0(it, "tomb_keep") > cutoff {
		return 0, false, nil
	}
	// The fence first, under the same condition: a re-registration since
	// the read (the mailbox live again) fails it, and none can revive the
	// mailbox while its contents go (fence.go).
	due := item{":due": avS(dueValue), ":cut": avN(cutoff)}
	tok, ok, err := s.fence(ctx, mailbox, "gpk = :due AND gsk <= :cut AND attribute_exists(deleted) AND (attribute_not_exists(tomb_keep) OR tomb_keep <= :cut)", due)
	if err != nil || !ok {
		return 0, false, err
	}
	// The contents; then the account and counters items (which carry the
	// tombstone and its nb) together, under the condition and the fence, so
	// a deletion since the read keeps both (§6.10).
	msgs, err = s.purgeFenced(ctx, mailbox, tok)
	if err != nil {
		s.unfence(ctx, mailbox, tok)
		if errors.Is(err, errFenceLost) {
			return 0, false, nil // taken over; that purge carries on
		}
		return 0, false, err
	}
	_, err = s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Delete: &types.Delete{
			TableName: &s.cfg.Table,
			Key:       key(mbPK(mailbox), skAccount),
			// Nor while a tomb_keep is still ahead: a writer that set gsk
			// from an older read can't end a tombstone the re-registration
			// kept.
			ConditionExpression:       aws.String("purge_by = :fby AND gpk = :due AND gsk <= :cut AND (attribute_not_exists(tomb_keep) OR tomb_keep <= :cut)"),
			ExpressionAttributeValues: item{":due": avS(dueValue), ":cut": avN(cutoff), ":fby": avS(tok)},
		}},
		{Delete: &types.Delete{TableName: &s.cfg.Table, Key: key(mbPK(mailbox), skStats)}},
	}})
	if err != nil {
		s.unfence(ctx, mailbox, tok)
	}
	if r := txReasons(err); r != nil {
		return msgs, false, nil // changed since the read; the next sweep looks again
	}
	s.forget(mailbox)
	return msgs, err == nil, err
}

// retire tombstones a rotated-away mailbox at the end of its grace: its
// contents go, and if its key registers again, tokens issued before now +
// margin are refused (the tombstone keeps the counters item dead
// meanwhile, so a stale cache cannot write either).
func (s *Store) retire(ctx context.Context, mailbox string, it item, cutoff int64) (int64, bool, error) {
	defer s.forget(mailbox)
	p, err := s.tombstones(ctx) // first: a failed read wastes no purge
	if err != nil {
		return 0, false, err
	}
	tok, ok, err := s.fence(ctx, mailbox, "gpk = :due AND gsk <= :cut AND attribute_not_exists(deleted)",
		item{":due": avS(dueValue), ":cut": avN(cutoff)})
	if err != nil || !ok {
		return 0, false, err // !ok: revived, deleted or being purged since the read
	}
	msgs, err := s.purgeFenced(ctx, mailbox, tok)
	if err != nil {
		s.unfence(ctx, mailbox, tok)
		if errors.Is(err, errFenceLost) {
			return 0, false, nil // taken over; that purge carries on
		}
		return 0, false, err
	}
	nb, keep := p.Times(s.now())
	nbv := max(ms(nb), getN0(it, "nb"))
	// An earlier tombstone kept as tomb_keep (a deletion, then a
	// re-registration, then this rotation) is not shortened (§6.10).
	keepv := max(ms(keep), getN0(it, "tomb_keep"))
	_, err = s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:           &s.cfg.Table,
			Key:                 key(mbPK(mailbox), skAccount),
			UpdateExpression:    aws.String("SET deleted = :now, nb = :nb, gsk = :keep REMOVE preds, purging, purge_by"),
			ConditionExpression: aws.String("purge_by = :fby AND gpk = :due AND gsk <= :cut AND attribute_not_exists(deleted)"),
			ExpressionAttributeValues: item{":now": avN(ms(s.now())), ":nb": avN(nbv), ":keep": avN(keepv),
				":due": avS(dueValue), ":cut": avN(cutoff), ":fby": avS(tok)},
		}},
		{Update: &types.Update{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(mailbox), skStats),
			UpdateExpression:          aws.String("SET dead_at = :zero, nb = :nb, msgs = :zero, bytes = :zero, blob_bytes = :zero, deny = :zero"),
			ExpressionAttributeValues: item{":zero": avN(0), ":nb": avN(nbv)},
		}},
	}})
	if err != nil {
		s.unfence(ctx, mailbox, tok)
	}
	if r := txReasons(err); r != nil {
		return msgs, false, nil // deleted meanwhile; the next sweep looks again
	}
	return msgs, err == nil, err
}

// CreateTable creates the relay table with the layout this package expects
// (tests and local development; production tables come from CDK, which
// must match: pk/sk strings, PAY_PER_REQUEST, TTL on ttl_s, and the
// KEYS_ONLY GSI "due" on gpk (S) / gsk (N)).
func CreateTable(ctx context.Context, db *dynamodb.Client, name string) error {
	_, err := db.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   &name,
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("sk"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("gpk"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("gsk"), AttributeType: types.ScalarAttributeTypeN},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("sk"), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{{
			IndexName: aws.String(dueGSI),
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String("gpk"), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String("gsk"), KeyType: types.KeyTypeRange},
			},
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeKeysOnly},
		}},
	})
	if err != nil {
		return err
	}
	w := dynamodb.NewTableExistsWaiter(db)
	if err := w.Wait(ctx, &dynamodb.DescribeTableInput{TableName: &name}, time.Minute); err != nil {
		return err
	}
	_, err = db.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName:               &name,
		TimeToLiveSpecification: &types.TimeToLiveSpecification{AttributeName: aws.String("ttl_s"), Enabled: aws.Bool(true)},
	})
	return err
}
