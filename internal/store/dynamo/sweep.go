package dynamo

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vettid/vettid-relay/internal/store"
)

// Sweep implements store.Backend. Expiry needs no sweeping here: every read
// checks exp, Collect and quota recomputation delete expired items they
// meet, DynamoDB TTL reclaims the rest, and the S3 lifecycle rule expires
// blob bodies. What TTL cannot do is cascade: Sweep purges rotated mailboxes
// whose grace period ended at least PurgeDelay ago — every item in the
// mailbox, its blob bodies and its claims — the way the SQLite store's
// ON DELETE CASCADE does. Any number of processes may sweep concurrently;
// purging is idempotent.
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
	for _, mb := range due {
		n, purged, err := s.purge(ctx, mb, cutoff)
		if err != nil {
			return st, err
		}
		st.Messages += n
		if purged {
			st.Mailboxes++
		}
	}
	return st, nil
}

// purge deletes everything in a mailbox's partition, then (conditionally,
// in case it was revived as a rotation successor or re-registered
// meanwhile) the mailbox.
func (s *Store) purge(ctx context.Context, mailbox string, cutoff int64) (msgs int64, purged bool, err error) {
	msgs, err = s.purgeItems(ctx, mailbox, func(sk string) bool { return sk != skAccount })
	if err != nil {
		return 0, false, err
	}
	_, err = s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(mailbox), skAccount),
		ConditionExpression:       aws.String("gpk = :due AND gsk <= :cut"),
		ExpressionAttributeValues: item{":due": avS(dueValue), ":cut": avN(cutoff)},
	})
	if isCCF(err) {
		return msgs, false, nil
	}
	s.forget(mailbox)
	return msgs, err == nil, err
}

// purgeContents deletes what a mailbox holds — messages, leases, denylist,
// token counters, consumed open tokens, blobs (with their bodies) and the
// claims it created — and keeps the A and S items (a deletion's
// tombstone).
func (s *Store) purgeContents(ctx context.Context, mailbox string) (msgs int64, err error) {
	return s.purgeItems(ctx, mailbox, func(sk string) bool { return sk != skAccount && sk != skStats })
}

// purgeItems deletes the partition's items for which del(sk) holds, with
// their blob bodies and claim items. It is idempotent.
func (s *Store) purgeItems(ctx context.Context, mailbox string, del func(sk string) bool) (msgs int64, err error) {
	var keys []item
	err = s.queryAll(ctx, &dynamodb.QueryInput{
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: item{":pk": avS(mbPK(mailbox))},
		ProjectionExpression:      aws.String("pk, sk"),
	}, func(it item) error {
		sk := getS(it, "sk")
		switch {
		case !del(sk):
			return nil
		case strings.HasPrefix(sk, "M#"):
			msgs++
		case strings.HasPrefix(sk, "C#"):
			keys = append(keys, key(claimPK(sk[2:]), "CL"))
		case strings.HasPrefix(sk, "B#") && s.cfg.S3 != nil:
			if _, err := s.cfg.S3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.cfg.Bucket, Key: aws.String(blobKey(mailbox, sk[2:]))}); err != nil {
				return err
			}
		}
		keys = append(keys, key(mbPK(mailbox), sk))
		return nil
	})
	if err != nil {
		return 0, err
	}
	return msgs, s.batchDelete(ctx, keys)
}

func (s *Store) batchDelete(ctx context.Context, keys []item) error {
	for len(keys) > 0 {
		n := min(25, len(keys))
		reqs := make([]types.WriteRequest, 0, n)
		for _, k := range keys[:n] {
			reqs = append(reqs, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: k}})
		}
		keys = keys[n:]
		pending := map[string][]types.WriteRequest{s.cfg.Table: reqs}
		for attempt := 0; len(pending) > 0; attempt++ {
			out, err := s.cfg.DB.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: pending})
			if err != nil {
				return err
			}
			pending = out.UnprocessedItems
			if len(pending) > 0 {
				if attempt > 10 {
					return errors.New("dynamo: purge: unprocessed deletes")
				}
				if err := backoff(ctx, attempt); err != nil {
					return err
				}
			}
		}
	}
	return nil
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
