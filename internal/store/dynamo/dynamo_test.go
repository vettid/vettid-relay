package dynamo_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/store/dynamo"
	"github.com/vettid/vettid-relay/internal/store/storetest"
	"github.com/vettid/vettid-relay/internal/testutil/ddblocal"
	"github.com/vettid/vettid-relay/internal/testutil/fakes3"
)

var ctx = context.Background()

func pk(mb string) types.AttributeValue { return &types.AttributeValueMemberS{Value: "MB#" + mb} }

// Items removed behind the store's back (DynamoDB TTL) leave the counters
// high; a failing quota check recomputes them (once per interval).
func TestCountersRecoverFromTTLDeletes(t *testing.T) {
	db := ddblocal.Client(t)
	table := ddblocal.Table(t, db)
	c := storetest.NewClock()
	s, err := dynamo.New(dynamo.Config{Table: table, DB: db, S3: fakes3.New(t).Client(), Bucket: "b", Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, "a", make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	lim := store.Limits{MailboxMaxMsgs: 2}
	m1, _ := s.Deposit(ctx, "a", "s", []byte("1"), time.Hour, lim)
	if _, err := s.Deposit(ctx, "a", "s", []byte("2"), time.Hour, lim); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "a", "s", []byte("3"), time.Hour, lim); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("full: %v", err)
	}
	// "TTL" deletes m1 without the store knowing.
	if _, err := db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &table, Key: map[string]types.AttributeValue{
		"pk": pk("a"), "sk": &types.AttributeValueMemberS{Value: "M#" + m1.ID}}}); err != nil {
		t.Fatal(err)
	}
	// The reconcile that just ran (and found 2) gates the next one.
	if _, err := s.Deposit(ctx, "a", "s", []byte("3"), time.Hour, lim); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("within the reconcile interval: %v", err)
	}
	c.Add(time.Minute)
	if _, err := s.Deposit(ctx, "a", "s", []byte("3"), time.Hour, lim); err != nil {
		t.Fatalf("after recompute: %v", err)
	}
}

// Collect deletes expired messages it walks past and releases their quota.
func TestCollectDropsExpired(t *testing.T) {
	db := ddblocal.Client(t)
	table := ddblocal.Table(t, db)
	c := storetest.NewClock()
	s, _ := dynamo.New(dynamo.Config{Table: table, DB: db, Now: c.Now})
	s.Register(ctx, "a", make([]byte, 32))
	for i := 0; i < 3; i++ {
		if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Minute, store.Limits{}); err != nil {
			t.Fatal(err)
		}
	}
	c.Add(2 * time.Minute)
	if got, _, err := s.Collect(ctx, "a", 10, time.Minute); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	out, err := db.Query(ctx, &dynamodb.QueryInput{
		TableName: &table, KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :m)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": pk("a"), ":m": &types.AttributeValueMemberS{Value: "M#"}},
	})
	if err != nil || len(out.Items) != 0 {
		t.Fatalf("expired messages left: %d %v", len(out.Items), err)
	}
	// Counters were released: a 1-message cap admits a new deposit at once.
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Minute, store.Limits{MailboxMaxMsgs: 1}); err != nil {
		t.Fatal(err)
	}
}
