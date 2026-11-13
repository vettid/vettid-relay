package dynamo_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
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

// A sender's share item has no TTL: it is deleted when it lists no blob,
// whether its blobs were deleted or expired and recounted.
func TestSenderItemsDoNotAccumulate(t *testing.T) {
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
	senderItems := func() int {
		out, err := db.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(table),
			KeyConditionExpression:    aws.String("pk = :pk AND begins_with(sk, :p)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":pk": pk("a"), ":p": &types.AttributeValueMemberS{Value: "BS#"}},
			ConsistentRead:            aws.Bool(true),
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range out.Items {
			if _, ok := it["ttl_s"]; ok {
				t.Fatal("a sender item has a TTL")
			}
		}
		return len(out.Items)
	}
	put := func(sender string, ttl time.Duration) store.BlobInfo {
		b, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Sender: sender, Size: 10, TTL: ttl, Limits: store.Limits{MailboxMaxBytes: 1 << 20},
			SenderMaxBytes: 1 << 20, SenderMaxBlobs: 16}, bytesReader(10))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b1, b2 := put("s1", time.Hour), put("s1", time.Hour)
	put("s2", time.Minute)
	if n := senderItems(); n != 2 {
		t.Fatalf("%d sender items", n)
	}
	s.DeleteBlob(ctx, "a", b1.ID)
	if n := senderItems(); n != 2 {
		t.Fatalf("after one delete: %d", n)
	}
	s.DeleteBlob(ctx, "a", b2.ID)
	if n := senderItems(); n != 1 {
		t.Fatalf("s1's item outlived its blobs: %d", n)
	}
	// s2's blob expires; a recount of the mailbox removes it, and its
	// sender's item with it.
	c.Add(2 * time.Minute)
	if _, _, _, err := s.ListBlobs(ctx, "a", "", 10); err != nil { // a first page recounts
		t.Fatal(err)
	}
	if n := senderItems(); n != 0 {
		t.Fatalf("s2's item outlived its expired blob: %d", n)
	}
}

func bytesReader(n int) *bytes.Reader { return bytes.NewReader(make([]byte, n)) }

// racingDB is another collector winning lease writes: for the first lose
// lease writes, it leases the message itself and reports the conditional
// failure the store sees when another collector got there first.
type racingDB struct {
	dynamo.DB
	mu   sync.Mutex
	lose int
	fail error // when set, every lease write fails with it (not a lost race)
}

func (r *racingDB) PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	sk, _ := in.Item["sk"].(*types.AttributeValueMemberS)
	r.mu.Lock()
	if fail := r.fail; fail != nil && sk != nil && strings.HasPrefix(sk.Value, "L#") {
		r.mu.Unlock()
		return nil, fail
	}
	steal := sk != nil && strings.HasPrefix(sk.Value, "L#") && r.lose > 0
	if steal {
		r.lose--
	}
	r.mu.Unlock()
	if !steal {
		return r.DB.PutItem(ctx, in, opts...)
	}
	theirs := *in
	theirs.ConditionExpression, theirs.ExpressionAttributeValues = nil, nil
	if _, err := r.DB.PutItem(ctx, &theirs, opts...); err != nil {
		return nil, err
	}
	return nil, &types.ConditionalCheckFailedException{Message: aws.String("leased by another collector")}
}

func racingStore(t *testing.T, lose int) (*dynamo.Store, []string) {
	s, ids, _ := racingStoreDB(t, lose)
	return s, ids
}

func racingStoreDB(t *testing.T, lose int) (*dynamo.Store, []string, *racingDB) {
	t.Helper()
	db := ddblocal.Client(t)
	table := ddblocal.Table(t, db)
	r := &racingDB{DB: db}
	s, err := dynamo.New(dynamo.Config{Table: table, DB: r, S3: fakes3.New(t).Client(), Bucket: "b", Now: storetest.NewClock().Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, "a", make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < 20; i++ {
		m, err := s.Deposit(ctx, "a", "s", []byte{byte(i)}, time.Hour, store.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	r.mu.Lock()
	r.lose = lose
	r.mu.Unlock()
	return s, ids, r
}

// A collect that loses every candidate to another collector, its walk cut
// at max, walks again and leases the messages past them, instead of
// answering empty.
func TestCollectRewalksAfterLosingAll(t *testing.T) {
	s, ids := racingStore(t, 3)
	got, _, err := s.Collect(ctx, "a", 3, time.Minute)
	if err != nil || len(got) != 3 {
		t.Fatalf("%d messages (%v)", len(got), err)
	}
	for i, m := range got {
		if m.ID != ids[3+i] {
			t.Fatalf("message %d is %s, want %s", i, m.ID, ids[3+i])
		}
	}
}

// One that keeps losing past its bound reports ErrContended, never an
// empty mailbox.
func TestCollectContended(t *testing.T) {
	s, _ := racingStore(t, 1000)
	got, next, err := s.Collect(ctx, "a", 3, time.Minute)
	if !errors.Is(err, store.ErrContended) || len(got) != 0 || !next.IsZero() {
		t.Fatalf("%d messages, next %v, err %v", len(got), next, err)
	}
}

// A lease write that fails for another reason than a lost race, with no
// lease won, is an error: never an empty answer, never ErrContended.
func TestCollectLeaseWriteError(t *testing.T) {
	s, _, r := racingStoreDB(t, 0)
	r.mu.Lock()
	r.fail = errors.New("throttled")
	r.mu.Unlock()
	got, _, err := s.Collect(ctx, "a", 3, time.Minute)
	if err == nil || errors.Is(err, store.ErrContended) || len(got) != 0 {
		t.Fatalf("%d messages, err %v", len(got), err)
	}
}
