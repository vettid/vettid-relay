package dynamo_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	if _, _, err := s.Register(ctx, "a", make([]byte, 32)); err != nil {
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
	if _, _, err := s.Register(ctx, "a", make([]byte, 32)); err != nil {
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
	if _, _, err := s.Register(ctx, "a", make([]byte, 32)); err != nil {
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

// A deletion repeated between a registration's read and its revive (the
// owner retrying a DELETE whose 204 was lost) raises the tombstone: the
// registration reads again and reports the raised time, which is the one
// deposits are checked against.
func TestRegisterRacingDeleteReportsRaisedNB(t *testing.T) {
	db := ddblocal.Client(t)
	table := ddblocal.Table(t, db)
	c := storetest.NewClock()
	s, err := dynamo.New(dynamo.Config{Table: table, DB: db, S3: fakes3.New(t).Client(), Bucket: "b", Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	if _, _, err := s.Register(ctx, "a", pub); err != nil {
		t.Fatal(err)
	}
	nb1 := c.Now().Add(90 * time.Second)
	if _, err := s.DeleteMailbox(ctx, "a", pub, nb1, c.Now().Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	nb2 := nb1.Add(30 * time.Second)
	once := false
	dynamo.SetBeforeRevive(s, func() {
		if once {
			return
		}
		once = true
		if _, err := s.DeleteMailbox(ctx, "a", pub, nb2, c.Now().Add(48*time.Hour)); err != nil {
			t.Error(err)
		}
	})
	created, got, err := s.Register(ctx, "a", pub)
	if err != nil || !created || !once {
		t.Fatalf("register: %v %v (hook ran: %v)", created, err, once)
	}
	mb, err := s.Mailbox(ctx, "a")
	if err != nil || !got.Equal(nb2.Truncate(time.Millisecond)) || !mb.TokensNotBefore.Equal(got) {
		t.Fatalf("reported %v, stored %v (want %v), %v", got, mb.TokensNotBefore, nb2, err)
	}
	old := store.Limits{TokenJTI: "t", TokenIssuedAt: nb1.Add(time.Second), TokenExpires: nb2.Add(time.Hour)}
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, old); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("a token between the two deletions: %v", err)
	}
}

// Without a stored lifetime mark (the relay always raises it at start),
// the store's own removals of a rotated mailbox fail closed rather than
// fall back to the start-time policy.
func TestMissingMarkFailsClosed(t *testing.T) {
	db := ddblocal.Client(t)
	table := ddblocal.Table(t, db)
	c := storetest.NewClock()
	s, err := dynamo.New(dynamo.Config{Table: table, DB: db, S3: fakes3.New(t).Client(), Bucket: "b", Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LifetimeMark(ctx); err == nil {
		t.Fatal("a missing mark read as a value")
	}
	if _, _, err := s.Register(ctx, "a", make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "a", "b", append(make([]byte, 31), 2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Hour + time.Minute)
	if _, _, err := s.Register(ctx, "a", make([]byte, 32)); err == nil {
		t.Fatal("a rotated mailbox was removed without a mark")
	}
}

// newMarked is a store on a fresh table with the mark raised, as at start.
func newMarked(t *testing.T) (*dynamo.Store, *storetest.Clock) {
	t.Helper()
	db := ddblocal.Client(t)
	c := storetest.NewClock()
	s, err := dynamo.New(dynamo.Config{Table: ddblocal.Table(t, db), DB: db, S3: fakes3.New(t).Client(), Bucket: "b", Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RaiseLifetimeMark(ctx, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	return s, c
}

func k(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// held reports whether id's tombstone holds once until has passed and the
// sweep ran: the registration reports a not-before, and a token issued
// before it is refused.
func held(t *testing.T, s *dynamo.Store, c *storetest.Clock, id string, b byte, until time.Time) bool {
	t.Helper()
	c.Add(until.Sub(c.Now()) + 11*time.Minute)
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, id, k(b)); err != nil {
		t.Fatal(err)
	}
	mb, err := s.Mailbox(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if mb.TokensNotBefore.IsZero() {
		return false
	}
	_, err = s.Deposit(ctx, id, "s", []byte("x"), time.Hour, store.Limits{TokenJTI: "old", TokenIssuedAt: mb.TokensNotBefore.Add(-time.Hour), TokenExpires: c.Now().Add(time.Hour)})
	return errors.Is(err, store.ErrRevoked)
}

// A repeated deletion with a longer keep lands between Register's read
// and its revive: the revive's guard refuses the stale keep, the
// registration reads again, and the longer tombstone outlives a later
// short deletion.
func TestReviveGuardRace(t *testing.T) {
	s, c := newMarked(t)
	day := 24 * time.Hour
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(10*day)); err != nil {
		t.Fatal(err)
	}
	long := c.Now().Add(1000 * day)
	once := true
	dynamo.SetBeforeRevive(s, func() {
		if once {
			once = false
			if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), long); err != nil {
				t.Error(err)
			}
		}
	})
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	dynamo.SetBeforeRevive(s, nil)
	short := c.Now().Add(time.Hour)
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now(), short); err != nil {
		t.Fatal(err)
	}
	if !held(t, s, c, "a", 1, c.Now().Add(500*day)) {
		t.Fatal("the longer tombstone raised during the revive was lost")
	}
}

// A repeated deletion of the rotation's successor id with a longer keep
// lands between Rotate's reads and its write: the successor's guard
// refuses the stale keep, Rotate reads again, and the longer tombstone
// outlives a later short deletion.
func TestRotateSuccessorGuardRace(t *testing.T) {
	s, c := newMarked(t)
	day := 24 * time.Hour
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(10*day)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	long := c.Now().Add(1000 * day)
	once := true
	dynamo.SetBeforeRotate(s, func() {
		if once {
			once = false
			if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), long); err != nil {
				t.Error(err)
			}
		}
	})
	if err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	dynamo.SetBeforeRotate(s, nil)
	short := c.Now().Add(time.Hour)
	if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now(), short); err != nil {
		t.Fatal(err)
	}
	if !held(t, s, c, "b", 2, c.Now().Add(500*day)) {
		t.Fatal("the longer tombstone raised during the rotation was lost")
	}
}

// Rotating onto another key's id is a collision, not retried away.
func TestRotateOntoAnotherKeyCollides(t *testing.T) {
	s, _ := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(3)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "a", "b", k(2), time.Now().Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("rotate onto another key's id: %v", err)
	}
}

// retire folds an earlier, longer tomb_keep into the gsk it sets.
func TestRetireFoldsTombKeep(t *testing.T) {
	s, c := newMarked(t)
	day := 24 * time.Hour
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	long := c.Now().Add(1000 * day)
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), long); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Hour + 11*time.Minute)
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if g := dynamo.AccountN(s, "a", "gsk"); g < long.UnixMilli() {
		t.Fatalf("retired with gsk %d, below the earlier tombstone %d", g, long.UnixMilli())
	}
}

// A deleted item whose gsk passed while its tomb_keep is still ahead (a
// state a deletion racing a re-registration can leave) isn't purged, and
// its tokens-not-before still refuses old tokens.
func TestSweepWaitsForTombKeep(t *testing.T) {
	s, c := newMarked(t)
	day := 24 * time.Hour
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	dynamo.SetAccountN(s, "a", map[string]int64{"tomb_keep": c.Now().Add(1000 * day).UnixMilli()})
	if !held(t, s, c, "a", 1, c.Now().Add(500*day)) {
		t.Fatal("purged while tomb_keep was still ahead")
	}
}

// A repeated deletion with a longer keep (and a raised nb) commits between
// the sweep's read of an expired tombstone and its purge: neither the
// account nor the counters item goes, and an old token stays refused after
// a re-registration.
func TestSweepPurgeRace(t *testing.T) {
	s, c := newMarked(t)
	day := 24 * time.Hour
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Hour + 11*time.Minute) // the tombstone is due
	once := true
	dynamo.SetBeforePurge(s, func() {
		if once {
			once = false
			if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(1000*day)); err != nil {
				t.Error(err)
			}
		}
	})
	st, err := s.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dynamo.SetBeforePurge(s, nil)
	if st.Mailboxes != 0 {
		t.Fatalf("a refused purge counted as purged: %+v", st)
	}
	if !dynamo.StatsExists(s, "a") {
		t.Fatal("the refused purge still removed the counters item (and its nb)")
	}
	if !dynamo.AccountHas(s, "a", "deleted") || dynamo.AccountN(s, "a", "gsk") < c.Now().Add(999*day).UnixMilli() {
		t.Fatalf("after the refused purge: deleted %v, gsk %d", dynamo.AccountHas(s, "a", "deleted"), dynamo.AccountN(s, "a", "gsk"))
	}
	if !held(t, s, c, "a", 1, c.Now().Add(500*day)) {
		t.Fatal("the sweep purged a tombstone a deletion raised during it")
	}
}

// A tomb_keep raised between DeleteMailbox's read and its write: the
// deletion refuses (the owner retries) rather than store a gsk below it.
func TestMarkDeletedGuardRace(t *testing.T) {
	s, c := newMarked(t)
	day := 24 * time.Hour
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	high := c.Now().Add(1000 * day).UnixMilli()
	dynamo.SetBeforeMark(s, func() { dynamo.SetAccountN(s, "a", map[string]int64{"tomb_keep": high}) })
	_, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetBeforeMark(s, nil)
	switch {
	case err != nil && !strings.Contains(err.Error(), "ConditionalCheckFailed"):
		t.Fatalf("the deletion failed, but not as the guard's refusal: %v", err)
	case err == nil && dynamo.AccountN(s, "a", "gsk") < high:
		t.Fatalf("deleted with gsk %d below the tomb_keep %d raised meanwhile", dynamo.AccountN(s, "a", "gsk"), high)
	}
}

// A successor whose tombstone keeps being raised: Rotate gives up after
// its attempts with its transaction error (not a nil one).
func TestRotateRetriesExhausted(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	g := c.Now().Add(2 * time.Hour).UnixMilli()
	dynamo.SetBeforeRotate(s, func() { g += 1000; dynamo.SetAccountN(s, "b", map[string]int64{"gsk": g}) })
	err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour))
	dynamo.SetBeforeRotate(s, nil)
	if !errors.Is(err, store.ErrBusy) || !strings.Contains(err.Error(), "dynamo: rotate:") || strings.Contains(err.Error(), "%!") {
		t.Fatalf("rotate: %v", err)
	}
}

// A counters item without nb (a state an older race could leave) gets the
// kept nb back at a re-registration: old tokens are refused.
func TestReviveWritesNBToCounters(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(1000*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	dynamo.RemoveStatsNB(s, "a")
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	mb, err := s.Mailbox(ctx, "a")
	if err != nil || mb.TokensNotBefore.IsZero() {
		t.Fatalf("%+v %v", mb, err)
	}
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, store.Limits{TokenJTI: "old", TokenIssuedAt: mb.TokensNotBefore.Add(-time.Hour), TokenExpires: c.Now().Add(time.Hour)}); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("an old token after the revive: %v", err)
	}
}

// pastGrace leaves b (key 2) rotated away and past its grace, not swept.
func pastGrace(t *testing.T, s *dynamo.Store, c *storetest.Clock) {
	t.Helper()
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "b", "x", k(3), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Hour + time.Minute)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
}

// Rotating onto a same-key id past its grace keeps that removal's
// tombstone: a later short deletion doesn't end it early.
func TestRotatePastGraceKeepsRemoval(t *testing.T) {
	s, c := newMarked(t)
	pastGrace(t, s, c)
	_, removedKeep := store.DefaultTombstonePolicy.WithMark(time.Millisecond).Times(c.Now())
	if err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !held(t, s, c, "b", 2, removedKeep.Add(-time.Hour)) {
		t.Fatal("the removal's tombstone ended with the later short deletion")
	}
}

// A deletion raising the successor's nb between Rotate's read and its
// write (with a shorter keep) isn't undone: Rotate reads again.
func TestRotateKeepsRaisedNB(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(1000*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	c.Add(10 * time.Minute)
	raised := c.Now().Add(90 * time.Second)
	once := true
	dynamo.SetBeforeRotate(s, func() {
		if once {
			once = false
			if _, err := s.DeleteMailbox(ctx, "b", k(2), raised, c.Now().Add(time.Hour)); err != nil {
				t.Error(err)
			}
		}
	})
	err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour))
	dynamo.SetBeforeRotate(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	mb, err := s.Mailbox(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	if mb.TokensNotBefore.Before(raised) {
		t.Fatalf("tokens-not-before %v, want at least the raised %v", mb.TokensNotBefore, raised)
	}
	if _, err := s.Deposit(ctx, "b", "s", []byte("x"), time.Hour, store.Limits{TokenJTI: "mid", TokenIssuedAt: raised.Add(-time.Second), TokenExpires: c.Now().Add(time.Hour)}); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("a token issued before the raised not-before: %v", err)
	}
}

// dueTombstone registers id (key b), deletes it with a 1-hour keep and
// moves the clock until its tombstone is due for the sweep.
func dueTombstone(t *testing.T, s *dynamo.Store, c *storetest.Clock, id string, b byte) {
	t.Helper()
	if _, _, err := s.Register(ctx, id, k(b)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, id, k(b), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Hour + 11*time.Minute)
}

// fill gives a live mailbox contents a purge must not touch: a message
// and a denylist entry.
func fill(t *testing.T, s *dynamo.Store, c *storetest.Clock, id string) {
	t.Helper()
	if _, err := s.Deposit(ctx, id, "s", []byte("x"), time.Hour, store.Limits{TokenJTI: "m1", TokenIssuedAt: c.Now(), TokenExpires: c.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddDenylist(ctx, id, []store.DenyEntry{{Kind: "jti", Value: "J"}}, c.Now().Add(time.Hour), 10); err != nil {
		t.Fatal(err)
	}
}

// filled reports whether id still has what fill gave it.
func filled(t *testing.T, s *dynamo.Store, id string) bool {
	t.Helper()
	denied, err := s.IsDenied(ctx, id, "J", "")
	if err != nil {
		t.Fatal(err)
	}
	msgs, _, err := s.Collect(ctx, id, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return denied && len(msgs) == 1
}

// The key registers again between the sweep's read of its expired
// tombstone and the purge, and the revived mailbox gets contents: the
// sweep leaves them (its revocation list above all) alone.
func TestSweepSparesRevivedMailbox(t *testing.T) {
	s, c := newMarked(t)
	dueTombstone(t, s, c, "a", 1)
	once := true
	dynamo.SetBeforePurge(s, func() {
		if once {
			once = false
			if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
				t.Fatal(err)
			}
			fill(t, s, c, "a")
		}
	})
	st, err := s.Sweep(ctx)
	dynamo.SetBeforePurge(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mailboxes != 0 || !filled(t, s, "a") {
		t.Fatalf("the sweep purged the revived mailbox: %+v, contents kept %v", st, filled(t, s, "a"))
	}
}

// While the sweep purges a tombstone, neither a registration nor a
// rotation onto it revives it (each gives up and is retried); after the
// purge, both work.
func TestNoReviveDuringPurge(t *testing.T) {
	s, c := newMarked(t)
	dueTombstone(t, s, c, "a", 1)
	if _, _, err := s.Register(ctx, "x", k(3)); err != nil {
		t.Fatal(err)
	}
	once := true
	dynamo.SetDuringPurge(s, func() {
		if once {
			once = false
			if _, _, err := s.Register(ctx, "a", k(1)); !errors.Is(err, store.ErrBusy) {
				t.Errorf("a registration during the sweep's purge: %v, want ErrBusy", err)
			}
			if err := s.Rotate(ctx, "x", "a", k(1), c.Now().Add(time.Hour)); !errors.Is(err, store.ErrBusy) {
				t.Errorf("a rotation during the sweep's purge: %v, want ErrBusy", err)
			}
		}
	})
	st, err := s.Sweep(ctx)
	dynamo.SetDuringPurge(s, nil)
	if err != nil || st.Mailboxes != 1 {
		t.Fatalf("sweep: %+v %v", st, err)
	}
	if once {
		t.Fatal("the purge hook never ran")
	}
	if dynamo.StatsExists(s, "a") || dynamo.AccountHas(s, "a", "pub") {
		t.Fatal("the purge left the account or counters item")
	}
	if err := s.Rotate(ctx, "x", "a", k(1), c.Now().Add(time.Hour)); err != nil {
		t.Fatalf("rotation after the purge: %v", err)
	}
	fill(t, s, c, "a")
	if !filled(t, s, "a") {
		t.Fatal("the mailbox after the purge")
	}
}

// A registration waits for a deletion's purge in the same way.
func TestNoReviveDuringDeletionPurge(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	once := true
	dynamo.SetDuringPurge(s, func() {
		if once {
			once = false
			if _, _, err := s.Register(ctx, "a", k(1)); err == nil {
				t.Error("a registration revived the mailbox its deletion is purging")
			}
		}
	})
	_, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetDuringPurge(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if once {
		t.Fatal("the purge hook never ran")
	}
	if dynamo.AccountHas(s, "a", "purge_by") {
		t.Fatal("the deletion left its fence")
	}
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatalf("registration after the deletion: %v", err)
	}
}

// A fence older than the lease (its purge died) is taken over; a fresh
// one is waited for.
func TestStaleFence(t *testing.T) {
	s, c := newMarked(t)
	for _, id := range []string{"a", "b", "d"} {
		if _, _, err := s.Register(ctx, id, k(1)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeleteMailbox(ctx, id, k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	dynamo.SetFence(s, "a", c.Now().Add(-6*time.Minute))
	dynamo.SetFence(s, "b", c.Now().Add(-time.Minute))
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatalf("a dead purge's fence held a registration: %v", err)
	}
	if dynamo.AccountHas(s, "a", "purge_by") {
		t.Fatal("the revive left the fence")
	}
	if _, _, err := s.Register(ctx, "b", k(1)); err == nil {
		t.Fatal("a registration revived a mailbox under a live fence")
	}
	c.Add(5 * time.Minute)
	if _, _, err := s.Register(ctx, "b", k(1)); err != nil {
		t.Fatalf("the fence after its lease: %v", err)
	}
	// The sweep carries on a dead purge of a due tombstone.
	c.Add(time.Hour + 11*time.Minute)
	dynamo.SetFence(s, "d", c.Now().Add(-6*time.Minute))
	if st, err := s.Sweep(ctx); err != nil || st.Mailboxes != 1 || dynamo.AccountHas(s, "d", "pub") {
		t.Fatalf("the sweep after a dead purge: %+v %v", st, err)
	}
}

// Rotating onto a same-key id past its grace makes it a fresh mailbox,
// as a registration would: counters reset, version raised, no links of
// the mailbox it was, no fence left.
func TestRotateOntoPastGraceResets(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "b", "s", []byte("x"), 3*time.Hour, store.Limits{TokenJTI: "m0", TokenIssuedAt: c.Now(), TokenExpires: c.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "b", "x", k(3), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	v := dynamo.StatsN(s, "b", "v")
	if dynamo.StatsN(s, "b", "msgs") != 1 || !dynamo.AccountHas(s, "b", "successor") {
		t.Fatal("setup: b holds a message and names its successor")
	}
	c.Add(time.Hour + time.Minute)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := dynamo.StatsN(s, "b", "msgs"); n != 0 {
		t.Fatalf("b's message count %d after its removal", n)
	}
	if dynamo.StatsN(s, "b", "v") <= v {
		t.Fatal("b's version not raised")
	}
	if dynamo.AccountHas(s, "b", "successor") || dynamo.AccountHas(s, "b", "purge_by") {
		t.Fatal("b keeps its old successor link or the fence")
	}
	if msgs, _, err := s.Collect(ctx, "b", 10, time.Minute); err != nil || len(msgs) != 0 {
		t.Fatalf("b's old messages: %d %v", len(msgs), err)
	}
}

// While the sweep retires a rotated-away mailbox past its grace, its key
// can't register it again; after the retire, it can, and the tombstone
// holds.
func TestNoReviveDuringRetire(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "b", "x", k(3), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Hour + 11*time.Minute)
	once := true
	dynamo.SetDuringPurge(s, func() {
		if once {
			once = false
			if _, _, err := s.Register(ctx, "b", k(2)); err == nil {
				t.Error("a registration revived the mailbox the sweep is retiring")
			}
		}
	})
	st, err := s.Sweep(ctx)
	dynamo.SetDuringPurge(s, nil)
	if err != nil || st.Mailboxes != 1 || once {
		t.Fatalf("sweep: %+v %v (hook ran: %v)", st, err, !once)
	}
	if !dynamo.AccountHas(s, "b", "deleted") || dynamo.AccountHas(s, "b", "purge_by") {
		t.Fatal("after the retire: not a tombstone, or the fence left")
	}
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatalf("registration after the retire: %v", err)
	}
}

// The successor was live at Rotate's read; before its write, the grace
// ends and a purge takes the fence. Rotate doesn't revive it under the
// purge: it reads again and waits (here, until it gives up).
func TestRotateWaitsForFenceTakenAfterRead(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "b", "y", k(3), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "x", k(1)); err != nil {
		t.Fatal(err)
	}
	once := true
	dynamo.SetBeforeRotate(s, func() {
		if once {
			once = false
			c.Add(time.Hour + 11*time.Minute)
			dynamo.SetFence(s, "b", c.Now())
		}
	})
	err := s.Rotate(ctx, "x", "b", k(2), c.Now().Add(2*time.Hour))
	dynamo.SetBeforeRotate(s, nil)
	if err == nil {
		t.Fatal("the rotation revived its successor under a purge's fence")
	}
	if dynamo.AccountN(s, "b", "purging") != c.Now().UnixMilli() {
		t.Fatal("the purge's fence was taken or removed")
	}
}

// takeover makes another purge take id's fence over while the current
// holder purges (as after the lease, with a holder that stalled).
func takeover(s *dynamo.Store, c *storetest.Clock, id string) {
	once := true
	dynamo.SetDuringPurge(s, func() {
		if once {
			once = false
			dynamo.SetFence(s, id, c.Now())
		}
	})
}

// A holder whose fence was taken over doesn't commit: not a revive, the
// sweep's removal of a tombstone, a retire, or a rotation onto a dead
// successor.
func TestNoCommitAfterTakeover(t *testing.T) {
	t.Run("revive", func(t *testing.T) {
		s, c := newMarked(t)
		if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		takeover(s, c, "a")
		_, _, err := s.Register(ctx, "a", k(1))
		dynamo.SetDuringPurge(s, nil)
		if err == nil || !dynamo.AccountHas(s, "a", "deleted") {
			t.Fatalf("revived after its fence was taken over: %v", err)
		}
	})
	t.Run("sweep", func(t *testing.T) {
		s, c := newMarked(t)
		dueTombstone(t, s, c, "a", 1)
		takeover(s, c, "a")
		st, err := s.Sweep(ctx)
		dynamo.SetDuringPurge(s, nil)
		if err != nil || st.Mailboxes != 0 || !dynamo.AccountHas(s, "a", "pub") || !dynamo.StatsExists(s, "a") {
			t.Fatalf("removed the tombstone after its fence was taken over: %+v %v", st, err)
		}
	})
	t.Run("retire", func(t *testing.T) {
		s, c := newMarked(t)
		if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
			t.Fatal(err)
		}
		if err := s.Rotate(ctx, "b", "x", k(3), c.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		c.Add(time.Hour + 11*time.Minute)
		takeover(s, c, "b")
		st, err := s.Sweep(ctx)
		dynamo.SetDuringPurge(s, nil)
		if err != nil || st.Mailboxes != 0 || dynamo.AccountHas(s, "b", "deleted") {
			t.Fatalf("retired after its fence was taken over: %+v %v", st, err)
		}
	})
	t.Run("rotate", func(t *testing.T) {
		s, c := newMarked(t)
		if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
			t.Fatal(err)
		}
		takeover(s, c, "b")
		err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour))
		dynamo.SetDuringPurge(s, nil)
		if err == nil || !dynamo.AccountHas(s, "b", "deleted") {
			t.Fatalf("rotated onto b after its fence was taken over: %v", err)
		}
	})
}

// A deletion whose mailbox another purge holds waits for it, and answers
// only once the mailbox is empty: while that purge (here, one that
// stopped) holds the fence, the deletion fails and keeps nothing it
// shouldn't; after the lease, a repeat empties it.
func TestDeletionWaitsForFence(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	fill(t, s, c, "a")
	dynamo.SetBeforeMark(s, func() { dynamo.SetFence(s, "a", c.Now()) })
	_, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetBeforeMark(s, nil)
	if !errors.Is(err, store.ErrBusy) {
		t.Fatalf("the deletion under another's fence: %v, want ErrBusy (%d items left)", err, dynamo.ContentN(s, "a"))
	}
	if !dynamo.AccountHas(s, "a", "deleted") {
		t.Fatal("the deletion didn't tombstone the mailbox first")
	}
	c.Add(6 * time.Minute)
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := dynamo.ContentN(s, "a"); n != 0 {
		t.Fatalf("%d items left after the repeat", n)
	}
}

// Two registrations of a deleted key: the second revives and fills the
// mailbox between the first's read and its fence. The first's fence
// requires the mailbox still dead, so it purges nothing of it.
func TestConcurrentRegisters(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	once := true
	dynamo.SetBeforeRevive(s, func() {
		if once {
			once = false
			if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
				t.Fatal(err)
			}
			fill(t, s, c, "a")
		}
	})
	_, _, err := s.Register(ctx, "a", k(1))
	dynamo.SetBeforeRevive(s, nil)
	if err != nil || once {
		t.Fatalf("register: %v (hook ran: %v)", err, !once)
	}
	if !filled(t, s, "a") {
		t.Fatal("the slower registration purged the mailbox the other revived")
	}
}

// A rotation onto a deleted id whose key registers again (and fills it)
// between the rotation's reads and its fence: the rotation purges nothing
// of the live mailbox.
func TestRotateOntoRevivedSuccessor(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	once := true
	dynamo.SetBeforeRotate(s, func() {
		if once {
			once = false
			if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
				t.Fatal(err)
			}
			fill(t, s, c, "b")
		}
	})
	err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour))
	dynamo.SetBeforeRotate(s, nil)
	if err != nil || once {
		t.Fatalf("rotate: %v (hook ran: %v)", err, !once)
	}
	if !filled(t, s, "b") {
		t.Fatal("the rotation purged the successor its key revived")
	}
}

// The key of a rotated-away mailbox past its grace registers it again
// (and fills it) between the sweep's read and the retire's fence: the
// retire purges nothing of it.
func TestSweepSparesRevivedRetire(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "b", "x", k(3), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Hour + 11*time.Minute)
	once := true
	dynamo.SetBeforePurge(s, func() {
		if once {
			once = false
			if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
				t.Fatal(err)
			}
			c.Add(2 * time.Minute) // past the not-before the removal set
			fill(t, s, c, "b")
		}
	})
	st, err := s.Sweep(ctx)
	dynamo.SetBeforePurge(s, nil)
	if err != nil || st.Mailboxes != 0 || once {
		t.Fatalf("sweep: %+v %v (hook ran: %v)", st, err, !once)
	}
	if !filled(t, s, "b") {
		t.Fatal("the retire purged the mailbox its key revived")
	}
}

// The key registers again (and fills the mailbox) between a deletion's
// mark and its fence: the deletion purges nothing of the live mailbox.
func TestDeletionSparesReRegistration(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	once := true
	dynamo.SetAfterMark(s, func() {
		if once {
			once = false
			c.Add(2 * time.Minute)
			if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
				t.Fatal(err)
			}
			fill(t, s, c, "a")
		}
	})
	_, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetAfterMark(s, nil)
	if err != nil || once {
		t.Fatalf("delete: %v (hook ran: %v)", err, !once)
	}
	if !filled(t, s, "a") {
		t.Fatal("the deletion purged the mailbox its key registered again")
	}
}

// A rotation onto a dead successor under another purge's fence waits and
// retries; once that purge lets go, it goes through.
func TestRotateRetriesThroughFence(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	dynamo.SetFence(s, "b", c.Now())
	n := 0
	dynamo.SetBeforeRotate(s, func() {
		if n++; n == 3 {
			dynamo.ClearFence(s, "b")
		}
	})
	err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour))
	dynamo.SetBeforeRotate(s, nil)
	if err != nil || n < 3 {
		t.Fatalf("rotate: %v after %d tries", err, n)
	}
}

// A purge whose fence was taken over (it stalled past the lease) and
// whose mailbox was revived and filled meanwhile deletes none of the new
// contents, however it got there: each batch requires the fence.
func TestPurgeStopsWhenFenceLost(t *testing.T) {
	s, c := newMarked(t)
	var blob string
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	once := true
	dynamo.SetDuringPurge(s, func() {
		if once {
			once = false
			// The deletion's purge stalls past its lease; a registration
			// takes the fence over, revives and fills the mailbox.
			c.Add(6 * time.Minute)
			if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
				t.Fatal(err)
			}
			fill(t, s, c, "a")
			b, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 4, TTL: time.Hour,
				Limits: store.Limits{TokenJTI: "b1", TokenIssuedAt: c.Now(), TokenExpires: c.Now().Add(time.Hour)}}, bytes.NewReader([]byte("blob")))
			if err != nil {
				t.Fatal(err)
			}
			blob = b.ID
		}
	})
	_, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetDuringPurge(s, nil)
	if err != nil || once {
		t.Fatalf("delete: %v (hook ran: %v)", err, !once)
	}
	if !filled(t, s, "a") || dynamo.StatsN(s, "a", "msgs") != 1 {
		t.Fatalf("the stalled purge deleted the revived mailbox's contents or counters (msgs %d)", dynamo.StatsN(s, "a", "msgs"))
	}
	// Nor a blob's body (its item and body both stay).
	_, body, err := s.OpenBlob(ctx, "a", blob)
	if err != nil {
		t.Fatalf("the revived mailbox's blob: %v", err)
	}
	got, err := io.ReadAll(body)
	body.Close()
	if err != nil || string(got) != "blob" {
		t.Fatalf("the revived mailbox's blob body: %q %v", got, err)
	}
}

// The fence is taken over after a deletion's purge and before its
// counters reset; the key registers again and fills the mailbox. The
// reset requires the fence: the revived counters stay.
func TestCountersResetNeedsFence(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	once := true
	dynamo.SetAfterPurge(s, func() {
		if once {
			once = false
			c.Add(6 * time.Minute)
			if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
				t.Fatal(err)
			}
			fill(t, s, c, "a")
		}
	})
	_, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetAfterPurge(s, nil)
	if err != nil || once {
		t.Fatalf("delete: %v (hook ran: %v)", err, !once)
	}
	if n := dynamo.StatsN(s, "a", "msgs"); n != 1 {
		t.Fatalf("the revived mailbox's message count is %d after the deletion's reset", n)
	}
}

// A revive whose commit is refused (the nb raised during its purge) gives
// its fence back, so its retry goes through.
func TestReviveUnfencesAfterRefusedCommit(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	once := true
	dynamo.SetDuringPurge(s, func() {
		if once {
			once = false
			dynamo.SetAccountN(s, "a", map[string]int64{"nb": c.Now().Add(time.Hour).UnixMilli()})
		}
	})
	_, nb, err := s.Register(ctx, "a", k(1))
	dynamo.SetDuringPurge(s, nil)
	if err != nil || once || nb.UnixMilli() != c.Now().Add(time.Hour).UnixMilli() {
		t.Fatalf("register: %v, nb %v (hook ran: %v)", err, nb, !once)
	}
	if dynamo.AccountHas(s, "a", "purge_by") {
		t.Fatal("the revive left a fence")
	}
}

// A purge cut short by its budget gives the fence back; the deletion
// reports the mailbox (it is dead) and fails, and a repeat empties it.
func TestPurgeBudget(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	fill(t, s, c, "a")
	dynamo.SetPurgeBudget(s, time.Nanosecond)
	ids, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetPurgeBudget(s, 0)
	if err == nil || len(ids) != 1 || ids[0] != "a" {
		t.Fatalf("a deletion cut short: %v %v", ids, err)
	}
	if dynamo.AccountHas(s, "a", "purge_by") {
		t.Fatal("the purge cut short left its fence")
	}
	if _, err := s.Mailbox(ctx, "a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the mailbox after a deletion cut short: %v", err)
	}
	if ids, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil || len(ids) != 0 {
		t.Fatalf("the repeat: %v %v", ids, err)
	}
	if n := dynamo.ContentN(s, "a"); n != 0 {
		t.Fatalf("%d items left after the repeat", n)
	}
}

// A deletion whose purge fails after its mark still reaches the
// predecessors (reported, and dead); a repeat reaches them again.
func TestDeletionFailureKeepsPredecessors(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "p", k(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "p", "b", k(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	dynamo.SetPurgeBudget(s, time.Nanosecond)
	ids, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetPurgeBudget(s, 0)
	if err == nil || len(ids) != 2 {
		t.Fatalf("a deletion cut short: %v %v", ids, err)
	}
	if _, err := s.Mailbox(ctx, "p"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the predecessor after a deletion cut short: %v", err)
	}
	if got := dynamo.AccountSS(s, "b", "preds"); len(got) != 1 || got[0] != "p" {
		t.Fatalf("the tombstone's preds: %v", got)
	}
	if _, err := s.DeleteMailbox(ctx, "b", k(2), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// A rotation onto a successor past its grace replaces its preds (the
// mailboxes rotated into what it was) with the rotation's own.
func TestRotateReplacesPreds(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "p", k(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "p", "b", k(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "b", "x", k(3), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Hour + time.Minute)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := dynamo.AccountSS(s, "b", "preds"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("b's preds: %v", got)
	}
}

// A purge larger than one transaction empties the whole mailbox.
func TestLargePurge(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	for i := range 150 {
		if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, store.Limits{TokenJTI: fmt.Sprint("m", i), TokenIssuedAt: c.Now(), TokenExpires: c.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := dynamo.ContentN(s, "a"); n != 0 {
		t.Fatalf("%d items left", n)
	}
}

// flakyDB wraps the DynamoDB client to inject what DynamoDB Local doesn't
// produce: a single-item write refused for a transaction in flight, and a
// fence write that applied but whose answer was lost.
type flakyDB struct {
	dynamo.DB
	mu             sync.Mutex
	putConflicts   int  // PutItem: TransactionConflictException this many times
	fenceConflicts int  // the fence's UpdateItem: the same
	lostFence      bool // the next fence write applies, then errors
}

func (f *flakyDB) take(n *int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if *n > 0 {
		*n--
		return true
	}
	return false
}

func conflict() error {
	return &types.TransactionConflictException{Message: aws.String("transaction in progress")}
}

func (f *flakyDB) PutItem(ctx context.Context, in *dynamodb.PutItemInput, o ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	if f.take(&f.putConflicts) {
		return nil, conflict()
	}
	return f.DB.PutItem(ctx, in, o...)
}

func (f *flakyDB) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, o ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	isFence := in.UpdateExpression != nil && strings.HasPrefix(*in.UpdateExpression, "SET purging")
	if isFence && f.take(&f.fenceConflicts) {
		return nil, conflict()
	}
	out, err := f.DB.UpdateItem(ctx, in, o...)
	f.mu.Lock()
	lost := isFence && err == nil && f.lostFence
	if lost {
		f.lostFence = false
	}
	f.mu.Unlock()
	if lost {
		return nil, errors.New("connection reset (the write applied)")
	}
	return out, err
}

// newFlaky is newMarked over a flakyDB.
func newFlaky(t *testing.T) (*dynamo.Store, *storetest.Clock, *flakyDB) {
	t.Helper()
	db := ddblocal.Client(t)
	f := &flakyDB{DB: db}
	c := storetest.NewClock()
	s, err := dynamo.New(dynamo.Config{Table: ddblocal.Table(t, db), DB: f, S3: fakes3.New(t).Client(), Bucket: "b", Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RaiseLifetimeMark(ctx, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	return s, c, f
}

// A single-item write that meets a purge's transaction on the account
// item (TransactionConflictException) is retried, not an error: the
// registration's put, and the fence.
func TestTxConflictIsRetried(t *testing.T) {
	s, c, f := newFlaky(t)
	f.putConflicts = 2
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatalf("a registration meeting a transaction: %v", err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	f.fenceConflicts = 2
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatalf("a revive whose fence met a transaction: %v", err)
	}
}

// A fence write that applied but whose answer was lost is given back: the
// key isn't kept waiting for the lease.
func TestLostFenceWriteUnfenced(t *testing.T) {
	s, c, f := newFlaky(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	f.lostFence = true
	if _, _, err := s.Register(ctx, "a", k(1)); err == nil {
		t.Fatal("the lost answer wasn't reported")
	}
	if dynamo.AccountHas(s, "a", "purge_by") {
		t.Fatal("the fence was left behind")
	}
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatalf("the next registration: %v", err)
	}
}

// A deletion whose purge loses its fence (during the purge, or before
// its counters reset) to another purge that keeps it doesn't answer done:
// it waits, then answers ErrBusy.
func TestDeletionLostFenceNotDone(t *testing.T) {
	for _, during := range []bool{true, false} {
		s, c := newMarked(t)
		if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
			t.Fatal(err)
		}
		take := func() { dynamo.SetFence(s, "a", c.Now()) }
		if during {
			dynamo.SetDuringPurge(s, take)
		} else {
			dynamo.SetAfterPurge(s, take)
		}
		ids, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
		dynamo.SetDuringPurge(s, nil)
		dynamo.SetAfterPurge(s, nil)
		if !errors.Is(err, store.ErrBusy) || len(ids) != 1 {
			t.Fatalf("during %v: a deletion whose fence was taken: %v %v, want [a] and ErrBusy", during, ids, err)
		}
	}
}

// The counters reset doesn't make a counters item the sweep removed.
func TestCountersResetKeepsRemovedItem(t *testing.T) {
	s, c := newMarked(t)
	if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
		t.Fatal(err)
	}
	dynamo.SetAfterPurge(s, func() { dynamo.DeleteStats(s, "a") })
	_, err := s.DeleteMailbox(ctx, "a", k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour))
	dynamo.SetAfterPurge(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dynamo.StatsExists(s, "a") {
		t.Fatal("the counters reset made the removed counters item again")
	}
}

// A revive or a rotation whose purge lost its fence mid-way (b, rotated
// away and past its grace, still holds a message to delete) reads again,
// waits for the other purge, and goes through once it lets go.
func TestReReadAfterFenceLost(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		s, c := newMarked(t)
		if _, _, err := s.Register(ctx, "b", k(2)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Deposit(ctx, "b", "s", []byte("x"), 3*time.Hour, store.Limits{TokenJTI: "m0", TokenIssuedAt: c.Now(), TokenExpires: c.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := s.Rotate(ctx, "b", "x", k(3), c.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		c.Add(time.Hour + time.Minute) // b past its grace, not swept
		if _, _, err := s.Register(ctx, "a", k(1)); err != nil {
			t.Fatal(err)
		}
		once := true
		dynamo.SetDuringPurge(s, func() {
			if once {
				once = false
				dynamo.SetFence(s, "b", c.Now())
			}
		})
		n := 0
		release := func() {
			if n++; n == 3 {
				dynamo.ClearFence(s, "b")
			}
		}
		var err error
		if rotate {
			dynamo.SetBeforeRotate(s, release)
			err = s.Rotate(ctx, "a", "b", k(2), c.Now().Add(time.Hour))
		} else {
			dynamo.SetBeforeRevive(s, release)
			_, _, err = s.Register(ctx, "b", k(2))
		}
		dynamo.SetDuringPurge(s, nil)
		dynamo.SetBeforeRotate(s, nil)
		dynamo.SetBeforeRevive(s, nil)
		if err != nil || once || n < 3 {
			t.Fatalf("rotate %v: %v after %d tries (fence taken: %v)", rotate, err, n, !once)
		}
	}
}

// One due mailbox's failed purge doesn't stop the sweep: the other is
// purged, and the error counts the failures without naming a mailbox.
func TestSweepGoesOnPastAFailure(t *testing.T) {
	s, c := newMarked(t)
	for _, id := range []string{"mbx-one", "mbx-two"} {
		if _, _, err := s.Register(ctx, id, k(1)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeleteMailbox(ctx, id, k(1), c.Now().Add(90*time.Second), c.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	c.Add(time.Hour + 11*time.Minute)
	n := 0
	dynamo.SetBeforePurge(s, func() {
		n++
		if n == 1 {
			dynamo.SetPurgeBudget(s, time.Nanosecond)
		} else {
			dynamo.SetPurgeBudget(s, 0)
		}
	})
	st, err := s.Sweep(ctx)
	dynamo.SetBeforePurge(s, nil)
	dynamo.SetPurgeBudget(s, 0)
	if err == nil || st.Mailboxes != 1 || n != 2 {
		t.Fatalf("sweep: %+v %v after %d purges", st, err, n)
	}
	if msg := err.Error(); !strings.Contains(msg, "1 of 2") || strings.Contains(msg, "mbx-") {
		t.Fatalf("the sweep's error: %q", msg)
	}
}
