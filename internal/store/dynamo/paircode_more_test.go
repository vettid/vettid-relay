package dynamo_test

import (
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

// hookDB runs `before` once, just before the first TransactWriteItems that
// `match` picks, so a test can put another process's write in between a
// read and its transaction.
type hookDB struct {
	dynamo.DB
	mu     sync.Mutex
	match  func(*dynamodb.TransactWriteItemsInput) bool
	before func()
}

func (h *hookDB) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput, o ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	h.mu.Lock()
	var f func()
	if h.before != nil && h.match != nil && h.match(in) {
		f, h.before = h.before, nil
	}
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return h.DB.TransactWriteItems(ctx, in, o...)
}

type codeEnv struct {
	s     *dynamo.Store
	c     *storetest.Clock
	db    dynamo.DB
	table string
	hook  *hookDB
	flaky *flakyDB
}

func newCodeEnv(t *testing.T) codeEnv {
	t.Helper()
	raw := ddblocal.Client(t)
	table := ddblocal.Table(t, raw)
	f := &flakyDB{DB: raw}
	h := &hookDB{DB: f}
	c := storetest.NewClock()
	s, err := dynamo.New(dynamo.Config{Table: table, DB: h, S3: fakes3.New(t).Client(), Bucket: "b", Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	for _, mb := range []string{"a", "b"} {
		if _, _, err := s.Register(ctx, mb, []byte(strings.Repeat(mb, 32))); err != nil {
			t.Fatal(err)
		}
	}
	return codeEnv{s: s, c: c, db: raw, table: table, hook: h, flaky: f}
}

// putsMarker picks a code claim put (its transaction puts a mailbox's P#).
func putsMarker(in *dynamodb.TransactWriteItemsInput) bool {
	for _, it := range in.TransactItems {
		if it.Put != nil {
			if sk, ok := it.Put.Item["sk"].(*types.AttributeValueMemberS); ok && sk.Value == "P#" {
				return true
			}
		}
	}
	return false
}

// deletesCode picks a redeem's one-item delete of a code claim.
func deletesCode(in *dynamodb.TransactWriteItemsInput) bool {
	if len(in.TransactItems) != 1 || in.TransactItems[0].Delete == nil {
		return false
	}
	pk, ok := in.TransactItems[0].Delete.Key["pk"].(*types.AttributeValueMemberS)
	return ok && strings.HasPrefix(pk.Value, "PCB#")
}

func blobBytes(t *testing.T, e codeEnv, mb string) int64 {
	t.Helper()
	out, err := e.db.GetItem(ctx, &dynamodb.GetItemInput{TableName: &e.table, ConsistentRead: aws.Bool(true),
		Key: map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: "MB#" + mb}, "sk": &types.AttributeValueMemberS{Value: "S"}}})
	if err != nil {
		t.Fatal(err)
	}
	n, _ := out.Item["blob_bytes"].(*types.AttributeValueMemberN)
	if n == nil {
		return 0
	}
	var v int64
	for _, ch := range n.Value {
		if ch == '-' {
			continue
		}
		v = v*10 + int64(ch-'0')
	}
	if strings.HasPrefix(n.Value, "-") {
		v = -v
	}
	return v
}

// Two PUTs from one mailbox with the same claim id and different tags:
// a re-PUT of the old tag lands between the other's read of the marker and
// its transaction. One live claim is left, the later one.
func TestCodePutRacesASameIDRePut(t *testing.T) {
	e := newCodeEnv(t)
	t1, t2 := codeMAC(1), codeMAC(2)
	if _, err := e.s.PutCode(ctx, codePut(codeID1, t1), 0); err != nil {
		t.Fatal(err)
	}
	e.hook.match = putsMarker
	e.hook.before = func() {
		e.c.Add(time.Second)
		if _, err := e.s.PutCode(ctx, codePut(codeID1, t1), 0); err != nil {
			t.Error(err)
		}
	}
	if _, err := e.s.PutCode(ctx, codePut(codeID1, t2), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.RedeemCode(ctx, "k1", codeLook(t1), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the replaced claim is live: %v", err)
	}
	if got, err := e.s.RedeemCode(ctx, "k1", codeLook(t2), false); err != nil || got.ClaimID != codeID1 {
		t.Fatalf("the later claim: %+v %v", got, err)
	}
}

// A redeem whose read is followed by a same-id re-PUT (a new exp) before
// its delete loses the race: the new claim stays, tracked.
func TestCodeRedeemPinnedToTheClaimRead(t *testing.T) {
	e := newCodeEnv(t)
	m := codeMAC(3)
	if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
		t.Fatal(err)
	}
	e.hook.match = deletesCode
	e.hook.before = func() {
		e.c.Add(time.Second)
		if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
			t.Error(err)
		}
	}
	if _, err := e.s.RedeemCode(ctx, "k1", codeLook(m), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("redeemed a claim it didn't read: %v", err)
	}
	if got, err := e.s.RedeemCode(ctx, "k1", codeLook(m), false); err != nil || got.ClaimID != codeID1 {
		t.Fatalf("the re-PUT claim: %+v %v", got, err)
	}
}

// A DELETE's claim delete, id delete and marker delete are pinned to the
// claim it read: a same-id re-PUT just before them keeps its claim, its id
// (a later DELETE finds it) and its marker.
func TestCodeDeletePinnedToTheClaimRead(t *testing.T) {
	e := newCodeEnv(t)
	m := codeMAC(4)
	if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
		t.Fatal(err)
	}
	once := false
	dynamo.SetBeforeCodeDrop(e.s, func() {
		if once {
			return
		}
		once = true
		e.c.Add(time.Second)
		if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
			t.Error(err)
		}
	})
	if err := e.s.DeleteCode(ctx, "a", codeID1); err != nil {
		t.Fatal(err)
	}
	dynamo.SetBeforeCodeDrop(e.s, nil)
	// The re-PUT claim is still stored.
	if n := slotItems(t, e, "PCB#k1#a12213d1#0404"); n != 1 {
		t.Fatalf("%d claims in the slot after the DELETE; the re-PUT one went", n)
	}
	// Its id is there: a DELETE now removes it.
	if err := e.s.DeleteCode(ctx, "a", codeID1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.RedeemCode(ctx, "k1", codeLook(m), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the re-PUT claim's id was lost (a DELETE didn't find it): %v", err)
	}
	if n := blobBytes(t, e, "a"); n != 0 {
		t.Fatalf("blob_bytes %d after both claims went", n)
	}
}

// A claim whose misses reached the limit can't be redeemed, even before
// its cancel lands.
func TestCodeRedeemRefusesACancelledClaim(t *testing.T) {
	e := newCodeEnv(t)
	m := codeMAC(5)
	if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
		t.Fatal(err)
	}
	// Its slot: the only PCB# item.
	out, err := e.db.Query(ctx, &dynamodb.QueryInput{TableName: &e.table, ConsistentRead: aws.Bool(true),
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": &types.AttributeValueMemberS{Value: "PCB#k1#a12213d1#0505"}}})
	if err != nil || len(out.Items) != 1 {
		t.Fatalf("slot: %v %d", err, len(out.Items))
	}
	if _, err := e.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &e.table,
		Key:                       map[string]types.AttributeValue{"pk": out.Items[0]["pk"], "sk": out.Items[0]["sk"]},
		UpdateExpression:          aws.String("SET miss = :m"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":m": &types.AttributeValueMemberN{Value: "32"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.RedeemCode(ctx, "k1", codeLook(m), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a cancelled claim was redeemed: %v", err)
	}
}

// Transaction conflicts on a redeem, on its cleanup and on the misses are
// retried: they end as the redeem or the miss, never as an error.
func TestCodeConflictsAreRetried(t *testing.T) {
	e := newCodeEnv(t)
	m := codeMAC(6)
	if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
		t.Fatal(err)
	}
	e.flaky.txConflicts, e.flaky.delConflicts = 2, 2
	if got, err := e.s.RedeemCode(ctx, "k1", codeLook(m), false); err != nil || got.ClaimID != codeID1 {
		t.Fatalf("redeem through conflicts: %+v %v", got, err)
	}
	if n := blobBytes(t, e, "a"); n != 0 {
		t.Fatalf("blob_bytes %d after the redeem's cleanup", n)
	}
	if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
		t.Fatal(err)
	}
	e.flaky.missConflicts = 2
	miss := codeMAC(6)
	miss[31] = 9 // same bucket, no match
	if _, err := e.s.RedeemCode(ctx, "k1", codeLook(miss), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a miss through conflicts: %v", err)
	}
	if e.flaky.missConflicts != 0 {
		t.Fatal("the miss update wasn't tried")
	}
}

// The purge of a deleted mailbox follows only a live marker: a stale one's
// slot may hold another mailbox's claim now.
func TestCodePurgeSkipsAStaleMarker(t *testing.T) {
	e := newCodeEnv(t)
	m := codeMAC(7)
	if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
		t.Fatal(err)
	}
	e.c.Add(store.CodeTTL) // a's claim expires; its marker stays until TTL
	p := codePut(codeID2, m)
	p.Mailbox = "b"
	if _, err := e.s.PutCode(ctx, p, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.DeleteMailbox(ctx, "a", []byte(strings.Repeat("a", 32)), e.c.Now(), e.c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, err := e.s.RedeemCode(ctx, "k1", codeLook(m), false); err != nil || got.ClaimID != codeID2 {
		t.Fatalf("b's claim after a's purge: %+v %v", got, err)
	}
}

// Reconcile counts the code claim marker toward the storage cap.
func TestCodeReconcileCountsTheMarker(t *testing.T) {
	e := newCodeEnv(t)
	p := codePut(codeID1, codeMAC(8))
	p.Blob = make([]byte, 6)
	if _, err := e.s.PutCode(ctx, p, 10); err != nil {
		t.Fatal(err)
	}
	// The counter drifts high behind the store's back; a refused write
	// recounts it from the items, the marker included.
	if _, err := e.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &e.table,
		Key:                       map[string]types.AttributeValue{"pk": &types.AttributeValueMemberS{Value: "MB#a"}, "sk": &types.AttributeValueMemberS{Value: "S"}},
		UpdateExpression:          aws.String("SET blob_bytes = :b"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":b": &types.AttributeValueMemberN{Value: "100"}}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.s.PutClaim(ctx, "a", make([]byte, 4), time.Hour, 10); err != nil {
		t.Fatalf("4 more bytes after a recount: %v", err)
	}
	if _, _, err := e.s.PutClaim(ctx, "a", make([]byte, 1), time.Hour, 10); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("over the cap the marker fills: %v", err)
	}
}

// A collision gives the victim's mailbox its charge back.
func TestCodeCollisionRefundsTheVictim(t *testing.T) {
	e := newCodeEnv(t)
	m := codeMAC(9)
	if _, err := e.s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
		t.Fatal(err)
	}
	if n := blobBytes(t, e, "a"); n != int64(len("bundle")) {
		t.Fatalf("blob_bytes %d", n)
	}
	q := codePut(codeID2, m)
	q.Mailbox = "b"
	if _, err := e.s.PutCode(ctx, q, 0); !errors.Is(err, store.ErrCodeTaken) {
		t.Fatalf("collision: %v", err)
	}
	if n := blobBytes(t, e, "a"); n != 0 {
		t.Fatalf("the victim's blob_bytes %d after the collision", n)
	}
}

func slotItems(t *testing.T, e codeEnv, pk string) int {
	t.Helper()
	out, err := e.db.Query(ctx, &dynamodb.QueryInput{TableName: &e.table, ConsistentRead: aws.Bool(true),
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": &types.AttributeValueMemberS{Value: pk}}})
	if err != nil {
		t.Fatal(err)
	}
	return len(out.Items)
}
