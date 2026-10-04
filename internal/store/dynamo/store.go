// Package dynamo is a store.Backend on DynamoDB (state) and S3 (blob
// bodies), shared by any number of relay processes. It is the store for
// multi-task hosting: there is no single writer, and every operation that
// the SQLite store performs in one transaction is a DynamoDB transaction or
// a single conditional write here.
//
// # Table layout (one table, pk/sk strings, TTL attribute "ttl_s")
//
//	pk            sk               what
//	MB#<mailbox>  A                mailbox: pub, created, [delete_after, successor, preds, deleted, nb, gpk/gsk]
//	MB#<mailbox>  S                counters: msgs, bytes, blob_bytes, deny; last_id; v; dead_at; nb; rec_*
//	MB#<mailbox>  M#<ulid>         message: sz, dep, exp, sender, jti, payload (binary)
//	MB#<mailbox>  L#<ulid>         lease of that message: lease_until
//	MB#<mailbox>  D#<kind>#<value> denylist entry: exp
//	MB#<mailbox>  T#<jti>          token quota usage: msgs, bytes, exp
//	MB#<mailbox>  X#<jti>          consumed one-shot open token: exp
//	MB#<mailbox>  B#<ulid>         blob metadata: sz, exp, sender (body in S3)
//	MB#<mailbox>  C#<claim id>     claim marker (counts toward the storage cap)
//	CL#<claim id> CL               claim: mb, sz, exp, body
//
// The sparse GSI "due" (gpk = "due", gsk = delete_after ms) lists rotated
// mailboxes so Sweep can purge them after their grace period. Attribute
// names avoid DynamoDB reserved words (size, data, ttl, until, stored, ...).
//
// # Deletion (protocol 0.5.0, §6.10)
//
// A deleted mailbox keeps two items as its tombstone: A with `deleted` (the
// mailbox never resolves again until its key re-registers), `nb` (tokens
// issued before it are refused after a re-registration) and gsk = the
// tombstone's expiry, so Sweep purges it like a rotated mailbox once every
// token minted before the deletion has expired; and S with dead_at = 0 and
// the same nb, so that a write on another process whose mailbox cache is
// stale still fails in its transaction. Everything else in the partition
// is deleted right away. A re-registration revives both items (keeping
// nb); Rotate keeps preds, the mailboxes rotated into this one, so a
// deletion can follow them (SQLite uses successor_id).
//
// # Consistency
//
// All reads that decide anything are strongly consistent. Expiry is always
// checked against the clock (items carry exp in ms); DynamoDB TTL only
// reclaims space, days later. Mailbox message/byte counts, blob+claim bytes
// and denylist size are counters on the S item, changed in the same
// transaction as the write they account for. Deletions that do not run in a
// transaction (ack, expiry, TTL) can leave a counter high; when a quota
// check fails the counter is recomputed from the items (at most once per
// ReconcileInterval per mailbox) and the write retried, so the observable
// behaviour matches the SQLite store's live counts. Token quotas are exact.
//
// Per-mailbox ULID order is commit order: each deposit's transaction
// requires its ULID to be greater than the mailbox's last_id and sets it, so
// a deposit that loses a race retries with a later ULID.
package dynamo

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/oklog/ulid/v2"

	"github.com/vettid/vettid-relay/internal/store"
)

// DB is the subset of the DynamoDB client the store uses.
type DB interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	BatchGetItem(context.Context, *dynamodb.BatchGetItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
	BatchWriteItem(context.Context, *dynamodb.BatchWriteItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

// Objects is the subset of the S3 client the store uses for blob bodies.
type Objects interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// Config configures a Store.
type Config struct {
	Table  string
	Bucket string // blob bodies; may be empty if blobs are disabled
	DB     DB
	S3     Objects // nil if blobs are disabled

	Now func() time.Time // default time.Now

	// MailboxCacheTTL caches live, un-rotated mailboxes (id → pubkey) in
	// process; every deposit and every owner request (each long-poll) looks
	// its mailbox up. Pubkeys never change for an id, so the only staleness
	// is a rotation's deletion time, which is a whole rotation grace period
	// away: keep this well below the grace. Default 5 min; negative
	// disables.
	MailboxCacheTTL time.Duration
	// PurgeDelay is how long after a rotated mailbox's deletion time Sweep
	// purges it, so no request that passed the liveness check just before
	// the deadline is still writing. Default 10 min.
	PurgeDelay time.Duration
	// ReconcileInterval bounds counter recomputation per mailbox and kind.
	// Default 1 min.
	ReconcileInterval time.Duration
	// Tombstones is the tombstone policy for rotated-away mailboxes
	// removed at the end of their grace (default
	// store.DefaultTombstonePolicy).
	Tombstones store.TombstonePolicy
}

// Store implements store.Backend.
type Store struct {
	cfg Config
	now func() time.Time

	idMu    sync.Mutex
	entropy io.Reader

	cacheMu sync.Mutex
	cache   map[string]cachedMailbox
}

type cachedMailbox struct {
	mb store.Mailbox
	at time.Time
}

var _ store.Backend = (*Store)(nil)

// New returns a Store. The table must exist (CreateTable for tests; CDK in
// production).
func New(cfg Config) (*Store, error) {
	if cfg.Table == "" || cfg.DB == nil {
		return nil, errors.New("dynamo: table and client are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MailboxCacheTTL == 0 {
		cfg.MailboxCacheTTL = 5 * time.Minute
	}
	if cfg.PurgeDelay == 0 {
		cfg.PurgeDelay = 10 * time.Minute
	}
	if cfg.ReconcileInterval == 0 {
		cfg.ReconcileInterval = time.Minute
	}
	return &Store{cfg: cfg, now: cfg.Now, entropy: ulid.Monotonic(rand.Reader, 0), cache: map[string]cachedMailbox{}}, nil
}

// Close implements store.Backend (the SDK clients hold no resources).
func (s *Store) Close() error { return nil }

// Ping implements store.Backend: one cheap read.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table,
		Key:       key("PING", "PING"),
	})
	return err
}

// ------------------------------------------------------------- attributes

const (
	skAccount = "A"
	skStats   = "S"
	dueGSI    = "due"
	dueValue  = "due"
)

func mbPK(id string) string             { return "MB#" + id }
func msgSK(id string) string            { return "M#" + id }
func leaseSK(id string) string          { return "L#" + id }
func denySK(kind, v string) string      { return "D#" + kind + "#" + v }
func tokenSK(jti string) string         { return "T#" + jti }
func consumedSK(jti string) string      { return "X#" + jti }
func blobSK(id string) string           { return "B#" + id }
func claimMarkSK(id string) string      { return "C#" + id }
func claimPK(id string) string          { return "CL#" + id }
func blobKey(mb, id string) string      { return "blobs/" + mb + "/" + id }
func ms(t time.Time) int64              { return t.UnixMilli() }
func fromMS(v int64) time.Time          { return time.UnixMilli(v).UTC() }
func ttlSec(t time.Time) int64          { return t.Unix() + 1 }
func avS(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }
func avN(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}
func avB(v []byte) types.AttributeValue {
	if v == nil {
		v = []byte{}
	}
	return &types.AttributeValueMemberB{Value: v}
}

type item = map[string]types.AttributeValue

func key(pk, sk string) item { return item{"pk": avS(pk), "sk": avS(sk)} }

func getS(it item, k string) string {
	if v, ok := it[k].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func getN(it item, k string) (int64, bool) {
	if v, ok := it[k].(*types.AttributeValueMemberN); ok {
		n, err := strconv.ParseInt(v.Value, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func getN0(it item, k string) int64 { n, _ := getN(it, k); return n }

func getB(it item, k string) []byte {
	if v, ok := it[k].(*types.AttributeValueMemberB); ok {
		return v.Value
	}
	return nil
}

func isCCF(err error) bool {
	var e *types.ConditionalCheckFailedException
	return errors.As(err, &e)
}

// txReasons returns the per-item cancellation codes of a cancelled
// transaction (nil if err is something else).
func txReasons(err error) []types.CancellationReason {
	var e *types.TransactionCanceledException
	if errors.As(err, &e) {
		return e.CancellationReasons
	}
	return nil
}

func reasonCode(r []types.CancellationReason, i int) string {
	if i < 0 || i >= len(r) || r[i].Code == nil {
		return ""
	}
	return *r[i].Code
}

func isConflict(r []types.CancellationReason) bool {
	for i := range r {
		if c := reasonCode(r, i); c == "TransactionConflict" || c == "ThrottlingError" || c == "ProvisionedThroughputExceeded" {
			return true
		}
	}
	return false
}

// backoff sleeps before retry attempt n (jittered, growing, capped).
func backoff(ctx context.Context, n int) error {
	d := time.Duration(5+mrand.IntN(10*(n+1))) * time.Millisecond
	t := time.NewTimer(min(d, 250*time.Millisecond))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

const maxTxAttempts = 30

// newID returns a fresh ULID strictly greater than after (if given).
func (s *Store) newID(t time.Time, after string) string {
	s.idMu.Lock()
	id := ulid.MustNew(ulid.Timestamp(t), s.entropy)
	s.idMu.Unlock()
	if after != "" && id.String() <= after {
		if prev, err := ulid.ParseStrict(after); err == nil {
			return increment(prev).String()
		}
	}
	return id.String()
}

// increment returns the ULID one greater than u (128-bit big-endian add).
func increment(u ulid.ULID) ulid.ULID {
	n := new(big.Int).SetBytes(u[:])
	n.Add(n, big.NewInt(1))
	var out ulid.ULID
	b := n.Bytes()
	if len(b) > len(out) {
		return u // overflow: cannot happen before year 10889
	}
	copy(out[len(out)-len(b):], b)
	return out
}

// --------------------------------------------------------------- mailboxes

func parseMailbox(it item) store.Mailbox {
	mb := store.Mailbox{ID: strings.TrimPrefix(getS(it, "pk"), "MB#"), PubKey: getB(it, "pub"), CreatedAt: fromMS(getN0(it, "created"))}
	if d, ok := getN(it, "delete_after"); ok {
		t := fromMS(d)
		mb.DeleteAfter = &t
	}
	if _, ok := it["deleted"]; ok {
		// A tombstone is dead on every clock (the zero time is long past).
		mb.DeleteAfter = &time.Time{}
	}
	if nb, ok := getN(it, "nb"); ok {
		mb.TokensNotBefore = fromMS(nb)
	}
	return mb
}

// dead reports a mailbox past its rotation grace or deleted.
func dead(mb store.Mailbox, now time.Time) bool {
	return mb.DeleteAfter != nil && !now.Before(*mb.DeleteAfter)
}

func (s *Store) getMailbox(ctx context.Context, id string) (store.Mailbox, bool, error) {
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(id), skAccount), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return store.Mailbox{}, false, err
	}
	if len(out.Item) == 0 {
		return store.Mailbox{}, false, nil
	}
	return parseMailbox(out.Item), true, nil
}

// Forget drops mailboxes from this process's cache (another process
// deleted them: api.Server.MailboxGone).
func (s *Store) Forget(ids ...string) { s.forget(ids...) }

func (s *Store) forget(ids ...string) {
	s.cacheMu.Lock()
	for _, id := range ids {
		delete(s.cache, id)
	}
	s.cacheMu.Unlock()
}

// Register implements store.Backend.
func (s *Store) Register(ctx context.Context, id string, pub []byte) (bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		_, err := s.cfg.DB.PutItem(ctx, &dynamodb.PutItemInput{
			TableName: &s.cfg.Table,
			Item: item{
				"pk": avS(mbPK(id)), "sk": avS(skAccount),
				"pub": avB(pub), "created": avN(ms(s.now())),
			},
			ConditionExpression: aws.String("attribute_not_exists(pk)"),
		})
		if err == nil {
			s.forget(id)
			return true, nil
		}
		if !isCCF(err) {
			return false, err
		}
		mb, ok, err := s.getMailbox(ctx, id)
		if err != nil {
			return false, err
		}
		if !ok {
			continue // purged in between; try again
		}
		if subtle.ConstantTimeCompare(mb.PubKey, pub) != 1 {
			return false, fmt.Errorf("store: mailbox id collision")
		}
		if !dead(mb, s.now()) {
			return false, nil
		}
		// Deleted, or past its rotation grace and not purged yet: the key
		// starts a fresh, empty mailbox. A rotated-away one is removed now:
		// its tokens get the tombstone it would have got from the sweep.
		var nb time.Time
		if !mb.DeleteAfter.IsZero() { // not a deletion tombstone (parseMailbox)
			nb, _ = s.cfg.Tombstones.Times(s.now())
		}
		revived, err := s.revive(ctx, id, pub, nb)
		if err != nil || revived {
			return revived, err
		}
	}
	return false, errors.New("dynamo: register: mailbox keeps disappearing")
}

// revive turns a dead mailbox item back into a fresh, empty, live mailbox:
// its contents are purged first, then A and S are reset in one
// transaction that requires the mailbox to be still dead (false: it
// changed meanwhile, look again). nb stays: tokens minted before a
// deletion remain refused. A non-zero setNB (a rotated-away mailbox
// removed now) sets it.
func (s *Store) revive(ctx context.Context, id string, pub []byte, setNB time.Time) (bool, error) {
	defer s.forget(id)
	if _, err := s.purgeContents(ctx, id); err != nil {
		return false, err
	}
	now := s.now()
	setA, setS := "SET created = :now", "SET msgs = :z, bytes = :z, blob_bytes = :z, deny = :z, v = if_not_exists(v, :z) + :one"
	valsA, valsS := item{":p": avB(pub), ":now": avN(ms(now))}, item{":z": avN(0), ":one": avN(1)}
	if !setNB.IsZero() {
		setA, setS = setA+", nb = :nb", setS+", nb = :nb"
		valsA[":nb"], valsS[":nb"] = avN(ms(setNB)), avN(ms(setNB))
	}
	_, err := s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(id), skAccount),
			UpdateExpression:          aws.String(setA + " REMOVE deleted, delete_after, successor, preds, gpk, gsk"),
			ConditionExpression:       aws.String("pub = :p AND (attribute_exists(deleted) OR delete_after <= :now)"),
			ExpressionAttributeValues: valsA,
		}},
		{Update: &types.Update{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(id), skStats),
			UpdateExpression:          aws.String(setS + " REMOVE dead_at"),
			ExpressionAttributeValues: valsS,
		}},
	}})
	if err == nil {
		return true, nil
	}
	if r := txReasons(err); r != nil && (reasonCode(r, 0) == "ConditionalCheckFailed" || isConflict(r)) {
		return false, nil
	}
	return false, err
}

// Mailbox implements store.Backend.
func (s *Store) Mailbox(ctx context.Context, id string) (store.Mailbox, error) {
	now := s.now()
	if s.cfg.MailboxCacheTTL > 0 {
		s.cacheMu.Lock()
		c, ok := s.cache[id]
		s.cacheMu.Unlock()
		if ok && now.Sub(c.at) < s.cfg.MailboxCacheTTL && now.Sub(c.at) >= 0 {
			return c.mb, nil
		}
	}
	mb, ok, err := s.getMailbox(ctx, id)
	if err != nil {
		return store.Mailbox{}, err
	}
	if !ok || dead(mb, now) {
		return store.Mailbox{}, store.ErrNotFound
	}
	if s.cfg.MailboxCacheTTL > 0 && mb.DeleteAfter == nil {
		s.cacheMu.Lock()
		if len(s.cache) > 100_000 {
			clear(s.cache)
		}
		s.cache[id] = cachedMailbox{mb: mb, at: now}
		s.cacheMu.Unlock()
	}
	return mb, nil
}

// Rotate implements store.Backend in one transaction: schedule the old
// mailbox (never later than an existing schedule), create or revive the
// successor, and mark the old mailbox's counters item dead at the same time
// so a deposit racing the deadline fails.
func (s *Store) Rotate(ctx context.Context, oldID, newID string, newPub []byte, deleteAfter time.Time) error {
	defer s.forget(oldID, newID)
	for attempt := 0; ; attempt++ {
		now := s.now()
		old, ok, err := s.getMailbox(ctx, oldID)
		if err != nil {
			return err
		}
		if !ok || dead(old, now) {
			return store.ErrNotFound
		}
		// A successor id that was deleted before starts empty (its
		// contents are normally purged already).
		if nm, ok, err := s.getMailbox(ctx, newID); err != nil {
			return err
		} else if ok && dead(nm, now) {
			if _, err := s.purgeContents(ctx, newID); err != nil {
				return err
			}
		}
		da := deleteAfter
		oldCond := "pub = :oldpub AND attribute_not_exists(delete_after) AND attribute_not_exists(deleted)"
		vals := item{":oldpub": avB(old.PubKey), ":da": avN(ms(da)), ":new": avS(newID), ":due": avS(dueValue)}
		if old.DeleteAfter != nil {
			if old.DeleteAfter.Before(da) {
				da = *old.DeleteAfter
				vals[":da"] = avN(ms(da))
			}
			oldCond = "pub = :oldpub AND delete_after = :prev AND attribute_not_exists(deleted)"
			vals[":prev"] = avN(ms(*old.DeleteAfter))
		}
		_, err = s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
			{Update: &types.Update{
				TableName:                 &s.cfg.Table,
				Key:                       key(mbPK(oldID), skAccount),
				UpdateExpression:          aws.String("SET delete_after = :da, successor = :new, gpk = :due, gsk = :da"),
				ConditionExpression:       &oldCond,
				ExpressionAttributeValues: vals,
			}},
			{Update: &types.Update{
				TableName:           &s.cfg.Table,
				Key:                 key(mbPK(newID), skAccount),
				UpdateExpression:    aws.String("SET pub = if_not_exists(pub, :p), created = if_not_exists(created, :now) ADD preds :old REMOVE delete_after, deleted, gpk, gsk"),
				ConditionExpression: aws.String("attribute_not_exists(pk) OR pub = :p"),
				ExpressionAttributeValues: item{
					":p": avB(newPub), ":now": avN(ms(now)), ":old": &types.AttributeValueMemberSS{Value: []string{oldID}},
				},
			}},
			{Update: &types.Update{
				TableName:                 &s.cfg.Table,
				Key:                       key(mbPK(oldID), skStats),
				UpdateExpression:          aws.String("SET dead_at = :da"),
				ExpressionAttributeValues: item{":da": avN(ms(da))},
			}},
			{Update: &types.Update{
				TableName:        &s.cfg.Table,
				Key:              key(mbPK(newID), skStats),
				UpdateExpression: aws.String("REMOVE dead_at"),
			}},
		}})
		if err == nil {
			return nil
		}
		r := txReasons(err)
		if r == nil {
			return err
		}
		if reasonCode(r, 1) == "ConditionalCheckFailed" {
			return fmt.Errorf("store: mailbox id collision")
		}
		if attempt >= maxTxAttempts {
			return fmt.Errorf("dynamo: rotate: %w", err)
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
}

// --------------------------------------------------------------- counters

// counter kinds and the timestamp attribute gating their recomputation.
const (
	kindMsgs   = "rec_m"
	kindStored = "rec_s"
	kindDeny   = "rec_d"
)

// reconcile recomputes a mailbox counter from its items, deleting expired
// items on the way (space only — they no longer count). It runs at most
// once per ReconcileInterval per mailbox and kind, and only commits if no
// counted write happened meanwhile (v unchanged). It reports whether it
// recomputed.
func (s *Store) reconcile(ctx context.Context, mailbox, kind string) (bool, error) {
	now := s.now()
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), skStats), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	if last, ok := getN(out.Item, kind); ok && now.Sub(fromMS(last)) < s.cfg.ReconcileInterval && now.Sub(fromMS(last)) >= 0 {
		return false, nil
	}
	v, hasV := getN(out.Item, "v")

	var prefixes []string
	switch kind {
	case kindMsgs:
		prefixes = []string{"M#"}
	case kindStored:
		prefixes = []string{"B#", "C#"}
	case kindDeny:
		prefixes = []string{"D#"}
	}
	var count, sum int64
	for _, p := range prefixes {
		err := s.queryAll(ctx, &dynamodb.QueryInput{
			KeyConditionExpression:    aws.String("pk = :pk AND begins_with(sk, :p)"),
			ExpressionAttributeValues: item{":pk": avS(mbPK(mailbox)), ":p": avS(p)},
			ProjectionExpression:      aws.String("pk, sk, exp, sz"),
		}, func(it item) error {
			exp, _ := getN(it, "exp")
			if exp > ms(now) {
				count++
				sum += getN0(it, "sz")
				return nil
			}
			return s.dropExpired(ctx, mailbox, getS(it, "sk"), now)
		})
		if err != nil {
			return false, err
		}
	}
	var set string
	vals := item{":now": avN(ms(now)), ":one": avN(1)}
	switch kind {
	case kindMsgs:
		set = "msgs = :c, bytes = :b"
		vals[":c"], vals[":b"] = avN(count), avN(sum)
	case kindStored:
		set = "blob_bytes = :b"
		vals[":b"] = avN(sum)
	case kindDeny:
		set = "deny = :c"
		vals[":c"] = avN(count)
	}
	cond := "attribute_not_exists(v)"
	if hasV {
		cond = "v = :v0"
		vals[":v0"] = avN(v)
	}
	_, err = s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(mailbox), skStats),
		UpdateExpression:          aws.String("SET " + set + ", " + kind + " = :now, v = if_not_exists(v, :zero) + :one"),
		ConditionExpression:       &cond,
		ExpressionAttributeValues: withZero(vals),
	})
	if isCCF(err) {
		return false, nil // a concurrent write moved the counters; leave them
	}
	return err == nil, err
}

func withZero(v item) item { v[":zero"] = avN(0); return v }

// dropExpired deletes one expired item found while scanning a mailbox
// (no counter change: callers recount or never counted it).
func (s *Store) dropExpired(ctx context.Context, mailbox, sk string, now time.Time) error {
	_, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(mailbox), sk),
		ConditionExpression:       aws.String("exp <= :now"),
		ExpressionAttributeValues: item{":now": avN(ms(now))},
	})
	if err != nil && !isCCF(err) {
		return err
	}
	switch {
	case strings.HasPrefix(sk, "M#"):
		return s.deleteKey(ctx, mbPK(mailbox), leaseSK(strings.TrimPrefix(sk, "M#")))
	case strings.HasPrefix(sk, "B#") && s.cfg.S3 != nil:
		_, err := s.cfg.S3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.cfg.Bucket, Key: aws.String(blobKey(mailbox, strings.TrimPrefix(sk, "B#")))})
		return err
	}
	return nil
}

func (s *Store) deleteKey(ctx context.Context, pk, sk string) error {
	_, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: &s.cfg.Table, Key: key(pk, sk)})
	return err
}

// adjust applies counter deltas outside a transaction (after a delete).
// A missing counters item is left alone.
func (s *Store) adjust(ctx context.Context, mailbox string, deltas map[string]int64) error {
	var parts []string
	vals := item{":one": avN(1)}
	i := 0
	for k, d := range deltas {
		ph := fmt.Sprintf(":d%d", i)
		parts = append(parts, k+" "+ph)
		vals[ph] = avN(d)
		i++
	}
	_, err := s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(mbPK(mailbox), skStats),
		UpdateExpression:          aws.String("ADD " + strings.Join(parts, ", ") + ", v :one"),
		ConditionExpression:       aws.String("attribute_exists(sk)"),
		ExpressionAttributeValues: vals,
	})
	if isCCF(err) {
		return nil
	}
	return err
}

// queryAll runs a strongly consistent query over all pages.
func (s *Store) queryAll(ctx context.Context, in *dynamodb.QueryInput, fn func(item) error) error {
	in.TableName = &s.cfg.Table
	if in.IndexName == nil {
		in.ConsistentRead = aws.Bool(true)
	}
	for {
		out, err := s.cfg.DB.Query(ctx, in)
		if err != nil {
			return err
		}
		for _, it := range out.Items {
			if err := fn(it); err != nil {
				return err
			}
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}
