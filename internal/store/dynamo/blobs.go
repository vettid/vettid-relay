package dynamo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/oklog/ulid/v2"

	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Blob bodies live in S3 under blobs/<mailbox>/<blob id>; their metadata
// (size, expiry, sender) and the mailbox storage counter live in
// DynamoDB, and so does each sender's share of a mailbox (an item per
// sender and mailbox, BS#<sender>, listing its blobs). An upload's body
// is streamed to S3 first, under the id it will have (StageBlob), while
// nothing points at it: a reader finds a blob only by its metadata, so a
// staged body is invisible and counts against nothing. Commit then writes
// the metadata with every quota check in one transaction; a staged body
// that is not committed is deleted (Discard), and one left by a process
// that stopped mid-upload is expired by the bucket's lifecycle rule.

var errBlobsDisabled = errors.New("dynamo: blob storage not configured")

// extraCheck names an extra item of a chargeStored transaction whose
// failed condition means a quota: err, after reconcile (if any) has
// recomputed what it guards once and the transaction failed again.
type extraCheck struct {
	idx       int
	err       error
	reconcile func(context.Context) (bool, error)
}

// chargeStored runs a transaction that adds delta to the mailbox's
// blob+claim byte counter (within maxStored) together with extra items,
// recomputing the counter once if the cap appears exceeded
// (ErrQuotaMailboxBlobs). checks lists the extra items whose condition
// failure means a quota, in order of precedence after the mailbox's. A
// non-zero iat is the token's issue time (ErrRevoked before the mailbox's
// TokensNotBefore).
func (s *Store) chargeStored(ctx context.Context, mailbox string, delta, maxStored int64, iat time.Time, extra []types.TransactWriteItem, checks ...extraCheck) error {
	reconciled := map[int]bool{}
outer:
	for attempt := 0; ; attempt++ {
		now := s.now()
		q := newQuotaCond(now)
		q.issuedAt(iat)
		q.room("blob_bytes", delta, maxStored)
		q.vals[":d"], q.vals[":one"] = avN(delta), avN(1)
		items := append([]types.TransactWriteItem{{Update: &types.Update{
			TableName:                           &s.cfg.Table,
			Key:                                 key(mbPK(mailbox), skStats),
			UpdateExpression:                    aws.String("ADD blob_bytes :d, v :one"),
			ConditionExpression:                 q.expr(),
			ExpressionAttributeValues:           q.vals,
			ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
		}}}, extra...)
		_, err := s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
		if err == nil {
			return nil
		}
		r := txReasons(err)
		if r == nil {
			return err
		}
		if reasonCode(r, 0) == "ConditionalCheckFailed" {
			if err := deadOrRevoked(r[0].Item, now, iat); err != nil {
				return err
			}
			if !reconciled[-1] {
				reconciled[-1] = true
				if ok, err := s.reconcile(ctx, mailbox, kindStored); err != nil {
					return err
				} else if ok {
					continue
				}
			}
			return store.ErrQuotaMailboxBlobs
		}
		for _, c := range checks {
			if reasonCode(r, c.idx+1) != "ConditionalCheckFailed" {
				continue
			}
			if c.reconcile != nil && !reconciled[c.idx] {
				reconciled[c.idx] = true
				if ok, err := c.reconcile(ctx); err != nil {
					return err
				} else if ok {
					continue outer
				}
			}
			return c.err
		}
		if !isConflict(r) || attempt >= maxTxAttempts {
			return fmt.Errorf("dynamo: %w", err)
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
}

// senderSK is the item holding sender's share of a mailbox: its blobs, as
// attributes e_<blob id> = {s: size, e: expiry}, with their bytes b and
// number n (which the commit's condition checks) and a version v.
func senderSK(sender string) string { return "BS#" + sender }

const senderEntryPrefix = "e_"

// senderEntries returns the blobs listed in a sender item: id → size,
// expiry.
func senderEntries(it item) map[string][2]int64 {
	out := map[string][2]int64{}
	for k, v := range it {
		if !strings.HasPrefix(k, senderEntryPrefix) {
			continue
		}
		m, ok := v.(*types.AttributeValueMemberM)
		if !ok {
			continue
		}
		out[strings.TrimPrefix(k, senderEntryPrefix)] = [2]int64{getN0(m.Value, "s"), getN0(m.Value, "e")}
	}
	return out
}

// liveShare sums the entries of a sender item that have not expired.
func liveShare(it item, now time.Time) (n, bytes int64) {
	for _, e := range senderEntries(it) {
		if e[1] > ms(now) {
			n++
			bytes += e[0]
		}
	}
	return n, bytes
}

// reconcileSender recomputes a sender's share of mailbox from its entries,
// dropping those whose blob has expired or is gone (deleted without its
// entry, or removed by TTL), and commits only if the item did not change
// meanwhile (v). It reports whether it changed anything.
func (s *Store) reconcileSender(ctx context.Context, mailbox, sender string) (bool, error) {
	now := s.now()
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), senderSK(sender)), ConsistentRead: aws.Bool(true),
	})
	if err != nil || len(out.Item) == 0 {
		return false, err
	}
	entries := senderEntries(out.Item)
	var keys []item
	for id, e := range entries {
		if e[1] > ms(now) {
			keys = append(keys, key(mbPK(mailbox), blobSK(id)))
		}
	}
	exists := map[string]int64{}
	for len(keys) > 0 { // batchGet takes at most 100 keys
		n := min(100, len(keys))
		got, err := s.batchGet(ctx, keys[:n])
		if err != nil {
			return false, err
		}
		for sk, exp := range got {
			exists[sk] = exp
		}
		keys = keys[n:]
	}
	var n, sum int64
	var drop []string
	for id, e := range entries {
		if exp, ok := exists[blobSK(id)]; ok && exp > ms(now) && e[1] > ms(now) {
			n++
			sum += e[0]
			continue
		}
		drop = append(drop, id)
	}
	if len(drop) == 0 && n == getN0(out.Item, "n") && sum == getN0(out.Item, "b") {
		return false, nil
	}
	cond := "attribute_not_exists(v)"
	vals := item{}
	if v, ok := getN(out.Item, "v"); ok {
		cond = "v = :v0"
		vals[":v0"] = avN(v)
	}
	if n == 0 {
		_, err = s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: &s.cfg.Table, Key: key(mbPK(mailbox), senderSK(sender)),
			ConditionExpression: &cond, ExpressionAttributeValues: nilIfEmpty(vals),
		})
	} else {
		names := map[string]string{}
		var rm []string
		for i, id := range drop {
			ph := fmt.Sprintf("#r%d", i)
			names[ph] = senderEntryPrefix + id
			rm = append(rm, ph)
		}
		expr := "SET b = :b, n = :n, v = if_not_exists(v, :zero) + :one"
		if len(rm) > 0 {
			expr += " REMOVE " + strings.Join(rm, ", ")
		}
		vals[":b"], vals[":n"], vals[":one"] = avN(sum), avN(n), avN(1)
		in := &dynamodb.UpdateItemInput{
			TableName: &s.cfg.Table, Key: key(mbPK(mailbox), senderSK(sender)),
			UpdateExpression: &expr, ConditionExpression: &cond, ExpressionAttributeValues: withZero(vals),
		}
		if len(names) > 0 {
			in.ExpressionAttributeNames = names
		}
		_, err = s.cfg.DB.UpdateItem(ctx, in)
	}
	if isCCF(err) {
		return false, nil // changed meanwhile: leave it
	}
	return err == nil, err
}

func nilIfEmpty(v item) item {
	if len(v) == 0 {
		return nil
	}
	return v
}

// s3Staged is a body uploaded to S3 under its blob's key, not yet
// committed.
type s3Staged struct {
	s           *Store
	mailbox, id string
	size        int64
	mu          sync.Mutex
	done        bool // committed or discarded
}

// guardedReader lets the SDK read the body only until close: the HTTP
// transport may go on reading a request body in its own goroutine after
// the call returned, and the body here is the client's upload, which the
// relay hashes as it is read.
type guardedReader struct {
	mu     sync.Mutex
	r      io.Reader
	closed bool
}

func (g *guardedReader) Read(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return 0, errors.New("dynamo: staged body read after its upload ended")
	}
	return g.r.Read(p)
}

func (g *guardedReader) close() { g.mu.Lock(); g.closed = true; g.mu.Unlock() }

// StageBlob implements store.BlobStore: the body is streamed to S3 with
// one PutObject of known length (the SDK holds a buffer of it at a time),
// under the key of the id the blob will have.
func (s *Store) StageBlob(ctx context.Context, mailbox string, size int64, r io.Reader) (store.StagedBlob, error) {
	if s.cfg.S3 == nil {
		return nil, errBlobsDisabled
	}
	id := s.newID(s.now(), "")
	g := &guardedReader{r: store.ExactReader(r, size)}
	_, err := s.cfg.S3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &s.cfg.Bucket,
		Key:           aws.String(blobKey(mailbox, id)),
		Body:          g,
		ContentLength: aws.Int64(size),
		ContentType:   aws.String("application/octet-stream"),
	}, s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware)) // a stream: not hashed for the signature
	g.close()
	if err != nil {
		// S3 stores no object from a failed PUT; deleting is the safety net.
		_, _ = s.cfg.S3.DeleteObject(context.WithoutCancel(ctx), &s3.DeleteObjectInput{Bucket: &s.cfg.Bucket, Key: aws.String(blobKey(mailbox, id))})
		return nil, fmt.Errorf("dynamo: stage blob: %w", err)
	}
	return &s3Staged{s: s, mailbox: mailbox, id: id, size: size}, nil
}

// Discard implements store.StagedBlob.
func (b *s3Staged) Discard(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done {
		return nil
	}
	_, err := b.s.cfg.S3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &b.s.cfg.Bucket, Key: aws.String(blobKey(b.mailbox, b.id))})
	if err == nil {
		b.done = true
	}
	return err
}

// Commit implements store.StagedBlob in one transaction: the mailbox's
// counter (live, within the cap), the blob's metadata, the sender's share
// and the token's usage.
func (b *s3Staged) Commit(ctx context.Context, p store.BlobPut) (store.BlobInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done || p.Mailbox != b.mailbox || p.Size != b.size {
		return store.BlobInfo{}, errors.New("dynamo: commit of a blob not staged as such")
	}
	s := b.s
	if store.BlobNeverFits(p) {
		if _, err := s.Mailbox(ctx, p.Mailbox); err != nil {
			return store.BlobInfo{}, err
		}
		u, err := s.BlobUsage(ctx, p.Mailbox, p.Sender, "", false)
		if err != nil {
			return store.BlobInfo{}, err
		}
		return store.BlobInfo{}, store.QuotaFor(p, u)
	}
	now := s.now()
	info := store.BlobInfo{ID: b.id, Mailbox: p.Mailbox, Sender: p.Sender, Size: p.Size, CreatedAt: now.UTC(), ExpiresAt: now.Add(p.TTL).UTC()}
	blob := item{
		"pk": avS(mbPK(p.Mailbox)), "sk": avS(blobSK(info.ID)),
		"sz": avN(p.Size), "cr": avN(ms(now)), "exp": avN(ms(info.ExpiresAt)), "ttl_s": avN(ttlSec(info.ExpiresAt)),
	}
	if p.Sender != "" {
		blob["snd"] = avS(p.Sender)
	}
	extra := []types.TransactWriteItem{{Put: &types.Put{
		TableName: &s.cfg.Table, Item: blob, ConditionExpression: aws.String("attribute_not_exists(sk)"),
	}}}
	var checks []extraCheck
	if p.Sender != "" {
		var cond []string
		vals := item{
			":ent": &types.AttributeValueMemberM{Value: item{"s": avN(p.Size), "e": avN(ms(info.ExpiresAt))}},
			":t":   avN(ttlSec(info.ExpiresAt)), ":sz": avN(p.Size), ":one": avN(1),
		}
		if p.SenderMaxBytes > 0 {
			cond = append(cond, "(attribute_not_exists(b) OR b <= :qb)")
			vals[":qb"] = avN(p.SenderMaxBytes - p.Size)
		}
		if p.SenderMaxBlobs > 0 {
			cond = append(cond, "(attribute_not_exists(n) OR n <= :qn)")
			vals[":qn"] = avN(p.SenderMaxBlobs - 1)
		}
		u := &types.Update{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(p.Mailbox), senderSK(p.Sender)),
			UpdateExpression:          aws.String("SET #e = :ent, ttl_s = :t ADD b :sz, n :one, v :one"),
			ExpressionAttributeNames:  map[string]string{"#e": senderEntryPrefix + info.ID},
			ExpressionAttributeValues: vals,
		}
		if len(cond) > 0 {
			u.ConditionExpression = aws.String(strings.Join(cond, " AND "))
		}
		checks = append(checks, extraCheck{idx: len(extra), err: store.ErrQuotaSenderBlobs,
			reconcile: func(ctx context.Context) (bool, error) { return s.reconcileSender(ctx, p.Mailbox, p.Sender) }})
		extra = append(extra, types.TransactWriteItem{Update: u})
	}
	if u := s.tokenCharge(p.Mailbox, p.Limits, 0, p.Size); u != nil { // blobs count bytes only (§6.8)
		checks = append(checks, extraCheck{idx: len(extra), err: store.ErrQuotaToken})
		extra = append(extra, types.TransactWriteItem{Update: u})
	}
	if err := s.chargeStored(ctx, p.Mailbox, p.Size, p.Limits.MailboxMaxBytes, p.Limits.TokenIssuedAt, extra, checks...); err != nil {
		return store.BlobInfo{}, err
	}
	b.done = true
	return info, nil
}

// PutBlob implements store.BlobStore.
func (s *Store) PutBlob(ctx context.Context, p store.BlobPut, r io.Reader) (store.BlobInfo, error) {
	if s.cfg.S3 == nil {
		return store.BlobInfo{}, errBlobsDisabled
	}
	return store.PutStaged(ctx, s, p, r)
}

// BlobUsage implements store.BlobStore: the mailbox's counter (which may
// run above the truth until it is recomputed; fresh recomputes it, at
// most once per ReconcileInterval, and the sender's share), the sender's
// unexpired entries and the token's usage.
func (s *Store) BlobUsage(ctx context.Context, mailbox, sender, jti string, fresh bool) (store.BlobUsage, error) {
	var u store.BlobUsage
	if fresh {
		if _, err := s.reconcile(ctx, mailbox, kindStored); err != nil {
			return u, err
		}
		if sender != "" {
			if _, err := s.reconcileSender(ctx, mailbox, sender); err != nil {
				return u, err
			}
		}
	}
	keys := []item{key(mbPK(mailbox), skStats)}
	if sender != "" {
		keys = append(keys, key(mbPK(mailbox), senderSK(sender)))
	}
	if jti != "" {
		keys = append(keys, key(mbPK(mailbox), tokenSK(jti)))
	}
	req := map[string]types.KeysAndAttributes{s.cfg.Table: {Keys: keys, ConsistentRead: aws.Bool(true)}}
	now := s.now()
	for attempt := 0; len(req) > 0; attempt++ {
		res, err := s.cfg.DB.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: req})
		if err != nil {
			return u, err
		}
		for _, it := range res.Responses[s.cfg.Table] {
			switch sk := getS(it, "sk"); {
			case sk == skStats:
				u.MailboxBytes = getN0(it, "blob_bytes")
			case strings.HasPrefix(sk, "BS#"):
				u.SenderBlobs, u.SenderBytes = liveShare(it, now)
			case strings.HasPrefix(sk, "T#"):
				u.TokenBytes = getN0(it, "bytes")
			}
		}
		req = res.UnprocessedKeys
		if len(req) > 0 {
			if err := backoff(ctx, attempt); err != nil {
				return u, err
			}
		}
	}
	return u, nil
}

// ListBlobs implements store.BlobStore: one strongly consistent query of
// the mailbox's blob items (B#, which sort by id) from after on, and the
// mailbox's counter (recomputed first, at most once per
// ReconcileInterval, for a list's first page).
func (s *Store) ListBlobs(ctx context.Context, mailbox, after string, max int) ([]store.BlobInfo, string, int64, error) {
	if after == "" {
		if _, err := s.reconcile(ctx, mailbox, kindStored); err != nil {
			return nil, "", 0, err
		}
	}
	now := s.now()
	in := &dynamodb.QueryInput{
		TableName:                 &s.cfg.Table,
		KeyConditionExpression:    aws.String("pk = :pk AND begins_with(sk, :p)"),
		ExpressionAttributeValues: item{":pk": avS(mbPK(mailbox)), ":p": avS("B#")},
		ProjectionExpression:      aws.String("sk, sz, cr, exp, snd"),
		ConsistentRead:            aws.Bool(true),
		Limit:                     aws.Int32(int32(max + 1)),
	}
	if after != "" {
		in.ExclusiveStartKey = key(mbPK(mailbox), blobSK(after))
	}
	var out []store.BlobInfo
	for len(out) <= max {
		res, err := s.cfg.DB.Query(ctx, in)
		if err != nil {
			return nil, "", 0, err
		}
		for _, it := range res.Items {
			if getN0(it, "exp") <= ms(now) {
				continue // expired: not a blob any more (TTL or a recount removes it)
			}
			out = append(out, blobInfo(mailbox, it))
		}
		if len(res.LastEvaluatedKey) == 0 {
			break
		}
		in.ExclusiveStartKey = res.LastEvaluatedKey
	}
	next := ""
	if len(out) > max {
		out = out[:max]
		next = out[max-1].ID
	}
	st, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), skStats), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, "", 0, err
	}
	return out, next, max0(getN0(st.Item, "blob_bytes")), nil
}

func max0(n int64) int64 { return max(n, 0) }

// blobInfo reads a blob item. Items written before protocol 0.9.2 have no
// sender (snd) and no creation time (cr), which their ULID gives.
func blobInfo(mailbox string, it item) store.BlobInfo {
	id := strings.TrimPrefix(getS(it, "sk"), "B#")
	b := store.BlobInfo{ID: id, Mailbox: mailbox, Sender: getS(it, "snd"), Size: getN0(it, "sz"), ExpiresAt: fromMS(getN0(it, "exp"))}
	if cr, ok := getN(it, "cr"); ok {
		b.CreatedAt = fromMS(cr)
	} else if u, err := ulid.ParseStrict(id); err == nil {
		b.CreatedAt = ulid.Time(u.Time()).UTC()
	}
	return b
}

// OpenBlob implements store.BlobStore: the metadata (strongly consistent)
// decides existence, owner and expiry; the body streams from S3.
func (s *Store) OpenBlob(ctx context.Context, mailbox, blobID string) (store.BlobInfo, io.ReadCloser, error) {
	if s.cfg.S3 == nil {
		return store.BlobInfo{}, nil, store.ErrNotFound
	}
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), blobSK(blobID)), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return store.BlobInfo{}, nil, err
	}
	exp := getN0(out.Item, "exp")
	if len(out.Item) == 0 || exp <= ms(s.now()) {
		return store.BlobInfo{}, nil, store.ErrNotFound
	}
	obj, err := s.cfg.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.cfg.Bucket, Key: aws.String(blobKey(mailbox, blobID))})
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return store.BlobInfo{}, nil, store.ErrNotFound
	}
	if err != nil {
		return store.BlobInfo{}, nil, err
	}
	return blobInfo(mailbox, out.Item), obj.Body, nil
}

// DeleteBlob implements store.BlobStore (idempotent; other mailboxes' blobs
// are untouched because the key includes the mailbox). The blob leaves its
// sender's share with it.
func (s *Store) DeleteBlob(ctx context.Context, mailbox, blobID string) error {
	out, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), blobSK(blobID)), ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil || len(out.Attributes) == 0 {
		return err
	}
	var s3err, shareErr error
	if s.cfg.S3 != nil {
		_, s3err = s.cfg.S3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.cfg.Bucket, Key: aws.String(blobKey(mailbox, blobID))})
	}
	size := getN0(out.Attributes, "sz")
	if snd := getS(out.Attributes, "snd"); snd != "" {
		_, shareErr = s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName:                 &s.cfg.Table,
			Key:                       key(mbPK(mailbox), senderSK(snd)),
			UpdateExpression:          aws.String("REMOVE #e ADD b :nb, n :nn, v :one"),
			ConditionExpression:       aws.String("attribute_exists(#e)"),
			ExpressionAttributeNames:  map[string]string{"#e": senderEntryPrefix + blobID},
			ExpressionAttributeValues: item{":nb": avN(-size), ":nn": avN(-1), ":one": avN(1)},
		})
		if isCCF(shareErr) {
			shareErr = nil
		}
	}
	return errors.Join(s3err, shareErr, s.adjust(ctx, mailbox, map[string]int64{"blob_bytes": -size}))
}

// ------------------------------------------------------------------ claims

// PutClaim implements store.Backend: the claim item (keyed by its id, for
// the unauthenticated GET), a marker in the creator's mailbox and the
// storage charge commit together.
func (s *Store) PutClaim(ctx context.Context, mailbox string, data []byte, ttl time.Duration, maxStored int64) (string, time.Time, error) {
	size := int64(len(data))
	if maxStored > 0 && size > maxStored {
		return "", time.Time{}, store.ErrQuotaMailboxBlobs
	}
	id := auth.NewClaimID()
	exp := s.now().Add(ttl).UTC()
	extra := []types.TransactWriteItem{
		{Put: &types.Put{
			TableName: &s.cfg.Table,
			Item: item{
				"pk": avS(claimPK(id)), "sk": avS("CL"), "mb": avS(mailbox),
				"sz": avN(size), "exp": avN(ms(exp)), "ttl_s": avN(ttlSec(exp)), "body": avB(data),
			},
			ConditionExpression: aws.String("attribute_not_exists(pk)"),
		}},
		{Put: &types.Put{
			TableName: &s.cfg.Table,
			Item: item{
				"pk": avS(mbPK(mailbox)), "sk": avS(claimMarkSK(id)),
				"sz": avN(size), "exp": avN(ms(exp)), "ttl_s": avN(ttlSec(exp)),
			},
		}},
	}
	if err := s.chargeStored(ctx, mailbox, size, maxStored, time.Time{}, extra); err != nil {
		return "", time.Time{}, err
	}
	return id, exp, nil
}

// TakeClaim implements store.Backend. A conditional delete is the single
// fetch: exactly one caller gets the item back.
func (s *Store) TakeClaim(ctx context.Context, claimID string) ([]byte, error) {
	out, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(claimPK(claimID), "CL"),
		ConditionExpression:       aws.String("exp > :now"),
		ExpressionAttributeValues: item{":now": avN(ms(s.now()))},
		ReturnValues:              types.ReturnValueAllOld,
	})
	if isCCF(err) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	data := getB(out.Attributes, "body")
	s.releaseClaim(context.WithoutCancel(ctx), getS(out.Attributes, "mb"), claimID)
	return data, nil
}

// releaseClaim removes the creator's marker and its storage charge.
func (s *Store) releaseClaim(ctx context.Context, mailbox, claimID string) {
	out, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), claimMarkSK(claimID)), ReturnValues: types.ReturnValueAllOld,
	})
	if err == nil && len(out.Attributes) > 0 {
		_ = s.adjust(ctx, mailbox, map[string]int64{"blob_bytes": -getN0(out.Attributes, "sz")})
	}
}

// DeleteClaim implements store.Backend (only the creator's mailbox).
func (s *Store) DeleteClaim(ctx context.Context, mailbox, claimID string) error {
	_, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 &s.cfg.Table,
		Key:                       key(claimPK(claimID), "CL"),
		ConditionExpression:       aws.String("mb = :mb"),
		ExpressionAttributeValues: item{":mb": avS(mailbox)},
	})
	if isCCF(err) {
		return nil
	}
	if err != nil {
		return err
	}
	s.releaseClaim(ctx, mailbox, claimID)
	return nil
}
