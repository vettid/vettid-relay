package dynamo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Blob bodies live in S3 under blobs/<mailbox>/<blob id>; their metadata
// (size, expiry) and the mailbox storage counter live in DynamoDB. The
// metadata commits first (with the quota checks) and the body is uploaded
// after, so a body never exists without accounting; a reader that finds
// metadata but no body yet sees blob_unknown, and the uploader only learns
// the id once both are in place.

var errBlobsDisabled = errors.New("dynamo: blob storage not configured")

// chargeStored runs a transaction that adds delta to the mailbox's
// blob+claim byte counter (within maxStored) together with extra items,
// recomputing the counter once if the cap appears exceeded. extraQuota
// lists indexes of extra items whose condition failure means ErrQuota. A
// non-zero iat is the token's issue time (ErrRevoked before the mailbox's
// TokensNotBefore).
func (s *Store) chargeStored(ctx context.Context, mailbox string, delta, maxStored int64, iat time.Time, extra []types.TransactWriteItem, extraQuota ...int) error {
	reconciled := false
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
		for _, i := range extraQuota {
			if reasonCode(r, i+1) == "ConditionalCheckFailed" {
				return store.ErrQuota
			}
		}
		if reasonCode(r, 0) == "ConditionalCheckFailed" {
			if err := deadOrRevoked(r[0].Item, now, iat); err != nil {
				return err
			}
			if !reconciled {
				reconciled = true
				if ok, err := s.reconcile(ctx, mailbox, kindStored); err != nil {
					return err
				} else if ok {
					continue
				}
			}
			return store.ErrQuota
		}
		if !isConflict(r) || attempt >= maxTxAttempts {
			return fmt.Errorf("dynamo: %w", err)
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
}

// PutBlob implements store.BlobStore.
func (s *Store) PutBlob(ctx context.Context, p store.BlobPut, r io.Reader) (store.BlobInfo, error) {
	if s.cfg.S3 == nil {
		return store.BlobInfo{}, errBlobsDisabled
	}
	data, err := io.ReadAll(io.LimitReader(r, p.Size+1))
	if err != nil {
		return store.BlobInfo{}, err
	}
	if int64(len(data)) != p.Size {
		return store.BlobInfo{}, fmt.Errorf("store: blob size mismatch")
	}
	if (p.Limits.MailboxMaxBytes > 0 && p.Size > p.Limits.MailboxMaxBytes) || overTokenQuota(p.Limits, 0, p.Size) {
		return store.BlobInfo{}, store.ErrQuota
	}
	now := s.now()
	info := store.BlobInfo{ID: s.newID(now, ""), Mailbox: p.Mailbox, Size: p.Size, ExpiresAt: now.Add(p.TTL).UTC()}
	extra := []types.TransactWriteItem{{Put: &types.Put{
		TableName: &s.cfg.Table,
		Item: item{
			"pk": avS(mbPK(p.Mailbox)), "sk": avS(blobSK(info.ID)),
			"sz": avN(p.Size), "exp": avN(ms(info.ExpiresAt)), "ttl_s": avN(ttlSec(info.ExpiresAt)),
			"sender": avS(p.SenderSub),
		},
		ConditionExpression: aws.String("attribute_not_exists(sk)"),
	}}}
	var quotaIdx []int
	if u := s.tokenCharge(p.Mailbox, p.Limits, 0, p.Size); u != nil { // blobs count bytes only (§6.8)
		quotaIdx = append(quotaIdx, len(extra))
		extra = append(extra, types.TransactWriteItem{Update: u})
	}
	if err := s.chargeStored(ctx, p.Mailbox, p.Size, p.Limits.MailboxMaxBytes, p.Limits.TokenIssuedAt, extra, quotaIdx...); err != nil {
		return store.BlobInfo{}, err
	}
	_, err = s.cfg.S3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &s.cfg.Bucket,
		Key:           aws.String(blobKey(p.Mailbox, info.ID)),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(p.Size),
		ContentType:   aws.String("application/octet-stream"),
	})
	if err != nil {
		// Undo the accounting so the failed upload does not hold quota.
		_ = s.DeleteBlob(context.WithoutCancel(ctx), p.Mailbox, info.ID)
		return store.BlobInfo{}, fmt.Errorf("dynamo: blob upload: %w", err)
	}
	return info, nil
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
	return store.BlobInfo{ID: blobID, Mailbox: mailbox, Size: getN0(out.Item, "sz"), ExpiresAt: fromMS(exp)}, obj.Body, nil
}

// DeleteBlob implements store.BlobStore (idempotent; other mailboxes' blobs
// are untouched because the key includes the mailbox).
func (s *Store) DeleteBlob(ctx context.Context, mailbox, blobID string) error {
	out, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), blobSK(blobID)), ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil || len(out.Attributes) == 0 {
		return err
	}
	var s3err error
	if s.cfg.S3 != nil {
		_, s3err = s.cfg.S3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.cfg.Bucket, Key: aws.String(blobKey(mailbox, blobID))})
	}
	return errors.Join(s3err, s.adjust(ctx, mailbox, map[string]int64{"blob_bytes": -getN0(out.Attributes, "sz")}))
}

// ------------------------------------------------------------------ claims

// PutClaim implements store.Backend: the claim item (keyed by its id, for
// the unauthenticated GET), a marker in the creator's mailbox and the
// storage charge commit together.
func (s *Store) PutClaim(ctx context.Context, mailbox string, data []byte, ttl time.Duration, maxStored int64) (string, time.Time, error) {
	size := int64(len(data))
	if maxStored > 0 && size > maxStored {
		return "", time.Time{}, store.ErrQuota
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
