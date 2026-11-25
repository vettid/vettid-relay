package dynamo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/vettid-relay/internal/store"
)

// Code claims (spec §6.9.1). Items:
//
//	pk                                   sk            what
//	PCB#<key id>#<salt_id>#<bucket hex>  <code_mac hex> the code claim: cid, ver, mb, salt, body, sz, exp, miss
//	PCI#<claim id>                       PCI           its id: mb, cpk, csk, ver, exp (the id namespace; DELETE)
//	MB#<mailbox>                         P#            the mailbox's one live code claim: cid, cpk, csk, ver, sz, exp
//
// ver is a random token each put writes into its three items: every
// write that must touch one put's items and no other's (a later PUT of the
// same id, even in the same millisecond) is conditional on it.
//	META                                 PCN#<epoch>   an hour's lookup salt nonce: nonce
//
// A redeem is a GetItem and a conditional delete in its claim's bucket
// partition; misses are a Query of that one partition. The P# marker
// counts toward the mailbox's storage cap (reconcile) and goes with the
// mailbox (purgeFenced). Every item has a TTL; a code claim is checked
// against exp wherever it is read.

const (
	skCodePtr = "P#"
	metaPK    = "META"
)

func codeBucketPK(keyID, saltID string, mac []byte) string {
	return fmt.Sprintf("PCB#%s#%s#%04x", keyID, saltID, store.CodeBucket(mac))
}
func codeSK(mac []byte) string     { return hex.EncodeToString(mac) }
func codeIDPK(id string) string    { return "PCI#" + id }
func nonceSK(epoch int64) string   { return "PCN#" + strconv.FormatInt(epoch, 10) }
func codeAttempts() int            { return maxTxAttempts }
func liveCond() string             { return "attribute_not_exists(pk) OR exp <= :now OR mb = :mb" }
func live(it item, now int64) bool { n, ok := getN(it, "exp"); return ok && n > now }

var (
	errCodeCollision = errors.New("dynamo: code collision")
	errCodePtrMoved  = errors.New("dynamo: code pointer moved")
	errCodeOldGone   = errors.New("dynamo: old code claim gone")
)

// codePtr reads mailbox's P# marker (nil if none).
func (s *Store) codePtr(ctx context.Context, mailbox string) (item, error) {
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(mailbox), skCodePtr), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	return out.Item, nil
}

// DeleteMailboxCode implements store.CodeBackend.
func (s *Store) DeleteMailboxCode(ctx context.Context, mailbox string) error {
	p, err := s.codePtr(ctx, mailbox)
	if err != nil || p == nil {
		return err
	}
	return s.dropCode(ctx, mailbox, getS(p, "cid"), getS(p, "cpk"), getS(p, "csk"), getS(p, "ver"), false)
}

// dropCode deletes code claim cid of mailbox, the one put with token ver:
// the claim first unless claimGone (it is unredeemable from then on), then
// its id and the mailbox's marker, whose charge is given back. Each delete
// is conditional on naming cid, its slot and ver, so nothing of a later
// claim goes, not even one PUT again with the same id and tag (a PUT
// retried after a lost 201, §6.9.1 step 1), which has its own ver.
func (s *Store) dropCode(ctx context.Context, mailbox, cid, cpk, csk, ver string, claimGone bool) error {
	vals := item{":cid": avS(cid), ":ver": avS(ver)}
	at := item{":mb": avS(mailbox), ":cpk": avS(cpk), ":csk": avS(csk), ":ver": avS(ver)}
	ptr := item{":cid": avS(cid), ":cpk": avS(cpk), ":csk": avS(csk), ":ver": avS(ver)}
	if !claimGone {
		if s.beforeCodeDrop != nil {
			s.beforeCodeDrop()
		}
		if err := s.retryConflicts(ctx, func() error {
			_, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName: &s.cfg.Table, Key: key(cpk, csk),
				ConditionExpression: aws.String("cid = :cid AND ver = :ver"), ExpressionAttributeValues: vals,
			})
			return err
		}); err != nil && !isCCF(err) {
			return err
		}
	}
	if s.beforeCodeCleanup != nil {
		s.beforeCodeCleanup()
	}
	if err := s.retryConflicts(ctx, func() error {
		_, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: &s.cfg.Table, Key: key(codeIDPK(cid), "PCI"),
			ConditionExpression: aws.String("mb = :mb AND cpk = :cpk AND csk = :csk AND ver = :ver"), ExpressionAttributeValues: at,
		})
		return err
	}); err != nil && !isCCF(err) {
		return err
	}
	var out *dynamodb.DeleteItemOutput
	err := s.retryConflicts(ctx, func() error {
		var err error
		out, err = s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: &s.cfg.Table, Key: key(mbPK(mailbox), skCodePtr),
			ConditionExpression: aws.String("cid = :cid AND cpk = :cpk AND csk = :csk AND ver = :ver"), ExpressionAttributeValues: ptr,
			ReturnValues: types.ReturnValueAllOld,
		})
		return err
	})
	if isCCF(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(out.Attributes) > 0 {
		return s.adjust(ctx, mailbox, map[string]int64{"blob_bytes": -getN0(out.Attributes, "sz")})
	}
	return nil
}

// retryConflicts runs f again, after a backoff, while it fails only
// because a transaction on its item was in flight (nothing was written);
// a lost race must end as a condition failure, never as a fault.
func (s *Store) retryConflicts(ctx context.Context, f func() error) error {
	for attempt := 0; ; attempt++ {
		err := f()
		conflict := isTxConflict(err)
		if r := txReasons(err); r != nil && isConflict(r) && reasonCode(r, 0) != "ConditionalCheckFailed" {
			conflict = true
		}
		if !conflict || attempt >= maxTxAttempts {
			return err
		}
		if err := backoff(ctx, attempt); err != nil {
			return err
		}
	}
}

// PutCode implements store.CodeBackend. One transaction charges the
// mailbox's storage (less its old code claim's size), deletes its old
// code claim, puts the claim, its id and the mailbox's marker; the marker
// is conditional on being the one read, so two PUTs of one mailbox can't
// both leave a live claim. A collision deletes the live claim it met.
func (s *Store) PutCode(ctx context.Context, c store.CodePut, maxStored int64) (time.Time, error) {
	size := int64(len(c.Blob))
	if maxStored > 0 && size > maxStored {
		return time.Time{}, store.ErrQuotaMailboxBlobs
	}
	cpk, csk := codeBucketPK(c.KeyID, c.SaltID, c.CodeMAC), codeSK(c.CodeMAC)
	skipOld := "" // the old claim (id and ver) whose keys name another claim now
	for attempt := 0; ; attempt++ {
		if attempt > codeAttempts() {
			return time.Time{}, fmt.Errorf("dynamo: code claim put kept conflicting")
		}
		now := s.now()
		exp := now.Add(store.CodeTTL).UTC()
		ver := redeemToken()
		old, err := s.codePtr(ctx, c.Mailbox)
		if err != nil {
			return time.Time{}, err
		}
		vals := item{":now": avN(ms(now)), ":mb": avS(c.Mailbox)}
		var extra []types.TransactWriteItem
		var checks []extraCheck
		extra = append(extra, types.TransactWriteItem{Put: &types.Put{
			TableName: &s.cfg.Table,
			Item: item{"pk": avS(cpk), "sk": avS(csk), "cid": avS(c.ClaimID), "ver": avS(ver), "mb": avS(c.Mailbox),
				"salt": avB(c.Salt), "body": avB(c.Blob), "sz": avN(size), "exp": avN(ms(exp)),
				"ttl_s": avN(ttlSec(exp)), "miss": avN(0)},
			ConditionExpression: aws.String(liveCond()), ExpressionAttributeValues: vals,
		}})
		extra = append(extra, types.TransactWriteItem{Put: &types.Put{
			TableName: &s.cfg.Table,
			Item: item{"pk": avS(codeIDPK(c.ClaimID)), "sk": avS("PCI"), "mb": avS(c.Mailbox),
				"cpk": avS(cpk), "csk": avS(csk), "ver": avS(ver), "exp": avN(ms(exp)), "ttl_s": avN(ttlSec(exp))},
			ConditionExpression: aws.String(liveCond()), ExpressionAttributeValues: vals,
		}})
		// The claim id first, then the collision (§6.9.1 steps 2 and 4).
		checks = append(checks, extraCheck{idx: 1, err: store.ErrClaimIDTaken}, extraCheck{idx: 0, err: errCodeCollision})
		ptr := &types.Put{
			TableName: &s.cfg.Table,
			Item: item{"pk": avS(mbPK(c.Mailbox)), "sk": avS(skCodePtr), "cid": avS(c.ClaimID),
				"cpk": avS(cpk), "csk": avS(csk), "ver": avS(ver), "sz": avN(size), "exp": avN(ms(exp)), "ttl_s": avN(ttlSec(exp))},
			ConditionExpression: aws.String("attribute_not_exists(sk)"),
		}
		delta := size
		if old != nil {
			// The marker read, and no other: a same-id re-PUT between the
			// read and this transaction writes its own ver, and this one
			// starts again from it.
			ptr.ConditionExpression = aws.String("cid = :ocid AND ver = :over")
			ptr.ExpressionAttributeValues = item{":ocid": avS(getS(old, "cid")), ":over": avS(getS(old, "ver"))}
			delta -= getN0(old, "sz")
		}
		extra = append(extra, types.TransactWriteItem{Put: ptr})
		checks = append(checks, extraCheck{idx: 2, err: errCodePtrMoved})
		if old != nil && oldKey(old) != skipOld {
			ocid, ocpk, ocsk, over := getS(old, "cid"), getS(old, "cpk"), getS(old, "csk"), getS(old, "ver")
			if ocpk != cpk || ocsk != csk {
				extra = append(extra, types.TransactWriteItem{Delete: &types.Delete{
					TableName: &s.cfg.Table, Key: key(ocpk, ocsk),
					ConditionExpression:       aws.String("attribute_not_exists(pk) OR (cid = :ocid AND ver = :over)"),
					ExpressionAttributeValues: item{":ocid": avS(ocid), ":over": avS(over)},
				}})
				checks = append(checks, extraCheck{idx: len(extra) - 1, err: errCodeOldGone})
			}
			if ocid != c.ClaimID {
				extra = append(extra, types.TransactWriteItem{Delete: &types.Delete{
					TableName: &s.cfg.Table, Key: key(codeIDPK(ocid), "PCI"),
					ConditionExpression:       aws.String("attribute_not_exists(pk) OR (mb = :mb AND ver = :over)"),
					ExpressionAttributeValues: item{":mb": avS(c.Mailbox), ":over": avS(over)},
				}})
				checks = append(checks, extraCheck{idx: len(extra) - 1, err: errCodeOldGone})
			}
		}
		err = s.chargeStored(ctx, c.Mailbox, delta, maxStored, time.Time{}, extra, checks...)
		switch {
		case err == nil:
			return exp, nil
		case errors.Is(err, errCodePtrMoved):
			continue
		case errors.Is(err, errCodeOldGone):
			// The old claim's keys name another claim now: leave them,
			// for that old claim only.
			skipOld = oldKey(old)
			continue
		case errors.Is(err, errCodeCollision):
			done, err := s.collide(ctx, cpk, csk, now)
			if err != nil {
				return time.Time{}, err
			}
			if done {
				// This mailbox's own old claim goes too (step 1).
				if err := s.DeleteMailboxCode(ctx, c.Mailbox); err != nil {
					return time.Time{}, err
				}
				return time.Time{}, store.ErrCodeTaken
			}
			continue // it went meanwhile: try again
		default:
			return time.Time{}, err
		}
	}
}

// collide deletes the live code claim at cpk/csk that a new claim's
// code_mac met, in one transaction with its id, its mailbox's marker and
// that marker's charge. It reports false if no live claim is there (it
// was redeemed, cancelled or expired meanwhile).
func (s *Store) collide(ctx context.Context, cpk, csk string, now time.Time) (bool, error) {
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(cpk, csk), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return false, err
	}
	if !live(out.Item, ms(now)) {
		return false, nil
	}
	cid, mb, sz, ver := getS(out.Item, "cid"), getS(out.Item, "mb"), getN0(out.Item, "sz"), getS(out.Item, "ver")
	vals := item{":cid": avS(cid), ":ver": avS(ver)}
	_, err = s.cfg.DB.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Delete: &types.Delete{TableName: &s.cfg.Table, Key: key(cpk, csk),
			ConditionExpression: aws.String("cid = :cid AND ver = :ver"), ExpressionAttributeValues: vals}},
		{Delete: &types.Delete{TableName: &s.cfg.Table, Key: key(codeIDPK(cid), "PCI"),
			ConditionExpression: aws.String("attribute_not_exists(pk) OR ver = :ver"), ExpressionAttributeValues: item{":ver": avS(ver)}}},
		{Delete: &types.Delete{TableName: &s.cfg.Table, Key: key(mbPK(mb), skCodePtr),
			ConditionExpression: aws.String("attribute_not_exists(pk) OR (cid = :cid AND ver = :ver)"), ExpressionAttributeValues: vals}},
	}})
	if r := txReasons(err); r != nil && (reasonCode(r, 0) == "ConditionalCheckFailed" || isConflict(r)) {
		return false, nil // gone or moving meanwhile: the put tries again
	} else if r != nil && (reasonCode(r, 1) == "ConditionalCheckFailed" || reasonCode(r, 2) == "ConditionalCheckFailed") {
		// The victim's id or marker names a newer claim of its mailbox:
		// only the claim met goes (its marker and charge stay with the
		// newer one, or expire).
		_, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: &s.cfg.Table, Key: key(cpk, csk),
			ConditionExpression: aws.String("cid = :cid AND ver = :ver"), ExpressionAttributeValues: vals,
		})
		if isCCF(err) {
			return false, nil
		}
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	return true, s.adjust(ctx, mb, map[string]int64{"blob_bytes": -sz})
}

// RedeemCode implements store.CodeBackend.
func (s *Store) RedeemCode(ctx context.Context, keyID string, lookups []store.CodeLookup, dry bool) (store.CodeClaim, error) {
	now := ms(s.now())
	matched := false
	for _, l := range lookups {
		cpk, csk := codeBucketPK(keyID, l.SaltID, l.CodeMAC), codeSK(l.CodeMAC)
		out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
			TableName: &s.cfg.Table, Key: key(cpk, csk), ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return store.CodeClaim{}, err
		}
		if dry || !live(out.Item, now) {
			continue
		}
		matched = true
		cid, a := getS(out.Item, "cid"), out.Item
		// The delete is a one-item transaction with a request token, so
		// an SDK retry after a lost answer is idempotent: a commit is
		// never reported as a lost race. ver pins the item read (a PUT
		// again by its mailbox rewrites the slot with its own ver), and a
		// claim its misses cancel can't be redeemed (limit 15). It runs
		// to its end even if the request goes: a commit must reach the
		// 200 it was made for.
		dctx := context.WithoutCancel(ctx)
		err = s.retryConflicts(dctx, func() error {
			_, err := s.cfg.DB.TransactWriteItems(dctx, &dynamodb.TransactWriteItemsInput{
				ClientRequestToken: aws.String(redeemToken()),
				TransactItems: []types.TransactWriteItem{{Delete: &types.Delete{
					TableName: &s.cfg.Table, Key: key(cpk, csk),
					ConditionExpression: aws.String("cid = :cid AND ver = :ver AND exp > :now AND miss < :max"),
					ExpressionAttributeValues: item{":cid": avS(cid), ":ver": avS(getS(a, "ver")), ":now": avN(now),
						":max": avN(store.CodeMaxMisses)},
				}}},
			})
			return err
		})
		if r := txReasons(err); r != nil && reasonCode(r, 0) == "ConditionalCheckFailed" {
			continue // lost the race
		}
		if err != nil {
			return store.CodeClaim{}, err
		}
		c := store.CodeClaim{ClaimID: cid, Salt: getB(a, "salt"), Blob: getB(a, "body"), ExpiresAt: fromMS(getN0(a, "exp"))}
		// Best effort, as for a claim (releaseClaim): the claim is gone,
		// and a left-over id or marker expires with it.
		_ = s.dropCode(dctx, getS(a, "mb"), cid, cpk, csk, getS(a, "ver"), true)
		return c, nil
	}
	if matched {
		return store.CodeClaim{}, store.ErrNotFound
	}
	for _, l := range lookups {
		if err := s.codeMisses(ctx, codeBucketPK(keyID, l.SaltID, l.CodeMAC), now, dry); err != nil {
			return store.CodeClaim{}, err
		}
	}
	return store.CodeClaim{}, store.ErrNotFound
}

// codeMisses adds one miss to each live code claim in bucket partition
// cpk (only reads it when dry), and deletes those that reach
// store.CodeMaxMisses. Every write is conditional on the claim's id, so a
// match and a cancel can't both win.
func (s *Store) codeMisses(ctx context.Context, cpk string, now int64, dry bool) error {
	var live []item
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: item{":pk": avS(cpk)},
		ProjectionExpression:      aws.String("pk, sk, cid, ver, mb, exp"),
		ConsistentRead:            aws.Bool(true),
	}, func(it item) error {
		if n, _ := getN(it, "exp"); n > now {
			live = append(live, it)
		}
		return nil
	})
	if err != nil || dry {
		return err
	}
	for _, it := range live {
		cid, csk, ver := getS(it, "cid"), getS(it, "sk"), getS(it, "ver")
		var out *dynamodb.UpdateItemOutput
		err := s.retryConflicts(ctx, func() error {
			var err error
			out, err = s.cfg.DB.UpdateItem(ctx, &dynamodb.UpdateItemInput{
				TableName: &s.cfg.Table, Key: key(cpk, csk),
				UpdateExpression:          aws.String("ADD miss :one"),
				ConditionExpression:       aws.String("cid = :cid AND ver = :ver AND exp > :now"),
				ExpressionAttributeValues: item{":one": avN(1), ":cid": avS(cid), ":ver": avS(ver), ":now": avN(now)},
				ReturnValues:              types.ReturnValueUpdatedNew,
			})
			return err
		})
		if isCCF(err) {
			continue
		}
		if err != nil {
			return err
		}
		if getN0(out.Attributes, "miss") < store.CodeMaxMisses {
			continue
		}
		err = s.retryConflicts(ctx, func() error {
			_, err := s.cfg.DB.DeleteItem(ctx, &dynamodb.DeleteItemInput{
				TableName: &s.cfg.Table, Key: key(cpk, csk),
				ConditionExpression:       aws.String("cid = :cid AND ver = :ver AND miss >= :max"),
				ExpressionAttributeValues: item{":cid": avS(cid), ":ver": avS(ver), ":max": avN(store.CodeMaxMisses)},
			})
			return err
		})
		if isCCF(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err := s.dropCode(ctx, getS(it, "mb"), cid, cpk, csk, ver, true); err != nil {
			return err
		}
	}
	return nil
}

// DeleteCode implements store.CodeBackend.
func (s *Store) DeleteCode(ctx context.Context, mailbox, claimID string) error {
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(codeIDPK(claimID), "PCI"), ConsistentRead: aws.Bool(true),
	})
	if err != nil || out.Item == nil || getS(out.Item, "mb") != mailbox {
		return err
	}
	return s.dropCode(ctx, mailbox, claimID, getS(out.Item, "cpk"), getS(out.Item, "csk"), getS(out.Item, "ver"), false)
}

// PairCodeNonce implements store.CodeBackend.
func (s *Store) PairCodeNonce(ctx context.Context, epoch int64, fresh []byte) ([]byte, error) {
	keep := time.Unix((epoch+26)*3600, 0)
	_, err := s.cfg.DB.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &s.cfg.Table,
		Item:                item{"pk": avS(metaPK), "sk": avS(nonceSK(epoch)), "nonce": avB(fresh), "ttl_s": avN(ttlSec(keep))},
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	if err != nil && !isCCF(err) {
		return nil, err
	}
	out, err := s.cfg.DB.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(metaPK, nonceSK(epoch)), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	n := getB(out.Item, "nonce")
	if len(n) == 0 {
		return nil, errors.New("dynamo: pair code nonce missing")
	}
	return n, nil
}

var _ store.CodeBackend = (*Store)(nil)

// redeemToken is a fresh ClientRequestToken (36 characters at most).
func redeemToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// oldKey names a marker's claim by id and ver, for PutCode's skipOld.
func oldKey(old item) string { return getS(old, "cid") + "#" + getS(old, "ver") }
