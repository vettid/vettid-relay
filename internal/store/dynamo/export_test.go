package dynamo

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// SetBeforeRevive sets a hook that runs between Register's read of a dead
// mailbox and its revive (tests only).
func SetBeforeRevive(s *Store, f func()) { s.beforeRevive = f }

// SetBeforePurge sets a hook between the sweep's read of a tombstone and
// its purge (tests only).
func SetBeforePurge(s *Store, f func()) { s.beforePurge = f }

// SetBeforeMark sets a hook between DeleteMailbox's read and markDeleted
// (tests only).
func SetBeforeMark(s *Store, f func()) { s.beforeMark = f }

// SetDuringPurge sets a hook that runs once a purge holds the fence,
// before it deletes (tests only).
func SetDuringPurge(s *Store, f func()) { s.duringPurge = f }

// SetAfterPurge sets a hook that runs once a purge deleted everything,
// before its holder commits (tests only).
func SetAfterPurge(s *Store, f func()) { s.afterPurge = f }

// SetAfterMark sets a hook between a deletion's mark and its purge (tests
// only).
func SetAfterMark(s *Store, f func()) { s.afterMark = f }

// SetPurgeBudget overrides a purge's budget (tests only).
func SetPurgeBudget(s *Store, d time.Duration) { s.purgeBudget = d }

// ClearFence removes any purge fence from id's account item (tests only).
func ClearFence(s *Store, id string) {
	if _, err := s.cfg.DB.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(id), skAccount),
		UpdateExpression: aws.String("REMOVE purging, purge_by"),
	}); err != nil {
		panic(err)
	}
}

// AccountSS reads a string-set attribute of an account item (tests only).
func AccountSS(s *Store, id, attr string) []string {
	it, err := s.getAccount(context.Background(), id)
	if err != nil {
		panic(err)
	}
	if v, ok := it[attr].(*types.AttributeValueMemberSS); ok {
		return v.Value
	}
	return nil
}

// SetFence puts a purge fence on id's account item, taken at at (tests
// only): a purge that holds it, or one that died.
func SetFence(s *Store, id string, at time.Time) {
	if _, err := s.cfg.DB.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(id), skAccount),
		UpdateExpression:          aws.String("SET purging = :t, purge_by = :b"),
		ExpressionAttributeValues: item{":t": avN(ms(at)), ":b": avS("other")},
	}); err != nil {
		panic(err)
	}
}

// AccountHas reports whether id's account item has attr (tests only).
func AccountHas(s *Store, id, attr string) bool {
	it, err := s.getAccount(context.Background(), id)
	if err != nil {
		panic(err)
	}
	_, ok := it[attr]
	return ok
}

// ContentN counts a mailbox's items other than its account and counters
// items (tests only).
func ContentN(s *Store, id string) int {
	n := 0
	if err := s.queryAll(context.Background(), &dynamodb.QueryInput{
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: item{":pk": avS(mbPK(id))},
		ProjectionExpression:      aws.String("pk, sk"),
	}, func(it item) error {
		if sk := getS(it, "sk"); sk != skAccount && sk != skStats {
			n++
		}
		return nil
	}); err != nil {
		panic(err)
	}
	return n
}

// StatsN reads a number attribute of a mailbox's counters item (tests
// only).
func StatsN(s *Store, id, attr string) int64 {
	out, err := s.cfg.DB.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(id), skStats), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		panic(err)
	}
	return getN0(out.Item, attr)
}

// SetBeforeRotate sets a hook that runs between Rotate's reads and its
// write (tests only).
func SetBeforeRotate(s *Store, f func()) { s.beforeRotate = f }

// AccountN reads a number attribute of an account item (tests only).
func AccountN(s *Store, id, attr string) int64 {
	it, err := s.getAccount(context.Background(), id)
	if err != nil {
		panic(err)
	}
	return getN0(it, attr)
}

// SetAccountN sets number attributes of an account item (tests only): a
// state a race could leave.
func SetAccountN(s *Store, id string, attrs map[string]int64) {
	expr, vals := "SET", item{}
	i := 0
	for k, v := range attrs {
		if i > 0 {
			expr += ","
		}
		expr += " " + k + " = :v" + string(rune('a'+i))
		vals[":v"+string(rune('a'+i))] = avN(v)
		i++
	}
	if _, err := s.cfg.DB.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(id), skAccount),
		UpdateExpression: &expr, ExpressionAttributeValues: vals,
	}); err != nil {
		panic(err)
	}
}

// RemoveStatsNB removes nb from a mailbox's counters item (tests only): the
// state a sweep racing a deletion could leave before #11632.
func RemoveStatsNB(s *Store, id string) {
	if _, err := s.cfg.DB.UpdateItem(context.Background(), &dynamodb.UpdateItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(id), skStats), UpdateExpression: aws.String("REMOVE nb"),
	}); err != nil {
		panic(err)
	}
}

// StatsExists reports whether a mailbox's counters item exists (tests only).
func StatsExists(s *Store, id string) bool {
	out, err := s.cfg.DB.GetItem(context.Background(), &dynamodb.GetItemInput{
		TableName: &s.cfg.Table, Key: key(mbPK(id), skStats), ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		panic(err)
	}
	return len(out.Item) > 0
}
