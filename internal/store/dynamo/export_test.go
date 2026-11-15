package dynamo

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
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
