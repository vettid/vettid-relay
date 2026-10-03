package dynamo_test

import (
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/store/dynamo"
	"github.com/vettid/vettid-relay/internal/store/storetest"
	"github.com/vettid/vettid-relay/internal/testutil/ddblocal"
	"github.com/vettid/vettid-relay/internal/testutil/fakes3"
)

func TestConformanceDynamo(t *testing.T) {
	db := ddblocal.Client(t)
	mk := func(t *testing.T, table string, s3 *fakes3.Server, now func() time.Time) store.Backend {
		st, err := dynamo.New(dynamo.Config{Table: table, Bucket: "blobs", DB: db, S3: s3.Client(), Now: now})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	storetest.Run(t, storetest.Harness{
		New: func(t *testing.T, now func() time.Time) store.Backend {
			return mk(t, ddblocal.Table(t, db), fakes3.New(t), now)
		},
		// Two relay processes: separate Store instances (own caches and ID
		// generators) on one table and bucket.
		Pair: func(t *testing.T, now func() time.Time) (store.Backend, store.Backend) {
			table, s3 := ddblocal.Table(t, db), fakes3.New(t)
			return mk(t, table, s3, now), mk(t, table, s3, now)
		},
		SweepGrace: 10 * time.Minute,
	})
}
