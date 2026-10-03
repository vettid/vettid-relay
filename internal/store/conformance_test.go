package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/store/storetest"
)

func TestConformanceSQLite(t *testing.T) {
	storetest.Run(t, storetest.Harness{
		New: func(t *testing.T, now func() time.Time) store.Backend {
			s, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "relay.db"), store.WithClock(now))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		},
	})
}
