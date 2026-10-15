package store_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/store/storetest"
)

func TestConformanceSQLite(t *testing.T) {
	var mu sync.Mutex
	dirs := map[store.Backend]string{}
	storetest.Run(t, storetest.Harness{
		New: func(t *testing.T, now func() time.Time) store.Backend {
			dir := t.TempDir()
			s, err := store.Open(context.Background(), filepath.Join(dir, "relay.db"), store.WithClock(now))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			mu.Lock()
			dirs[s] = dir
			mu.Unlock()
			return s
		},
		// Staged bodies are files next to the database.
		Bodies: func(s store.Backend) int {
			mu.Lock()
			dir := dirs[s]
			mu.Unlock()
			n, _ := filepath.Glob(filepath.Join(dir, ".relay-blob-staged-*"))
			return len(n)
		},
	})
}
