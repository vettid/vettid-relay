package store_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/store/storetest"
)

// The SQLite sweep deletes expired code claims, and counts them.
func TestSweepDeletesExpiredCodeClaims(t *testing.T) {
	ctx := context.Background()
	c := storetest.NewClock()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "relay.db"), store.WithClock(c.Now))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err := s.Register(ctx, "a", bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutCode(ctx, store.CodePut{Mailbox: "a", ClaimID: "q4f7m2xk5n3p6r7t2v4w6y7z3a", KeyID: "k1", SaltID: "a12213d1",
		CodeMAC: bytes.Repeat([]byte{1}, 32), Salt: make([]byte, 16), Blob: []byte("x")}, 0); err != nil {
		t.Fatal(err)
	}
	if st, err := s.Sweep(ctx); err != nil || st.CodeClaims != 0 {
		t.Fatalf("live: %+v %v", st, err)
	}
	c.Add(store.CodeTTL)
	if st, err := s.Sweep(ctx); err != nil || st.CodeClaims != 1 {
		t.Fatalf("expired: %+v %v", st, err)
	}
}
