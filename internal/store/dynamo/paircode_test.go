package dynamo_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/store/dynamo"
	"github.com/vettid/vettid-relay/internal/store/storetest"
	"github.com/vettid/vettid-relay/internal/testutil/ddblocal"
	"github.com/vettid/vettid-relay/internal/testutil/fakes3"
)

func codeStore(t *testing.T) (*dynamo.Store, *storetest.Clock) {
	t.Helper()
	db := ddblocal.Client(t)
	table := ddblocal.Table(t, db)
	c := storetest.NewClock()
	s, err := dynamo.New(dynamo.Config{Table: table, DB: db, S3: fakes3.New(t).Client(), Bucket: "b", Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(ctx, "a", make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	return s, c
}

func codeMAC(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func codePut(id string, mac []byte) store.CodePut {
	return store.CodePut{Mailbox: "a", ClaimID: id, KeyID: "k1", SaltID: "a12213d1", CodeMAC: mac,
		Salt: make([]byte, 16), Blob: []byte("bundle")}
}

func codeLook(mac []byte) []store.CodeLookup {
	return []store.CodeLookup{{SaltID: "a12213d1", CodeMAC: mac}}
}

const (
	codeID1 = "q4f7m2xk5n3p6r7t2v4w6y7z3a"
	codeID2 = "b4f7m2xk5n3p6r7t2v4w6y7z3a"
)

// The same code PUT again (§6.9.1 step 1: a PUT retried after a lost 201)
// between a claim's delete and the cleanup of its id and marker: the
// cleanup leaves the new claim's id and marker, so the new claim stays
// tracked (the mailbox's next PUT replaces it) and is never orphaned.
func TestCodeCleanupLeavesARePut(t *testing.T) {
	for _, path := range []string{"delete", "redeem"} {
		t.Run(path, func(t *testing.T) {
			s, c := codeStore(t)
			m := codeMAC(1)
			if _, err := s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
				t.Fatal(err)
			}
			once := false
			dynamo.SetBeforeCodeCleanup(s, func() {
				if once {
					return
				}
				once = true
				c.Add(time.Second) // a later exp
				if _, err := s.PutCode(ctx, codePut(codeID1, m), 0); err != nil {
					t.Error(err)
				}
			})
			switch path {
			case "delete":
				if err := s.DeleteCode(ctx, "a", codeID1); err != nil {
					t.Fatal(err)
				}
			case "redeem":
				if _, err := s.RedeemCode(ctx, "k1", codeLook(m), false); err != nil {
					t.Fatal(err)
				}
			}
			dynamo.SetBeforeCodeCleanup(s, nil)
			if !once {
				t.Fatal("the hook didn't run")
			}
			// The re-PUT claim is tracked: the mailbox's next PUT
			// replaces it, so it can't be redeemed after that.
			m2 := codeMAC(2)
			if _, err := s.PutCode(ctx, codePut(codeID2, m2), 0); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RedeemCode(ctx, "k1", codeLook(m), false); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the re-PUT claim was orphaned (still live after a replacement): %v", err)
			}
			if got, err := s.RedeemCode(ctx, "k1", codeLook(m2), false); err != nil || got.ClaimID != codeID2 {
				t.Fatalf("the replacement: %+v %v", got, err)
			}
		})
	}
}

// A collision removes the victim's id and its marker's charge: the victim
// mailbox can use the id again, within a cap the old claim filled.
func TestCodeCollisionFreesTheVictim(t *testing.T) {
	s, _ := codeStore(t)
	if _, _, err := s.Register(ctx, "b", bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	m := codeMAC(3)
	p := codePut(codeID1, m)
	if _, err := s.PutCode(ctx, p, int64(len(p.Blob))); err != nil {
		t.Fatal(err)
	}
	q := codePut(codeID2, m)
	q.Mailbox = "b"
	if _, err := s.PutCode(ctx, q, 0); !errors.Is(err, store.ErrCodeTaken) {
		t.Fatalf("collision: %v", err)
	}
	// The victim's id is free again, and its cap is free (the marker went).
	if _, err := s.PutCode(ctx, codePut(codeID1, codeMAC(4)), int64(len(p.Blob))); err != nil {
		t.Fatalf("the victim's id or cap after the collision: %v", err)
	}
}
