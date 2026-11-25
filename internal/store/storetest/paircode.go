package storetest

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/store"
)

// Code claims (spec §6.9.1).

// mac is a 32-byte code_mac whose bucket is bucket and whose rest is b.
func mac(bucket int, b byte) []byte {
	m := bytes.Repeat([]byte{b}, 32)
	m[0], m[1] = byte(bucket>>8), byte(bucket)
	return m
}

func codePut(mailbox, claimID string, m []byte) store.CodePut {
	return store.CodePut{Mailbox: mailbox, ClaimID: claimID, KeyID: "k1", SaltID: "a12213d1", CodeMAC: m,
		Salt: bytes.Repeat([]byte{7}, 16), Blob: []byte("sealed bundle")}
}

func look(m []byte) []store.CodeLookup { return []store.CodeLookup{{SaltID: "a12213d1", CodeMAC: m}} }

const (
	cid1 = "q4f7m2xk5n3p6r7t2v4w6y7z3a"
	cid2 = "b4f7m2xk5n3p6r7t2v4w6y7z3a"
	cid3 = "c4f7m2xk5n3p6r7t2v4w6y7z3a"
)

func testCodeClaims(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	m1 := mac(7, 1)
	exp, err := s.PutCode(ctx, codePut("a", cid1, m1), 0)
	if err != nil || !exp.Equal(c.Now().Add(store.CodeTTL)) {
		t.Fatalf("put: %v %v", exp, err)
	}
	// Another mailbox can't delete it; a redeem under another key id, or
	// with another salt, doesn't find it.
	if err := s.DeleteCode(ctx, "b", cid1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemCode(ctx, "k2", look(m1), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other key id: %v", err)
	}
	if _, err := s.RedeemCode(ctx, "k1", []store.CodeLookup{{SaltID: "00000000", CodeMAC: m1}}, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other salt: %v", err)
	}
	// A dry redeem never matches.
	if _, err := s.RedeemCode(ctx, "k1", look(m1), true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("dry: %v", err)
	}
	got, err := s.RedeemCode(ctx, "k1", []store.CodeLookup{{SaltID: "a12213d1", CodeMAC: mac(9, 9)}, {SaltID: "a12213d1", CodeMAC: m1}}, false)
	if err != nil || got.ClaimID != cid1 || string(got.Blob) != "sealed bundle" || !bytes.Equal(got.Salt, bytes.Repeat([]byte{7}, 16)) || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("redeem: %+v %v", got, err)
	}
	if _, err := s.RedeemCode(ctx, "k1", look(m1), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second redeem: %v", err)
	}
	// Expired.
	if _, err := s.PutCode(ctx, codePut("a", cid1, m1), 0); err != nil {
		t.Fatalf("put again after redeem: %v", err)
	}
	c.Add(store.CodeTTL)
	if _, err := s.RedeemCode(ctx, "k1", look(m1), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired redeem: %v", err)
	}
	// An expired claim frees its id and its code_mac.
	if _, err := s.PutCode(ctx, codePut("b", cid1, m1), 0); err != nil {
		t.Fatalf("put over an expired claim: %v", err)
	}
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	// Deleted by its creator.
	if err := s.DeleteCode(ctx, "b", cid1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemCode(ctx, "k1", look(m1), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted claim redeemed: %v", err)
	}
	if err := s.DeleteCode(ctx, "b", cid1); err != nil {
		t.Fatalf("delete again: %v", err)
	}
	// A claim id in use by another live code claim.
	if _, err := s.PutCode(ctx, codePut("a", cid1, m1), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutCode(ctx, codePut("b", cid1, mac(8, 2)), 0); !errors.Is(err, store.ErrClaimIDTaken) {
		t.Fatalf("claim id taken: %v", err)
	}
	// One live code claim per mailbox.
	if err := s.DeleteMailboxCode(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemCode(ctx, "k1", look(m1), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replaced claim redeemed: %v", err)
	}
	// A collision deletes both.
	if _, err := s.PutCode(ctx, codePut("a", cid1, m1), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutCode(ctx, codePut("b", cid2, m1), 0); !errors.Is(err, store.ErrCodeTaken) {
		t.Fatalf("collision: %v", err)
	}
	if _, err := s.RedeemCode(ctx, "k1", look(m1), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("collided claim redeemed: %v", err)
	}
	// Nor was the second one stored: its id is free.
	if _, err := s.PutCode(ctx, codePut("b", cid2, mac(8, 2)), 0); err != nil {
		t.Fatalf("id of the refused claim: %v", err)
	}
	if err := s.DeleteMailboxCode(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	// A deleted mailbox (one deleted while its request ran).
	mustRegister(t, s, "zz", 3)
	if _, err := s.DeleteMailbox(ctx, "zz", key(3), c.Now(), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutCode(ctx, codePut("zz", cid3, mac(1, 3)), 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted mailbox: %v", err)
	}
}

func testCodeClaimsCap(t *testing.T, h Harness) {
	s, _ := h.open(t)
	mustRegister(t, s, "a", 1)
	// Code claims share the creator's storage cap with claims and blobs.
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 600), time.Hour, 1000); err != nil {
		t.Fatal(err)
	}
	p := codePut("a", cid1, mac(1, 1))
	p.Blob = make([]byte, 401)
	if _, err := s.PutCode(ctx, p, 1000); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("over cap: %v", err)
	}
	p.Blob = make([]byte, 400)
	if _, err := s.PutCode(ctx, p, 1000); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 1), time.Hour, 1000); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("claim over a cap the code claim fills: %v", err)
	}
	// A redeemed code claim frees its share.
	if _, err := s.RedeemCode(ctx, "k1", look(p.CodeMAC), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 400), time.Hour, 1000); err != nil {
		t.Fatalf("cap not freed by the redeem: %v", err)
	}
}

func testCodeMisses(t *testing.T, h Harness) {
	s, _ := h.open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	mustRegister(t, s, "c", 3)
	m := mac(5, 1)
	if _, err := s.PutCode(ctx, codePut("a", cid1, m), 0); err != nil {
		t.Fatal(err)
	}
	other := mac(6, 2) // another bucket
	if _, err := s.PutCode(ctx, codePut("b", cid2, other), 0); err != nil {
		t.Fatal(err)
	}
	same := mac(5, 3) // the same bucket, matched below
	if _, err := s.PutCode(ctx, codePut("c", cid3, same), 0); err != nil {
		t.Fatal(err)
	}
	miss := mac(5, 9) // the same bucket, no match
	// None of these add misses: dry redeems, misses under another key id
	// or salt, and a request in which a tag matched.
	for range store.CodeMaxMisses {
		if _, err := s.RedeemCode(ctx, "k1", look(miss), true); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := s.RedeemCode(ctx, "k2", look(miss), false); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := s.RedeemCode(ctx, "k1", []store.CodeLookup{{SaltID: "00000000", CodeMAC: miss}}, false); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
	}
	if got, err := s.RedeemCode(ctx, "k1", []store.CodeLookup{{SaltID: "a12213d1", CodeMAC: miss}, {SaltID: "a12213d1", CodeMAC: same}}, false); err != nil || got.ClaimID != cid3 {
		t.Fatalf("a matching request: %+v %v", got, err)
	}
	// 31 misses: still live.
	for i := range store.CodeMaxMisses - 1 {
		if _, err := s.RedeemCode(ctx, "k1", look(miss), false); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("miss %d: %v", i, err)
		}
	}
	if got, err := s.RedeemCode(ctx, "k1", look(m), false); err != nil || got.ClaimID != cid1 {
		t.Fatalf("after %d misses: %+v %v", store.CodeMaxMisses-1, got, err)
	}
	// 32 cancel it.
	if _, err := s.PutCode(ctx, codePut("a", cid1, m), 0); err != nil {
		t.Fatal(err)
	}
	for range store.CodeMaxMisses {
		s.RedeemCode(ctx, "k1", look(miss), false)
	}
	if _, err := s.RedeemCode(ctx, "k1", look(m), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("redeemed after %d misses: %v", store.CodeMaxMisses, err)
	}
	// The other bucket's claim took no misses.
	if got, err := s.RedeemCode(ctx, "k1", look(other), false); err != nil || got.ClaimID != cid2 {
		t.Fatalf("other bucket: %+v %v", got, err)
	}
}

// A code claim goes with its mailbox.
func testCodeClaimsDeletedMailbox(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	m := mac(1, 1)
	if _, err := s.PutCode(ctx, codePut("a", cid1, m), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", key(1), c.Now(), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemCode(ctx, "k1", look(m), false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("code claim of a deleted mailbox: %v", err)
	}
	mustRegister(t, s, "b", 2)
	if _, err := s.PutCode(ctx, codePut("b", cid1, m), 0); err != nil {
		t.Fatalf("the deleted claim's id and code_mac: %v", err)
	}
}

// Across processes, exactly one redeem of a code claim wins.
func testRedeemCodeConcurrent(t *testing.T, h Harness) {
	a, b, _ := h.pair(t)
	mustRegister(t, a, "a", 1)
	m := mac(3, 3)
	if _, err := a.PutCode(ctx, codePut("a", cid1, m), 0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	hits := 0
	for i := range 20 {
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.RedeemCode(ctx, "k1", look(m), false)
			switch {
			case err == nil:
				mu.Lock()
				hits++
				mu.Unlock()
				if got.ClaimID != cid1 {
					t.Error("claim id")
				}
			case !errors.Is(err, store.ErrNotFound):
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if hits != 1 {
		t.Fatalf("code claim redeemed %d times", hits)
	}
}

// An epoch's nonce is the first one stored, on every process.
func testPairCodeNonce(t *testing.T, h Harness) {
	a, b, _ := h.pair(t)
	n1 := bytes.Repeat([]byte{1}, 16)
	n2 := bytes.Repeat([]byte{2}, 16)
	got, err := a.PairCodeNonce(ctx, 493044, n1)
	if err != nil || !bytes.Equal(got, n1) {
		t.Fatalf("first: %x %v", got, err)
	}
	for _, s := range []store.Backend{a, b} {
		if got, err := s.PairCodeNonce(ctx, 493044, n2); err != nil || !bytes.Equal(got, n1) {
			t.Fatalf("again: %x %v", got, err)
		}
	}
	if got, err := b.PairCodeNonce(ctx, 493045, n2); err != nil || !bytes.Equal(got, n2) {
		t.Fatalf("next epoch: %x %v", got, err)
	}
}

// Concurrent PUTs from one mailbox, on two processes, leave one live code
// claim (§6.9.1 step 1).
func testPutCodeConcurrentOneLive(t *testing.T, h Harness) {
	a, b, _ := h.pair(t)
	mustRegister(t, a, "a", 1)
	const n = 8
	ids := []string{cid1, cid2, cid3, "d4f7m2xk5n3p6r7t2v4w6y7z3a", "e4f7m2xk5n3p6r7t2v4w6y7z3a",
		"f4f7m2xk5n3p6r7t2v4w6y7z3a", "g4f7m2xk5n3p6r7t2v4w6y7z3a", "h4f7m2xk5n3p6r7t2v4w6y7z3a"}
	var wg sync.WaitGroup
	for i := range n {
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.PutCode(ctx, codePut("a", ids[i], mac(i, byte(i+1))), 0); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	live := 0
	for i := range n {
		if _, err := a.RedeemCode(ctx, "k1", look(mac(i, byte(i+1))), false); err == nil {
			live++
		} else if !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
	}
	if live != 1 {
		t.Fatalf("%d live code claims for one mailbox", live)
	}
}
