// Package storetest is the store.Backend conformance suite. Every backend
// (SQLite, DynamoDB) must pass it unchanged: it pins down the observable
// semantics the API layer and the protocol rely on — ordering, leases,
// quotas, single-use open tokens, single-fetch claims, rotation, denylist —
// without looking at how a backend stores anything.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Clock is a controllable clock shared by a test and its backends.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts a clock at a fixed instant.
func NewClock() *Clock { return &Clock{t: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)} }

// Now returns the clock's time.
func (c *Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

// Add advances the clock.
func (c *Clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// Harness creates backends for one test.
type Harness struct {
	// New returns a fresh, empty backend using now as its clock. It must
	// register its own cleanup.
	New func(t *testing.T, now func() time.Time) store.Backend
	// Pair, if set, returns two backends sharing one fresh state (two relay
	// processes on one shared store). Concurrency tests spread their calls
	// across both. Nil means the backend cannot be shared (SQLite), and those
	// tests use one instance.
	Pair func(t *testing.T, now func() time.Time) (store.Backend, store.Backend)
	// SweepGrace is how long after a rotated mailbox's deletion time the
	// backend's Sweep is guaranteed to have removed it.
	SweepGrace time.Duration
}

var ctx = context.Background()

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func i64(v int64) *int64 { return &v }

func (h Harness) open(t *testing.T) (store.Backend, *Clock) {
	c := NewClock()
	return h.New(t, c.Now), c
}

// pair returns two handles on one state (the same one twice without Pair).
func (h Harness) pair(t *testing.T) (store.Backend, store.Backend, *Clock) {
	c := NewClock()
	if h.Pair != nil {
		a, b := h.Pair(t, c.Now)
		return a, b, c
	}
	s := h.New(t, c.Now)
	return s, s, c
}

func mustRegister(t *testing.T, s store.Backend, id string, b byte) {
	t.Helper()
	if _, err := s.Register(ctx, id, key(b)); err != nil {
		t.Fatal(err)
	}
}

// Run runs the whole suite.
func Run(t *testing.T, h Harness) {
	tests := []struct {
		name string
		fn   func(*testing.T, Harness)
	}{
		{"RegisterIdempotent", testRegisterIdempotent},
		{"DepositCollectAck", testDepositCollectAck},
		{"MessageExpiry", testMessageExpiry},
		{"Quotas", testQuotas},
		{"QuotaRecoversAfterAckAndExpiry", testQuotaRecovers},
		{"Denylist", testDenylist},
		{"Rotate", testRotate},
		{"RotatedMailboxIsPurged", testRotatedMailboxPurged},
		{"Blobs", testBlobs},
		{"ConcurrentDepositsKeepOrderAndQuota", testConcurrentDeposits},
		{"ConsumeOpenToken", testConsumeOpenToken},
		{"ConcurrentOpenTokenSingleUse", testConcurrentOpenToken},
		{"Claims", testClaims},
		{"TakeClaimConcurrent", testTakeClaimConcurrent},
		{"ConcurrentCollectorsNeverShareALease", testConcurrentCollect},
		{"LargePayload", testLargePayload},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, h) })
	}
}

func testRegisterIdempotent(t *testing.T, h Harness) {
	s, _ := h.open(t)
	created, err := s.Register(ctx, "mbx", key(1))
	if err != nil || !created {
		t.Fatalf("first register: created=%v err=%v", created, err)
	}
	created, err = s.Register(ctx, "mbx", key(1))
	if err != nil || created {
		t.Fatalf("second register: created=%v err=%v", created, err)
	}
	if _, err := s.Register(ctx, "mbx", key(2)); err == nil {
		t.Fatal("expected collision error for different key")
	}
	mb, err := s.Mailbox(ctx, "mbx")
	if err != nil || !bytes.Equal(mb.PubKey, key(1)) || mb.ID != "mbx" {
		t.Fatalf("mailbox: %+v %v", mb, err)
	}
	if _, err := s.Mailbox(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}

func testDepositCollectAck(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	var ids []string
	for i := 0; i < 5; i++ {
		m, err := s.Deposit(ctx, "a", "sender", []byte{byte(i)}, time.Hour, store.Limits{TokenJTI: "j"})
		if err != nil {
			t.Fatal(err)
		}
		if len(m.ID) != 26 || m.Mailbox != "a" || !m.DepositedAt.Equal(c.Now()) {
			t.Fatalf("deposit result %+v", m)
		}
		ids = append(ids, m.ID)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("ULIDs not monotonic: %v", ids)
		}
	}
	got, _, err := s.Collect(ctx, "a", 3, time.Minute)
	if err != nil || len(got) != 3 || got[0].ID != ids[0] || got[2].ID != ids[2] || got[1].Payload[0] != 1 ||
		got[0].Sender != "sender" || got[0].TokenJTI != "j" || !got[0].DepositedAt.Equal(c.Now()) {
		t.Fatalf("collect 1: %+v %v", got, err)
	}
	got, _, _ = s.Collect(ctx, "a", 10, time.Minute)
	if len(got) != 2 || got[0].ID != ids[3] {
		t.Fatalf("collect 2: %+v", got)
	}
	got, next, err := s.Collect(ctx, "a", 10, time.Minute)
	if err != nil || len(got) != 0 {
		t.Fatalf("all leased, got %d (%v)", len(got), err)
	}
	if !next.Equal(c.Now().Add(time.Minute)) {
		t.Fatalf("next visible %v, want %v", next, c.Now().Add(time.Minute))
	}
	// Ack scoping: another mailbox cannot delete it.
	if d, _ := s.Ack(ctx, "b", ids[0]); d {
		t.Fatal("foreign ack deleted a message")
	}
	if d, err := s.Ack(ctx, "a", ids[0]); !d || err != nil {
		t.Fatalf("ack did not delete: %v", err)
	}
	if d, _ := s.Ack(ctx, "a", ids[0]); d {
		t.Fatal("re-ack reported a deletion")
	}
	// Lease expiry → redelivery of unacked messages, in order.
	c.Add(time.Minute)
	got, _, _ = s.Collect(ctx, "a", 10, time.Minute)
	if len(got) != 4 || got[0].ID != ids[1] || got[3].ID != ids[4] {
		t.Fatalf("redelivery: %+v", got)
	}
	if got, next, _ := s.Collect(ctx, "b", 10, time.Minute); len(got) != 0 || !next.IsZero() {
		t.Fatal("mailbox b must be empty")
	}
}

func testMessageExpiry(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Minute, store.Limits{}); err != nil {
		t.Fatal(err)
	}
	if got, _, err := s.Collect(ctx, "a", 1, 10*time.Second); err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	c.Add(30 * time.Second)
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Collect(ctx, "a", 1, 10*time.Second); len(got) != 1 {
		t.Fatal("lease expired: message must be redelivered")
	}
	c.Add(time.Minute)
	if got, next, _ := s.Collect(ctx, "a", 1, time.Minute); len(got) != 0 || !next.IsZero() {
		t.Fatalf("expired message must not be leased (%d, next %v)", len(got), next)
	}
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
}

func testQuotas(t *testing.T, h Harness) {
	s, _ := h.open(t)
	mustRegister(t, s, "a", 1)
	exp := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	lim := store.Limits{MailboxMaxMsgs: 2}
	for i := 0; i < 2; i++ {
		if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, lim); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, lim); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("want ErrQuota, got %v", err)
	}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 10), time.Hour, store.Limits{MailboxMaxBytes: 11}); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("byte cap: %v", err)
	}
	tl := store.Limits{TokenJTI: "j1", TokenExpires: exp, TokenQuotaMsgs: i64(1)}
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, tl); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, tl); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("token msgs quota: %v", err)
	}
	tb := store.Limits{TokenJTI: "j2", TokenExpires: exp, TokenQuotaBytes: i64(10)}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 6), time.Hour, tb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", SenderSub: "s", Size: 5, TTL: time.Hour, Limits: tb}, bytes.NewReader(make([]byte, 5))); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("token bytes quota on blob: %v", err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", SenderSub: "s", Size: 4, TTL: time.Hour, Limits: tb}, bytes.NewReader(make([]byte, 4))); err != nil {
		t.Fatal(err)
	}
	// A failed deposit charges nothing to the token.
	tq := store.Limits{TokenJTI: "j3", TokenExpires: exp, TokenQuotaMsgs: i64(1), MailboxMaxBytes: 5}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 6), time.Hour, tq); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("mailbox bytes: %v", err)
	}
	tq.MailboxMaxBytes = 0
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, tq); err != nil {
		t.Fatalf("token charged by a failed deposit: %v", err)
	}
}

// The mailbox quota counts live messages: acking or expiry frees room.
func testQuotaRecovers(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	lim := store.Limits{MailboxMaxMsgs: 2, MailboxMaxBytes: 100}
	m1, err := s.Deposit(ctx, "a", "s", make([]byte, 40), time.Hour, lim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 40), 2*time.Minute, lim); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 1), time.Hour, lim); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("full: %v", err)
	}
	if d, err := s.Ack(ctx, "a", m1.ID); !d || err != nil {
		t.Fatal("ack", err)
	}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 40), time.Hour, lim); err != nil {
		t.Fatalf("after ack: %v", err)
	}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 1), time.Hour, lim); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("full again: %v", err)
	}
	c.Add(3 * time.Minute) // the 2-minute message expires
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 40), time.Hour, lim); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func testDenylist(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	exp := c.Now().Add(time.Hour)
	if err := s.AddDenylist(ctx, "a", []store.DenyEntry{{Kind: "jti", Value: "J"}, {Kind: "sub", Value: "S"}}, exp, 10); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		jti, sub string
		want     bool
	}{{"J", "x", true}, {"x", "S", true}, {"x", "x", false}, {"S", "J", false}} {
		if got, err := s.IsDenied(ctx, "a", tc.jti, tc.sub); err != nil || got != tc.want {
			t.Errorf("IsDenied(%s,%s)=%v,%v want %v", tc.jti, tc.sub, got, err, tc.want)
		}
	}
	if got, _ := s.IsDenied(ctx, "other", "J", "S"); got {
		t.Fatal("denylist must be per mailbox")
	}
	// Re-adding live entries does not count twice.
	if err := s.AddDenylist(ctx, "a", []store.DenyEntry{{Kind: "jti", Value: "J"}, {Kind: "sub", Value: "S"}, {Kind: "jti", Value: "K"}}, exp, 3); err != nil {
		t.Fatalf("re-add within cap: %v", err)
	}
	if err := s.AddDenylist(ctx, "a", []store.DenyEntry{{Kind: "jti", Value: "L"}}, exp, 3); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("denylist cap: %v", err)
	}
	if got, _ := s.IsDenied(ctx, "a", "L", ""); got {
		t.Fatal("an add refused for quota must write nothing")
	}
	// Extending an entry keeps it alive past its first expiry.
	if err := s.AddDenylist(ctx, "a", []store.DenyEntry{{Kind: "jti", Value: "J"}}, exp.Add(time.Hour), 3); err != nil {
		t.Fatal(err)
	}
	c.Add(90 * time.Minute)
	if got, _ := s.IsDenied(ctx, "a", "x", "S"); got {
		t.Fatal("expired entries must not match")
	}
	if got, _ := s.IsDenied(ctx, "a", "J", ""); !got {
		t.Fatal("extended entry must still match")
	}
	// Expired entries no longer count toward the cap.
	if err := s.AddDenylist(ctx, "a", []store.DenyEntry{{Kind: "jti", Value: "M"}, {Kind: "jti", Value: "N"}}, c.Now().Add(time.Hour), 3); err != nil {
		t.Fatalf("cap after expiry: %v", err)
	}
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
}

func testRotate(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "old", 1)
	if _, err := s.Deposit(ctx, "old", "s", []byte("x"), time.Hour*24*30, store.Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "old", "new", key(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Mailbox(ctx, "old"); err != nil {
		t.Fatal(err)
	}
	if mb, err := s.Mailbox(ctx, "new"); err != nil || !bytes.Equal(mb.PubKey, key(2)) {
		t.Fatal(mb, err)
	}
	// Idempotent, and never later than the existing schedule.
	if err := s.Rotate(ctx, "old", "new", key(2), c.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Both collect during grace.
	if got, _, _ := s.Collect(ctx, "old", 10, time.Minute); len(got) != 1 {
		t.Fatal("old mailbox must still collect during grace")
	}
	// A successor id owned by another key is a collision.
	mustRegister(t, s, "taken", 3)
	if err := s.Rotate(ctx, "new", "taken", key(4), c.Now().Add(time.Hour)); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rotate onto another key's id: %v", err)
	}
	c.Add(time.Hour)
	if _, err := s.Mailbox(ctx, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old mailbox after grace: %v", err)
	}
	if _, err := s.Deposit(ctx, "old", "s", []byte("late"), time.Hour, store.Limits{}); err == nil {
		t.Fatal("deposit into a mailbox past its deletion time must fail")
	}
	if err := s.Rotate(ctx, "old", "x", key(5), c.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rotate dead mailbox: %v", err)
	}
	if _, err := s.Mailbox(ctx, "new"); err != nil {
		t.Fatal("successor must survive", err)
	}
}

// After its grace period and a sweep, a rotated mailbox and everything in it
// is gone: re-registering the same key starts empty.
func testRotatedMailboxPurged(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "old", 1)
	if _, err := s.Deposit(ctx, "old", "s", []byte("x"), 30*24*time.Hour, store.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "old", SenderSub: "s", Size: 3, TTL: 30 * 24 * time.Hour}, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatal(err)
	}
	claim, _, err := s.PutClaim(ctx, "old", []byte("c"), 24*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "old", "new", key(2), c.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Minute + h.SweepGrace)
	st, err := s.Sweep(ctx)
	if err != nil || st.Mailboxes != 1 {
		t.Fatalf("sweep: %+v %v", st, err)
	}
	if _, err := s.TakeClaim(ctx, claim); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claim of a purged mailbox: %v", err)
	}
	created, err := s.Register(ctx, "old", key(1))
	if err != nil || !created {
		t.Fatalf("re-register after purge: %v %v", created, err)
	}
	if got, _, _ := s.Collect(ctx, "old", 10, time.Minute); len(got) != 0 {
		t.Fatalf("purged mailbox kept %d messages", len(got))
	}
	if _, err := s.Deposit(ctx, "old", "s", []byte("fresh"), time.Hour, store.Limits{MailboxMaxMsgs: 1}); err != nil {
		t.Fatalf("fresh mailbox quota: %v", err)
	}
}

func testBlobs(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	data := bytes.Repeat([]byte("z"), 1000)
	info, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", SenderSub: "s", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(info.ID) != 26 || !info.ExpiresAt.Equal(c.Now().Add(time.Hour)) {
		t.Fatalf("info %+v", info)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", SenderSub: "s", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data)); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("mailbox blob cap: %v", err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", SenderSub: "s", Size: 10, TTL: time.Hour}, bytes.NewReader(data)); err == nil {
		t.Fatal("size mismatch must fail")
	}
	got, rc, err := s.OpenBlob(ctx, "a", info.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(b, data) || got.Size != 1000 {
		t.Fatal("blob content mismatch")
	}
	if _, _, err := s.OpenBlob(ctx, "b", info.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign blob: %v", err)
	}
	if err := s.DeleteBlob(ctx, "b", info.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.OpenBlob(ctx, "a", info.ID); err != nil {
		t.Fatal("foreign delete must not remove the blob")
	}
	// Owner delete frees the cap.
	if err := s.DeleteBlob(ctx, "a", info.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.OpenBlob(ctx, "a", info.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted blob: %v", err)
	}
	info2, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", SenderSub: "s", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("cap not freed by delete: %v", err)
	}
	c.Add(2 * time.Hour)
	if _, _, err := s.OpenBlob(ctx, "a", info2.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired blob: %v", err)
	}
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBlob(ctx, "a", info2.ID); err != nil {
		t.Fatal("delete must be idempotent")
	}
	// Expired blobs no longer count toward the cap.
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", SenderSub: "s", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data)); err != nil {
		t.Fatalf("cap after expiry: %v", err)
	}
}

func testConcurrentDeposits(t *testing.T, h Harness) {
	a, b, _ := h.pair(t)
	mustRegister(t, a, "a", 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, quota := 0, 0
	for i := 0; i < 40; i++ {
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, store.Limits{MailboxMaxMsgs: 25})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrQuota):
				quota++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 25 || quota != 15 {
		t.Fatalf("ok=%d quota=%d", ok, quota)
	}
	got, _, _ := b.Collect(ctx, "a", 100, time.Minute)
	if len(got) != 25 {
		t.Fatalf("collected %d", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID <= got[i-1].ID {
			t.Fatal("lease order is not ULID order")
		}
	}
}

func testConsumeOpenToken(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	exp := c.Now().Add(10 * time.Minute)
	open := store.Limits{TokenJTI: "otk", TokenExpires: exp, ConsumeJTI: true}
	q := open
	q.MailboxMaxMsgs = -1
	q.MailboxMaxBytes = 1
	if _, err := s.Deposit(ctx, "a", "signer", []byte("too big"), time.Hour, q); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("quota: %v", err)
	}
	if used, _ := s.IsConsumed(ctx, "a", "otk"); used {
		t.Fatal("failed deposit consumed the token")
	}
	if _, err := s.Deposit(ctx, "a", "signer", []byte("hello"), time.Hour, open); err != nil {
		t.Fatal(err)
	}
	if used, err := s.IsConsumed(ctx, "a", "otk"); err != nil || !used {
		t.Fatalf("consumed: %v %v", used, err)
	}
	if _, err := s.Deposit(ctx, "a", "other", []byte("again"), time.Hour, open); !errors.Is(err, store.ErrTokenUsed) {
		t.Fatalf("second use: %v", err)
	}
	mustRegister(t, s, "b", 2)
	if _, err := s.Deposit(ctx, "b", "signer", []byte("x"), time.Hour, open); err != nil {
		t.Fatal("same jti in another mailbox is independent:", err)
	}
	if got, _, _ := s.Collect(ctx, "a", 10, time.Minute); len(got) != 1 || string(got[0].Payload) != "hello" {
		t.Fatalf("exactly one message: %+v", got)
	}
}

func testConcurrentOpenToken(t *testing.T, h Harness) {
	a, b, c := h.pair(t)
	mustRegister(t, a, "a", 1)
	lim := store.Limits{TokenJTI: "race", TokenExpires: c.Now().Add(time.Minute), ConsumeJTI: true}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, lim); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			} else if !errors.Is(err, store.ErrTokenUsed) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("open token used %d times", ok)
	}
	if got, _, _ := a.Collect(ctx, "a", 100, time.Minute); len(got) != 1 {
		t.Fatalf("%d messages stored", len(got))
	}
}

func testClaims(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	id, exp, err := s.PutClaim(ctx, "a", []byte("bundle"), 15*time.Minute, 0)
	if err != nil || !exp.Equal(c.Now().Add(15*time.Minute)) {
		t.Fatalf("put: %v %v", exp, err)
	}
	if _, ok := auth.ParseClaimID(id); !ok {
		t.Fatalf("bad id %q", id)
	}
	if err := s.DeleteClaim(ctx, "b", id); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakeClaim(ctx, id)
	if err != nil || string(got) != "bundle" {
		t.Fatalf("take: %q %v", got, err)
	}
	if _, err := s.TakeClaim(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second take: %v", err)
	}
	id2, _, _ := s.PutClaim(ctx, "a", []byte("x"), time.Minute, 0)
	c.Add(time.Minute)
	if _, err := s.TakeClaim(ctx, id2); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired take: %v", err)
	}
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	id3, _, _ := s.PutClaim(ctx, "a", []byte("x"), time.Minute, 0)
	s.DeleteClaim(ctx, "a", id3)
	if _, err := s.TakeClaim(ctx, id3); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("deleted claim still fetchable")
	}
	if _, err := s.TakeClaim(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown claim: %v", err)
	}
	// Claims and blobs share the creator's storage cap.
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 600), time.Hour, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", SenderSub: "s", Size: 500, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1000}}, bytes.NewReader(make([]byte, 500))); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("blob over shared cap: %v", err)
	}
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 401), time.Hour, 1000); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("claim over cap: %v", err)
	}
	id4, _, err := s.PutClaim(ctx, "a", make([]byte, 400), time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	// A fetched claim frees its share of the cap.
	if _, err := s.TakeClaim(ctx, id4); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 400), time.Hour, 1000); err != nil {
		t.Fatalf("cap not freed by fetch: %v", err)
	}
}

func testTakeClaimConcurrent(t *testing.T, h Harness) {
	a, b, _ := h.pair(t)
	mustRegister(t, a, "a", 1)
	id, _, err := a.PutClaim(ctx, "a", []byte("once"), time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	hits := 0
	for i := 0; i < 20; i++ {
		s := a
		if i%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d, err := s.TakeClaim(ctx, id); err == nil {
				mu.Lock()
				hits++
				mu.Unlock()
				if string(d) != "once" {
					t.Error("content")
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if hits != 1 {
		t.Fatalf("claim fetched %d times", hits)
	}
}

// Two collectors (possibly on two processes) racing for one mailbox never
// receive the same message under the same lease.
func testConcurrentCollect(t *testing.T, h Harness) {
	a, b, _ := h.pair(t)
	mustRegister(t, a, "a", 1)
	const n = 30
	for i := 0; i < n; i++ {
		if _, err := a.Deposit(ctx, "a", "s", []byte(fmt.Sprint(i)), time.Hour, store.Limits{}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < 6; w++ {
		s := a
		if w%2 == 1 {
			s = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				got, _, err := s.Collect(ctx, "a", 4, time.Hour)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				for _, m := range got {
					seen[m.ID]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != n {
		t.Fatalf("delivered %d distinct of %d", len(seen), n)
	}
	for id, k := range seen {
		if k != 1 {
			t.Fatalf("%s delivered %d times under one lease", id, k)
		}
	}
}

// A maximum-size payload (256 KiB, the protocol default) round-trips.
func testLargePayload(t *testing.T, h Harness) {
	s, _ := h.open(t)
	mustRegister(t, s, "a", 1)
	p := bytes.Repeat([]byte{0xA5}, 262144)
	if _, err := s.Deposit(ctx, "a", "s", p, time.Hour, store.Limits{MailboxMaxBytes: 128 << 20, MailboxMaxMsgs: 10000}); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Collect(ctx, "a", 100, time.Minute)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].Payload, p) {
		t.Fatalf("large payload: %d %v", len(got), err)
	}
}
