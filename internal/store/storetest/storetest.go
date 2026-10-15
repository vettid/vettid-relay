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
	"slices"
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
	// Bodies counts the blob bodies a backend made by New holds outside
	// its database (staged or committed): S3 objects, staged files. Nil
	// if it holds none there.
	Bodies func(s store.Backend) int
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
		{"CollectRange", testCollectRange},
		{"IDsOnlyGrow", testIDsOnlyGrow},
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
		{"DeleteMailbox", testDeleteMailbox},
		{"DeleteMailboxReRegister", testDeleteReRegister},
		{"DeleteMailboxRotation", testDeleteRotation},
		{"DeleteMailboxAcrossProcesses", testDeleteAcrossProcesses},
		{"DeleteMailboxTombstoneExpires", testDeleteTombstoneExpires},
		{"RegisterAfterRotationGrace", testRegisterAfterGrace},
		{"RotatedMailboxLeavesTombstone", testRotatedTombstone},
		{"RotatedMailboxTombstoneAcrossProcesses", testRotatedTombstoneAcrossProcesses},
		{"BlobSenderShare", testBlobSenderShare},
		{"BlobQuotaPrecedence", testBlobQuotaPrecedence},
		{"BlobUsage", testBlobUsage},
		{"ListBlobs", testListBlobs},
		{"StagedBlobs", testStagedBlobs},
		{"ConcurrentBlobSenderShare", testConcurrentBlobShare},
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

// CollectRange leases the messages of an id range only, oldest first, and
// reports the next lease end of that range only; Collect is the range
// without bounds.
func testCollectRange(t *testing.T, h Harness) {
	a, b, c := h.pair(t)
	mustRegister(t, a, "a", 1)
	mustRegister(t, a, "other", 2)
	var id []string
	for i := 0; i < 80; i++ { // more than a query page of leases and of messages
		m, err := a.Deposit(ctx, "a", "s", []byte{byte(i)}, time.Hour, store.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		id = append(id, m.ID)
	}
	if _, err := a.Deposit(ctx, "other", "s", []byte("x"), time.Hour, store.Limits{}); err != nil {
		t.Fatal(err)
	}
	ids := func(msgs []store.Message) []string {
		var out []string
		for _, m := range msgs {
			if m.Mailbox != "a" || len(m.Payload) != 1 || id[m.Payload[0]] != m.ID {
				t.Fatalf("bad message %+v", m)
			}
			out = append(out, m.ID)
		}
		return out
	}
	want := func(what string, got []store.Message, err error, from, to int) {
		t.Helper()
		if g := ids(got); err != nil || !slices.Equal(g, id[from:to]) {
			t.Fatalf("%s: got %d messages (%v), want ids %d..%d", what, len(g), err, from, to-1)
		}
	}
	// after is exclusive, upTo inclusive, max limits, oldest first.
	got, next, err := a.CollectRange(ctx, "a", id[9], id[49], 20, time.Minute)
	want("inside", got, err, 10, 30)
	if !next.IsZero() {
		t.Fatalf("next %v with messages", next)
	}
	got, _, err = b.CollectRange(ctx, "a", id[9], id[49], 100, time.Minute)
	want("rest of the range", got, err, 30, 50)
	// The range is leased: nothing, and its next lease end.
	got, next, err = a.CollectRange(ctx, "a", id[9], id[49], 100, time.Minute)
	if err != nil || len(got) != 0 || next.Sub(c.Now()) < 50*time.Second || next.Sub(c.Now()) > 70*time.Second {
		t.Fatalf("leased range: %d messages, next in %v, %v", len(got), next.Sub(c.Now()), err)
	}
	// Ranges without collectable or leased messages: nothing, no next.
	for name, r := range map[string][2]string{
		"after the last":   {id[79], ""},
		"empty":            {id[20], id[20]},
		"inverted":         {id[30], id[20]},
		"before the first": {"", "00000000000000000000000000"},
	} {
		if got, next, err := b.CollectRange(ctx, "a", r[0], r[1], 100, time.Minute); err != nil || len(got) != 0 || !next.IsZero() {
			t.Fatalf("%s range: %d messages, next %v, %v", name, len(got), next, err)
		}
	}
	// Open-ended ranges; what is leased inside them is skipped.
	got, _, err = a.CollectRange(ctx, "a", "", id[11], 100, time.Minute)
	want("up to", got, err, 0, 10)
	got, _, err = b.CollectRange(ctx, "a", id[69], "", 100, time.Minute)
	want("after", got, err, 70, 80)
	// Collect is the whole mailbox: what no range took.
	got, _, err = a.Collect(ctx, "a", 100, time.Minute)
	want("collect", got, err, 50, 70)
	// When the leases end the range is collectable again, by either handle.
	c.Add(61 * time.Second)
	got, _, err = b.CollectRange(ctx, "a", id[39], id[44], 100, time.Minute)
	want("after the leases ended", got, err, 40, 45)
	if ok, err := a.Ack(ctx, "a", id[40]); err != nil || !ok {
		t.Fatal(ok, err)
	}
	c.Add(61 * time.Second)
	got, _, err = a.CollectRange(ctx, "a", id[39], id[44], 100, time.Minute)
	want("after an ack", got, err, 41, 45)
}

// A message deposited later never gets a smaller id, whatever the clock
// does: collectors that have seen an id rely on new messages sorting after it.
func testIDsOnlyGrow(t *testing.T, h Harness) {
	a, b, c := h.pair(t)
	mustRegister(t, a, "a", 1)
	last := ""
	for i, s := range []store.Backend{a, b, a, b, a} {
		if i%2 == 1 {
			c.Add(-time.Hour) // the clock is set back
		}
		m, err := s.Deposit(ctx, "a", "s", []byte("x"), 24*time.Hour, store.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if m.ID <= last {
			t.Fatalf("deposit %d: id %s is not above the earlier %s", i, m.ID, last)
		}
		last = m.ID
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
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 5, TTL: time.Hour, Limits: tb}, bytes.NewReader(make([]byte, 5))); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("token bytes quota on blob: %v", err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 4, TTL: time.Hour, Limits: tb}, bytes.NewReader(make([]byte, 4))); err != nil {
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
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "old", Size: 3, TTL: 30 * 24 * time.Hour}, bytes.NewReader([]byte("abc"))); err != nil {
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
	info, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(info.ID) != 26 || !info.ExpiresAt.Equal(c.Now().Add(time.Hour)) {
		t.Fatalf("info %+v", info)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data)); !errors.Is(err, store.ErrQuota) {
		t.Fatalf("mailbox blob cap: %v", err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 10, TTL: time.Hour}, bytes.NewReader(data)); err == nil {
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
	info2, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data))
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
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data)); err != nil {
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
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 500, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 1000}}, bytes.NewReader(make([]byte, 500))); !errors.Is(err, store.ErrQuota) {
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

// ------------------------------------------------------- mailbox deletion

// deleteTimes are the tombstone times a deletion at now uses (the API
// passes now+freshness and that plus the denylist retention).
func deleteTimes(c *Clock) (notBefore, keepUntil time.Time) {
	nb := c.Now().Add(90 * time.Second)
	return nb, nb.Add(30 * 24 * time.Hour)
}

// Deletion removes everything the mailbox holds and refuses every later
// write; it is idempotent and needs the registered key.
func testDeleteMailbox(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	exp := c.Now().Add(time.Hour)
	if _, err := s.Deposit(ctx, "a", "s", []byte("m"), time.Hour, store.Limits{TokenJTI: "t1", TokenExpires: exp, TokenQuotaMsgs: i64(10)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "a", "s", []byte("o"), time.Hour, store.Limits{TokenJTI: "open", TokenExpires: exp, ConsumeJTI: true}); err != nil {
		t.Fatal(err)
	}
	blob, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 3, TTL: time.Hour}, bytes.NewReader([]byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	claim, _, err := s.PutClaim(ctx, "a", []byte("c"), time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddDenylist(ctx, "a", []store.DenyEntry{{Kind: "jti", Value: "J"}}, exp, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "b", "s", []byte("keep"), time.Hour, store.Limits{}); err != nil {
		t.Fatal(err)
	}
	nb, keep := deleteTimes(c)
	if ids, err := s.DeleteMailbox(ctx, "a", key(9), nb, keep); err != nil || len(ids) != 0 {
		t.Fatalf("delete with another key: %v %v", ids, err)
	}
	if _, err := s.Mailbox(ctx, "a"); err != nil {
		t.Fatal("a delete with another key must not delete:", err)
	}
	ids, err := s.DeleteMailbox(ctx, "a", key(1), nb, keep)
	if err != nil || len(ids) != 1 || ids[0] != "a" {
		t.Fatalf("delete: %v %v", ids, err)
	}
	if _, err := s.Mailbox(ctx, "a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted mailbox resolves: %v", err)
	}
	if _, err := s.Deposit(ctx, "a", "s", []byte("late"), time.Hour, store.Limits{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deposit after delete: %v", err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 1, TTL: time.Hour}, bytes.NewReader([]byte("x"))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("blob put after delete: %v", err)
	}
	if _, _, err := s.PutClaim(ctx, "a", []byte("c"), time.Hour, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claim put after delete: %v", err)
	}
	if err := s.AddDenylist(ctx, "a", []store.DenyEntry{{Kind: "jti", Value: "K"}}, exp, 10); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("denylist after delete: %v", err)
	}
	if _, _, err := s.OpenBlob(ctx, "a", blob.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("blob after delete: %v", err)
	}
	if _, err := s.TakeClaim(ctx, claim); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claim after delete: %v", err)
	}
	if got, _, _ := s.Collect(ctx, "a", 10, time.Minute); len(got) != 0 {
		t.Fatalf("deleted mailbox kept %d messages", len(got))
	}
	if got, _ := s.IsDenied(ctx, "a", "J", ""); got {
		t.Fatal("denylist survived the deletion")
	}
	if got, _ := s.IsConsumed(ctx, "a", "open"); got {
		t.Fatal("consumed open token survived the deletion")
	}
	// Idempotent; other mailboxes untouched.
	if ids, err := s.DeleteMailbox(ctx, "a", key(1), nb, keep); err != nil || len(ids) != 0 {
		t.Fatalf("repeat delete: %v %v", ids, err)
	}
	if ids, err := s.DeleteMailbox(ctx, "never", key(7), nb, keep); err != nil || len(ids) != 0 {
		t.Fatalf("delete of an unregistered key: %v %v", ids, err)
	}
	if got, _, _ := s.Collect(ctx, "b", 10, time.Minute); len(got) != 1 {
		t.Fatal("another mailbox lost its message")
	}
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
}

// Re-registering a deleted key starts a fresh, empty mailbox, and tokens
// issued before the deletion stay refused (ErrRevoked) — the denylist and
// usage records that would have refused them are gone.
func testDeleteReRegister(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	oldIat := c.Now().Add(-time.Minute)
	exp := c.Now().Add(24 * time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, store.Limits{TokenJTI: "q", TokenIssuedAt: oldIat, TokenExpires: exp, TokenQuotaMsgs: i64(3)}); err != nil {
			t.Fatal(err)
		}
	}
	nb, keep := deleteTimes(c)
	if _, err := s.DeleteMailbox(ctx, "a", key(1), nb, keep); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Minute)
	created, err := s.Register(ctx, "a", key(1))
	if err != nil || !created {
		t.Fatalf("re-register: %v %v", created, err)
	}
	mb, err := s.Mailbox(ctx, "a")
	if err != nil || !mb.TokensNotBefore.Equal(nb.Truncate(time.Millisecond)) {
		t.Fatalf("TokensNotBefore %v (want %v), %v", mb.TokensNotBefore, nb, err)
	}
	if created, err := s.Register(ctx, "a", key(1)); err != nil || created {
		t.Fatalf("second re-register: %v %v", created, err)
	}
	if got, _, _ := s.Collect(ctx, "a", 10, time.Minute); len(got) != 0 {
		t.Fatalf("re-registered mailbox has %d old messages", len(got))
	}
	old := store.Limits{TokenJTI: "q", TokenIssuedAt: oldIat, TokenExpires: exp, TokenQuotaMsgs: i64(3)}
	if _, err := s.Deposit(ctx, "a", "s", []byte("old token"), time.Hour, old); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("token from before the deletion: %v", err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Size: 1, TTL: time.Hour, Limits: old}, bytes.NewReader([]byte("x"))); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("blob with a token from before the deletion: %v", err)
	}
	fresh := store.Limits{TokenJTI: "q", TokenIssuedAt: nb, TokenExpires: exp, TokenQuotaMsgs: i64(3), MailboxMaxMsgs: 3}
	for i := 0; i < 3; i++ { // counters (token usage, mailbox count) restarted
		if _, err := s.Deposit(ctx, "a", "s", []byte("new"), time.Hour, fresh); err != nil {
			t.Fatalf("fresh token, deposit %d: %v", i, err)
		}
	}
}

// Deleting a rotation successor deletes the predecessors still in their
// grace period; deleting a predecessor ends only its own grace.
func testDeleteRotation(t *testing.T, h Harness) {
	s, c := h.open(t)
	nb, keep := deleteTimes(c)
	mustRegister(t, s, "o1", 1)
	if err := s.Rotate(ctx, "o1", "n1", key(2), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "n1", "n2", key(3), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "o1", "s", []byte("x"), time.Hour, store.Limits{}); err != nil {
		t.Fatal(err)
	}
	ids, err := s.DeleteMailbox(ctx, "n2", key(3), nb, keep)
	if err != nil || len(ids) != 3 {
		t.Fatalf("delete the chain's head: %v %v", ids, err)
	}
	for _, id := range []string{"o1", "n1", "n2"} {
		if _, err := s.Mailbox(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s survived: %v", id, err)
		}
		if _, err := s.Deposit(ctx, id, "s", []byte("late"), time.Hour, store.Limits{}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("deposit into %s: %v", id, err)
		}
	}

	mustRegister(t, s, "o2", 4)
	if err := s.Rotate(ctx, "o2", "n3", key(5), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ids, err = s.DeleteMailbox(ctx, "o2", key(4), nb, keep)
	if err != nil || len(ids) != 1 || ids[0] != "o2" {
		t.Fatalf("delete the predecessor: %v %v", ids, err)
	}
	if _, err := s.Mailbox(ctx, "n3"); err != nil {
		t.Fatal("the successor must survive its predecessor's deletion:", err)
	}
	// A rotation back onto a deleted key revives it with its TokensNotBefore.
	if err := s.Rotate(ctx, "n3", "o2", key(4), c.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if mb, err := s.Mailbox(ctx, "o2"); err != nil || mb.TokensNotBefore.IsZero() {
		t.Fatalf("rotated onto a deleted key: %+v %v", mb, err)
	}
}

// Two processes: a deletion on one is binding on the other at once, even
// where the other still has the mailbox cached; so is TokensNotBefore
// after a re-registration.
func testDeleteAcrossProcesses(t *testing.T, h Harness) {
	a, b, c := h.pair(t)
	mustRegister(t, a, "m", 1)
	if _, err := b.Mailbox(ctx, "m"); err != nil { // b caches it
		t.Fatal(err)
	}
	iat := c.Now().Add(-time.Minute)
	nb, keep := deleteTimes(c)
	if _, err := a.DeleteMailbox(ctx, "m", key(1), nb, keep); err != nil {
		t.Fatal(err)
	}
	lim := store.Limits{TokenJTI: "t", TokenIssuedAt: iat, TokenExpires: c.Now().Add(time.Hour)}
	if _, err := b.Deposit(ctx, "m", "s", []byte("x"), time.Hour, lim); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deposit on the other process: %v", err)
	}
	if _, err := b.PutBlob(ctx, store.BlobPut{Mailbox: "m", Size: 1, TTL: time.Hour, Limits: lim}, bytes.NewReader([]byte("x"))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("blob on the other process: %v", err)
	}
	if _, err := a.Register(ctx, "m", key(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Deposit(ctx, "m", "s", []byte("x"), time.Hour, lim); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("old token on the other process after re-registration: %v", err)
	}
}

// After the tombstone's lifetime (every token minted before the deletion
// has expired) a sweep forgets the deletion.
func testDeleteTombstoneExpires(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	nb, keep := deleteTimes(c)
	if _, err := s.DeleteMailbox(ctx, "a", key(1), nb, keep); err != nil {
		t.Fatal(err)
	}
	c.Add(keep.Sub(c.Now()) + h.SweepGrace + time.Minute)
	if _, err := s.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Register(ctx, "a", key(1)); err != nil {
		t.Fatal(err)
	}
	if mb, err := s.Mailbox(ctx, "a"); err != nil || !mb.TokensNotBefore.IsZero() {
		t.Fatalf("after the tombstone expired: %+v %v", mb, err)
	}
}

// A key whose mailbox passed its rotation grace (not yet swept) registers
// a fresh, empty mailbox.
func testRegisterAfterGrace(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "old", 1)
	if _, err := s.Deposit(ctx, "old", "s", []byte("x"), 30*24*time.Hour, store.Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "old", "new", key(2), c.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	oldIat := c.Now().Add(-time.Minute)
	c.Add(2 * time.Minute)
	at := c.Now()
	created, err := s.Register(ctx, "old", key(1))
	if err != nil || !created {
		t.Fatalf("register after grace: %v %v", created, err)
	}
	// The registration removed the rotated mailbox, as a sweep would have:
	// same tombstone, at the time of the registration.
	if mb, err := s.Mailbox(ctx, "old"); err != nil || !mb.TokensNotBefore.Equal(at.Add(90*time.Second)) {
		t.Fatalf("TokensNotBefore %+v, %v", mb.TokensNotBefore, err)
	}
	if _, err := s.Deposit(ctx, "old", "s", []byte("x"), time.Hour, store.Limits{TokenJTI: "t", TokenIssuedAt: oldIat, TokenExpires: at.Add(time.Hour)}); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("pre-rotation token after re-registration: %v", err)
	}
	if got, _, _ := s.Collect(ctx, "old", 10, time.Minute); len(got) != 0 {
		t.Fatalf("fresh mailbox has %d old messages", len(got))
	}
	if _, err := s.Mailbox(ctx, "new"); err != nil {
		t.Fatal("successor must survive", err)
	}
}

// A rotated-away mailbox removed at the end of its grace (§6.7) leaves the
// same tombstone as a deletion (§6.10), from the time of its removal: if
// its key registers again, tokens issued under it before then — whose
// revocations went with the mailbox — stay refused.
func testRotatedTombstone(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "old", 1)
	oldIat := c.Now().Add(-time.Minute)
	exp := c.Now().Add(30 * 24 * time.Hour)
	if err := s.AddDenylist(ctx, "old", []store.DenyEntry{{Kind: "jti", Value: "revoked"}}, exp, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "old", "new", key(2), c.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Minute + h.SweepGrace)
	removed := c.Now()
	if st, err := s.Sweep(ctx); err != nil || st.Mailboxes != 1 {
		t.Fatalf("sweep: %+v %v", st, err)
	}
	c.Add(time.Hour)
	if created, err := s.Register(ctx, "old", key(1)); err != nil || !created {
		t.Fatalf("re-register: %v %v", created, err)
	}
	mb, err := s.Mailbox(ctx, "old")
	if err != nil || !mb.TokensNotBefore.Equal(removed.Add(90*time.Second)) {
		t.Fatalf("TokensNotBefore %v (removed %v), %v", mb.TokensNotBefore, removed, err)
	}
	if got, _ := s.IsDenied(ctx, "old", "revoked", ""); got {
		t.Fatal("the old denylist survived")
	}
	old := store.Limits{TokenJTI: "revoked", TokenIssuedAt: oldIat, TokenExpires: exp}
	if _, err := s.Deposit(ctx, "old", "s", []byte("x"), time.Hour, old); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("revoked pre-rotation token after re-registration: %v", err)
	}
	if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "old", Size: 1, TTL: time.Hour, Limits: old}, bytes.NewReader([]byte("x"))); !errors.Is(err, store.ErrRevoked) {
		t.Fatalf("blob with a pre-rotation token: %v", err)
	}
	fresh := store.Limits{TokenJTI: "fresh", TokenIssuedAt: removed.Add(90 * time.Second), TokenExpires: exp}
	if _, err := s.Deposit(ctx, "old", "s", []byte("x"), time.Hour, fresh); err != nil {
		t.Fatalf("token issued after the tombstone's not-before: %v", err)
	}
	if _, err := s.Mailbox(ctx, "new"); err != nil {
		t.Fatal("successor must survive", err)
	}
}

// The same across two processes: the sweep runs on one, the key registers
// again on the other, an old token is refused on either.
func testRotatedTombstoneAcrossProcesses(t *testing.T, h Harness) {
	a, b, c := h.pair(t)
	mustRegister(t, a, "old", 1)
	oldIat := c.Now().Add(-time.Minute)
	if err := a.Rotate(ctx, "old", "new", key(2), c.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.Add(time.Minute + h.SweepGrace)
	if _, err := a.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Register(ctx, "old", key(1)); err != nil {
		t.Fatal(err)
	}
	old := store.Limits{TokenJTI: "t", TokenIssuedAt: oldIat, TokenExpires: c.Now().Add(time.Hour)}
	for i, s := range []store.Backend{a, b} {
		if _, err := s.Deposit(ctx, "old", "s", []byte("x"), time.Hour, old); !errors.Is(err, store.ErrRevoked) {
			t.Fatalf("process %d: pre-rotation token: %v", i, err)
		}
	}
}

// put stores a blob of n bytes from sender into mailbox with the share
// limits given.
func put(s store.Backend, mailbox, sender string, n int, capBytes, shareBytes, shareBlobs int64) (store.BlobInfo, error) {
	return s.PutBlob(ctx, store.BlobPut{Mailbox: mailbox, Sender: sender, Size: int64(n), TTL: time.Hour,
		Limits: store.Limits{MailboxMaxBytes: capBytes}, SenderMaxBytes: shareBytes, SenderMaxBlobs: shareBlobs}, bytes.NewReader(make([]byte, n)))
}

func wantQuota(t *testing.T, err error, kind store.QuotaKind) {
	t.Helper()
	if !errors.Is(err, store.ErrQuota) || store.QuotaOf(err) != kind {
		t.Fatalf("got %v, want quota %q", err, kind)
	}
}

// 0.9.2 (§6.8): one sender key's blobs in one mailbox are bounded in bytes
// and in number; other senders and other mailboxes are not affected; a
// delete or an expiry gives the share back; a blob without a sender (from
// before 0.9.2) counts against no share.
func testBlobSenderShare(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	const capB, share, count = 1 << 20, 2000, 3
	if _, err := put(s, "a", "s1", 1000, capB, share, count); err != nil {
		t.Fatal(err)
	}
	b2, err := put(s, "a", "s1", 1000, capB, share, count)
	if err != nil {
		t.Fatal(err)
	}
	_, err = put(s, "a", "s1", 1, capB, share, count)
	wantQuota(t, err, store.QuotaSenderBlobs)
	_, err = put(s, "a", "s1", share+1, capB, share, count) // can never fit
	wantQuota(t, err, store.QuotaSenderBlobs)
	if _, err := put(s, "a", "s2", 1000, capB, share, count); err != nil {
		t.Fatalf("another sender: %v", err)
	}
	if _, err := put(s, "b", "s1", 1000, capB, share, count); err != nil {
		t.Fatalf("another mailbox: %v", err)
	}
	if _, err := put(s, "a", "", 5000, capB, share, count); err != nil { // no sender: no share
		t.Fatalf("legacy blob: %v", err)
	}
	// A delete gives the share back (and is idempotent about it).
	for i := 0; i < 2; i++ {
		if err := s.DeleteBlob(ctx, "a", b2.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := put(s, "a", "s1", 1000, capB, share, count); err != nil {
		t.Fatalf("after a delete: %v", err)
	}
	_, err = put(s, "a", "s1", 1, capB, share, count)
	wantQuota(t, err, store.QuotaSenderBlobs)
	// The number of blobs: tiny blobs cannot fill the list.
	for i := 0; i < count; i++ {
		if _, err := put(s, "a", "s3", 46, capB, share, count); err != nil {
			t.Fatal(err)
		}
	}
	_, err = put(s, "a", "s3", 46, capB, share, count)
	wantQuota(t, err, store.QuotaSenderBlobs)
	// Expired blobs leave the share.
	c.Add(2 * time.Hour)
	for i := 0; i < count; i++ {
		if _, err := put(s, "a", "s3", 46, capB, share, count); err != nil {
			t.Fatalf("after expiry %d: %v", i, err)
		}
	}
	if _, err := put(s, "a", "s1", 2000, capB, share, count); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// The mailbox's cap comes before the sender's share, which comes before
// the token's quota; the cap counts the mailbox's claims.
func testBlobQuotaPrecedence(t *testing.T, h Harness) {
	s, _ := h.open(t)
	mustRegister(t, s, "a", 1)
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 500), time.Hour, 3000); err != nil {
		t.Fatal(err)
	}
	if _, err := put(s, "a", "s1", 2000, 3000, 2000, 16); err != nil {
		t.Fatal(err)
	}
	q := i64(10)
	lim := store.Limits{MailboxMaxBytes: 3000, TokenJTI: "j", TokenExpires: time.Now().Add(time.Hour), TokenQuotaBytes: q}
	try := func(n int, l store.Limits) error {
		_, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Sender: "s1", Size: int64(n), TTL: time.Hour, Limits: l,
			SenderMaxBytes: 2000, SenderMaxBlobs: 16}, bytes.NewReader(make([]byte, n)))
		return err
	}
	wantQuota(t, try(600, lim), store.QuotaMailboxBlobs) // all three exceeded
	lim.MailboxMaxBytes = 1 << 20
	wantQuota(t, try(600, lim), store.QuotaSenderBlobs) // share and token
	_, err := put(s, "a", "s2", 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("empty blob: %v", err)
	}
	wantQuota(t, func() error {
		_, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Sender: "s2", Size: 11, TTL: time.Hour, Limits: lim,
			SenderMaxBytes: 2000, SenderMaxBlobs: 16}, bytes.NewReader(make([]byte, 11)))
		return err
	}(), store.QuotaToken)
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, store.Limits{MailboxMaxMsgs: 1}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, store.Limits{MailboxMaxMsgs: 1})
	wantQuota(t, err, store.QuotaMailbox)
	_, err = s.Deposit(ctx, "a", "s", []byte("xx"), time.Hour, store.Limits{TokenJTI: "d", TokenExpires: time.Now().Add(time.Hour), TokenQuotaBytes: i64(1)})
	wantQuota(t, err, store.QuotaToken)
	_, _, err = s.PutClaim(ctx, "a", make([]byte, 1000), time.Hour, 3000)
	wantQuota(t, err, store.QuotaMailboxBlobs)
}

func testBlobUsage(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	lim := store.Limits{TokenJTI: "j", TokenExpires: c.Now().Add(time.Hour), TokenQuotaBytes: i64(1 << 20)}
	for _, n := range []int{100, 200} {
		if _, err := s.PutBlob(ctx, store.BlobPut{Mailbox: "a", Sender: "s1", Size: int64(n), TTL: time.Hour, Limits: lim}, bytes.NewReader(make([]byte, n))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := put(s, "a", "s2", 400, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 50), time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	for _, fresh := range []bool{false, true} {
		u, err := s.BlobUsage(ctx, "a", "s1", "j", fresh)
		if err != nil || u != (store.BlobUsage{MailboxBytes: 750, SenderBytes: 300, SenderBlobs: 2, TokenBytes: 300}) {
			t.Fatalf("usage (fresh %v): %+v %v", fresh, u, err)
		}
	}
	if u, err := s.BlobUsage(ctx, "a", "nobody", "", false); err != nil || u != (store.BlobUsage{MailboxBytes: 750}) {
		t.Fatalf("usage of another sender: %+v %v", u, err)
	}
	c.Add(2 * time.Hour) // all expired
	if u, err := s.BlobUsage(ctx, "a", "s1", "", true); err != nil || u.SenderBlobs != 0 || u.SenderBytes != 0 || u.MailboxBytes != 0 {
		t.Fatalf("usage after expiry: %+v %v", u, err)
	}
}

// The owner's list: its mailbox's unexpired blobs in id order, paged, with
// the sender where known, and the bytes the cap is checked against.
func testListBlobs(t *testing.T, h Harness) {
	s, c := h.open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	var ids []string
	for i := 0; i < 7; i++ {
		sender := fmt.Sprintf("s%d", i%2)
		if i == 6 {
			sender = "" // a blob from before 0.9.2
		}
		b, err := put(s, "a", sender, 10+i, 0, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if b.Sender != sender || b.CreatedAt.IsZero() {
			t.Fatalf("put info %+v", b)
		}
		ids = append(ids, b.ID)
		c.Add(time.Millisecond)
	}
	if _, err := put(s, "b", "s0", 99, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PutClaim(ctx, "a", make([]byte, 1000), time.Hour, 0); err != nil {
		t.Fatal(err)
	}
	var got []store.BlobInfo
	after := ""
	for page := 0; ; page++ {
		bs, next, used, err := s.ListBlobs(ctx, "a", after, 3)
		if err != nil {
			t.Fatal(err)
		}
		if used != 1000+10+11+12+13+14+15+16 {
			t.Fatalf("used %d", used)
		}
		got = append(got, bs...)
		if next == "" {
			if len(bs) != 1 || page != 2 {
				t.Fatalf("last page %d: %d blobs", page, len(bs))
			}
			break
		}
		if len(bs) != 3 || next != bs[2].ID {
			t.Fatalf("page %d: %d blobs, next %q", page, len(bs), next)
		}
		after = next
	}
	if len(got) != 7 {
		t.Fatalf("%d blobs listed", len(got))
	}
	for i, b := range got {
		want := fmt.Sprintf("s%d", i%2)
		if i == 6 {
			want = ""
		}
		if b.ID != ids[i] || b.Size != int64(10+i) || b.Sender != want || !b.ExpiresAt.After(c.Now()) || b.CreatedAt.IsZero() {
			t.Fatalf("blob %d: %+v", i, b)
		}
	}
	// A page of exactly what is left has no next.
	if bs, next, _, err := s.ListBlobs(ctx, "a", ids[3], 3); err != nil || len(bs) != 3 || next != "" {
		t.Fatalf("exact page: %d %q %v", len(bs), next, err)
	}
	// Deleted and expired blobs are not listed.
	if err := s.DeleteBlob(ctx, "a", ids[0]); err != nil {
		t.Fatal(err)
	}
	if bs, _, _, _ := s.ListBlobs(ctx, "a", "", 500); len(bs) != 6 || bs[0].ID != ids[1] {
		t.Fatalf("after a delete: %d", len(bs))
	}
	c.Add(2 * time.Hour)
	if bs, next, used, err := s.ListBlobs(ctx, "a", "", 500); err != nil || len(bs) != 0 || next != "" || used != 0 {
		t.Fatalf("after expiry: %d %q %d %v", len(bs), next, used, err)
	}
	if bs, _, _, err := s.ListBlobs(ctx, "nobody", "", 10); err != nil || len(bs) != 0 {
		t.Fatalf("unknown mailbox: %d %v", len(bs), err)
	}
}

type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("the client went away")
	}
	k := min(len(p), f.n)
	f.n -= k
	return k, nil
}

// A staged body is invisible and counts against nothing until committed;
// a stage that fails, a discarded stage and a commit that fails (and is
// then discarded) leave no body behind.
func testStagedBlobs(t *testing.T, h Harness) {
	s, _ := h.open(t)
	mustRegister(t, s, "a", 1)
	bodies := func() int {
		if h.Bodies == nil {
			return 0
		}
		return h.Bodies(s)
	}
	base := bodies()
	for name, r := range map[string]io.Reader{
		"short":   bytes.NewReader(make([]byte, 999)),
		"long":    bytes.NewReader(make([]byte, 1001)),
		"failing": &failingReader{n: 500},
	} {
		if st, err := s.StageBlob(ctx, "a", 1000, r); err == nil || st != nil {
			t.Fatalf("%s body staged: %v", name, err)
		}
		if n := bodies(); n != base {
			t.Fatalf("%s body left %d bodies", name, n-base)
		}
	}
	st, err := s.StageBlob(ctx, "a", 1000, bytes.NewReader(make([]byte, 1000)))
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := s.BlobUsage(ctx, "a", "s", "", true); u.MailboxBytes != 0 {
		t.Fatalf("a staged body counts: %+v", u)
	}
	if bs, _, _, _ := s.ListBlobs(ctx, "a", "", 10); len(bs) != 0 {
		t.Fatal("a staged body is listed")
	}
	for i := 0; i < 2; i++ {
		if err := st.Discard(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := bodies(); n != base {
		t.Fatalf("discard left %d bodies", n-base)
	}
	if _, err := st.Commit(ctx, store.BlobPut{Mailbox: "a", Size: 1000, TTL: time.Hour}); err == nil {
		t.Fatal("a discarded body was committed")
	}
	// A commit refused (quota), then discarded.
	st, err = s.StageBlob(ctx, "a", 1000, bytes.NewReader(make([]byte, 1000)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Commit(ctx, store.BlobPut{Mailbox: "a", Size: 999, TTL: time.Hour}); err == nil {
		t.Fatal("committed with another size")
	}
	_, err = st.Commit(ctx, store.BlobPut{Mailbox: "a", Sender: "s", Size: 1000, TTL: time.Hour, Limits: store.Limits{MailboxMaxBytes: 999}})
	wantQuota(t, err, store.QuotaMailboxBlobs)
	st.Discard(ctx)
	if n := bodies(); n != base {
		t.Fatalf("refused commit left %d bodies", n-base)
	}
	// A commit after the mailbox was deleted.
	st, err = s.StageBlob(ctx, "a", 10, bytes.NewReader(make([]byte, 10)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteMailbox(ctx, "a", key(1), c0(), c0().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Commit(ctx, store.BlobPut{Mailbox: "a", Size: 10, TTL: time.Hour}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("commit into a deleted mailbox: %v", err)
	}
	st.Discard(ctx)
	if n := bodies(); n != base {
		t.Fatalf("commit into a deleted mailbox left %d bodies", n-base)
	}
	// A committed body is read back whole; Discard after it changes nothing.
	mustRegister(t, s, "c", 3)
	data := bytes.Repeat([]byte("q"), 70_000)
	st, err = s.StageBlob(ctx, "c", int64(len(data)), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	info, err := st.Commit(ctx, store.BlobPut{Mailbox: "c", Sender: "s", Size: int64(len(data)), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Discard(ctx); err != nil {
		t.Fatal(err)
	}
	got, rc, err := s.OpenBlob(ctx, "c", info.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(b, data) || got.Sender != "s" || got.Size != int64(len(data)) {
		t.Fatalf("committed blob: %+v, %d bytes", got, len(b))
	}
}

func c0() time.Time { return NewClock().Now() }

// The share holds under concurrent uploads by one sender, on any number of
// processes.
func testConcurrentBlobShare(t *testing.T, h Harness) {
	a, b, _ := h.pair(t)
	mustRegister(t, a, "a", 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, quota := 0, 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(s store.Backend) {
			defer wg.Done()
			_, err := put(s, "a", "s1", 10, 1<<20, 1<<20, 4)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case store.QuotaOf(err) == store.QuotaSenderBlobs:
				quota++
			default:
				t.Error(err)
			}
		}([]store.Backend{a, b}[i%2])
	}
	wg.Wait()
	if ok != 4 || quota != 6 {
		t.Fatalf("%d stored, %d refused; want 4 and 6", ok, quota)
	}
}
