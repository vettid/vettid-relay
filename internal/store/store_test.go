package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func open(t *testing.T) (*Store, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)}
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "relay.db"), WithClock(c.now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, c
}

var ctx = context.Background()

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func mustRegister(t *testing.T, s *Store, id string, b byte) {
	t.Helper()
	if _, err := s.Register(ctx, id, key(b)); err != nil {
		t.Fatal(err)
	}
}

func TestOpenCreatesWALFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("db file not created: %v", err)
	}
	var mode string
	if err := s.r.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode=%q err=%v", mode, err)
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	// Re-open: migrations are idempotent.
	s.Close()
	s2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}

func TestRegisterIdempotent(t *testing.T) {
	s, _ := open(t)
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
	if err != nil || !bytes.Equal(mb.PubKey, key(1)) {
		t.Fatalf("mailbox: %+v %v", mb, err)
	}
	if _, err := s.Mailbox(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestDepositLeaseAck(t *testing.T) {
	s, c := open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	var ids []string
	for i := 0; i < 5; i++ {
		m, err := s.Deposit(ctx, "a", "sender", []byte{byte(i)}, time.Hour, Limits{})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("ULIDs not monotonic: %v", ids)
		}
	}
	got, err := s.Lease(ctx, "a", 3, time.Minute)
	if err != nil || len(got) != 3 || got[0].ID != ids[0] || got[2].ID != ids[2] || got[1].Payload[0] != 1 {
		t.Fatalf("lease 1: %+v %v", got, err)
	}
	got, _ = s.Lease(ctx, "a", 10, time.Minute)
	if len(got) != 2 || got[0].ID != ids[3] {
		t.Fatalf("lease 2: %+v", got)
	}
	if got, _ := s.Lease(ctx, "a", 10, time.Minute); len(got) != 0 {
		t.Fatalf("all leased, got %d", len(got))
	}
	if next, ok, err := s.NextLeaseExpiry(ctx, "a"); err != nil || !ok || !next.Equal(c.now().Add(time.Minute)) {
		t.Fatalf("next lease expiry %v %v %v", next, ok, err)
	}
	// Ack scoping: another mailbox cannot delete it.
	if d, _ := s.Ack(ctx, "b", ids[0]); d {
		t.Fatal("foreign ack deleted a message")
	}
	if d, _ := s.Ack(ctx, "a", ids[0]); !d {
		t.Fatal("ack did not delete")
	}
	if d, _ := s.Ack(ctx, "a", ids[0]); d {
		t.Fatal("re-ack reported a deletion")
	}
	// Lease expiry → redelivery of unacked messages, in order.
	c.add(time.Minute)
	got, _ = s.Lease(ctx, "a", 10, time.Minute)
	if len(got) != 4 || got[0].ID != ids[1] {
		t.Fatalf("redelivery: %+v", got)
	}
	if got, _ := s.Lease(ctx, "b", 10, time.Minute); len(got) != 0 {
		t.Fatal("mailbox b must be empty")
	}
}

func TestMessageExpiryAndSweep(t *testing.T) {
	s, c := open(t)
	mustRegister(t, s, "a", 1)
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Minute, Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lease(ctx, "a", 1, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	c.add(30 * time.Second)
	st, err := s.Sweep(ctx)
	if err != nil || st.Leases != 1 || st.Messages != 0 {
		t.Fatalf("sweep 1: %+v %v", st, err)
	}
	c.add(time.Minute)
	if got, _ := s.Lease(ctx, "a", 1, time.Minute); len(got) != 0 {
		t.Fatal("expired message must not be leased")
	}
	st, _ = s.Sweep(ctx)
	if st.Messages != 1 {
		t.Fatalf("sweep 2: %+v", st)
	}
}

func i64(v int64) *int64 { return &v }

func TestQuotas(t *testing.T) {
	s, _ := open(t)
	mustRegister(t, s, "a", 1)
	exp := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	// Mailbox message-count cap.
	lim := Limits{MailboxMaxMsgs: 2}
	for i := 0; i < 2; i++ {
		if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, lim); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, lim); !errors.Is(err, ErrQuota) {
		t.Fatalf("want ErrQuota, got %v", err)
	}
	// Mailbox byte cap.
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 10), time.Hour, Limits{MailboxMaxBytes: 11}); !errors.Is(err, ErrQuota) {
		t.Fatalf("byte cap: %v", err)
	}
	// Token msgs quota.
	tl := Limits{TokenJTI: "j1", TokenExpires: exp, TokenQuotaMsgs: i64(1)}
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, tl); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, tl); !errors.Is(err, ErrQuota) {
		t.Fatalf("token msgs quota: %v", err)
	}
	// Token bytes quota shared between messages and blobs.
	tb := Limits{TokenJTI: "j2", TokenExpires: exp, TokenQuotaBytes: i64(10)}
	if _, err := s.Deposit(ctx, "a", "s", make([]byte, 6), time.Hour, tb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlob(ctx, BlobPut{Mailbox: "a", SenderSub: "s", Size: 5, TTL: time.Hour, Limits: tb}, bytes.NewReader(make([]byte, 5))); !errors.Is(err, ErrQuota) {
		t.Fatalf("token bytes quota on blob: %v", err)
	}
	if _, err := s.PutBlob(ctx, BlobPut{Mailbox: "a", SenderSub: "s", Size: 4, TTL: time.Hour, Limits: tb}, bytes.NewReader(make([]byte, 4))); err != nil {
		t.Fatal(err)
	}
}

func TestDenylist(t *testing.T) {
	s, c := open(t)
	mustRegister(t, s, "a", 1)
	exp := c.now().Add(time.Hour)
	if err := s.AddDenylist(ctx, "a", []DenyEntry{{"jti", "J"}, {"sub", "S"}}, exp, 10); err != nil {
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
	if err := s.AddDenylist(ctx, "a", []DenyEntry{{"jti", "K"}, {"jti", "L"}}, exp, 3); !errors.Is(err, ErrQuota) {
		t.Fatalf("denylist cap: %v", err)
	}
	c.add(2 * time.Hour)
	if got, _ := s.IsDenied(ctx, "a", "J", "S"); got {
		t.Fatal("expired entries must not match")
	}
	if st, _ := s.Sweep(ctx); st.Denylist != 2 {
		t.Fatalf("sweep denylist: %+v", st)
	}
}

func TestRotate(t *testing.T) {
	s, c := open(t)
	mustRegister(t, s, "old", 1)
	if _, err := s.Deposit(ctx, "old", "s", []byte("x"), time.Hour*24*30, Limits{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Rotate(ctx, "old", "new", key(2), c.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Both live during grace.
	if _, err := s.Mailbox(ctx, "old"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Mailbox(ctx, "new"); err != nil {
		t.Fatal(err)
	}
	// Idempotent.
	if err := s.Rotate(ctx, "old", "new", key(2), c.now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.add(time.Hour)
	if _, err := s.Mailbox(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old mailbox after grace: %v", err)
	}
	st, err := s.Sweep(ctx)
	if err != nil || st.Mailboxes != 1 {
		t.Fatalf("sweep: %+v %v", st, err)
	}
	var n int
	s.r.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n)
	if n != 0 {
		t.Fatalf("cascade delete left %d messages", n)
	}
	if err := s.Rotate(ctx, "old", "x", key(3), c.now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotate dead mailbox: %v", err)
	}
}

func TestBlobs(t *testing.T) {
	s, c := open(t)
	mustRegister(t, s, "a", 1)
	mustRegister(t, s, "b", 2)
	data := bytes.Repeat([]byte("z"), 1000)
	info, err := s.PutBlob(ctx, BlobPut{Mailbox: "a", SenderSub: "s", Size: 1000, TTL: time.Hour, Limits: Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlob(ctx, BlobPut{Mailbox: "a", SenderSub: "s", Size: 1000, TTL: time.Hour, Limits: Limits{MailboxMaxBytes: 1500}}, bytes.NewReader(data)); !errors.Is(err, ErrQuota) {
		t.Fatalf("mailbox blob cap: %v", err)
	}
	if _, err := s.PutBlob(ctx, BlobPut{Mailbox: "a", SenderSub: "s", Size: 10, TTL: time.Hour}, bytes.NewReader(data)); err == nil {
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
	if _, _, err := s.OpenBlob(ctx, "b", info.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign blob: %v", err)
	}
	if err := s.DeleteBlob(ctx, "b", info.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.OpenBlob(ctx, "a", info.ID); err != nil {
		t.Fatal("foreign delete must not remove the blob")
	}
	c.add(2 * time.Hour)
	if _, _, err := s.OpenBlob(ctx, "a", info.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired blob: %v", err)
	}
	if st, _ := s.Sweep(ctx); st.Blobs != 1 {
		t.Fatalf("sweep blobs: %+v", st)
	}
	if err := s.DeleteBlob(ctx, "a", info.ID); err != nil {
		t.Fatal("delete must be idempotent")
	}
}

func TestConcurrentDepositsKeepOrderAndQuota(t *testing.T) {
	s, _ := open(t)
	mustRegister(t, s, "a", 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, quota := 0, 0
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Deposit(ctx, "a", "s", []byte("x"), time.Hour, Limits{MailboxMaxMsgs: 25})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrQuota):
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
	got, _ := s.Lease(ctx, "a", 100, time.Minute)
	for i := 1; i < len(got); i++ {
		if got[i].ID <= got[i-1].ID {
			t.Fatal("lease order is not ULID order")
		}
	}
}
