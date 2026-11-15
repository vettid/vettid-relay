package api

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/store"
)

// retentionCfg reads the mark stored now: a mark another process raised
// after this one started gives deletions and revocations its retention.
func TestRetentionReadsStoredMark(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxTokenLifetime = 30 * 24 * time.Hour })
	m, ok := f.s.st.(store.LifetimeMarker)
	if !ok {
		t.Fatal("the fixture's store keeps no mark")
	}
	before, err := f.s.retentionCfg(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := denylistRetention(before); got >= 400*24*time.Hour {
		t.Fatalf("retention %s before the raise", got)
	}
	if _, err := m.RaiseLifetimeMark(context.Background(), 400*24*time.Hour); err != nil { // another process
		t.Fatal(err)
	}
	after, err := f.s.retentionCfg(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := denylistRetention(after); got < 400*24*time.Hour {
		t.Fatalf("retention %s after another process raised the mark", got)
	}
	if p := TombstonePolicy(after); p.Retention < 400*24*time.Hour {
		t.Fatalf("tombstone retention %s", p.Retention)
	}
}

// A revocation and a deletion made after another process raised the mark
// are kept for the raised mark, not this process's start-time limits.
func TestRevokeAndDeleteUseRaisedMark(t *testing.T) {
	day := 24 * time.Hour
	f := newFixture(t, func(c *config.Config) { c.MaxTokenLifetime = 30 * day })
	m, ok := f.s.st.(store.LifetimeMarker)
	if !ok {
		t.Fatal("the fixture's store keeps no mark")
	}
	ctx := context.Background()
	if _, err := m.RaiseLifetimeMark(ctx, 400*day); err != nil { // another process
		t.Fatal(err)
	}
	owner, other := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	f.register(other)
	f.revoke(owner, "jti", "x")
	if code, b := f.deleteMailbox(other); code != 204 && code != 200 {
		t.Fatalf("delete: %d %s", code, b)
	}
	f.clk.add(100 * day) // past 30 days, within 400
	if denied, err := f.s.st.IsDenied(ctx, owner.mbx, "x", ""); err != nil || !denied {
		t.Fatalf("the revocation expired with the start-time limit: %v %v", denied, err)
	}
	if _, err := f.s.st.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	f.register(other)
	if mb, err := f.s.st.Mailbox(ctx, other.mbx); err != nil || mb.TokensNotBefore.IsZero() {
		t.Fatalf("the tombstone expired with the start-time limit: %+v %v", mb, err)
	}
}
