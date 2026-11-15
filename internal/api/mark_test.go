package api

import (
	"context"
	"encoding/json"
	"errors"
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

// failMark wraps the fixture's store with a lifetime mark that fails.
type failMark struct{ store.Backend }

func (failMark) RaiseLifetimeMark(context.Context, time.Duration) (time.Duration, error) {
	return 0, errors.New("store down")
}
func (failMark) SetTombstones(store.TombstonePolicy) {}

// With the mark unreadable, a deletion and a revocation answer 500 and
// write nothing (fail closed: no entry shorter than a live token).
func TestDeleteAndRevokeFailClosedWithoutMark(t *testing.T) {
	f := newFixture(t, nil)
	owner := newPrincipal(1)
	f.register(owner)
	real := f.s.st
	f.s.st = failMark{real}
	body := []byte(`{"revoke":[{"kind":"jti","value":"x"}]}`)
	f.expectCode(req{method: "POST", path: "/v1/mailbox/denylist", body: body, signer: &owner}, 500, CodeInternal)
	f.expectCode(req{method: "DELETE", path: "/v1/mailbox", signer: &owner}, 500, CodeInternal)
	f.s.st = real
	ctx := context.Background()
	if denied, err := real.IsDenied(ctx, owner.mbx, "x", ""); err != nil || denied {
		t.Fatalf("revocation written: %v %v", denied, err)
	}
	if _, err := real.Mailbox(ctx, owner.mbx); err != nil {
		t.Fatalf("mailbox deleted: %v", err)
	}
}

// After a lowering, registration advertises the configured (new) limits,
// not the mark.
func TestRegisterAdvertisesCurrentLimits(t *testing.T) {
	day := 24 * time.Hour
	f := newFixture(t, func(c *config.Config) { c.MaxTokenLifetime = 30 * day; c.RetentionLifetime = 400 * day })
	owner := newPrincipal(1)
	code, b := f.do(req{method: "POST", path: "/v1/register", body: []byte(`{"pubkey":"` + owner.b64 + `"}`), signer: &owner})
	if code != 201 && code != 200 {
		t.Fatalf("register: %d %s", code, b)
	}
	var ans struct {
		Limits struct {
			Max int64 `json:"max_token_lifetime_seconds"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(b, &ans); err != nil || ans.Limits.Max != int64(30*day/time.Second) {
		t.Fatalf("advertised %d (%v), want %d", ans.Limits.Max, err, int64(30*day/time.Second))
	}
}
