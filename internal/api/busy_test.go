package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/store"
	"github.com/vettid/vettid-relay/internal/store/dynamo"
)

// busyStore answers store.ErrBusy (another operation holds the mailbox)
// while busy is set.
type busyStore struct {
	store.Backend
	busy atomic.Bool
}

func (b *busyStore) Register(ctx context.Context, id string, pub []byte) (bool, time.Time, error) {
	if b.busy.Load() {
		return false, time.Time{}, fmt.Errorf("purging: %w", store.ErrBusy)
	}
	return b.Backend.Register(ctx, id, pub)
}

func (b *busyStore) Rotate(ctx context.Context, oldID, newID string, newPub []byte, deleteAfter time.Time) (time.Time, error) {
	if b.busy.Load() {
		return time.Time{}, fmt.Errorf("purging: %w", store.ErrBusy)
	}
	return b.Backend.Rotate(ctx, oldID, newID, newPub, deleteAfter)
}

func (b *busyStore) DeleteMailbox(ctx context.Context, id string, pub []byte, notBefore, keepUntil time.Time) ([]string, error) {
	if b.busy.Load() {
		return nil, fmt.Errorf("purging: %w", store.ErrBusy)
	}
	return b.Backend.DeleteMailbox(ctx, id, pub, notBefore, keepUntil)
}

// A registration, rotation or deletion the store gave up on because a purge held
// the mailbox is answered 429 rate_limited with retry_after (overload,
// RELAY-PROTOCOL §7), not 500; once the purge is done, both go through.
func TestBusyIsRateLimited(t *testing.T) {
	f := newFixture(t, nil)
	bs, inner := &busyStore{}, f.newSt
	f.newSt = func() store.Backend { bs.Backend = inner(); return bs }
	f.restart()
	owner := newPrincipal(1)
	f.register(owner)

	bs.busy.Store(true)
	if code, ans := f.registerAnswer(newPrincipal(2)); code != 429 || ans["code"] != CodeRateLimited || ans["retry_after"] == nil {
		t.Fatalf("register while busy: %d %v", code, ans)
	}
	next := newPrincipal(4)
	proof := ed25519.Sign(next.priv, []byte(owner.mbx))
	body, _ := json.Marshal(map[string]any{"new_pubkey": next.b64, "new_key_proof": proof})
	if code, b := f.do(req{method: "POST", path: "/v1/mailbox/rotate", body: body, signer: &owner}); code != 429 || !bytes.Contains(b, []byte(`"retry_after":2`)) {
		t.Fatalf("rotate while busy: %d %s", code, b)
	}
	if code, b := f.deleteMailbox(owner); code != 429 || !bytes.Contains(b, []byte(CodeRateLimited)) || !bytes.Contains(b, []byte(`"retry_after":2`)) {
		t.Fatalf("delete while busy: %d %s", code, b)
	}

	bs.busy.Store(false)
	if code, ans := f.registerAnswer(newPrincipal(2)); code != 200 && code != 201 {
		t.Fatalf("register after: %d %v", code, ans)
	}
	if code, b := f.deleteMailbox(owner); code != 204 {
		t.Fatalf("delete after: %d %s", code, b)
	}
}

// A deletion is given longer than one purge may run in the DynamoDB
// store, so a large mailbox's purge isn't cut short by the deletion's own
// deadline.
func TestDeleteTimeoutOutlastsPurge(t *testing.T) {
	if deleteTimeout <= dynamo.PurgeBudget {
		t.Fatalf("deleteTimeout %s isn't longer than the purge budget %s", deleteTimeout, dynamo.PurgeBudget)
	}
}

// failRotateStore fails every Rotate with a plain error.
type failRotateStore struct{ store.Backend }

func (failRotateStore) Rotate(context.Context, string, string, []byte, time.Time) (time.Time, error) {
	return time.Time{}, errors.New("the store failed")
}

// A rotation the store failed is answered 500, never a 200: with the
// marker, a 200 without tokens_not_before tells the owner that no
// tombstone is held (§6.7).
func TestRotateStoreErrorIs500(t *testing.T) {
	f := newFixture(t, nil)
	inner := f.newSt
	f.newSt = func() store.Backend { return failRotateStore{inner()} }
	f.restart()
	owner := newPrincipal(1)
	f.register(owner)
	code, m := f.rotateAnswer(owner, newPrincipal(4))
	if code != http.StatusInternalServerError || m["code"] != CodeInternal || m["reports_tombstones_at_rotation"] != nil {
		t.Fatalf("rotate with a failing store: %d %v", code, m)
	}
}
