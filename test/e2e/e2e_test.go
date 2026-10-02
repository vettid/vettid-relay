// Package e2e runs the RELAY-PLAN Phase 4 integration scenario against a real
// relay instance (real HTTP server, real clock, real SQLite file) with two
// simulated principals: a vault (mailbox owner) and an app (sender).
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/api"
	"github.com/vettid/vettid-relay/internal/client"
	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
)

func startRelay(t *testing.T) string {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	cfg := config.Defaults()
	cfg.BaseURL = ts.URL // tokens are minted for this exact audience
	srv := api.New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New())
	ts.Config.Handler = srv.Handler()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Drain(ctx)
		ts.Close()
		srv.Close()
		st.Close()
	})
	return ts.URL
}

func newPrincipal(t *testing.T, url string) *client.Client {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return client.New(url, k)
}

func TestTwoPrincipals(t *testing.T) {
	url := startRelay(t)
	ctx := context.Background()
	vault := newPrincipal(t, url) // mailbox owner
	app := newPrincipal(t, url)   // authorized sender

	// 1. Register both principals.
	reg, err := vault.Register(ctx)
	if err != nil || !reg.Created || reg.MailboxID != vault.MailboxID() {
		t.Fatalf("register vault: %+v %v", reg, err)
	}
	if reg.Limits.MaxPayloadBytes != 262144 || reg.Limits.MaxBlobBytes == nil || *reg.Limits.MaxBlobBytes != 8388608 {
		t.Fatalf("limits: %+v", reg.Limits)
	}
	if _, err := app.Register(ctx); err != nil {
		t.Fatal(err)
	}
	again, err := vault.Register(ctx)
	if err != nil || again.Created {
		t.Fatalf("re-register must be idempotent: %+v %v", again, err)
	}

	// 2. The vault mints a deposit token for the app (out of band in reality).
	tok, err := vault.MintToken(app.PublicKeyB64(), url, client.TokenOptions{TTL: time.Hour, JTI: "conn-app-1"})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Vault parks a long-poll; app deposits; delivery is woken (< 1 s).
	type result struct {
		msgs []client.Message
		at   time.Time
		err  error
	}
	got := make(chan result, 1)
	go func() {
		m, err := vault.Collect(ctx, 25*time.Second, 10)
		got <- result{m, time.Now(), err}
	}()
	time.Sleep(300 * time.Millisecond) // let the collect park
	sentAt := time.Now()
	msgID, err := app.Deposit(ctx, vault.MailboxID(), tok, []byte("e2e-ciphertext-1"))
	if err != nil {
		t.Fatal(err)
	}
	var r result
	select {
	case r = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll not woken")
	}
	if r.err != nil || len(r.msgs) != 1 || r.msgs[0].MsgID != msgID || string(r.msgs[0].Payload) != "e2e-ciphertext-1" ||
		r.msgs[0].Sender != app.PublicKeyB64() {
		t.Fatalf("collect: %+v %v", r.msgs, r.err)
	}
	if lat := r.at.Sub(sentAt); lat >= time.Second {
		t.Fatalf("wake-on-deposit latency %v ≥ 1 s", lat)
	} else {
		t.Logf("deposit→long-poll delivery: %v", lat)
	}

	// 4. Ack; nothing left.
	if err := vault.Ack(ctx, msgID); err != nil {
		t.Fatal(err)
	}
	if err := vault.Ack(ctx, msgID); err != nil {
		t.Fatalf("ack must be idempotent: %v", err)
	}
	if m, err := vault.Collect(ctx, 0, 10); err != nil || len(m) != 0 {
		t.Fatalf("after ack: %+v %v", m, err)
	}

	// 5. Claim-check blob flow: app uploads ciphertext, then sends a small
	// message pointing at it; vault collects, fetches, verifies, deletes.
	blob := make([]byte, 5<<20)
	rand.Read(blob)
	sum := sha256.Sum256(blob)
	blobID, exp, err := app.PutBlob(ctx, vault.MailboxID(), tok, blob)
	if err != nil || time.Until(exp) < 6*24*time.Hour {
		t.Fatalf("put blob: %v exp=%v", err, exp)
	}
	ptr, _ := json.Marshal(map[string]any{"blob_id": blobID, "content_hash": sum[:], "size": len(blob)}) // E2E-encrypted in reality
	ptrID, err := app.Deposit(ctx, vault.MailboxID(), tok, ptr)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := vault.Collect(ctx, 5*time.Second, 10)
	if err != nil || len(msgs) != 1 || msgs[0].MsgID != ptrID {
		t.Fatalf("collect pointer: %+v %v", msgs, err)
	}
	var claim struct {
		BlobID      string `json:"blob_id"`
		ContentHash []byte `json:"content_hash"`
	}
	json.Unmarshal(msgs[0].Payload, &claim)
	fetched, err := vault.GetBlob(ctx, claim.BlobID)
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(fetched); !bytes.Equal(h[:], claim.ContentHash) {
		t.Fatal("blob content hash mismatch")
	}
	if _, err := app.GetBlob(ctx, blobID); err == nil {
		t.Fatal("sender must not be able to fetch the recipient's blob")
	}
	if err := vault.DeleteBlob(ctx, blobID); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.GetBlob(ctx, blobID); !client.IsCode(err, "blob_unknown") {
		t.Fatalf("deleted blob: %v", err)
	}
	vault.Ack(ctx, ptrID)

	// 6. WebSocket collect: live push and ack over the socket.
	stream, err := vault.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wsSent := time.Now()
	wsID, err := app.Deposit(ctx, vault.MailboxID(), tok, []byte("over websocket"))
	if err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	m, err := stream.Next(sctx)
	cancel()
	if err != nil || m.MsgID != wsID {
		t.Fatalf("ws next: %+v %v", m, err)
	}
	t.Logf("deposit→websocket delivery: %v", time.Since(wsSent))
	if err := stream.Ack(ctx, wsID); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		left, err := vault.Collect(ctx, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("websocket ack did not delete the message")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 7. A stolen token is useless without the sender's key.
	mallory := newPrincipal(t, url)
	if _, err := mallory.Deposit(ctx, vault.MailboxID(), tok, []byte("forged")); !client.IsCode(err, "signature_invalid") {
		t.Fatalf("stolen token: %v", err)
	}

	// 8. Revoke the app (by sub); its deposits and uploads are now rejected.
	if err := vault.Revoke(ctx, client.Revocation{Kind: "sub", Value: app.PublicKeyB64()}); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Deposit(ctx, vault.MailboxID(), tok, []byte("after revoke")); !client.IsCode(err, "token_revoked") {
		t.Fatalf("deposit after revoke: %v", err)
	}
	if _, _, err := app.PutBlob(ctx, vault.MailboxID(), tok, []byte("blob after revoke")); !client.IsCode(err, "token_revoked") {
		t.Fatalf("blob after revoke: %v", err)
	}
	// A freshly minted token for the same sub is also refused while the
	// sub entry is retained.
	tok2, _ := vault.MintToken(app.PublicKeyB64(), url, client.TokenOptions{TTL: time.Hour})
	if _, err := app.Deposit(ctx, vault.MailboxID(), tok2, []byte("x")); !client.IsCode(err, "token_revoked") {
		t.Fatalf("new token for revoked sub: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	url := startRelay(t)
	ctx := context.Background()
	vault, app := newPrincipal(t, url), newPrincipal(t, url)
	if _, err := vault.Register(ctx); err != nil {
		t.Fatal(err)
	}
	oldTok, _ := vault.MintToken(app.PublicKeyB64(), url, client.TokenOptions{TTL: time.Hour})
	pending, err := app.Deposit(ctx, vault.MailboxID(), oldTok, []byte("before rotation"))
	if err != nil {
		t.Fatal(err)
	}
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	newID, err := vault.Rotate(ctx, newKey)
	if err != nil {
		t.Fatal(err)
	}
	next := client.New(url, newKey)
	if newID != next.MailboxID() {
		t.Fatal("rotation returned the wrong mailbox id")
	}
	// Old mailbox still collects during the grace period.
	if m, err := vault.Collect(ctx, 0, 10); err != nil || len(m) != 1 || m[0].MsgID != pending {
		t.Fatalf("old mailbox during grace: %+v %v", m, err)
	}
	// New tokens are issued under the new key for the new address.
	newTok, _ := next.MintToken(app.PublicKeyB64(), url, client.TokenOptions{TTL: time.Hour})
	id, err := app.Deposit(ctx, newID, newTok, []byte("after rotation"))
	if err != nil {
		t.Fatal(err)
	}
	if m, err := next.Collect(ctx, 0, 10); err != nil || len(m) != 1 || m[0].MsgID != id {
		t.Fatalf("new mailbox: %+v %v", m, err)
	}
	// Old-key tokens cannot target the new mailbox.
	if _, err := app.Deposit(ctx, newID, oldTok, []byte("x")); !client.IsCode(err, "token_invalid") {
		t.Fatalf("old token on new mailbox: %v", err)
	}
}

// First contact (spec §5.6 + §6.9): the owner leaves a bootstrap bundle as a
// claim and mints a one-shot open token; both travel out of band (e.g. a QR
// code carrying {claim_id, bundle_hash, token}). A stranger with no prior
// relationship fetches the bundle, deposits exactly once with its own key,
// and the owner learns that key and answers with a sender-bound token.
func TestFirstContact(t *testing.T) {
	url := startRelay(t)
	ctx := context.Background()
	owner := newPrincipal(t, url)
	stranger := newPrincipal(t, url) // never registers
	if _, err := owner.Register(ctx); err != nil {
		t.Fatal(err)
	}

	bundle := []byte("owner's public key bundle")
	bundleHash := sha256.Sum256(bundle)
	claimID, _, err := owner.PutClaim(ctx, bundle, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	openTok, err := owner.MintOpenToken(url, 5*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	// --- out of band: {claimID, bundleHash, openTok, owner address} ---

	got, err := stranger.GetClaim(ctx, claimID)
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256(got); h != bundleHash {
		t.Fatal("bundle does not match the out-of-band hash")
	}
	if _, err := stranger.GetClaim(ctx, claimID); !client.IsCode(err, "claim_unknown") {
		t.Fatalf("claim must be single-fetch: %v", err)
	}

	hello, err := stranger.Deposit(ctx, owner.MailboxID(), openTok, []byte("hello (E2E-encrypted to the bundle)"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.Deposit(ctx, owner.MailboxID(), openTok, []byte("again")); !client.IsCode(err, "token_used") {
		t.Fatalf("second use: %v", err)
	}
	thief := newPrincipal(t, url)
	if _, err := thief.Deposit(ctx, owner.MailboxID(), openTok, []byte("me too")); !client.IsCode(err, "token_used") {
		t.Fatalf("reuse by another key: %v", err)
	}

	msgs, err := owner.Collect(ctx, 5*time.Second, 10)
	if err != nil || len(msgs) != 1 || msgs[0].MsgID != hello {
		t.Fatalf("collect: %+v %v", msgs, err)
	}
	if msgs[0].Sender != stranger.PublicKeyB64() {
		t.Fatalf("sender %q, want the stranger's key", msgs[0].Sender)
	}
	owner.Ack(ctx, hello)

	// The owner approves the contact: a normal sender-bound token for the
	// key it just learned. The stranger registers its own mailbox to receive.
	bound, err := owner.MintToken(msgs[0].Sender, url, client.TokenOptions{TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	id, err := stranger.Deposit(ctx, owner.MailboxID(), bound, []byte("now a known contact"))
	if err != nil {
		t.Fatal(err)
	}
	if m, err := owner.Collect(ctx, 5*time.Second, 10); err != nil || len(m) != 1 || m[0].MsgID != id || m[0].Sender != stranger.PublicKeyB64() {
		t.Fatalf("bound follow-up: %+v %v", m, err)
	}
	// The thief cannot use the bound token.
	if _, err := thief.Deposit(ctx, owner.MailboxID(), bound, []byte("x")); !client.IsCode(err, "signature_invalid") {
		t.Fatalf("bound token theft: %v", err)
	}
}
