package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/store"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Protocol 0.9.2 (§6.8): the mailbox's blob storage is shared; uploads are
// checked before their body against the cap (less one maximum blob kept
// for the owner's devices), the sender's share and the token's quota; the
// body streams to the store and nothing is left behind by an upload that
// does not end stored; the owner lists its blobs.

// shareFixture: blobs of at most 1,000 bytes, a mailbox cap of 4,000 (so
// 3,000 for peers), a share of 2,000 bytes in at most 3 blobs.
func shareFixture(t *testing.T, mut func(*config.Config)) *fixture {
	return newFixture(t, func(c *config.Config) {
		c.MaxBlobBytes, c.MailboxMaxBlobBytes, c.MaxSenderBlobs = 1000, 4000, 3
		if mut != nil {
			mut(c)
		}
	})
}

// leftovers counts blob bodies outside the database that no blob of the
// given mailboxes accounts for: staged files next to the SQLite database,
// or objects in the (fake) S3 bucket beyond the committed blobs.
func (f *fixture) leftovers(mailboxes ...principal) int {
	f.t.Helper()
	if f.s3 == nil {
		n, _ := filepath.Glob(filepath.Join(filepath.Dir(f.dbPath), ".relay-blob-staging-*", ".relay-blob-staged-*"))
		return len(n)
	}
	committed := 0
	for _, m := range mailboxes {
		bs, _, _, err := f.st.ListBlobs(context.Background(), m.mbx, "", 500)
		if err != nil {
			f.t.Fatal(err)
		}
		committed += len(bs)
	}
	return f.s3.Len() - committed
}

func (f *fixture) expectQuota(r req, kind string) {
	f.t.Helper()
	b := f.expectCode(r, 429, CodeQuotaExceeded)
	var e errorBody
	json.Unmarshal(b, &e)
	if e.Quota != kind {
		f.t.Fatalf("%s %s: quota %q, want %q (%s)", r.method, r.path, e.Quota, kind, b)
	}
}

func blobReq(owner, sender principal, tok string, n int) req {
	return req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: make([]byte, n), signer: &sender, token: tok}
}

// The per-sender share: bytes and number; another sender and another
// mailbox are not affected; a delete gives it back.
func TestBlobSenderShare(t *testing.T) {
	f := shareFixture(t, func(c *config.Config) { c.MailboxMaxBlobBytes = 10_000 })
	owner, other, s1, s2 := newPrincipal(1), newPrincipal(2), newPrincipal(11), newPrincipal(12)
	f.register(owner)
	f.register(other)
	t1 := f.mint(owner, s1, nil)
	f.mustPutBlob(owner, s1, t1, make([]byte, 1000))
	id := f.mustPutBlob(owner, s1, t1, make([]byte, 1000))
	f.expectQuota(blobReq(owner, s1, t1, 1), "sender_blobs")
	f.mustPutBlob(owner, s2, f.mint(owner, s2, nil), make([]byte, 1000))
	f.mustPutBlob(other, s1, f.mint(other, s1, nil), make([]byte, 1000))
	if code, _ := f.do(req{method: "DELETE", path: "/v1/blob/" + id, signer: &owner}); code != 204 {
		t.Fatal("delete")
	}
	f.mustPutBlob(owner, s1, t1, make([]byte, 999))
	// The number: tiny blobs cannot fill the mailbox's list.
	s3 := newPrincipal(13)
	t3 := f.mint(owner, s3, nil)
	for i := 0; i < 3; i++ {
		f.mustPutBlob(owner, s3, t3, make([]byte, 46))
	}
	f.expectQuota(blobReq(owner, s3, t3, 46), "sender_blobs")
}

// A token that names another key (minted by the mailbox owner, or leaked)
// cannot store anything under that key or use its share: the share is
// counted by the key that signed, after the body; and an upload under a
// token naming another key never adds to the signer's share either.
func TestForgedIdentityCannotUseAnotherShare(t *testing.T) {
	f := shareFixture(t, func(c *config.Config) { c.MailboxMaxBlobBytes = 10_000 })
	owner, victim, mallory := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	mt := f.mint(owner, mallory, func(c *auth.Claims) { c.Jti = "mallory" })
	f.mustPutBlob(owner, mallory, mt, make([]byte, 1000))
	f.mustPutBlob(owner, mallory, mt, make([]byte, 1000))
	f.expectQuota(blobReq(owner, mallory, mt, 1000), "sender_blobs") // mallory's share is used up
	// The victim's token, in mallory's hands: refused after the body, by
	// the signature; nothing is stored under either key.
	vt := f.mint(owner, victim, func(c *auth.Claims) { c.Jti = "victim" })
	for i := 0; i < 5; i++ {
		f.expectCode(blobReq(owner, mallory, vt, 1000), 401, CodeSignatureInvalid)
	}
	waitFor(t, f.s.blobRes.empty)
	// The victim's whole share is still its own.
	a := f.mustPutBlob(owner, victim, vt, make([]byte, 1000))
	b := f.mustPutBlob(owner, victim, vt, make([]byte, 1000))
	f.expectQuota(blobReq(owner, victim, vt, 1), "sender_blobs")
	// And each blob is the signer's.
	for _, bl := range f.listBlobs(owner, `{}`).Blobs {
		want := mallory.b64
		if bl.BlobID == a || bl.BlobID == b {
			want = victim.b64
		}
		if bl.Sender != want {
			t.Fatalf("blob %s sender %s, want %s", bl.BlobID, bl.Sender, want)
		}
	}
	if n := f.leftovers(owner); n != 0 {
		t.Fatalf("%d bodies left by refused uploads", n)
	}
}

// Room for the owner's devices: peers may fill the cap only up to one
// maximum blob short of it; uploads under an owner_device token, and the
// owner's claims, may use the whole cap. The claim is trusted only from
// the mailbox's own key.
func TestOwnerDeviceRoom(t *testing.T) {
	f := shareFixture(t, nil)
	owner, p1, p2, p3, phone, mallory := newPrincipal(1), newPrincipal(11), newPrincipal(12), newPrincipal(13), newPrincipal(20), newPrincipal(30)
	f.register(owner)
	f.register(mallory)
	f.mustPutBlob(owner, p1, f.mint(owner, p1, nil), make([]byte, 1000))
	f.mustPutBlob(owner, p1, f.mint(owner, p1, nil), make([]byte, 1000))
	f.mustPutBlob(owner, p2, f.mint(owner, p2, nil), make([]byte, 999))
	t3 := f.mint(owner, p3, nil)
	f.mustPutBlob(owner, p3, t3, []byte("x")) // 3,000: what peers may fill
	f.expectQuota(blobReq(owner, p3, t3, 1), "mailbox_blobs")
	// A forged device claim: a token naming the owner's mailbox, minted
	// by another key, and the owner's token with the claim added.
	forged, err := auth.MintToken(mallory.priv, auth.Claims{Iss: owner.mbx, Sub: p3.b64, Aud: testAud, Iat: f.clk.now().Add(-time.Minute),
		Exp: f.clk.now().Add(time.Hour), Jti: "forged", OwnerDevice: true})
	if err != nil {
		t.Fatal(err)
	}
	f.expectCode(blobReq(owner, p3, forged, 1), 401, CodeTokenInvalid)
	f.expectCode(blobReq(owner, p3, addOwnerDevice(t, t3), 1), 401, CodeTokenInvalid)
	// The owner's phone, under its device token: the kept room.
	dt := f.mint(owner, phone, func(c *auth.Claims) { c.Jti = "device"; c.OwnerDevice = true })
	f.mustPutBlob(owner, phone, dt, make([]byte, 500))
	// The owner's own claim may use the whole cap too.
	if code, b := f.do(req{method: "PUT", path: "/v1/claim", body: make([]byte, 500), signer: &owner}); code != 201 {
		t.Fatalf("claim: %d %s", code, b)
	}
	f.expectQuota(blobReq(owner, phone, dt, 1), "mailbox_blobs") // 4,000: full
	f.expectQuota(req{method: "PUT", path: "/v1/claim", body: []byte("x"), signer: &owner}, "mailbox_blobs")
}

// addOwnerDevice returns tok with "owner_device":true added to its claims
// and its signature left as it was.
func addOwnerDevice(t *testing.T, tok string) string {
	t.Helper()
	const prefix = "v4.public."
	raw, err := b64url(strings.TrimPrefix(tok, prefix))
	if err != nil {
		t.Fatal(err)
	}
	msg, sig := raw[:len(raw)-64], raw[len(raw)-64:]
	msg = append(bytes.TrimSuffix(msg, []byte("}")), []byte(`,"owner_device":true}`)...)
	return prefix + b64urlEncode(append(msg, sig...))
}

// Every quota_exceeded body says which quota: token, mailbox (deposits),
// mailbox_blobs, sender_blobs.
func TestQuotaMembers(t *testing.T) {
	f := shareFixture(t, func(c *config.Config) { c.MailboxMaxMessages = 1 })
	owner, s := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	q := int64(1)
	qt := f.mint(owner, s, func(c *auth.Claims) { c.Jti = "q"; c.Quota = &auth.Quota{Msgs: &q, Bytes: i64p(500)} })
	f.expectFrom(hostA, depositReq(owner, s, qt, "1"), 201, "")
	if e := f.expectFrom(hostA, depositReq(owner, s, qt, "2"), 429, CodeQuotaExceeded); e.Quota != "token" && e.Quota != "mailbox" {
		t.Fatalf("deposit quota %q", e.Quota)
	}
	tok := f.mint(owner, s, nil)
	if e := f.expectFrom(hostA, depositReq(owner, s, tok, "3"), 429, CodeQuotaExceeded); e.Quota != "mailbox" {
		t.Fatalf("deposit over the mailbox's quota: %q", e.Quota)
	}
	other := newPrincipal(3)
	f.register(other)
	ot := f.mint(other, s, func(c *auth.Claims) { c.Jti = "o"; c.Quota = &auth.Quota{Msgs: &q} })
	f.expectFrom(hostA, depositReq(other, s, ot, "1"), 201, "")
	if e := f.expectFrom(hostA, depositReq(other, s, ot, "2"), 429, CodeQuotaExceeded); e.Quota != "mailbox" {
		t.Fatalf("both exceeded: %q (the mailbox's first)", e.Quota)
	}
	f.mustPutBlob(owner, s, qt, make([]byte, 400))
	f.expectQuota(blobReq(owner, s, qt, 101), "token")
	f.mustPutBlob(owner, s, tok, make([]byte, 1000))
	f.expectQuota(blobReq(owner, s, tok, 1000), "sender_blobs") // 1,400 + 1,000 > 2,000
}

func i64p(v int64) *int64 { return &v }

func b64url(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
func b64urlEncode(b []byte) string    { return base64.RawURLEncoding.EncodeToString(b) }

// The checks before the body: an upload refused for any quota is answered
// at once, without its body being read (the client sends none), with
// Connection: close, holding no slot and charged nothing.
func TestBlobQuotaRefusedBeforeTheBody(t *testing.T) {
	f := shareFixture(t, func(c *config.Config) { c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 0.001, 10_000 })
	owner, s1, s2 := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	t1 := f.mint(owner, s1, nil)
	f.mustPutBlob(owner, s1, t1, make([]byte, 1000))
	f.mustPutBlob(owner, s1, t1, make([]byte, 1000))
	f.mustPutBlob(owner, s2, f.mint(owner, s2, nil), make([]byte, 1000)) // 3,000 of peers' 3,000
	q := int64(10)
	cases := map[string]string{
		// (under a device token, so that the mailbox's room, checked first, is not what refuses it)
		"sender_blobs":  f.mint(owner, s1, func(c *auth.Claims) { c.Jti = "s1-device"; c.OwnerDevice = true }),
		"mailbox_blobs": f.mint(owner, newPrincipal(4), nil),
		"token":         f.mint(owner, newPrincipal(4), func(c *auth.Claims) { c.Jti = "q"; c.OwnerDevice = true; c.Quota = &auth.Quota{Bytes: &q} }),
	}
	signers := map[string]principal{"sender_blobs": s1, "mailbox_blobs": newPrincipal(4), "token": newPrincipal(4)}
	for kind, tok := range cases {
		c := dial(t, f)
		began := time.Now()
		rawBlobPut(t, f, c, owner, signers[kind], tok, make([]byte, 500), 0) // headers only
		resp, e := readAnswer(t, c)
		if resp.StatusCode != 429 || e.Code != CodeQuotaExceeded || e.Quota != kind || !resp.Close || time.Since(began) > 2*time.Second {
			t.Fatalf("%s: %d %+v close=%v after %v", kind, resp.StatusCode, e, resp.Close, time.Since(began))
		}
	}
	if f.s.xfers.inFlight() != 0 || !f.s.blobRes.empty() {
		t.Fatal("a refused upload holds a slot or a reservation")
	}
	// Charged nothing: 10,000 − 3,000 is still there.
	if ok, _ := f.s.blobByteLimit.AllowN(rateKey(netip.MustParseAddr("127.0.0.1")), 7000, f.clk.now()); !ok {
		t.Fatal("refused uploads were charged")
	}
}

// An upload that holds a transfer slot holds its declared length against
// the mailbox, its sender's share and its token until it ends: two uploads
// that would together exceed the cap are not both let through to their
// bodies. One refused only for another's reservation is told to retry
// (rate_limited), not that the mailbox is full.
func TestBlobReservationHeldWhileTheBodyMoves(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		c.MaxBlobBytes, c.MailboxMaxBlobBytes = 100_000, 300_000 // peers: 200,000
	}, func(*fixture) []Option { return []Option{WithBlobPaceWindow(2 * time.Second)} })
	owner, s1, s2 := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	f.mustPutBlob(owner, s1, f.mint(owner, s1, nil), make([]byte, 50_000))
	c := dial(t, f)
	rawBlobPut(t, f, c, owner, s2, f.mint(owner, s2, nil), make([]byte, 100_000), 20_000) // 150,000 with the reservation
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	t3 := f.mint(owner, newPrincipal(4), nil)
	if b := f.expectCode(blobReq(owner, newPrincipal(4), t3, 60_000), 429, CodeRateLimited); !strings.Contains(string(b), `"retry_after":2`) {
		t.Fatalf("refused for a reservation: %s", b)
	}
	f.mustPutBlob(owner, newPrincipal(4), t3, make([]byte, 50_000)) // exactly 200,000
	// The stalled upload ends (dropped), its reservation with it.
	if resp, _ := readAnswer(t, c); resp.StatusCode != 400 {
		t.Fatalf("stalled upload: %d", resp.StatusCode)
	}
	waitFor(t, f.s.blobRes.empty)
	f.mustPutBlob(owner, newPrincipal(5), f.mint(owner, newPrincipal(5), nil), make([]byte, 100_000))
	if n := f.leftovers(owner); n != 0 {
		t.Fatalf("%d bodies left", n)
	}
	f.expectQuota(blobReq(owner, newPrincipal(6), f.mint(owner, newPrincipal(6), nil), 1), "mailbox_blobs") // what is stored: final
}

// An upload announced and never sent reserves nothing (it holds no slot):
// however many are announced, under however many keys, others' uploads
// go through.
func TestAnnouncedUploadsReserveNothing(t *testing.T) {
	f := shareFixture(t, nil) // peers may fill 3,000
	owner := newPrincipal(1)
	f.register(owner)
	for i := 0; i < 8; i++ {
		s := newPrincipal(byte(50 + i))
		c := dial(t, f)
		rawBlobPut(t, f, c, owner, s, f.mint(owner, s, nil), make([]byte, 1000), 0) // headers only
	}
	time.Sleep(100 * time.Millisecond)
	if !f.s.blobRes.empty() {
		t.Fatal("an announced upload reserved")
	}
	for i := 0; i < 3; i++ {
		s := newPrincipal(byte(70 + i))
		f.mustPutBlob(owner, s, f.mint(owner, s, nil), make([]byte, 1000))
	}
}

// An upload that passed the check before its body, and finds when it
// takes its slot that another upload has reserved meanwhile, is re-checked
// then: refused rate_limited, its connection closed, nothing kept.
func TestBlobReservationRecheckedAtTheSlot(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		c.MaxBlobBytes, c.MailboxMaxBlobBytes = 100_000, 300_000 // peers: 200,000
	}, func(*fixture) []Option { return []Option{WithBlobPaceWindow(3 * time.Second)} })
	owner, s1, s2, s3 := newPrincipal(1), newPrincipal(2), newPrincipal(3), newPrincipal(4)
	f.register(owner)
	f.mustPutBlob(owner, s1, f.mint(owner, s1, nil), make([]byte, 50_000))
	late := dial(t, f)
	data := make([]byte, 100_000)
	rawBlobPut(t, f, late, owner, s3, f.mint(owner, s3, nil), data, 0) // checked: 150,000 fits
	time.Sleep(50 * time.Millisecond)
	early := dial(t, f)
	rawBlobPut(t, f, early, owner, s2, f.mint(owner, s2, nil), data, 20_000) // reserves: 150,000
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	if _, err := late.Write(data[:20_000]); err != nil { // 250,000 with the reservation
		t.Fatal(err)
	}
	resp, e := readAnswer(t, late)
	if resp.StatusCode != 429 || e.Code != CodeRateLimited || e.RetryAfter != 2 || !resp.Close {
		t.Fatalf("re-check: %d %+v close=%v", resp.StatusCode, e, resp.Close)
	}
	if _, err := early.Write(data[20_000:]); err != nil {
		t.Fatal(err)
	}
	if resp, _ := readAnswer(t, early); resp.StatusCode != 201 {
		t.Fatalf("early: %d", resp.StatusCode)
	}
	waitFor(t, func() bool { return f.s.xfers.empty() && f.s.blobRes.empty() })
	if n := f.leftovers(owner); n != 0 {
		t.Fatalf("%d bodies left", n)
	}
}

// The commit is not cut short by the client going away after its last
// byte: the blob is stored whole (no counted blob without a body).
func TestBlobCommitOutlivesTheClient(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	hooks := &hookedBlobs{BlobStore: f.s.blobs, commitGate: make(chan struct{}), commitIn: make(chan struct{}, 1)}
	f.s.blobs = hooks
	data := bytes.Repeat([]byte{9}, 50_000)
	c := dial(t, f)
	rawBlobPut(t, f, c, owner, sender, f.mint(owner, sender, nil), data, len(data))
	<-hooks.commitIn
	c.Close()
	time.Sleep(200 * time.Millisecond) // the request's context is cancelled
	close(hooks.commitGate)
	waitFor(t, func() bool { return f.s.xfers.empty() && f.s.blobRes.empty() })
	if err := hooks.commitCtxErr.Load(); err != nil {
		t.Fatalf("the commit ran on a cancelled context: %v", err)
	}
	bs := f.listBlobs(owner, `{}`).Blobs
	if len(bs) != 1 {
		t.Fatalf("%d blobs", len(bs))
	}
	code, got, _ := f.send(f.build(req{method: "GET", path: "/v1/blob/" + bs[0].BlobID, signer: &owner}))
	if code != 200 || !bytes.Equal(got, data) {
		t.Fatalf("get: %d, %d bytes", code, len(got))
	}
}

// A commit that failed without a definite refusal (a timeout, say) may
// have been applied: the blob is deleted by its id, so no counted blob
// stays without a body. (Only a store that knows the id before the commit
// can be asked; the SQLite store's commit is one local transaction.)
func TestBlobAmbiguousCommitCleanedUp(t *testing.T) {
	f := newFixture(t, nil)
	if f.s3 == nil {
		t.Skip("the SQLite store's commit either happens or not")
	}
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	hooks := &hookedBlobs{BlobStore: f.s.blobs, applyThenFail: errors.New("timeout after the write")}
	f.s.blobs = hooks
	f.expectCode(blobReq(owner, sender, f.mint(owner, sender, nil), 5000), 500, CodeInternal)
	f.s.blobs = hooks.BlobStore
	waitFor(t, func() bool { return f.s.xfers.empty() && f.s.blobRes.empty() })
	out := f.listBlobs(owner, `{}`)
	if len(out.Blobs) != 0 || out.UsedBytes != 0 || f.leftovers(owner) != 0 {
		t.Fatalf("left: %+v, %d bodies", out, f.leftovers(owner))
	}
	if u, _ := f.st.BlobUsage(context.Background(), owner.mbx, sender.b64, "", true); u.SenderBlobs != 0 || u.SenderBytes != 0 {
		t.Fatalf("share left: %+v", u)
	}
}

// Whatever ends an upload after its body began, nothing stays behind: no
// staged body, no reservation; what it sent stays charged to its
// network, the rest is given back.
func TestBlobStreamFailuresLeaveNothing(t *testing.T) {
	f := newFixtureWith(t, func(c *config.Config) {
		c.MaxBlobBytes, c.MailboxMaxBlobBytes = 100_000, 1<<20
		c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 0.001, 1<<20
	}, func(*fixture) []Option { return []Option{WithBlobPaceWindow(300 * time.Millisecond)} })
	owner, sender, thief := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	data := bytes.Repeat([]byte{7}, 100_000)
	check := func(what string) {
		t.Helper()
		waitFor(t, func() bool { return f.s.xfers.empty() && f.s.blobRes.empty() })
		if n := f.leftovers(owner); n != 0 {
			t.Fatalf("%s: %d bodies left", what, n)
		}
		if bs := f.listBlobs(owner, `{}`).Blobs; len(bs) != 0 {
			t.Fatalf("%s: %d blobs stored", what, len(bs))
		}
	}
	// A body that stalls part-way.
	c := dial(t, f)
	rawBlobPut(t, f, c, owner, sender, tok, data, 40_000)
	if resp, _ := readAnswer(t, c); resp.StatusCode != 400 || !resp.Close {
		t.Fatalf("stalled: %d", resp.StatusCode)
	}
	check("stalled")

	// A client that goes away part-way.
	c = dial(t, f)
	rawBlobPut(t, f, c, owner, sender, tok, data, 40_000)
	waitFor(t, func() bool { return f.s.xfers.inFlight() == 1 })
	c.Close()
	check("gone")

	// A whole body whose signature is not the token's sender's.
	f.expectCode(req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: data, signer: &thief, token: tok}, 401, CodeSignatureInvalid)
	check("signature")

	// A body that is not what was signed.
	signed := f.build(req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: data, signer: &sender, token: tok})
	tampered, _ := http.NewRequest("PUT", signed.URL.String(), bytes.NewReader(bytes.Repeat([]byte{8}, 100_000)))
	tampered.Header = signed.Header
	if code, b, _ := f.send(tampered); code != 401 || !strings.Contains(string(b), CodeSignatureInvalid) {
		t.Fatalf("tampered: %d %s", code, b)
	}
	check("tampered")

	// The store refuses at the commit (another process filled the
	// mailbox meanwhile), or fails to stage or to commit.
	for _, h := range []struct {
		name   string
		stage  error
		commit error
		code   string
		quota  string
	}{
		{"commit quota", nil, store.ErrQuotaMailboxBlobs, CodeQuotaExceeded, "mailbox_blobs"},
		{"commit share", nil, store.ErrQuotaSenderBlobs, CodeQuotaExceeded, "sender_blobs"},
		{"commit failure", nil, errors.New("store down"), CodeInternal, ""},
		{"stage failure", errors.New("bucket down"), nil, CodeInternal, ""},
	} {
		hooks := &hookedBlobs{BlobStore: f.s.blobs, stageErr: h.stage, commitErr: h.commit}
		f.s.blobs = hooks
		b := f.expectCode(req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: data, signer: &sender, token: tok}, statusFor(h.code), h.code)
		var e errorBody
		json.Unmarshal(b, &e)
		if e.Quota != h.quota {
			t.Fatalf("%s: quota %q", h.name, e.Quota)
		}
		f.s.blobs = hooks.BlobStore
		check(h.name)
		if h.commit != nil && hooks.discards.Load() == 0 {
			t.Fatalf("%s: the staged body was not discarded", h.name)
		}
	}
	// After all that, an upload is stored.
	f.mustPutBlob(owner, sender, tok, data)
}

// hookedBlobs makes StageBlob or Commit fail (the staged body is kept
// until the handler discards it).
type hookedBlobs struct {
	store.BlobStore
	stageErr, commitErr error
	applyThenFail       error // the commit is applied, then fails with this
	commitIn            chan struct{}
	commitGate          chan struct{} // the commit waits for it to close
	commitCtxErr        atomic.Value
	discards            atomicInt
}

type atomicInt struct {
	mu sync.Mutex
	n  int
}

func (a *atomicInt) Add(d int) { a.mu.Lock(); a.n += d; a.mu.Unlock() }
func (a *atomicInt) Load() int { a.mu.Lock(); defer a.mu.Unlock(); return a.n }

func (h *hookedBlobs) StageBlob(ctx context.Context, mailbox string, size int64, r io.Reader) (store.StagedBlob, error) {
	if h.stageErr != nil {
		io.Copy(io.Discard, r) // the body arrives; the store fails
		return nil, h.stageErr
	}
	st, err := h.BlobStore.StageBlob(ctx, mailbox, size, r)
	if err != nil {
		return nil, err
	}
	return &hookedStaged{StagedBlob: st, h: h}, nil
}

type hookedStaged struct {
	store.StagedBlob
	h *hookedBlobs
}

func (s *hookedStaged) Commit(ctx context.Context, p store.BlobPut) (store.BlobInfo, error) {
	if s.h.commitErr != nil {
		return store.BlobInfo{}, s.h.commitErr
	}
	if s.h.commitGate != nil {
		s.h.commitIn <- struct{}{}
		<-s.h.commitGate
		if err := ctx.Err(); err != nil {
			s.h.commitCtxErr.Store(err)
		}
	}
	info, err := s.StagedBlob.Commit(ctx, p)
	if err == nil && s.h.applyThenFail != nil {
		return store.BlobInfo{}, s.h.applyThenFail
	}
	return info, err
}

func (s *hookedStaged) Discard(ctx context.Context) error {
	s.h.discards.Add(1)
	return s.StagedBlob.Discard(ctx)
}

// An upload whose slot goes to a newer one leaves nothing behind either.
func TestEvictedUploadLeavesNothing(t *testing.T) {
	f := evictFixture(t, func(c *config.Config) { c.BlobEvictMinAge = 0 })
	owner, slow, fast := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	data := make([]byte, 64<<10)
	c := dial(t, f)
	rawBlobPutVia(t, f, c, trickler, owner, slow, data, 20_000)
	waitFor(t, func() bool { return f.uploadOf(owner.mbx) != nil })
	f.clk.add(10 * time.Second) // past the grace
	c2 := dial(t, f)
	rawBlobPutVia(t, f, c2, "203.0.113.77", owner, fast, data, len(data))
	if resp, e := readAnswer(t, c); resp.StatusCode != 429 || e.Code != CodeRateLimited {
		t.Fatalf("evicted: %d %+v", resp.StatusCode, e)
	}
	if resp, _ := readAnswer(t, c2); resp.StatusCode != 201 {
		t.Fatalf("newcomer: %d", resp.StatusCode)
	}
	waitFor(t, func() bool { return f.s.xfers.empty() && f.s.blobRes.empty() })
	if n := f.leftovers(owner); n != 0 {
		t.Fatalf("%d bodies left", n)
	}
	if bs := f.listBlobs(owner, `{}`).Blobs; len(bs) != 1 || bs[0].Sender != fast.b64 {
		t.Fatalf("stored %+v", bs)
	}
}

func (f *fixture) listBlobs(owner principal, body string) blobListResponse {
	f.t.Helper()
	code, b := f.do(req{method: "POST", path: "/v1/blobs", body: []byte(body), signer: &owner})
	if code != 200 {
		f.t.Fatalf("list: %d %s", code, b)
	}
	var out blobListResponse
	if err := json.Unmarshal(b, &out); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// POST /v1/blobs: the owner's list, paged by its signed body.
func TestBlobList(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxSenderBlobs = 100 })
	owner, other, s1, s2 := newPrincipal(1), newPrincipal(2), newPrincipal(11), newPrincipal(12)
	f.register(owner)
	f.register(other)
	var ids []string
	for i := 0; i < 5; i++ {
		s := s1
		if i%2 == 1 {
			s = s2
		}
		ids = append(ids, f.mustPutBlob(owner, s, f.mint(owner, s, nil), make([]byte, 100+i)))
	}
	f.mustPutBlob(other, s1, f.mint(other, s1, nil), make([]byte, 7))
	if code, _ := f.do(req{method: "PUT", path: "/v1/claim", body: make([]byte, 90), signer: &owner}); code != 201 {
		t.Fatal("claim")
	}
	// Pages of 2 with next, until a page without one.
	var got []wireBlob
	body := `{"max":2}`
	for page := 0; page < 3; page++ {
		out := f.listBlobs(owner, body)
		if out.UsedBytes != 90+100+101+102+103+104 || out.MaxBytes != f.cfg.MailboxMaxBlobBytes {
			t.Fatalf("used %d max %d", out.UsedBytes, out.MaxBytes)
		}
		got = append(got, out.Blobs...)
		if page < 2 && (len(out.Blobs) != 2 || out.Next != out.Blobs[1].BlobID) || page == 2 && (len(out.Blobs) != 1 || out.Next != "") {
			t.Fatalf("page %d: %+v", page, out)
		}
		body = `{"after":"` + out.Next + `","max":2}`
	}
	for i, b := range got {
		want := s1.b64
		if i%2 == 1 {
			want = s2.b64
		}
		exp, err1 := time.Parse(time.RFC3339, b.ExpiresAt)
		_, err2 := time.Parse(time.RFC3339, b.CreatedAt)
		if b.BlobID != ids[i] || b.Size != int64(100+i) || b.Sender != want || err1 != nil || err2 != nil || !exp.After(f.clk.now()) {
			t.Fatalf("blob %d: %+v", i, b)
		}
	}
	// Defaults: an empty body or {} lists up to 100.
	if out := f.listBlobs(owner, ``); len(out.Blobs) != 5 || out.Next != "" {
		t.Fatalf("empty body: %+v", out)
	}
	if out := f.listBlobs(owner, ` {} `); len(out.Blobs) != 5 {
		t.Fatalf("{}: %+v", out)
	}
	// Another owner sees only its own; a key without a mailbox nothing.
	if out := f.listBlobs(other, `{}`); len(out.Blobs) != 1 || out.UsedBytes != 7 {
		t.Fatalf("other: %+v", out)
	}
	stranger := newPrincipal(40)
	f.expectCode(req{method: "POST", path: "/v1/blobs", body: []byte(`{}`), signer: &stranger}, 404, CodeMailboxUnknown)
	f.expectCode(req{method: "POST", path: "/v1/blobs", body: []byte(`{}`)}, 401, CodeSignatureInvalid)
	// Malformed paging: never clamped.
	for _, b := range []string{`{"max":0}`, `{"max":501}`, `{"max":"5"}`, `{"max":1.5}`, `{"max":-1}`, `{"max":05}`, `{"after":"nope"}`, `{"after":5}`, `[]`, `{"max":2}{}`, `not json`} {
		f.expectCode(req{method: "POST", path: "/v1/blobs", body: []byte(b), signer: &owner}, 400, CodeBadRequest)
	}
	if out := f.listBlobs(owner, `{"max":500}`); len(out.Blobs) != 5 {
		t.Fatal("max 500")
	}
	f.expectCode(req{method: "POST", path: "/v1/blobs", body: append([]byte(`{"max":2,"x":"`), append(bytes.Repeat([]byte("a"), 1100), '"', '}')...), signer: &owner}, 413, CodePayloadTooLarge)
}

// The paging parameters are covered by the signature (they are in the
// body), and a list request cannot be replayed.
func TestBlobListSignedAndNotReplayable(t *testing.T) {
	f := newFixture(t, nil)
	owner, s := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	tok := f.mint(owner, s, nil)
	first := f.mustPutBlob(owner, s, tok, []byte("a"))
	f.mustPutBlob(owner, s, tok, []byte("bb"))
	at := f.sigTime()
	r := req{method: "POST", path: "/v1/blobs", body: []byte(`{"max":1}`), signer: &owner, at: at}
	if code, _ := f.do(r); code != 200 {
		t.Fatal("first list")
	}
	f.expectCode(r, 401, CodeReplayDetected)
	// Another page in the same millisecond has another signature.
	r2 := req{method: "POST", path: "/v1/blobs", body: []byte(`{"after":"` + first + `","max":1}`), signer: &owner, at: at}
	if code, b := f.do(r2); code != 200 || !strings.Contains(string(b), `"size":2`) {
		t.Fatalf("second page: %d %s", code, b)
	}
	// Changing the body in transit breaks the signature.
	signed := f.build(req{method: "POST", path: "/v1/blobs", body: []byte(`{"max":1}`), signer: &owner})
	altered, _ := http.NewRequest("POST", signed.URL.String(), strings.NewReader(`{"max":2}`))
	altered.Header = signed.Header
	if code, b, _ := f.send(altered); code != 401 || !strings.Contains(string(b), CodeSignatureInvalid) {
		t.Fatalf("altered: %d %s", code, b)
	}
	// The query string is not read.
	if code, b := f.do(req{method: "POST", path: "/v1/blobs?max=1", body: []byte(`{}`), signer: &owner}); code != 200 || strings.Count(string(b), "blob_id") != 2 {
		t.Fatalf("query: %d %s", code, b)
	}
}

// Without blobs there is no list.
func TestBlobListNeedsBlobs(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.BlobsEnabled = false })
	owner := newPrincipal(1)
	f.register(owner)
	f.expectCode(req{method: "POST", path: "/v1/blobs", body: []byte(`{}`), signer: &owner}, 404, CodeNotFound)
}
