package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	auth "github.com/vettid/vettid-relay/relayauth"
)

func (f *fixture) putBlob(owner, sender principal, token string, data []byte) (int, []byte) {
	f.t.Helper()
	r := req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: data, signer: &sender, token: token,
		header: http.Header{"Content-Type": {"application/octet-stream"}}}
	return f.do(r)
}

func (f *fixture) mustPutBlob(owner, sender principal, token string, data []byte) string {
	f.t.Helper()
	code, b := f.putBlob(owner, sender, token, data)
	if code != http.StatusCreated {
		f.t.Fatalf("put blob: %d %s", code, b)
	}
	var out struct {
		BlobID    string `json:"blob_id"`
		ExpiresAt string `json:"expires_at"`
	}
	json.Unmarshal(b, &out)
	exp, err := time.Parse(time.RFC3339, out.ExpiresAt)
	if len(out.BlobID) != 26 || err != nil || !exp.Equal(f.clk.now().Add(f.cfg.BlobTTL)) {
		f.t.Fatalf("put blob body %s", b)
	}
	return out.BlobID
}

func TestBlobPutGetDelete(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender, other := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	f.register(other)
	tok := f.mint(owner, sender, nil)
	data := bytes.Repeat([]byte{0xC1, 0x9E}, 3<<20) // 6 MiB of "ciphertext"
	id := f.mustPutBlob(owner, sender, tok, data)

	code, got, h := f.send(f.build(req{method: "GET", path: "/v1/blob/" + id, signer: &owner}))
	if code != 200 || !bytes.Equal(got, data) || h.Get("Content-Type") != "application/octet-stream" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("get: %d len=%d %v", code, len(got), h)
	}
	// No existence oracle: another mailbox's blob and a random id look identical.
	b1 := f.expectCode(req{method: "GET", path: "/v1/blob/" + id, signer: &other}, 404, CodeBlobUnknown)
	b2 := f.expectCode(req{method: "GET", path: "/v1/blob/01J00000000000000000000000", signer: &owner}, 404, CodeBlobUnknown)
	b3 := f.expectCode(req{method: "GET", path: "/v1/blob/nope", signer: &owner}, 404, CodeBlobUnknown)
	if !bytes.Equal(b1, b2) || !bytes.Equal(b2, b3) {
		t.Fatal("blob_unknown responses differ")
	}
	// The sender cannot fetch what it uploaded (it does not own the mailbox).
	f.expectCode(req{method: "GET", path: "/v1/blob/" + id, signer: &sender}, 404, CodeMailboxUnknown)

	// Delete by a non-owner is a no-op 204; the owner's delete removes it.
	if code, _ := f.do(req{method: "DELETE", path: "/v1/blob/" + id, signer: &other}); code != 204 {
		t.Fatal("foreign delete")
	}
	if code, _ := f.do(req{method: "GET", path: "/v1/blob/" + id, signer: &owner}); code != 200 {
		t.Fatal("foreign delete removed the blob")
	}
	for i := 0; i < 2; i++ {
		if code, _ := f.do(req{method: "DELETE", path: "/v1/blob/" + id, signer: &owner}); code != 204 {
			t.Fatal("delete not idempotent")
		}
	}
	f.expectCode(req{method: "GET", path: "/v1/blob/" + id, signer: &owner}, 404, CodeBlobUnknown)
}

func TestBlobLimitsAndAuth(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.MaxBlobBytes = 1000
		c.MailboxMaxBlobBytes = 2500
	})
	owner, sender, mallory := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	f.register(owner)
	tok := f.mint(owner, sender, nil)
	path := "/v1/blob/" + owner.mbx

	// Exactly at the limit is accepted; one byte over is not.
	f.mustPutBlob(owner, sender, tok, make([]byte, 1000))
	f.expectCode(req{method: "PUT", path: path, body: make([]byte, 1001), signer: &sender, token: tok}, 413, CodePayloadTooLarge)

	// Chunked (no Content-Length): enforced while streaming.
	hr := f.build(req{method: "PUT", path: path, signer: &sender, token: tok})
	hr.Body = io.NopCloser(struct{ io.Reader }{bytes.NewReader(make([]byte, 5000))})
	hr.ContentLength = -1
	if code, b, _ := f.send(hr); code != 413 || !strings.Contains(string(b), CodePayloadTooLarge) {
		t.Fatalf("chunked oversize: %d %s", code, b)
	}

	// Authorization happens before the body is read: a revoked token gets
	// token_revoked even when the (chunked) body is oversized.
	rt := f.mint(owner, sender, func(c *auth.Claims) { c.Jti = "revoked-blob" })
	f.revoke(owner, "jti", "revoked-blob")
	hr = f.build(req{method: "PUT", path: path, signer: &sender, token: rt})
	hr.Body = io.NopCloser(struct{ io.Reader }{bytes.NewReader(make([]byte, 5000))})
	hr.ContentLength = -1
	if code, b, _ := f.send(hr); code != 403 || !strings.Contains(string(b), CodeTokenRevoked) {
		t.Fatalf("revoked chunked: %d %s", code, b)
	}

	// Tampered body: signature computed over different bytes.
	signed := f.build(req{method: "PUT", path: path, body: []byte("original"), signer: &sender, token: tok})
	tampered, _ := http.NewRequest("PUT", signed.URL.String(), bytes.NewReader([]byte("tampered")))
	tampered.Header = signed.Header
	if code, b, _ := f.send(tampered); code != 401 || !strings.Contains(string(b), CodeSignatureInvalid) {
		t.Fatalf("tampered blob: %d %s", code, b)
	}
	// Stolen token, wrong signer.
	f.expectCode(req{method: "PUT", path: path, body: []byte("x"), signer: &mallory, token: tok}, 401, CodeSignatureInvalid)
	// Unknown mailbox.
	ghost := newPrincipal(9)
	f.expectCode(req{method: "PUT", path: "/v1/blob/" + ghost.mbx, body: []byte("x"), signer: &sender, token: tok}, 404, CodeMailboxUnknown)

	// Mailbox blob storage cap: 1000 stored; +1000 ok; +1000 over 2500.
	f.mustPutBlob(owner, sender, tok, make([]byte, 1000))
	f.expectCode(req{method: "PUT", path: path, body: make([]byte, 1000), signer: &sender, token: tok}, 429, CodeQuotaExceeded)

	// Token byte quota counts blob bytes.
	q := int64(600)
	qt := f.mint(owner, sender, func(c *auth.Claims) { c.Jti = "bytes-quota"; c.Quota = &auth.Quota{Bytes: &q} })
	f.mustPutBlob(owner, sender, qt, make([]byte, 400))
	f.expectCode(req{method: "PUT", path: path, body: make([]byte, 300), signer: &sender, token: qt}, 429, CodeQuotaExceeded)
}

func TestBlobTTL(t *testing.T) {
	f := newFixture(t, nil)
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	id := f.mustPutBlob(owner, sender, f.mint(owner, sender, nil), []byte("short-lived"))
	f.clk.add(f.cfg.BlobTTL)
	f.expectCode(req{method: "GET", path: "/v1/blob/" + id, signer: &owner}, 404, CodeBlobUnknown)
}

func TestBlobsDisabled(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.BlobsEnabled = false })
	owner, sender := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	f.expectCode(req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: []byte("x"), signer: &sender, token: f.mint(owner, sender, nil)}, 404, CodeNotFound)
}
