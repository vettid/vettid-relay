package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
	client "github.com/vettid/vettid-relay/relayclient"
)

// countingSeeker counts the bytes read from it (a streamed upload reads
// its body once to hash it and once per attempt to send it).
type countingSeeker struct {
	*bytes.Reader
	n int64
}

func (c *countingSeeker) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	c.n += int64(n)
	return n, err
}

// The 0.9.2 client side: the advertised blob limits, streamed uploads,
// the owner's list, device tokens, and quota errors that say which quota
// and are not retried.
func TestBlobsProtocol092(t *testing.T) {
	url := startRelay(t)
	ctx := context.Background()
	vault, app, peer := newPrincipal(t, url), newPrincipal(t, url), newPrincipal(t, url)
	reg, err := vault.Register(ctx)
	if err != nil {
		t.Fatal(err)
	}
	l := reg.Limits
	if l.MaxMailboxBlobBytes == nil || *l.MaxMailboxBlobBytes != 64<<20 || l.MaxSenderBlobBytes == nil || *l.MaxSenderBlobBytes != 16<<20 ||
		l.MaxSenderBlobs == nil || *l.MaxSenderBlobs != 16 {
		t.Fatalf("limits %+v", l)
	}

	// A streamed upload: read once to hash, once to send.
	data := make([]byte, 3<<20)
	rand.Read(data)
	body := &countingSeeker{Reader: bytes.NewReader(data)}
	devTok, err := vault.MintToken(app.PublicKeyB64(), url, client.TokenOptions{OwnerDevice: true})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := auth.ParseToken(devTok, vault.PublicKey()); err != nil || !c.OwnerDevice {
		t.Fatalf("device token: %+v %v", c, err)
	}
	id, exp, err := app.PutBlobFrom(ctx, vault.MailboxID(), devTok, body, int64(len(data)))
	if err != nil || time.Until(exp) < 6*24*time.Hour {
		t.Fatalf("streamed put: %v", err)
	}
	if body.n != 2*int64(len(data)) {
		t.Fatalf("read %d bytes", body.n)
	}
	if got, err := vault.GetBlob(ctx, id); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("get: %v", err)
	}

	// The peer fills its share (16 MiB): the third 8 MiB blob is refused,
	// sender_blobs, at once (not retried).
	peerTok, _ := vault.MintToken(peer.PublicKeyB64(), url, client.TokenOptions{})
	big := make([]byte, 8<<20)
	for i := 0; i < 2; i++ {
		if _, _, err := peer.PutBlob(ctx, vault.MailboxID(), peerTok, big); err != nil {
			t.Fatal(err)
		}
	}
	began := time.Now()
	_, _, err = peer.PutBlobFrom(ctx, vault.MailboxID(), peerTok, bytes.NewReader(big), int64(len(big)))
	if !client.IsCode(err, "quota_exceeded") || client.QuotaOf(err) != client.QuotaSenderBlobs || time.Since(began) > 2*time.Second {
		t.Fatalf("over the share: %v (%s, %v)", err, client.QuotaOf(err), time.Since(began))
	}
	// A token's quota says token.
	q := int64(10)
	small, _ := vault.MintToken(app.PublicKeyB64(), url, client.TokenOptions{Quota: &auth.Quota{Bytes: &q}})
	if _, _, err := app.PutBlob(ctx, vault.MailboxID(), small, make([]byte, 11)); client.QuotaOf(err) != client.QuotaToken {
		t.Fatalf("token quota: %v", err)
	}

	// The owner's list, paged.
	var seen []client.BlobEntry
	after := ""
	for {
		p, err := vault.ListBlobs(ctx, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		if p.UsedBytes != int64(len(data))+2*int64(len(big)) || p.MaxBytes != 64<<20 {
			t.Fatalf("page %+v", p)
		}
		seen = append(seen, p.Blobs...)
		if p.Next == "" {
			break
		}
		after = p.Next
	}
	all, err := vault.AllBlobs(ctx)
	if err != nil || len(all) != 3 || len(seen) != 3 || all[0].BlobID != id || all[0].Sender != app.PublicKeyB64() || all[1].Sender != peer.PublicKeyB64() {
		t.Fatalf("list %+v %v", all, err)
	}
	// The owner deletes what it does not expect.
	for _, b := range all[1:] {
		if err := vault.DeleteBlob(ctx, b.BlobID); err != nil {
			t.Fatal(err)
		}
	}
	if p, err := vault.ListBlobs(ctx, "", 0); err != nil || len(p.Blobs) != 1 || p.UsedBytes != int64(len(data)) {
		t.Fatalf("after deletes %+v %v", p, err)
	}
}
