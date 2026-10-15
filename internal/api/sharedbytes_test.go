package api

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/coord"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/testutil/vklocal"
)

// The network ceilings of the byte budgets (§7.2 limits 11 and 12) are
// relay-wide (proposed 0.9.4): two relay instances sharing one Valkey
// draw on one bucket per network, with the charges, refunds and kept
// charges of TestByteChargesRefundedWhenNothingIsStored made across them.
// Each instance has a store of its own; only the limits are shared.

// The shared ceilings say which backend took a charge, so that a refund
// goes back to it.
var _ SourcedByteLimiter = (*coord.ByteLimiter)(nil)

// sharedByteFixtures starts n relay instances whose byte ceilings share
// one Valkey namespace (each through its own client, as separate
// processes would), and returns them with their clients.
func sharedByteFixtures(t *testing.T, n int, mut func(*config.Config)) ([]*fixture, []*coord.Client) {
	t.Helper()
	addr, prefix := vklocal.Addr(t), vklocal.Prefix()
	var fs []*fixture
	var vcs []*coord.Client
	for i := 0; i < n; i++ {
		vc, err := coord.Open(context.Background(), coord.Config{Addr: addr, Prefix: prefix}, metrics.New())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(vc.Close)
		vcs = append(vcs, vc)
		fs = append(fs, newFixtureWith(t, mut, func(f *fixture) []Option {
			return []Option{WithRateLimiters(Limiters{
				Bytes:     vc.ByteLimiter("bytes", f.cfg.RateIPBytesPerSec, f.cfg.RateIPBytesBurst),
				BlobBytes: vc.ByteLimiter("blob_bytes", f.cfg.RateBlobBytesPerSec, f.cfg.RateBlobBytesBurst),
			})}
		}))
	}
	return fs, vcs
}

func TestByteCeilingsSharedAcrossInstances(t *testing.T) {
	fs, vcs := sharedByteFixtures(t, 2, func(c *config.Config) {
		c.RateIPBytesPerSec, c.RateIPBytesBurst = 0.001, 3000
		c.RateBlobBytesPerSec, c.RateBlobBytesBurst = 0.001, 2500
		c.MaxBlobBytes, c.MailboxMaxBlobBytes = 1000, 3000
		c.MailboxMaxMessages = 1
	})
	a, b := fs[0], fs[1]
	owner, sender, thief := newPrincipal(1), newPrincipal(2), newPrincipal(3)
	a.register(owner)
	b.register(owner)
	tokA, tokB := a.mint(owner, sender, nil), b.mint(owner, sender, nil)
	payload := strings.Repeat("x", 1000) // a body of 1,350 bytes

	// Deposits and claims: 3,000 bytes for both instances together. What
	// is not stored is refunded, whichever instance refused it.
	a.expectFrom(hostA, depositReq(owner, sender, tokA, payload), 201, "")
	for i := 0; i < 10; i++ {
		a.expectFrom(hostA, depositReq(owner, sender, tokA, payload), 429, CodeQuotaExceeded) // a's mailbox is full
		b.expectFrom(hostA, depositReq(owner, thief, tokB, payload), 401, CodeSignatureInvalid)
		b.expectFrom(hostA, req{method: "POST", path: "/v1/mailbox/" + owner.mbx, body: []byte("not json"), signer: &sender, token: tokB}, 400, CodeBadRequest)
	}
	// 1,650 bytes left: a 1,000-byte claim on b fits, then nothing on a.
	b.expectFrom(hostA, req{method: "PUT", path: "/v1/claim", body: make([]byte, 1000), signer: &owner}, 201, "")
	a.expectFrom(hostA, req{method: "PUT", path: "/v1/claim", body: make([]byte, 1000), signer: &owner}, 429, CodeRateLimited)
	b.expectFrom(hostA, depositReq(owner, sender, tokB, payload), 429, CodeRateLimited)
	key := rateKey(netip.MustParseAddr(hostA))
	if ok, _ := a.s.byteLimit.AllowN(key, 650, a.clk.now()); !ok {
		t.Fatal("the shared ceiling lost more than was stored")
	}
	if ok, _ := b.s.byteLimit.AllowN(key, 1, b.clk.now()); ok {
		t.Fatal("the shared ceiling holds more than its burst")
	}

	// Blobs: 2,500 bytes for both. One stored on a (1,000). An upload to b
	// refused after its body arrived (its signature) keeps the bytes it
	// sent charged (2,000); the next on a is refused (500 left).
	blob := func(f *fixture, signer principal) req {
		return req{method: "PUT", path: "/v1/blob/" + owner.mbx, body: make([]byte, 1000), signer: &signer, token: f.mint(owner, sender, nil)}
	}
	a.expectFrom(hostA, blob(a, sender), 201, "")
	b.expectFrom(hostA, blob(b, thief), 401, CodeSignatureInvalid)
	a.expectFrom(hostA, blob(a, sender), 429, CodeRateLimited)
	b.expectFrom(hostA, blob(b, sender), 429, CodeRateLimited)
	if ok, _ := b.s.blobByteLimit.AllowN(key, 500, b.clk.now()); !ok {
		t.Fatal("a budget-refused upload was charged")
	}
	if ok, _ := a.s.blobByteLimit.AllowN(key, 1, a.clk.now()); ok {
		t.Fatal("the signature-refused upload's bytes were given back")
	}
	for _, f := range fs {
		if r := f.counter(`relay_ratelimit_refused_total{limiter="blob_bytes"}`); r != 1 {
			t.Fatalf("blob_bytes refused on one instance: %d", r)
		}
	}

	// Another network has its own buckets.
	a.expectFrom(hostB, req{method: "PUT", path: "/v1/claim", body: make([]byte, 1000), signer: &owner}, 201, "")

	// Valkey unreachable for a: like the request limits, a falls back to a
	// per-process bucket of the configured size (best-effort policy,
	// availability first); b still answers from the shared one.
	vcs[0].Close()
	a.expectFrom(hostA, req{method: "PUT", path: "/v1/claim", body: make([]byte, 1000), signer: &owner}, 201, "")
	b.expectFrom(hostA, req{method: "PUT", path: "/v1/claim", body: make([]byte, 1000), signer: &owner}, 429, CodeRateLimited)
	if ok, _ := a.s.byteLimit.AllowN(key, 2000, a.clk.now()); !ok {
		t.Fatal("the per-process fallback is not the configured burst")
	}
	if ok, _ := a.s.byteLimit.AllowN(key, 1, a.clk.now()); ok {
		t.Fatal("the per-process fallback holds more than the burst")
	}
}
