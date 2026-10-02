package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/internal/config"
)

type claimResp struct {
	ClaimID   string `json:"claim_id"`
	ExpiresAt string `json:"expires_at"`
}

func (f *fixture) putClaim(owner principal, data []byte, ttl string) (int, claimResp, []byte) {
	f.t.Helper()
	h := http.Header{"Content-Type": {"application/octet-stream"}}
	path := "/v1/claim"
	if ttl != "" {
		path += "/ttl/" + ttl
	}
	code, b := f.do(req{method: "PUT", path: path, body: data, signer: &owner, header: h})
	var cr claimResp
	json.Unmarshal(b, &cr)
	return code, cr, b
}

func (f *fixture) mustPutClaim(owner principal, data []byte, ttl string) claimResp {
	f.t.Helper()
	code, cr, b := f.putClaim(owner, data, ttl)
	if code != http.StatusCreated {
		f.t.Fatalf("put claim: %d %s", code, b)
	}
	return cr
}

func (f *fixture) getClaim(id string, header http.Header) (int, []byte, http.Header) {
	f.t.Helper()
	return f.send(f.build(req{method: "GET", path: "/v1/claim/" + id, header: header}))
}

func TestClaimPutGetOnce(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.ClaimTTL = 7 * 24 * time.Hour })
	owner := newPrincipal(1)
	f.register(owner)
	bundle := []byte("public key bundle")

	cr := f.mustPutClaim(owner, bundle, "")
	if _, ok := auth.ParseClaimID(cr.ClaimID); !ok {
		t.Fatalf("claim id %q", cr.ClaimID)
	}
	exp, err := time.Parse(time.RFC3339, cr.ExpiresAt)
	if err != nil || !exp.Equal(f.clk.now().Add(900*time.Second)) {
		t.Fatalf("default TTL: %s", cr.ExpiresAt)
	}
	// Unauthenticated, single fetch.
	code, got, h := f.getClaim(cr.ClaimID, nil)
	if code != 200 || !bytes.Equal(got, bundle) || h.Get("Content-Type") != "application/octet-stream" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("get: %d %q %v", code, got, h)
	}
	_, again, _ := f.getClaim(cr.ClaimID, nil)

	// Expired, deleted, never-existed, malformed and already-fetched all look the same.
	expiring := f.mustPutClaim(owner, bundle, "60")
	deleted := f.mustPutClaim(owner, bundle, "")
	if code, _ := f.do(req{method: "DELETE", path: "/v1/claim/" + deleted.ClaimID, signer: &owner}); code != 204 {
		t.Fatal("delete")
	}
	f.clk.add(61 * time.Second)
	var bodies [][]byte
	for _, id := range []string{expiring.ClaimID, deleted.ClaimID, auth.NewClaimID(), "nope", cr.ClaimID} {
		code, b, _ := f.getClaim(id, nil)
		if code != 404 {
			t.Fatalf("%s: %d", id, code)
		}
		bodies = append(bodies, b)
	}
	bodies = append(bodies, again)
	for _, b := range bodies {
		if !bytes.Equal(b, bodies[0]) || !bytes.Contains(b, []byte(CodeClaimUnknown)) {
			t.Fatalf("non-uniform miss: %s vs %s", b, bodies[0])
		}
	}
	// A 7-day TTL is allowed when the relay is configured for it.
	week := f.mustPutClaim(owner, bundle, "604800")
	if exp, _ := time.Parse(time.RFC3339, week.ExpiresAt); !exp.Equal(f.clk.now().Add(7 * 24 * time.Hour)) {
		t.Fatalf("7-day TTL: %s", week.ExpiresAt)
	}
}

func TestClaimPutValidation(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MaxClaimBytes = 100; c.ClaimTTL = 600 * time.Second })
	owner, stranger := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	f.mustPutClaim(owner, make([]byte, 100), "600")
	if code, _, _ := f.putClaim(owner, make([]byte, 101), ""); code != 413 {
		t.Fatalf("oversize: %d", code)
	}
	for _, ttl := range []string{"601", "0", "-5", "abc", "1.5", "0060", "+60"} {
		if code, _, b := f.putClaim(owner, []byte("x"), ttl); code != 400 {
			t.Fatalf("ttl %q: %d %s", ttl, code, b)
		}
	}
	h := http.Header{"X-Vettid-Claim-Ttl": {"60", "70"}}
	f.expectCode(req{method: "PUT", path: "/v1/claim", body: []byte("x"), signer: &owner, header: h}, 400, CodeBadRequest)
	f.expectCode(req{method: "PUT", path: "/v1/claim", body: []byte{}, signer: &owner}, 400, CodeBadRequest)
	// Default TTL is min(900 s, claim_ttl_seconds).
	cr := f.mustPutClaim(owner, []byte("x"), "")
	if exp, _ := time.Parse(time.RFC3339, cr.ExpiresAt); !exp.Equal(f.clk.now().Add(600 * time.Second)) {
		t.Fatalf("default capped TTL: %s", cr.ExpiresAt)
	}
	// Must be signed by a registered mailbox key.
	f.expectCode(req{method: "PUT", path: "/v1/claim", body: []byte("x"), signer: &stranger}, 404, CodeMailboxUnknown)
	f.expectCode(req{method: "PUT", path: "/v1/claim", body: []byte("x")}, 401, CodeSignatureInvalid)
}

func TestClaimDeleteScoping(t *testing.T) {
	f := newFixture(t, nil)
	owner, other := newPrincipal(1), newPrincipal(2)
	f.register(owner)
	f.register(other)
	cr := f.mustPutClaim(owner, []byte("x"), "")
	for _, p := range []principal{other, other} {
		if code, _ := f.do(req{method: "DELETE", path: "/v1/claim/" + cr.ClaimID, signer: &p}); code != 204 {
			t.Fatal("foreign delete must be a 204 no-op")
		}
	}
	if code, _, _ := f.getClaim(cr.ClaimID, nil); code != 200 {
		t.Fatal("foreign delete removed the claim")
	}
	for i := 0; i < 2; i++ {
		if code, _ := f.do(req{method: "DELETE", path: "/v1/claim/" + cr.ClaimID, signer: &owner}); code != 204 {
			t.Fatal("delete not idempotent")
		}
	}
	f.expectCode(req{method: "DELETE", path: "/v1/claim/" + cr.ClaimID}, 401, CodeSignatureInvalid)
}

func TestClaimQuota(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.MailboxMaxBlobBytes = 1000 })
	owner := newPrincipal(1)
	f.register(owner)
	f.mustPutClaim(owner, make([]byte, 900), "")
	if code, _, b := f.putClaim(owner, make([]byte, 200), ""); code != 429 || !bytes.Contains(b, []byte(CodeQuotaExceeded)) {
		t.Fatalf("quota: %d %s", code, b)
	}
}

func TestClaimGetRateLimit(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RateClaimPerSec, c.RateClaimBurst = 0.01, 2
		c.TrustProxy = true
	})
	owner := newPrincipal(1)
	f.register(owner)
	cr := f.mustPutClaim(owner, []byte("x"), "")
	ip := func(a string) http.Header { return http.Header{"X-Forwarded-For": {a}} }
	// Guesses consume the bucket too.
	f.getClaim(auth.NewClaimID(), ip("198.51.100.1"))
	f.getClaim(auth.NewClaimID(), ip("198.51.100.1"))
	code, b, h := f.getClaim(cr.ClaimID, ip("198.51.100.1"))
	if code != 429 || h.Get("Retry-After") == "" || !bytes.Contains(b, []byte(CodeRateLimited)) {
		t.Fatalf("limited: %d %s", code, b)
	}
	// Same IPv6 /64 shares a bucket; another network does not.
	f.getClaim("x", ip("2001:db8:1:2::1"))
	f.getClaim("x", ip("2001:db8:1:2::2"))
	if code, _, _ := f.getClaim("x", ip("2001:db8:1:2::3")); code != 429 {
		t.Fatal("IPv6 /64 not shared")
	}
	if code, _, _ := f.getClaim(cr.ClaimID, ip("198.51.100.2")); code != 200 {
		t.Fatalf("other client: %d", code)
	}
}

// The TTL travels in the signed path (§4.1, §6.9); the unsigned draft header
// is refused, and re-pathing a signed request breaks its signature.
func TestClaimTTLIsSigned(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.ClaimTTL = 7 * 24 * time.Hour })
	owner := newPrincipal(1)
	f.register(owner)
	h := http.Header{"Content-Type": {"application/octet-stream"}, "X-Vettid-Claim-Ttl": {"60"}}
	if code, b := f.do(req{method: "PUT", path: "/v1/claim", body: []byte("x"), signer: &owner, header: h}); code != 400 {
		t.Fatalf("header TTL: %d %s", code, b)
	}
	r := f.build(req{method: "PUT", path: "/v1/claim/ttl/60", body: []byte("x"), signer: &owner})
	r.URL.Path = "/v1/claim/ttl/604800"
	if code, b, _ := f.send(r); code != 401 {
		t.Fatalf("re-pathed TTL: %d %s", code, b)
	}
}
