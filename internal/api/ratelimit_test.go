package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/vettid/vettid-relay/internal/config"
)

func TestIPRateLimitBeforeParsing(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.RateIPPerSec, c.RateIPBurst = 0.01, 3 })
	// Unauthenticated garbage still consumes the bucket: limits apply before parsing.
	for i := 0; i < 3; i++ {
		if code, _ := f.do(req{method: "GET", path: "/v1/mailbox"}); code == http.StatusTooManyRequests {
			t.Fatalf("request %d limited too early", i)
		}
	}
	code, b, h := f.send(f.build(req{method: "POST", path: "/v1/mailbox/whatever", body: []byte("x")}))
	var e errorBody
	json.Unmarshal(b, &e)
	if code != http.StatusTooManyRequests || e.Code != CodeRateLimited || e.RetryAfter < 1 || h.Get("Retry-After") == "" {
		t.Fatalf("got %d %s retry-after=%q", code, b, h.Get("Retry-After"))
	}
	// Health checks are exempt.
	if code, _ := f.do(req{method: "GET", path: "/healthz"}); code != http.StatusOK {
		t.Fatalf("healthz limited: %d", code)
	}
}

func TestIPRateLimitTrustProxy(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.RateIPPerSec, c.RateIPBurst = 0.01, 1
		c.TrustProxy = true
	})
	hdr := func(xff string) http.Header { return http.Header{"X-Forwarded-For": {xff}} }
	// The client-controlled prefix varies; the proxy-appended last hop is the key.
	if code, _ := f.do(req{method: "GET", path: "/v1/mailbox", header: hdr("1.1.1.1, 203.0.113.7")}); code == 429 {
		t.Fatal("first request limited")
	}
	if code, _ := f.do(req{method: "GET", path: "/v1/mailbox", header: hdr("9.9.9.9, 203.0.113.7")}); code != 429 {
		t.Fatalf("spoofed prefix bypassed the limit: %d", code)
	}
	// A different real client is unaffected.
	if code, _ := f.do(req{method: "GET", path: "/v1/mailbox", header: hdr("203.0.113.8")}); code == 429 {
		t.Fatal("independent client limited")
	}
	// IPv6 clients share a /64.
	f.do(req{method: "GET", path: "/v1/mailbox", header: hdr("2001:db8:aa:bb::1")})
	if code, _ := f.do(req{method: "GET", path: "/v1/mailbox", header: hdr("2001:db8:aa:bb::2")}); code != 429 {
		t.Fatalf("same /64 not limited: %d", code)
	}
}
