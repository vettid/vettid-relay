package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
)

func newBareServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	s := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics.New())
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() { ts.Close(); s.Close(); st.Close() })
	return s, ts
}

func TestHealthzAndDrain(t *testing.T) {
	s, ts := newBareServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	resp, _ = http.Get(ts.URL + "/healthz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("draining healthz = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestUnknownRouteJSON(t *testing.T) {
	_, ts := newBareServer(t)
	resp, _ := http.Get(ts.URL + "/nope")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 404 || string(b) != `{"code":"not_found","message":"not found"}`+"\n" {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing")
	}
}

func TestClientIPAndRateKey(t *testing.T) {
	mk := func(remote string, xff ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		r     *http.Request
		trust bool
		want  string
	}{
		{mk("10.0.0.1:5000", "1.2.3.4"), false, "10.0.0.1"},
		{mk("10.0.0.1:5000", "6.6.6.6, 1.2.3.4"), true, "1.2.3.4"},
		{mk("10.0.0.1:5000", "6.6.6.6", "9.9.9.9, 1.2.3.4"), true, "1.2.3.4"},
		{mk("10.0.0.1:5000", "garbage"), true, "10.0.0.1"},
		{mk("10.0.0.1:5000"), true, "10.0.0.1"},
		{mk("[2001:db8:1:2:3:4:5:6]:443"), false, "2001:db8:1:2::/64"},
		{mk("10.0.0.1:1", "2001:db8:1:2:ffff::1"), true, "2001:db8:1:2::/64"},
		{mk("[::ffff:1.2.3.4]:80"), false, "1.2.3.4"},
	}
	for i, c := range cases {
		if got := rateKey(clientIP(c.r, c.trust)); got != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
	if rateKey(netip.Addr{}) != "unknown" {
		t.Fatal("invalid addr key")
	}
}
