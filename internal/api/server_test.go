package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
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

// /healthz is public and outside every rate limit, so it must not cost a
// store read per request: it answers from one ping per healthPingTTL,
// which concurrent callers share.
func TestHealthzReadsStoreOncePerInterval(t *testing.T) {
	f := newFixture(t, nil)
	cs := f.countStore()
	cs.slowPing = 50 * time.Millisecond // callers arrive while the first one looks
	get := func() (int, string) {
		code, b := f.do(req{method: "GET", path: "/healthz"})
		return code, string(b)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, b := get(); code != 200 || !strings.Contains(b, `"status":"ok"`) || !strings.Contains(b, `"protocol":"`+ProtocolVersion+`"`) {
				t.Errorf("healthz: %d %s", code, b)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 20; i++ {
		get()
	}
	if n := cs.pings.Load(); n != 1 {
		t.Fatalf("%d store pings for 60 requests in one interval, want 1", n)
	}
	// The next interval looks again, once.
	f.clk.add(healthPingTTL)
	get()
	get()
	if n := cs.pings.Load(); n != 2 {
		t.Fatalf("%d store pings after the interval, want 2", n)
	}
}

// A store that fails turns /healthz unhealthy within the interval, and one
// that recovers turns it healthy again.
func TestHealthzFollowsStoreWithinInterval(t *testing.T) {
	var logs syncBuf
	f := newFixtureLog(t, nil, &logs)
	cs := f.countStore()
	status := func() int { code, _ := f.do(req{method: "GET", path: "/healthz"}); return code }
	if status() != 200 {
		t.Fatal("healthy store")
	}
	cs.down.Store(true)
	f.clk.add(healthPingTTL - time.Millisecond)
	if status() != 200 {
		t.Fatal("answer changed inside the interval: not from the last ping")
	}
	f.clk.add(time.Millisecond)
	for i := 0; i < 5; i++ {
		if code, b := f.do(req{method: "GET", path: "/healthz"}); code != 503 || !strings.Contains(string(b), "db_unreachable") {
			t.Fatalf("failing store after the interval: %d %s", code, b)
		}
	}
	if n := strings.Count(logs.String(), "healthz: database unreachable"); n != 1 {
		t.Fatalf("%d error lines for one failed ping", n)
	}
	cs.down.Store(false)
	f.clk.add(healthPingTTL)
	if status() != 200 {
		t.Fatal("recovered store after the interval")
	}
	// A clock set back does not keep an old answer alive.
	cs.down.Store(true)
	f.clk.add(-time.Hour)
	if status() != 503 {
		t.Fatal("old answer served after the clock went back")
	}
	// Draining is not cached.
	cs.down.Store(false)
	f.clk.add(healthPingTTL)
	status()
	f.s.draining.Store(true)
	if status() != 503 {
		t.Fatal("draining relay reported healthy")
	}
	f.s.draining.Store(false)
}
