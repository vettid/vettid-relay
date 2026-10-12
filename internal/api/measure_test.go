package api

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	"github.com/vettid/vettid-relay/internal/ratelimit"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// TestMeasureMemory measures what the things the resource caps count cost
// this process: a parked long-poll, a WebSocket session, a key in each
// table. The numbers size the caps (spec §7.2 item 8, README "Memory
// budget"). It only runs when asked:
//
//	RELAY_MEASURE=1 go test ./internal/api -run TestMeasureMemory -v
//
// The clients are bare sockets in the same process, so nearly all of what
// is measured is the server's (Go heap and goroutine stacks; the kernel's
// socket buffers are not in it).
func TestMeasureMemory(t *testing.T) {
	if os.Getenv("RELAY_MEASURE") == "" {
		t.Skip("set RELAY_MEASURE=1")
	}
	inUse := func() float64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(m.HeapInuse + m.StackInuse)
	}
	const n = 2000
	f := newFixture(t, func(c *config.Config) { c.MaxCollectors, c.MaxCollectorsPerNetwork, c.RateIPBurst = 3*n, 3*n, 100*n })
	keys := make([]principal, n)
	for i := range keys {
		keys[i] = simPrincipal("measure", i)
		if _, err := f.st.Register(t.Context(), keys[i].mbx, keys[i].pub); err != nil {
			t.Fatal(err)
		}
	}
	open := func(p principal, path, extra string) net.Conn {
		c, err := net.Dial("tcp", f.ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		h := http.Header{}
		auth.SetHeaders(h, p.priv, "GET", path, f.sigTime(), auth.BodyHash(nil))
		q := ""
		if extra == "" {
			q = "?wait=25"
		}
		fmt.Fprintf(c, "GET %s%s HTTP/1.1\r\nHost: relay\r\n%sX-VettID-Key: %s\r\nX-VettID-Timestamp: %s\r\nX-VettID-Sig: %s\r\n\r\n",
			path, q, extra, h.Get(auth.HeaderKey), h.Get(auth.HeaderTimestamp), h.Get(auth.HeaderSig))
		return c
	}
	waitFor := func(what string, want int, got func() int) {
		deadline := time.Now().Add(20 * time.Second)
		for got() < want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d of %d", what, got(), want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	base := inUse()
	for i := 0; i < n; i++ {
		open(keys[i], "/v1/mailbox", "")
	}
	waitFor("parked long-polls", n, func() int { return int(f.s.m.parked.Value()) })
	polls := inUse()
	t.Logf("MEASURED parked long-poll: %.1f KiB each (%d parked, %.1f MiB)", (polls-base)/n/1024, n, (polls-base)/(1<<20))

	g := newFixture(t, func(c *config.Config) { c.MaxCollectors, c.MaxCollectorsPerNetwork, c.RateIPBurst = 3*n, 3*n, 100*n })
	for i := range keys {
		if _, err := g.st.Register(t.Context(), keys[i].mbx, keys[i].pub); err != nil {
			t.Fatal(err)
		}
	}
	f = g
	base = inUse()
	for i := 0; i < n; i++ {
		c := open(keys[i], "/v1/mailbox/ws", "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n")
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade %d: %v %v", i, resp, err)
		}
	}
	waitFor("WebSocket sessions", n, func() int { return int(g.s.m.wsSessions.Value()) })
	ws := inUse()
	t.Logf("MEASURED WebSocket session: %.1f KiB each (%d open, %.1f MiB)", (ws-base)/n/1024, n, (ws-base)/(1<<20))

	// The per-key and per-network tables, full.
	const keysN = maxHeldKeys
	names := make([]string, keysN)
	for i := range names {
		names[i] = simPrincipal("table", i%4096).b64[:40] + fmt.Sprintf("%04d", i%10000)
	}
	now := time.Now()
	var keep []any
	table := func(name string, fill func(k string)) {
		before := inUse()
		for _, k := range names {
			fill(string(append([]byte(nil), k...)))
		}
		after := inUse()
		t.Logf("MEASURED %s with %d keys: %.1f MiB (%.0f bytes a key)", name, keysN, (after-before)/(1<<20), (after-before)/keysN)
	}
	hold := ratelimit.NewHold(time.Second, time.Minute, keysN, 0)
	table("held-keys table", func(k string) { hold.Fail(k, now) })
	recent := ratelimit.NewRecent(time.Minute, keysN, 0)
	table("charged-once table", func(k string) { recent.Add(k, now, true) })
	debt := ratelimit.NewDebt(1, 60, time.Minute, keysN)
	table("failure-budget table", func(k string) { debt.Charge(k, now) })
	lim := ratelimit.New(20, 100, keysN)
	table("bucket table", func(k string) { lim.Allow(k, now) })
	keep = append(keep, hold, recent, debt, lim)
	runtime.KeepAlive(keep)
	runtime.KeepAlive(names)
}
