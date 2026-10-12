package api

import (
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/internal/config"
	auth "github.com/vettid/vettid-relay/relayauth"
)

// Load and attack simulation for the rate limits (spec §7.2).
//
// One client address carries N unlocked vaults, as a vault host does: all
// its vaults reach the relay from the host's one public address. Each
// simulated vault does what vettid-vault does (vault/relay.go,
// vault/inbound.go, relayclient):
//
//   - a long-poll collect that is re-issued when it returns, every 25 s
//     while idle (vault.LongPollWait): 2.4 requests a minute;
//   - per message received: one ack (DELETE) and the next collect; per
//     message sent: one deposit under the sender's key;
//   - on 429: wait retry_after plus up to 250 ms and try again, three
//     attempts in all (relayclient), then one second and from the top
//     (Manager.Run) for collects, the outbox backoff for deposits.
//
// The relay is the real handler chain on the in-memory limiters and replay
// cache and a SQLite store in a temporary directory. Requests are real
// (signed, with real deposit tokens) and are handed to the handler
// directly. Time is simulated: a discrete-event loop sets the relay's clock
// to each event's time, so nothing sleeps and the run is the same every
// time (fixed seeds). A long-poll is counted when it is issued, which is
// where the relay counts it, so the simulation sends it with wait=0 at the
// instant the vault would issue it.
//
//	go test ./internal/api -run 'TestLoad' -v
//	RELAY_LOADSIM=long go test ./internal/api -run 'TestLoad' -v   (ten simulated minutes)

const simHost = "198.51.100.77" // the vault host's one public address

type simEvent struct {
	at   time.Time
	seq  int
	kind int // evPoll, evDeposit, evAck
	v    int // vault
	gen  int // evPoll: the vault's poll generation when scheduled
	try  int // attempts so far
	id   string
	sent time.Time
}

const (
	evPoll = iota
	evDeposit
	evAck
)

type simQueue []*simEvent

func (q simQueue) Len() int { return len(q) }
func (q simQueue) Less(i, j int) bool {
	if !q[i].at.Equal(q[j].at) {
		return q[i].at.Before(q[j].at)
	}
	return q[i].seq < q[j].seq
}
func (q simQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *simQueue) Push(x any)   { *q = append(*q, x.(*simEvent)) }
func (q *simQueue) Pop() any {
	old := *q
	e := old[len(old)-1]
	*q = old[:len(old)-1]
	return e
}

type simVault struct {
	p       principal
	tok     string // deposit token for the next vault's mailbox (this vault as sender)
	gen     int
	limited bool
}

type simResult struct {
	requests, limited   int
	collects, collects4 int
	deposits, deposits4 int
	acks, acks4         int
	sent, delivered     int
	worstDelay          time.Duration
	limitedVaults       int
}

func (r simResult) rate() float64 {
	if r.requests == 0 {
		return 0
	}
	return 100 * float64(r.limited) / float64(r.requests)
}

func simPrincipal(kind string, i int) principal {
	seed := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", kind, i)))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return principal{priv: priv, pub: pub, b64: auth.EncodeKey(pub), mbx: auth.MailboxID(pub)}
}

// oldLimits is the limiter this change replaces: one bucket of 20/s, burst
// 40, per address, before anything else, and nothing per key. (It is this
// code with main's limits, not main's code.)
func oldLimits(c *config.Config) {
	c.RateIPPerSec, c.RateIPBurst = 20, 40
	c.RateKeyPerSec, c.RateKeyBurst = 1e6, 1_000_000
	c.RateRegisterPerSec, c.RateRegisterBurst = 1e6, 1_000_000
	c.RateSenderPerSec, c.RateSenderBurst = 5, 20
}

// newLimits is the relay's defaults.
func newLimits(c *config.Config) {
	d := config.Defaults()
	c.RateIPPerSec, c.RateIPBurst = d.RateIPPerSec, d.RateIPBurst
	c.RateKeyPerSec, c.RateKeyBurst = d.RateKeyPerSec, d.RateKeyBurst
	c.RateRegisterPerSec, c.RateRegisterBurst = d.RateRegisterPerSec, d.RateRegisterBurst
	c.RateSenderPerSec, c.RateSenderBurst = d.RateSenderPerSec, d.RateSenderBurst
	c.RateClaimPerSec, c.RateClaimBurst = d.RateClaimPerSec, d.RateClaimBurst
}

type sim struct {
	t   *testing.T
	f   *fixture
	h   http.Handler
	rng *rand.Rand
}

// skipOnOtherStores: the simulation is about the limiters, so it runs on
// the default store only (the whole API suite also runs on DynamoDB).
func skipOnOtherStores(t *testing.T) {
	if os.Getenv("RELAY_TEST_API_STORE") != "" {
		t.Skip("limiter simulation: default store only")
	}
}

func newSim(t *testing.T, limits func(*config.Config), seed uint64, jitter bool) *sim {
	rng := rand.New(rand.NewPCG(seed, 0x5eed))
	f := newFixture(t, limits)
	return &sim{t: t, f: f, h: f.s.Handler(), rng: rng}
}

// do sends one request from addr and returns the status and, for a 429,
// the retry_after.
func (s *sim) do(addr string, r req) (int, int, []byte) {
	hr := s.f.build(r)
	hr.RemoteAddr = addr + ":40000"
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, hr)
	ra := 0
	if rec.Code == http.StatusTooManyRequests {
		var e errorBody
		json.Unmarshal(rec.Body.Bytes(), &e)
		ra = e.RetryAfter
	}
	return rec.Code, ra, rec.Body.Bytes()
}

// retryWait is the client's wait before attempt try+1 after a 429.
func (s *sim) retryWait(try, retryAfter int, afterThree time.Duration) time.Duration {
	if try%3 == 0 {
		return afterThree
	}
	return time.Duration(retryAfter)*time.Second + time.Duration(s.rng.Int64N(int64(250*time.Millisecond)))
}

// runHost simulates n vaults behind one address for dur. Each vault
// receives perMin messages a minute from its neighbour (so it sends as
// many). With synced, every vault's long-poll is issued in the same
// instant, as after a relay deploy has ended them all together; otherwise
// they are spread over the 25 s period.
func runHost(t *testing.T, limits func(*config.Config), jitter bool, n int, perMin float64, synced bool, dur time.Duration) simResult {
	t.Helper()
	s := newSim(t, limits, uint64(n), jitter)
	f := s.f
	ctx := context.Background()
	start := f.clk.now()
	end := start.Add(dur)
	vaults := make([]*simVault, n)
	for i := range vaults {
		vaults[i] = &simVault{p: simPrincipal("vault", i)}
		if _, err := f.st.Register(ctx, vaults[i].p.mbx, vaults[i].p.pub); err != nil {
			t.Fatal(err)
		}
	}
	for i, v := range vaults {
		v.tok = f.mint(vaults[(i+1)%n].p, v.p, nil)
	}
	var q simQueue
	seq := 0
	push := func(e *simEvent) {
		if e.at.After(end) {
			return
		}
		seq++
		e.seq = seq
		heap.Push(&q, e)
	}
	for i := range vaults {
		at := start
		if !synced {
			at = start.Add(time.Duration(s.rng.Int64N(int64(25 * time.Second))))
		}
		push(&simEvent{at: at, kind: evPoll, v: i})
		if perMin > 0 {
			for at := start; ; {
				at = at.Add(time.Duration(s.rng.ExpFloat64() / perMin * float64(time.Minute)))
				if at.After(end) {
					break
				}
				push(&simEvent{at: at, kind: evDeposit, v: i, sent: at})
			}
		}
	}
	var res simResult
	seen := map[string]bool{}
	note := func(v *simVault, code int, n, n4 *int) {
		res.requests++
		*n++
		if code == http.StatusTooManyRequests {
			res.limited++
			*n4++
			if !v.limited {
				v.limited = true
				res.limitedVaults++
			}
		}
	}
	for q.Len() > 0 {
		e := heap.Pop(&q).(*simEvent)
		f.clk.set(e.at)
		v := vaults[e.v]
		switch e.kind {
		case evPoll:
			if e.gen != v.gen {
				continue // superseded: a deposit woke this vault's poll
			}
			code, ra, body := s.do(simHost, req{method: "GET", path: "/v1/mailbox?wait=0&max=32", signer: &v.p})
			note(v, code, &res.collects, &res.collects4)
			switch code {
			case http.StatusOK:
				var out collectResp
				json.Unmarshal(body, &out)
				for _, m := range out.Messages {
					if !seen[m.MsgID] {
						seen[m.MsgID] = true
						res.delivered++
						if sent, err := time.Parse(time.RFC3339Nano, string(m.Payload)); err == nil {
							res.worstDelay = max(res.worstDelay, e.at.Sub(sent))
						}
					}
					push(&simEvent{at: e.at, kind: evAck, v: e.v, id: m.MsgID})
				}
				next := e.at.Add(25 * time.Second)
				if len(out.Messages) == 32 {
					next = e.at
				}
				push(&simEvent{at: next, kind: evPoll, v: e.v, gen: v.gen})
			case http.StatusTooManyRequests:
				push(&simEvent{at: e.at.Add(s.retryWait(e.try+1, ra, time.Second)), kind: evPoll, v: e.v, gen: v.gen, try: e.try + 1})
			default:
				t.Fatalf("collect: %d %s", code, body)
			}
		case evAck:
			code, ra, body := s.do(simHost, req{method: "DELETE", path: "/v1/mailbox/" + e.id, signer: &v.p})
			note(v, code, &res.acks, &res.acks4)
			switch {
			case code == http.StatusTooManyRequests && e.try < 2: // relayclient's three attempts; then the vault drops the ack
				push(&simEvent{at: e.at.Add(s.retryWait(e.try+1, ra, 0)), kind: evAck, v: e.v, id: e.id, try: e.try + 1})
			case code != http.StatusNoContent && code != http.StatusTooManyRequests:
				t.Fatalf("ack: %d %s", code, body)
			}
		case evDeposit:
			if e.try == 0 {
				res.sent++
			}
			from, to := vaults[(e.v+n-1)%n], v // the neighbour holding a token for v's mailbox
			body := depositBody([]byte(e.sent.Format(time.RFC3339Nano)))
			code, ra, rb := s.do(simHost, req{method: "POST", path: "/v1/mailbox/" + to.p.mbx, body: body, signer: &from.p, token: from.tok})
			note(from, code, &res.deposits, &res.deposits4)
			switch code {
			case http.StatusCreated:
				// The recipient's parked long-poll returns with it now.
				to.gen++
				push(&simEvent{at: e.at, kind: evPoll, v: e.v, gen: to.gen})
			case http.StatusTooManyRequests:
				outbox := min(250*time.Millisecond<<min((e.try+1)/3, 7), 30*time.Second)
				push(&simEvent{at: e.at.Add(s.retryWait(e.try+1, ra, outbox)), kind: evDeposit, v: e.v, try: e.try + 1, sent: e.sent})
			default:
				t.Fatalf("deposit: %d %s", code, rb)
			}
		}
	}
	return res
}

// simDurations returns the simulated time for the old limiter's runs and
// for the new limits' runs. Under the old limiter a host over the limit
// settles into a retry storm of about one request per vault per second
// within seconds, so a shorter run shows it.
func simDurations() (old, cur time.Duration) {
	if raceEnabled || testing.Short() {
		return 26 * time.Second, 26 * time.Second // one long-poll period
	}
	if os.Getenv("RELAY_LOADSIM") == "long" {
		return 2 * time.Minute, 10 * time.Minute
	}
	return 40 * time.Second, time.Minute
}

// One address, N vaults: the old limiter against the new limits.
func TestLoadVaultHost(t *testing.T) {
	skipOnOtherStores(t)
	oldDur, dur := simDurations()
	var b strings.Builder
	fmt.Fprintf(&b, "\none address carrying N vaults; simulated time: old limiter %s, new limits %s\n", oldDur, dur)
	fmt.Fprintf(&b, "%-28s %6s %9s %9s %7s %14s %11s %12s\n", "case", "vaults", "requests", "429", "429 %", "vaults limited", "delivered", "worst delay")
	row := func(name string, n int, r simResult) {
		fmt.Fprintf(&b, "%-28s %6d %9d %9d %6.1f%% %14d %5d/%-5d %11.1fs\n", name, n, r.requests, r.limited, r.rate(), r.limitedVaults, r.delivered, r.sent, r.worstDelay.Seconds())
	}
	type hostCase struct {
		n        int
		perMin   float64
		label    string
		old, cur simResult
	}
	var cases []*hostCase
	// 900 is what a vault host is projected to hold; 2,000 is past what
	// the flood guard (100/s, burst 1,000) carries once the vaults are busy.
	sizes := []int{100, 500, 900, 2000}
	if raceEnabled || testing.Short() {
		sizes = []int{100, 600}
	}
	carried := func(n int) bool { return n <= 900 }
	for _, n := range sizes {
		cases = append(cases, &hostCase{n: n, label: "idle"}, &hostCase{n: n, perMin: 1, label: "1 msg/min each"})
	}
	// The worst moment for a host: every long-poll ended together (a relay
	// deploy drains them) and all are re-issued in the same instant, then
	// stay in step.
	var sync1000 simResult
	syncN := 900
	if raceEnabled || testing.Short() {
		syncN = 600
	}
	t.Run("sims", func(t *testing.T) { // returns when its parallel subtests are done
		for _, c := range cases {
			t.Run(fmt.Sprintf("old/%d/%s", c.n, c.label), func(t *testing.T) {
				t.Parallel()
				c.old = runHost(t, oldLimits, false, c.n, c.perMin, false, oldDur)
			})
			t.Run(fmt.Sprintf("new/%d/%s", c.n, c.label), func(t *testing.T) {
				t.Parallel()
				c.cur = runHost(t, newLimits, true, c.n, c.perMin, false, dur)
			})
		}
		t.Run("new/synchronised", func(t *testing.T) {
			t.Parallel()
			sync1000 = runHost(t, newLimits, true, syncN, 1, true, dur)
		})
	})
	for _, c := range cases {
		row("old 20/s, "+c.label, c.n, c.old)
		row("new, "+c.label, c.n, c.cur)
		if carried(c.n) && c.cur.limited != 0 {
			t.Errorf("new limits, %d vaults, %s: %d of %d requests refused", c.n, c.label, c.cur.limited, c.cur.requests)
		}
		// Messages sent in the last instants are collected in them too
		// (the wake is immediate), so everything sent must have arrived.
		if carried(c.n) && c.cur.delivered != c.cur.sent {
			t.Errorf("new limits, %d vaults: delivered %d of %d", c.n, c.cur.delivered, c.cur.sent)
		}
		// 500 idle vaults spread evenly are exactly 20 requests a second:
		// the old limit holds until anything else happens.
		if (c.n > 500 || c.n == 500 && c.perMin > 0) && c.old.rate() < 25 {
			t.Errorf("old limiter, %d vaults, %s: %.1f%% refused; the simulation does not show the problem", c.n, c.label, c.old.rate())
		}
	}
	row("new, synchronised polls", syncN, sync1000)
	if sync1000.limited != 0 {
		t.Errorf("synchronised polls: %d refused", sync1000.limited)
	}
	t.Log(b.String())
}
