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
	evOrphan  // a client whose mailbox is gone, asking again
	evUnlock  // a vault that was locked is unlocked: register, then collect
	evGarbage // a request with a wrong signature, from the host's own address
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
	// Blast-radius scenarios.
	unlocks, unlocks4          int // requests of vaults unlocked mid-run, and their 429s
	orphanAnswered, orphanHeld int // an orphan's requests answered mailbox_unknown, and refused by its key
	orphanMaxRetry             int // the longest retry_after an orphan was told
	stale                      int // requests answered timestamp_stale
	afterSkew, afterSkew4      int // requests in the first seconds after a clock was put right, and their 429s
	garbage, garbageChecked    int // wrongly signed requests sent, and those whose signature was checked
	penalisedSeconds           int // seconds (sampled at each event) the host's address was out of failure budget
	networkCharges             int // units of the address's failure budget used
	requests, limited          int
	collects, collects4        int
	deposits, deposits4        int
	acks, acks4                int
	sent, delivered            int
	worstDelay                 time.Duration
	limitedVaults              int
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

// scenario is one simulated vault host.
type scenario struct {
	limits   func(*config.Config)
	jitter   bool
	n        int     // unlocked vaults
	perMin   float64 // messages each receives (and sends) a minute
	synced   bool    // all long-polls issued in the same instant
	dur      time.Duration
	orphans  int // clients whose mailbox is gone, retrying
	unlock   int // further vaults, locked until unlockAt
	unlockAt time.Duration
	skew     time.Duration // the host's clock is 5 minutes slow for this long from the start
	garbage  int           // wrongly signed requests a second from the host's own address
}

// oldLimits is the limiter this change replaces: one bucket of 20/s, burst
// 40, per address, before anything else, and nothing per key.
func oldLimits(c *config.Config) {
	c.RateIPPerSec, c.RateIPBurst = 20, 40
	c.RateKeyPerSec, c.RateKeyBurst = 1e6, 1_000_000
	c.RateAuthFailPerSec, c.RateAuthFailBurst = 1e6, 1_000_000
	c.RateKeyFailPerSec, c.RateKeyFailBurst = 1e6, 1_000_000
	c.RateVerifyPerSec, c.RateVerifyBurst = 1e6, 1_000_000
	c.RateRegisterPerSec, c.RateRegisterBurst = 1e6, 1_000_000
	c.RateSenderPerSec, c.RateSenderBurst = 5, 20
}

// newLimits is the relay's defaults.
func newLimits(c *config.Config) {
	d := config.Defaults()
	c.RateIPPerSec, c.RateIPBurst = d.RateIPPerSec, d.RateIPBurst
	c.RateKeyPerSec, c.RateKeyBurst = d.RateKeyPerSec, d.RateKeyBurst
	c.RateAuthFailPerSec, c.RateAuthFailBurst, c.AuthFailMaxPenalty = d.RateAuthFailPerSec, d.RateAuthFailBurst, d.AuthFailMaxPenalty
	c.RateKeyFailPerSec, c.RateKeyFailBurst = d.RateKeyFailPerSec, d.RateKeyFailBurst
	c.RateVerifyPerSec, c.RateVerifyBurst = d.RateVerifyPerSec, d.RateVerifyBurst
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
	f := newFixtureWith(t, limits, func(*fixture) []Option {
		hold := holdBase
		if !jitter { // the old limiter: no holds either
			hold = 0
		}
		return []Option{WithNoMailboxHold(hold), WithRetryJitter(func() int {
			if !jitter {
				return 0
			}
			return rng.IntN(retryJitterMax + 1)
		})}
	})
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
	return runScenario(t, scenario{limits: limits, jitter: jitter, n: n, perMin: perMin, synced: synced, dur: dur})
}

// runScenario is runHost with the blast-radius extras: orphans (clients
// whose mailbox is gone and that ask again every second, as vettid-vault's
// Manager.Run does on mailbox_unknown), vaults unlocked mid-run after being
// locked (their first requests: register the existing key, then collect), a
// wrong host clock, and wrongly signed requests from the host's address.
func runScenario(t *testing.T, sc scenario) simResult {
	t.Helper()
	limits, jitter, n, perMin, synced, dur := sc.limits, sc.jitter, sc.n, sc.perMin, sc.synced, sc.dur
	s := newSim(t, limits, uint64(n), jitter)
	f := s.f
	ctx := context.Background()
	start := f.clk.now()
	end := start.Add(dur)
	skewEnd := start.Add(sc.skew)
	vaults := make([]*simVault, n+sc.unlock)
	orphans := make([]principal, sc.orphans)
	for i := range orphans {
		orphans[i] = simPrincipal("orphan", i)
	}
	for i := range vaults {
		vaults[i] = &simVault{p: simPrincipal("vault", i)}
		if _, err := f.st.Register(ctx, vaults[i].p.mbx, vaults[i].p.pub); err != nil {
			t.Fatal(err)
		}
	}
	for i, v := range vaults[:n] {
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
	for i := range orphans {
		push(&simEvent{at: start.Add(time.Duration(s.rng.Int64N(int64(time.Second)))), kind: evOrphan, v: i})
	}
	for i := n; i < len(vaults); i++ {
		push(&simEvent{at: start.Add(sc.unlockAt + time.Duration(s.rng.Int64N(int64(5*time.Second)))), kind: evUnlock, v: i})
	}
	if sc.garbage > 0 {
		push(&simEvent{at: start, kind: evGarbage})
	}
	for i := range vaults[:n] {
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
	lastSample := start
	for q.Len() > 0 {
		e := heap.Pop(&q).(*simEvent)
		f.clk.set(e.at)
		if e.at.Sub(lastSample) >= time.Second {
			if f.s.fails.Wait(simHost, e.at) > 0 {
				res.penalisedSeconds += int(e.at.Sub(lastSample) / time.Second)
			}
			lastSample = e.at
		}
		switch e.kind {
		case evOrphan:
			o := orphans[e.v]
			code, ra, body := s.do(simHost, req{method: "GET", path: "/v1/mailbox?wait=0&max=32", signer: &o})
			switch code {
			case http.StatusNotFound: // not retried by relayclient; Manager.Run tries again in a second
				res.orphanAnswered++
				push(&simEvent{at: e.at.Add(time.Second), kind: evOrphan, v: e.v})
			case http.StatusTooManyRequests:
				res.orphanHeld++
				res.orphanMaxRetry = max(res.orphanMaxRetry, ra)
				push(&simEvent{at: e.at.Add(s.retryWait(e.try+1, ra, time.Second)), kind: evOrphan, v: e.v, try: e.try + 1})
			default:
				t.Fatalf("orphan collect: %d %s", code, body)
			}
			continue
		case evGarbage:
			res.garbage++
			h := http.Header{}
			var k [32]byte
			var sig [64]byte
			for i := range k {
				k[i] = byte(s.rng.Uint32())
			}
			for i := range sig {
				sig[i] = byte(s.rng.Uint32())
			}
			h.Set(auth.HeaderKey, auth.EncodeKey(k[:]))
			h.Set(auth.HeaderTimestamp, e.at.UTC().Format(time.RFC3339Nano))
			h.Set(auth.HeaderSig, auth.EncodeKey(sig[:]))
			if code, _, _ := s.do(simHost, req{method: "GET", path: "/v1/mailbox", header: h}); code == http.StatusUnauthorized {
				res.garbageChecked++
			}
			push(&simEvent{at: e.at.Add(time.Second / time.Duration(sc.garbage)), kind: evGarbage})
			continue
		}
		v := vaults[e.v]
		switch e.kind {
		case evUnlock:
			// vault/unlock.go: register the (existing) key, then start collecting.
			body, _ := json.Marshal(map[string]string{"pubkey": v.p.b64})
			code, ra, rb := s.do(simHost, req{method: "POST", path: "/v1/register", body: body, signer: &v.p})
			res.unlocks++
			switch code {
			case http.StatusOK:
				push(&simEvent{at: e.at, kind: evPoll, v: e.v, gen: v.gen})
			case http.StatusTooManyRequests:
				res.unlocks4++
				push(&simEvent{at: e.at.Add(s.retryWait(e.try+1, ra, time.Second)), kind: evUnlock, v: e.v, try: e.try + 1})
			default:
				t.Fatalf("unlock: register: %d %s", code, rb)
			}
		case evPoll:
			if e.gen != v.gen {
				continue // superseded: a deposit woke this vault's poll
			}
			r := req{method: "GET", path: "/v1/mailbox?wait=0&max=32", signer: &v.p}
			if e.at.Before(skewEnd) {
				r.at = f.sigTime().Add(-5 * time.Minute) // the host's clock is slow
			}
			code, ra, body := s.do(simHost, r)
			note(v, code, &res.collects, &res.collects4)
			if e.v >= n {
				res.unlocks++
				if code == http.StatusTooManyRequests {
					res.unlocks4++
				}
			}
			if sc.skew > 0 && !e.at.Before(skewEnd) && e.at.Before(skewEnd.Add(5*time.Second)) {
				res.afterSkew++
				if code == http.StatusTooManyRequests {
					res.afterSkew4++
				}
			}
			switch code {
			case http.StatusUnauthorized: // timestamp_stale: not retried by relayclient; Manager.Run tries again in a second
				res.stale++
				push(&simEvent{at: e.at.Add(time.Second), kind: evPoll, v: e.v, gen: v.gen})
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
			if e.at.Before(skewEnd) {
				continue
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
	res.networkCharges = int(f.s.rl.charged.Value())
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
	sizes := []int{100, 500, 1000}
	if raceEnabled || testing.Short() {
		sizes = []int{100, 600}
	}
	for _, n := range sizes {
		cases = append(cases, &hostCase{n: n, label: "idle"}, &hostCase{n: n, perMin: 1, label: "1 msg/min each"})
	}
	// The worst moment for a host: every long-poll ended together (a relay
	// deploy drains them) and all are re-issued in the same instant, then
	// stay in step.
	var sync1000 simResult
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
			sync1000 = runHost(t, newLimits, true, sizes[len(sizes)-1], 1, true, dur)
		})
	})
	for _, c := range cases {
		row("old 20/s, "+c.label, c.n, c.old)
		row("new, "+c.label, c.n, c.cur)
		if c.cur.limited != 0 {
			t.Errorf("new limits, %d vaults, %s: %d of %d requests refused", c.n, c.label, c.cur.limited, c.cur.requests)
		}
		// Messages sent in the last instants are collected in them too
		// (the wake is immediate), so everything sent must have arrived.
		if c.cur.delivered != c.cur.sent {
			t.Errorf("new limits, %d vaults: delivered %d of %d", c.n, c.cur.delivered, c.cur.sent)
		}
		// 500 idle vaults spread evenly are exactly 20 requests a second:
		// the old limit holds until anything else happens.
		if (c.n > 500 || c.n == 500 && c.perMin > 0) && c.old.rate() < 25 {
			t.Errorf("old limiter, %d vaults, %s: %.1f%% refused; the simulation does not show the problem", c.n, c.label, c.old.rate())
		}
	}
	row("new, synchronised polls", sizes[len(sizes)-1], sync1000)
	if sync1000.limited != 0 {
		t.Errorf("synchronised polls: %d refused", sync1000.limited)
	}
	t.Log(b.String())
}

// attack sends perSec requests a second for dur from one address and
// returns how many got each status.
func (s *sim) attack(addr string, perSec int, dur time.Duration, next func(i int) req, each func(i int)) map[int]int {
	start := s.f.clk.now()
	out := map[int]int{}
	n := perSec * int(dur/time.Second)
	for i := 0; i < n; i++ {
		s.f.clk.set(start.Add(time.Duration(i) * time.Second / time.Duration(perSec)))
		code, _, _ := s.do(addr, next(i))
		out[code]++
		if each != nil {
			each(i)
		}
	}
	return out
}

// One address attacking, 500 requests a second for 30 s (100 a second
// under the race detector). What reaches
// the relay's verification, store and registrations stays bounded, by the
// numbers of spec §7.2.
func TestLoadAttacks(t *testing.T) {
	skipOnOtherStores(t)
	const (
		attacker = "192.0.2.66"
		dur      = 30 * time.Second
	)
	perSec := 500
	if raceEnabled || testing.Short() {
		perSec = 100
	}
	total := perSec * 30
	d := config.Defaults()
	floodMax := d.RateIPBurst + int(d.RateIPPerSec*dur.Seconds()) + 1
	regMax := d.RateRegisterBurst + int(d.RateRegisterPerSec*dur.Seconds()) + 1
	var lines [4]strings.Builder // one per attack, filled in parallel
	// checked: requests whose signature was checked (CPU only). worked:
	// requests that went further, to the store or to Valkey.
	row := func(b *strings.Builder, name, limits string, checked, worked, refused int) {
		fmt.Fprintf(b, "%-44s %7s %10d %10d %10d\n", name, limits, checked, worked, refused)
	}
	// past counts requests let past the flood guard since the last call:
	// on a penalised network that is after their signature verified.
	past := func(s *sim) func() int {
		last := s.f.s.rl.allowed.With(limAddress).Value()
		return func() int {
			now := s.f.s.rl.allowed.With(limAddress).Value()
			d := now - last
			last = now
			return int(d)
		}
	}
	garbage := func(s *sim) func(int) req {
		return func(int) req {
			var k [32]byte
			var sig [64]byte
			for i := range k {
				k[i] = byte(s.rng.Uint32())
			}
			for i := range sig {
				sig[i] = byte(s.rng.Uint32())
			}
			h := http.Header{}
			h.Set(auth.HeaderKey, auth.EncodeKey(k[:]))
			h.Set(auth.HeaderTimestamp, s.f.clk.now().UTC().Format(time.RFC3339Nano))
			h.Set(auth.HeaderSig, auth.EncodeKey(sig[:])) // plain standard base64
			return req{method: "GET", path: "/v1/mailbox", header: h}
		}
	}

	// 1. Bad signatures under fresh keys. Meanwhile a vault host elsewhere
	// and a vault behind the attacker's own address keep polling.
	t.Run("attacks", func(t *testing.T) { // returns when its parallel subtests are done
		t.Run("bad signatures", func(t *testing.T) {
			t.Parallel()
			b := &lines[0]
			for _, c := range []struct {
				name   string
				limits func(*config.Config)
			}{{"old", oldLimits}, {"new", newLimits}} {
				s := newSim(t, c.limits, 1, true)
				far, near := simPrincipal("vault", 1), simPrincipal("vault", 2)
				s.f.register(far)
				s.f.register(near)
				if code, _, _ := s.do(attacker, collectReq(near)); code != 200 { // near is known at the attacker's address
					t.Fatal(code)
				}
				farOK, nearOK, polls := 0, 0, 0
				admitted := past(s)
				out := s.attack(attacker, perSec, dur, garbage(s), func(i int) {
					if i%perSec != perSec/2 {
						return
					}
					polls++
					if code, _, _ := s.do(simHost, collectReq(far)); code == 200 {
						farOK++
					}
					if code, _, _ := s.do(attacker, collectReq(near)); code == 200 {
						nearOK++
					}
				})
				// A wrong signature goes no further than its check. What got
				// past the flood guard beyond the two vaults' polls is what
				// the attacker's requests cost in shared state (Valkey).
				worked := admitted() - farOK - nearOK
				row(b, "bad signatures, fresh keys", c.name, out[401], worked, out[429])
				fmt.Fprintf(b, "%-44s %7s   another address: %d/%d polls served; the attacker's own address: %d/%d\n", "", c.name, farOK, polls, nearOK, polls)
				if farOK != polls {
					t.Errorf("%s: a vault at another address was refused (%d/%d)", c.name, farOK, polls)
				}
				if c.name == "new" && (nearOK != polls || worked > d.RateAuthFailBurst+1) {
					t.Errorf("new limits: vault at the attacker's address served %d/%d; attacker's requests past the flood guard: %d, bound %d", nearOK, polls, worked, d.RateAuthFailBurst+1)
				}
			}
		})

		// 2. Valid signatures under fresh keys that have no mailbox.
		t.Run("fresh keys", func(t *testing.T) {
			t.Parallel()
			b := &lines[1]
			s := newSim(t, newLimits, 2, true)
			out := s.attack(attacker, perSec, dur, func(i int) req { return collectReq(simPrincipal("fresh", i)) }, nil)
			row(b, "valid signatures, fresh keys, no mailbox", "new", total-out[429]+int(s.f.s.rl.refused.With(limAddress).Value()), out[404], out[429])
			fmt.Fprintf(b, "%-44s %7s   store lookups: %d (the flood guard: %d); units of the network's failure budget used: %d\n", "", "new", out[404], floodMax, s.f.s.rl.charged.Value())
			// Telling a fresh key from a vault that was locked overnight takes
			// the mailbox lookup, so this is bounded by the flood guard, no
			// longer by the failure budget.
			if out[404] > floodMax {
				t.Errorf("fresh keys looked up: %d, bound %d", out[404], floodMax)
			}
			// The same key coming back costs neither the network nor the store.
			same := simPrincipal("fresh", 0)
			s.f.clk.add(11 * time.Minute)
			chargedBefore := s.f.s.rl.charged.Value()
			again := s.attack(attacker, perSec, dur, func(int) req { return collectReq(same) }, nil)
			row(b, "valid signatures, ONE key, no mailbox", "new", again[404], again[404], again[429])
			fmt.Fprintf(b, "%-44s %7s   units of the network's failure budget used: %d\n", "", "new", s.f.s.rl.charged.Value()-chargedBefore)
			if again[404] > 6 || s.f.s.rl.charged.Value()-chargedBefore != 1 {
				t.Errorf("one key without a mailbox: %d lookups, %d network charges in 30 s", again[404], s.f.s.rl.charged.Value()-chargedBefore)
			}
		})

		// 3. Fresh keys, each registering a mailbox.
		t.Run("registrations", func(t *testing.T) {
			t.Parallel()
			b := &lines[2]
			s := newSim(t, newLimits, 3, true)
			out := s.attack(attacker, perSec, dur, func(i int) req { return registerReq(simPrincipal("reg", i)) }, nil)
			row(b, "fresh keys, each registering a mailbox", "new", total-out[429]+int(s.f.s.rl.refused.With(limAddress).Value())+int(s.f.s.rl.refused.With(limRegister).Value()), int(s.f.s.rl.allowed.With(limAddress).Value()), out[429])
			fmt.Fprintf(b, "%-44s %7s   mailboxes created: %d\n", "", "new", out[201])
			if out[201] > regMax {
				t.Errorf("mailboxes created: %d, bound %d", out[201], regMax)
			}
		})

		// 4. Many registered keys (made earlier, patiently), valid requests:
		// per-key limits bound none of this; the flood guard bounds all of it.
		t.Run("many valid keys", func(t *testing.T) {
			t.Parallel()
			b := &lines[3]
			for _, c := range []struct {
				name   string
				limits func(*config.Config)
			}{{"old", oldLimits}, {"new", newLimits}} {
				s := newSim(t, c.limits, 4, true)
				keys := make([]principal, 500)
				for i := range keys {
					keys[i] = simPrincipal("owned", i)
					if _, err := s.f.st.Register(context.Background(), keys[i].mbx, keys[i].pub); err != nil {
						t.Fatal(err)
					}
				}
				out := s.attack(attacker, perSec, dur, func(i int) req { return collectReq(keys[i%len(keys)]) }, nil)
				row(b, "500 registered keys, valid collects", c.name, out[200], out[200], out[429])
				if c.name == "new" && (out[200] > floodMax || total > floodMax && out[200] < floodMax-perSec) {
					t.Errorf("served %d, flood guard bound %d", out[200], floodMax)
				}
			}
		})
	})
	var b strings.Builder
	fmt.Fprintf(&b, "\none address, %d requests a second for %s (%d requests)\n", perSec, dur, total)
	fmt.Fprintf(&b, "%-44s %7s %10s %10s %10s\n", "attack", "limits", "sig check", "went on", "429")
	for i := range lines {
		b.WriteString(lines[i].String())
	}
	t.Log(b.String())
}

// The blast radius of one address (spec §7.2): nothing keyed on an address,
// beyond the flood guard, may refuse a request properly signed by a key
// with a mailbox. A vault host with 500 vaults in normal use, and on the
// same address: clients whose mailbox is gone, retrying every second; 50
// vaults unlocked after being locked; a wrong clock; someone sending wrong
// signatures at 500 a second.
func TestLoadBlastRadius(t *testing.T) {
	skipOnOtherStores(t)
	n, unlock := 500, 50
	dur, unlockAt, skew := 6*time.Minute, 3*time.Minute, time.Minute
	switch {
	case raceEnabled || testing.Short():
		n, unlock = 100, 10
		dur, unlockAt, skew = 2*time.Minute, time.Minute, 30*time.Second
	case os.Getenv("RELAY_LOADSIM") == "long": // an hour; the vaults unlocked were locked for 30 minutes
		dur, unlockAt, skew = time.Hour, 30*time.Minute, 2*time.Minute
	}
	var orphan1, orphan10, skewed, attacked simResult
	t.Run("sims", func(t *testing.T) {
		t.Run("one orphan", func(t *testing.T) {
			t.Parallel()
			orphan1 = runScenario(t, scenario{limits: newLimits, jitter: true, n: n, perMin: 0.2, dur: dur, orphans: 1, unlock: unlock, unlockAt: unlockAt})
		})
		t.Run("ten orphans", func(t *testing.T) {
			t.Parallel()
			orphan10 = runScenario(t, scenario{limits: newLimits, jitter: true, n: n, perMin: 0.2, dur: dur, orphans: 10, unlock: unlock, unlockAt: unlockAt})
		})
		t.Run("wrong clock", func(t *testing.T) {
			t.Parallel()
			skewed = runScenario(t, scenario{limits: newLimits, jitter: true, n: n, dur: skew + time.Minute, skew: skew})
		})
		t.Run("attacker on the host's address", func(t *testing.T) {
			t.Parallel()
			attacked = runScenario(t, scenario{limits: newLimits, jitter: true, n: n, perMin: 1, dur: time.Minute, unlock: unlock, unlockAt: 20 * time.Second, garbage: 500})
		})
	})
	var b strings.Builder
	fmt.Fprintf(&b, "\none address, %d vaults in use (new limits)\n", n)
	for _, c := range []struct {
		name    string
		orphans int
		r       simResult
	}{{"(a) one orphan", 1, orphan1}, {"(b) ten orphans", 10, orphan10}} {
		r := c.r
		fmt.Fprintf(&b, "%s retrying for %s, %d vaults unlocked at %s:\n", c.name, dur, unlock, unlockAt)
		fmt.Fprintf(&b, "    vaults: %d requests, %d refused; unlocked vaults: %d requests, %d refused; messages %d/%d\n", r.requests, r.limited, r.unlocks, r.unlocks4, r.delivered, r.sent)
		fmt.Fprintf(&b, "    orphans: %d answered mailbox_unknown, %d refused by key (longest retry_after %d s); address penalised for %d s; failure budget units used: %d\n",
			r.orphanAnswered, r.orphanHeld, r.orphanMaxRetry, r.penalisedSeconds, r.networkCharges)
		if r.limited != 0 || r.unlocks4 != 0 || r.unlocks < 2*unlock || r.delivered != r.sent {
			t.Errorf("%s: vaults refused %d, unlocked vaults refused %d of %d, messages %d/%d", c.name, r.limited, r.unlocks4, r.unlocks, r.delivered, r.sent)
		}
		if r.penalisedSeconds != 0 || r.networkCharges != c.orphans {
			t.Errorf("%s: address penalised %d s, %d units of its failure budget used (want 0 and %d)", c.name, r.penalisedSeconds, r.networkCharges, c.orphans)
		}
		// Each orphan is answered from the store once per hold: 1 s, 2 s,
		// 4 s, ... 512 s, then every 10 minutes; never once a second.
		if r.orphanAnswered > c.orphans*(12+int(dur/(10*time.Minute))) || r.orphanMaxRetry < 30 {
			t.Errorf("%s: orphans answered %d times, longest retry_after %d", c.name, r.orphanAnswered, r.orphanMaxRetry)
		}
	}
	r := skewed
	fmt.Fprintf(&b, "(c) the host's clock 5 min slow for %s, then right:\n", skew)
	fmt.Fprintf(&b, "    answered timestamp_stale: %d; refused 429: %d; failure budget units used: %d (one per vault); address penalised for %d s\n", r.stale, r.limited, r.networkCharges, r.penalisedSeconds)
	fmt.Fprintf(&b, "    first 5 s after the clock was put right: %d requests, %d refused\n", r.afterSkew, r.afterSkew4)
	if r.afterSkew < n || r.afterSkew4 != 0 || r.networkCharges != n || r.stale < n {
		t.Errorf("wrong clock: after recovery %d requests, %d refused; %d units used (want %d); %d stale answers", r.afterSkew, r.afterSkew4, r.networkCharges, n, r.stale)
	}
	r = attacked
	fmt.Fprintf(&b, "(e) wrong signatures at 500/s from the host's own address for 1 min, %d vaults unlocked at 20 s:\n", unlock)
	fmt.Fprintf(&b, "    wrong signatures sent %d, checked %d; vaults: %d requests, %d refused; unlocked vaults: %d requests, %d refused; messages %d/%d\n",
		r.garbage, r.garbageChecked, r.requests, r.limited, r.unlocks, r.unlocks4, r.delivered, r.sent)
	if r.limited != 0 || r.unlocks4 != 0 || r.unlocks < 2*unlock || r.delivered != r.sent {
		t.Errorf("attacker on the host's address: vaults refused %d, unlocked vaults refused %d of %d, messages %d/%d", r.limited, r.unlocks4, r.unlocks, r.delivered, r.sent)
	}
	t.Log(b.String())
}
