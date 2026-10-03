package e2e

// Multi-process scenario (hosting option B): two real relay processes — the
// built binary, started twice — share one DynamoDB table (DynamoDB Local),
// one S3 bucket (in-process fake) and one Valkey namespace. Every check
// crosses processes: what one process accepts, the other must see, refuse
// or be woken by. Skipped unless RELAY_TEST_DYNAMODB_ENDPOINT and
// RELAY_TEST_VALKEY_ADDR are set (`make test-dynamo`).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/testutil/ddblocal"
	"github.com/vettid/vettid-relay/internal/testutil/fakes3"
	"github.com/vettid/vettid-relay/internal/testutil/vklocal"
	auth "github.com/vettid/vettid-relay/relayauth"
	client "github.com/vettid/vettid-relay/relayclient"
)

const multiAud = "https://relay.multi.e2e.test" // both processes serve one relay URL

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

func relayBinary(t *testing.T) string {
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "relay-e2e-bin")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "relay")
		cmd := exec.Command("go", "build", "-p", "2", "-o", binPath, "../../cmd/relay")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("build relay: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type proc struct {
	url     string
	metrics string
	cmd     *exec.Cmd
	out     *bytes.Buffer
}

// cluster is a shared backend for N relay processes.
type cluster struct {
	t   *testing.T
	env []string
}

func newCluster(t *testing.T, extra ...string) *cluster {
	db := ddblocal.Client(t)
	vk := vklocal.Addr(t)
	table := ddblocal.Table(t, db)
	s3 := fakes3.New(t)
	env := append(os.Environ(),
		"RELAY_STORE=dynamodb",
		"RELAY_DYNAMODB_TABLE="+table,
		"RELAY_DYNAMODB_ENDPOINT="+os.Getenv(ddblocal.EnvEndpoint),
		"RELAY_BLOB_BUCKET=blobs",
		"RELAY_S3_ENDPOINT="+s3.URL(),
		"RELAY_VALKEY_ADDR="+vk,
		"RELAY_VALKEY_PREFIX="+vklocal.Prefix(),
		"RELAY_BASE_URL="+multiAud,
		"RELAY_SHUTDOWN_TIMEOUT=5s",
		"RELAY_LOG_LEVEL=warn",
		"AWS_REGION=us-east-1", "AWS_ACCESS_KEY_ID=local", "AWS_SECRET_ACCESS_KEY=local",
		"AWS_EC2_METADATA_DISABLED=true",
	)
	return &cluster{t: t, env: append(env, extra...)}
}

func (c *cluster) start() *proc {
	t := c.t
	addr, maddr := freePort(t), freePort(t)
	cmd := exec.Command(relayBinary(t))
	cmd.Env = append(append([]string{}, c.env...), "RELAY_LISTEN_ADDR="+addr, "RELAY_METRICS_ADDR="+maddr)
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proc{url: "http://" + addr, metrics: "http://" + maddr + "/metrics", cmd: cmd, out: out}
	t.Cleanup(func() { p.stop() })
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(p.url + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return p
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay did not become healthy: %v\n%s", err, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (p *proc) stop() {
	if p.cmd.ProcessState != nil {
		return
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		p.cmd.Process.Kill()
		<-done
	}
}

func principal(t *testing.T, url string) *client.Client {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return client.New(url, k)
}

// as returns the same identity talking to another process.
func as(c *client.Client, url string) *client.Client { return client.New(url, c.Key) }

func TestMultiProcess(t *testing.T) {
	cl := newCluster(t)
	a, b := cl.start(), cl.start()
	ctx := context.Background()

	vault := principal(t, a.url) // registers on A
	app := principal(t, b.url)   // deposits on B
	if _, err := vault.Register(ctx); err != nil {
		t.Fatal(err)
	}
	tok, err := vault.MintToken(app.PublicKeyB64(), multiAud, client.TokenOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("long-poll on A wakes for a deposit on B", func(t *testing.T) {
		got := make(chan []client.Message, 1)
		go func() {
			m, err := vault.Collect(ctx, 25*time.Second, 10)
			if err != nil {
				t.Error(err)
			}
			got <- m
		}()
		time.Sleep(300 * time.Millisecond)
		sent := time.Now()
		id, err := app.Deposit(ctx, vault.MailboxID(), tok, []byte("cross-process"))
		if err != nil {
			t.Fatal(err)
		}
		select {
		case m := <-got:
			lat := time.Since(sent)
			if len(m) != 1 || m[0].MsgID != id {
				t.Fatalf("%+v", m)
			}
			if lat >= time.Second {
				t.Fatalf("wake latency %v ≥ 1 s (§6.2)", lat)
			}
			t.Logf("deposit on B → long-poll on A: %v", lat)
			if err := as(vault, b.url).Ack(ctx, id); err != nil { // ack on the other process
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("long-poll on A was not woken")
		}
		if m, err := vault.Collect(ctx, 0, 10); err != nil || len(m) != 0 {
			t.Fatalf("acked on B, still on A: %+v %v", m, err)
		}
	})

	t.Run("WebSocket on B wakes for a deposit on A", func(t *testing.T) {
		h := http.Header{}
		auth.SetHeaders(h, vault.Key, "GET", "/v1/mailbox/ws", time.Now(), auth.BodyHash(nil))
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		conn, _, err := websocket.Dial(wctx, "ws"+b.url[len("http"):]+"/v1/mailbox/ws", &websocket.DialOptions{HTTPHeader: h})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseNow()
		time.Sleep(300 * time.Millisecond)
		sent := time.Now()
		id, err := as(app, a.url).Deposit(ctx, vault.MailboxID(), tok, []byte("ws"))
		if err != nil {
			t.Fatal(err)
		}
		_, data, err := conn.Read(wctx)
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			MsgID string `json:"msg_id"`
		}
		json.Unmarshal(data, &f)
		if f.MsgID != id {
			t.Fatalf("frame %s", data)
		}
		if lat := time.Since(sent); lat >= time.Second {
			t.Fatalf("ws wake latency %v", lat)
		} else {
			t.Logf("deposit on A → WebSocket on B: %v", lat)
		}
		ack, _ := json.Marshal(map[string]string{"ack": id})
		if err := conn.Write(wctx, websocket.MessageText, ack); err != nil {
			t.Fatal(err)
		}
		conn.Close(websocket.StatusNormalClosure, "")
	})

	t.Run("open token: exactly one deposit across processes", func(t *testing.T) {
		open, err := vault.MintOpenToken(multiAud, 5*time.Minute, "")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok, used := 0, 0
		for i := 0; i < 12; i++ {
			url := a.url
			if i%2 == 1 {
				url = b.url
			}
			s := principal(t, url)
			s.MaxAttempts = 1
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.Deposit(ctx, vault.MailboxID(), open, []byte("first contact"))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case client.IsCode(err, "token_used"):
					used++
				default:
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if ok != 1 || used != 11 {
			t.Fatalf("ok=%d token_used=%d", ok, used)
		}
		m, err := vault.Collect(ctx, 0, 100)
		if err != nil || len(m) != 1 {
			t.Fatalf("%d messages (%v)", len(m), err)
		}
		vault.Ack(ctx, m[0].MsgID)
	})

	t.Run("claim: single fetch across processes", func(t *testing.T) {
		id, _, err := vault.PutClaim(ctx, []byte("bundle"), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		hits, misses := 0, 0
		for i := 0; i < 8; i++ {
			url := a.url
			if i%2 == 1 {
				url = b.url
			}
			s := principal(t, url)
			s.MaxAttempts = 1
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.GetClaim(ctx, id)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					hits++
				} else if client.IsCode(err, "claim_unknown") {
					misses++
				} else {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if hits != 1 || misses != 7 {
			t.Fatalf("hits=%d misses=%d", hits, misses)
		}
	})

	t.Run("a request replayed to the other process is refused", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"payload": "cmVwbGF5"})
		path := "/v1/mailbox/" + vault.MailboxID()
		h := http.Header{}
		auth.SetHeaders(h, app.Key, "POST", path, time.Now(), auth.BodyHash(body))
		h.Set("Authorization", "VettID-Deposit "+tok)
		h.Set("Content-Type", "application/json")
		send := func(base string) (int, string) {
			req, _ := http.NewRequest("POST", base+path, bytes.NewReader(body))
			req.Header = h.Clone()
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var e struct {
				Code string `json:"code"`
			}
			json.NewDecoder(resp.Body).Decode(&e)
			return resp.StatusCode, e.Code
		}
		if st, code := send(a.url); st != 201 {
			t.Fatalf("original: %d %s", st, code)
		}
		if st, code := send(b.url); st != 401 || code != "replay_detected" {
			t.Fatalf("replay on B: %d %s", st, code)
		}
		if st, code := send(a.url); st != 401 || code != "replay_detected" {
			t.Fatalf("replay on A: %d %s", st, code)
		}
		m, _ := vault.Collect(ctx, 0, 100)
		if len(m) != 1 {
			t.Fatalf("%d messages stored", len(m))
		}
		vault.Ack(ctx, m[0].MsgID)
	})

	t.Run("empty hints: idle polls skip the store, deposits are still delivered", func(t *testing.T) {
		vb := as(vault, b.url)
		q0, s0 := metric(t, b, "relay_collect_store_queries_total"), metric(t, b, "relay_collect_store_skips_total")
		for i := 0; i < 6; i++ {
			if m, err := vb.Collect(ctx, 0, 10); err != nil || len(m) != 0 {
				t.Fatalf("%+v %v", m, err)
			}
		}
		q1, s1 := metric(t, b, "relay_collect_store_queries_total"), metric(t, b, "relay_collect_store_skips_total")
		if s1-s0 < 5 || q1-q0 > 1 {
			t.Fatalf("6 idle polls: %d queries, %d skips", q1-q0, s1-s0)
		}
		// A deposit on A is found by the next poll on B (version bump), and
		// a long-poll parked on B in skip mode is woken by one.
		id, err := as(app, a.url).Deposit(ctx, vault.MailboxID(), tok, []byte("after idle"))
		if err != nil {
			t.Fatal(err)
		}
		if m, err := vb.Collect(ctx, 0, 10); err != nil || len(m) != 1 || m[0].MsgID != id {
			t.Fatalf("%+v %v", m, err)
		}
		vb.Ack(ctx, id)
		vb.Collect(ctx, 0, 10) // empty finding again
		got := make(chan []client.Message, 1)
		go func() { m, _ := vb.Collect(ctx, 20*time.Second, 10); got <- m }()
		time.Sleep(300 * time.Millisecond)
		id, _ = as(app, a.url).Deposit(ctx, vault.MailboxID(), tok, []byte("parked"))
		select {
		case m := <-got:
			if len(m) != 1 || m[0].MsgID != id {
				t.Fatalf("%+v", m)
			}
			vb.Ack(ctx, id)
		case <-time.After(5 * time.Second):
			t.Fatal("skipping long-poll on B not woken by a deposit on A")
		}
	})

	t.Run("a process stops: the other serves everything", func(t *testing.T) {
		id, err := as(app, a.url).Deposit(ctx, vault.MailboxID(), tok, []byte("before"))
		if err != nil {
			t.Fatal(err)
		}
		a.stop()
		m, err := as(vault, b.url).Collect(ctx, 0, 10)
		if err != nil || len(m) != 1 || m[0].MsgID != id {
			t.Fatalf("%+v %v", m, err)
		}
		if err := as(vault, b.url).Ack(ctx, id); err != nil {
			t.Fatal(err)
		}
		c := cl.start() // a replacement process joins
		if _, err := as(app, c.url).Deposit(ctx, vault.MailboxID(), tok, []byte("after")); err != nil {
			t.Fatal(err)
		}
		if m, err := as(vault, b.url).Collect(ctx, 5*time.Second, 10); err != nil || len(m) != 1 {
			t.Fatalf("%+v %v", m, err)
		}
	})
}

// Rate limits are shared: a client's per-network budget is the same however
// its requests are spread over processes.
func TestMultiProcessRateLimitShared(t *testing.T) {
	cl := newCluster(t, "RELAY_RATE_CLAIM_GET_RPS=0.05", "RELAY_RATE_CLAIM_GET_BURST=4")
	a, b := cl.start(), cl.start()
	ctx := context.Background()
	limited := 0
	var retryAfter int
	for i := 0; i < 8; i++ {
		url := a.url
		if i%2 == 1 {
			url = b.url
		}
		s := principal(t, url)
		s.MaxAttempts = 1
		_, err := s.GetClaim(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaa")
		var e *client.Error
		switch {
		case client.IsCode(err, "claim_unknown"):
		case client.IsCode(err, "rate_limited"):
			limited++
			if asErr(err, &e) {
				retryAfter = e.RetryAfter
			}
		default:
			t.Fatal(err)
		}
	}
	if limited != 4 {
		t.Fatalf("burst 4 over two processes: %d of 8 limited (want 4)", limited)
	}
	if retryAfter < 1 {
		t.Fatalf("retry_after %d", retryAfter)
	}
}

// metric reads one counter from a process's /metrics.
func metric(t *testing.T, p *proc, name string) int64 {
	resp, err := http.Get(p.metrics)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, name+" "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}

func asErr(err error, e **client.Error) bool {
	ce, ok := err.(*client.Error)
	if ok {
		*e = ce
	}
	return ok
}
