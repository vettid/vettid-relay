package relayclient_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	client "github.com/vettid/vettid-relay/relayclient"
)

// pairCodeVectors is testdata/pair-code.json, a copy of vettid-vault's
// testdata/vectors/pair-code.json (VAULT-MESSAGING 0.94.0 §6.7.2).
type pairCodeVectors struct {
	ClaimID string `json:"claim_id"`
	SaltID  string `json:"salt_id"`
	Epoch   int64  `json:"epoch"`
	Nonce   string `json:"nonce_b64"`
	PutBody struct {
		SaltID string `json:"salt_id"`
		Tag    string `json:"tag"`
		Salt   string `json:"salt"`
		Blob   string `json:"blob"`
	} `json:"put_body"`
}

func loadPairCode(t *testing.T) pairCodeVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/pair-code.json")
	if err != nil {
		t.Fatal(err)
	}
	var v pairCodeVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func b64d(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pcServer is a fake relay for the code claim routes: it checks each
// request's method, path and signature, keeps its body, and answers with
// the next reply.
type pcServer struct {
	t       *testing.T
	calls   atomic.Int32
	replies []reply
	method  string
	path    string
	signed  bool
	body    []byte
	key     string
	ctype   string
}

func (s *pcServer) start(name string) *client.Client {
	s.t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(s.calls.Add(1)) - 1
		s.method, s.path = r.Method, r.URL.EscapedPath()
		s.body, _ = io.ReadAll(r.Body)
		sr, err := relayauth.ParseHeaders(r.Header)
		s.signed = err == nil && sr.Verify(r.Method, r.URL.EscapedPath(), relayauth.BodyHash(s.body), time.Now()) == nil
		s.ctype = r.Header.Get("Content-Type")
		s.key = r.Header.Get(relayauth.HeaderKey)
		rp := s.replies[min(n, len(s.replies)-1)]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rp.status)
		io.WriteString(w, rp.body)
	}))
	s.t.Cleanup(ts.Close)
	c := newClient(ts.URL, name)
	c.MaxAttempts = 3 // the code claim calls still make one attempt
	return c
}

func TestPairCodeSalts(t *testing.T) {
	v := loadPairCode(t)
	ans := `{"salts":[{"salt_id":"` + v.SaltID + `","epoch":` + jsonInt(v.Epoch) + `,"nonce":"` + v.Nonce + `"}]}`
	s := &pcServer{t: t, replies: []reply{{200, ans}}}
	c := s.start("vault")
	got, err := c.PairCodeSalts(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	if got[0].SaltID != v.SaltID || got[0].Epoch != v.Epoch || !bytes.Equal(got[0].Nonce, b64d(t, v.Nonce)) {
		t.Fatalf("%+v", got[0])
	}
	if s.method != "GET" || s.path != "/v1/pair-code/salts" || s.key != "" {
		t.Fatalf("%s %s signed by %q (the salts are unauthenticated)", s.method, s.path, s.key)
	}
}

func TestPutPairCode(t *testing.T) {
	v := loadPairCode(t)
	s := &pcServer{t: t, replies: []reply{{201, `{"expires_at":"2026-03-31T12:27:00Z"}`}}}
	c := s.start("vault")
	exp, err := c.PutPairCode(context.Background(), v.ClaimID, client.PairCodePut{SaltID: v.PutBody.SaltID,
		Tag: b64d(t, v.PutBody.Tag), Salt: b64d(t, v.PutBody.Salt), Blob: b64d(t, v.PutBody.Blob)})
	if err != nil || !exp.Equal(time.Date(2026, 3, 31, 12, 27, 0, 0, time.UTC)) {
		t.Fatalf("%v %v", err, exp)
	}
	if s.method != "PUT" || s.path != "/v1/pair-code/"+v.ClaimID || !s.signed || s.key != relayauth.EncodeKey(testKey("vault").Public().(ed25519.PublicKey)) {
		t.Fatalf("%s %s signed %v by %q", s.method, s.path, s.signed, s.key)
	}
	if s.ctype != "application/json" {
		t.Fatalf("content type %q", s.ctype)
	}
	// The body is the vectors' put_body, member for member.
	var got, want map[string]string
	if json.Unmarshal(s.body, &got) != nil {
		t.Fatalf("body %s", s.body)
	}
	wb, _ := json.Marshal(v.PutBody)
	_ = json.Unmarshal(wb, &want)
	if len(got) != 4 || got["salt_id"] != want["salt_id"] || got["tag"] != want["tag"] || got["salt"] != want["salt"] || got["blob"] != want["blob"] {
		t.Fatalf("body %s, want %s", s.body, wb)
	}
}

// Each answer a creator acts on is one attempt, with its code; a 429 and
// a 5xx are not retried either.
func TestPairCodeCallsAreNotRetried(t *testing.T) {
	v := loadPairCode(t)
	put := func(c *client.Client) error {
		_, err := c.PutPairCode(context.Background(), v.ClaimID, client.PairCodePut{SaltID: v.SaltID, Tag: make([]byte, 32), Salt: make([]byte, 16), Blob: []byte{3}})
		return err
	}
	for _, tc := range []struct {
		name string
		rp   reply
		code string
		call func(*client.Client) error
	}{
		{"put code_taken", reply{409, `{"code":"code_taken","message":"x"}`}, client.CodeCodeTaken, put},
		{"put bad salt", reply{400, `{"code":"bad_request","message":"x"}`}, client.CodeBadRequest, put},
		{"put 429", reply{429, `{"code":"rate_limited","message":"x","retry_after":1}`}, "rate_limited", put},
		{"put 503", reply{503, `{"code":"unavailable","message":"x","retry_after":1}`}, "unavailable", put},
		{"salts 503", reply{503, `{"code":"unavailable","message":"x","retry_after":1}`}, "unavailable",
			func(c *client.Client) error { _, err := c.PairCodeSalts(context.Background()); return err }},
		{"delete 503", reply{503, `{"code":"unavailable","message":"x","retry_after":1}`}, "unavailable",
			func(c *client.Client) error { return c.DeletePairCode(context.Background(), v.ClaimID) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &pcServer{t: t, replies: []reply{tc.rp, {201, `{"expires_at":"2026-03-31T12:27:00Z"}`}}}
			c := s.start("vault")
			if err := tc.call(c); !client.IsCode(err, tc.code) {
				t.Fatalf("err %v, want %s", err, tc.code)
			}
			if n := s.calls.Load(); n != 1 {
				t.Fatalf("%d requests, want 1", n)
			}
		})
	}
}

func TestDeletePairCode(t *testing.T) {
	v := loadPairCode(t)
	s := &pcServer{t: t, replies: []reply{{204, ``}}}
	c := s.start("vault")
	if err := c.DeletePairCode(context.Background(), v.ClaimID); err != nil {
		t.Fatal(err)
	}
	if s.method != "DELETE" || s.path != "/v1/pair-code/"+v.ClaimID || !s.signed || len(s.body) != 0 ||
		s.key != relayauth.EncodeKey(testKey("vault").Public().(ed25519.PublicKey)) {
		t.Fatalf("%s %s signed %v body %q", s.method, s.path, s.signed, s.body)
	}
}

// A malformed claim id never makes a request (it would be a path).
func TestPairCodeClaimIDChecked(t *testing.T) {
	s := &pcServer{t: t, replies: []reply{{204, ``}}}
	c := s.start("vault")
	for _, id := range []string{"", "short", "Q4F7M2XK5N3P6R7T2V4W6Y7Z3A", "q4f7m2xk5n3p6r8t2v4w6y8z3a", "../../v1/mailbox/xxxxxxxxx",
		"q4f7m2xk5n3p6r7t2v4w6y7z3a0", "q4f7m2xk5n3p6r7t2v4w6y7z3b"} { // the last: not canonical
		if err := c.DeletePairCode(context.Background(), id); !errors.Is(err, client.ErrClaimID) {
			t.Errorf("%q: %v", id, err)
		}
		if _, err := c.PutPairCode(context.Background(), id, client.PairCodePut{}); !errors.Is(err, client.ErrClaimID) {
			t.Errorf("%q: %v", id, err)
		}
	}
	if n := s.calls.Load(); n != 0 {
		t.Fatalf("%d requests", n)
	}
}

func TestOffersPairCodes(t *testing.T) {
	for raw, want := range map[string]bool{`{}`: false, `{"pair_codes":true}`: true, `{"pair_codes":false}`: false,
		`{"pair_codes":"true"}`: false, `{"pair_codes":1}`: false, `{"pair_codes":null}`: false} {
		var l client.Limits
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatal(err)
		}
		if l.OffersPairCodes() != want {
			t.Errorf("%s: %v", raw, !want)
		}
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

// A body of the wrong form is refused before any request, so the relay's
// bad_request only ever stands for its own refusal.
func TestPutPairCodeChecksTheBody(t *testing.T) {
	v := loadPairCode(t)
	s := &pcServer{t: t, replies: []reply{{201, `{"expires_at":"2026-03-31T12:27:00Z"}`}}}
	c := s.start("vault")
	ok := client.PairCodePut{SaltID: v.SaltID, Tag: make([]byte, 32), Salt: make([]byte, 16), Blob: []byte{1}}
	for name, mut := range map[string]func(*client.PairCodePut){
		"a 31-byte tag":         func(p *client.PairCodePut) { p.Tag = p.Tag[:31] },
		"a 15-byte salt":        func(p *client.PairCodePut) { p.Salt = p.Salt[:15] },
		"no blob":               func(p *client.PairCodePut) { p.Blob = nil },
		"an upper-case salt id": func(p *client.PairCodePut) { p.SaltID = "ABCDEF01" },
		"a 33-byte tag":         func(p *client.PairCodePut) { p.Tag = make([]byte, 33) },
		"a 17-byte salt":        func(p *client.PairCodePut) { p.Salt = make([]byte, 17) },
		"a 9-character salt id": func(p *client.PairCodePut) { p.SaltID = "a12213d1f" },
		"a salt id not hex":     func(p *client.PairCodePut) { p.SaltID = "a12213dg" },
		"a short salt id":       func(p *client.PairCodePut) { p.SaltID = "abc" },
	} {
		p := ok
		mut(&p)
		if _, err := c.PutPairCode(context.Background(), v.ClaimID, p); !errors.Is(err, client.ErrPairCodePut) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := s.calls.Load(); n != 0 {
		t.Fatalf("%d requests", n)
	}
}

// A 201 whose answer does not read says so (the claim may be stored).
func TestPutPairCodeAnswerUnread(t *testing.T) {
	v := loadPairCode(t)
	for _, body := range []string{``, `{`, `{"expires_at":"soon"}`, `{"x":"` + strings.Repeat("a", 5000) + `","expires_at":"2026-03-31T12:27:00Z"}`} {
		s := &pcServer{t: t, replies: []reply{{201, body}}}
		c := s.start("vault")
		_, err := c.PutPairCode(context.Background(), v.ClaimID, client.PairCodePut{SaltID: v.SaltID, Tag: make([]byte, 32), Salt: make([]byte, 16), Blob: []byte{1}})
		if !errors.Is(err, client.ErrPairCodeAnswer) {
			t.Errorf("%q: %v", body, err)
		}
	}
}

func TestPairCodeSaltsAnswers(t *testing.T) {
	v := loadPairCode(t)
	e := func(ep int64) string {
		return `{"salt_id":"` + v.SaltID + `","epoch":` + jsonInt(ep) + `,"nonce":"` + v.Nonce + `"}`
	}
	for name, tc := range map[string]struct {
		body string
		n    int
		fail bool
	}{
		"two entries":         {`{"salts":[` + e(v.Epoch) + `,` + e(v.Epoch+1) + `]}`, 2, false},
		"no salts member":     {`{}`, 0, false},
		"a nonce not base64":  {`{"salts":[{"salt_id":"x","epoch":1,"nonce":"***"}]}`, 0, true},
		"something after it":  {`{"salts":[]} {}`, 0, true},
		"an oversized answer": {`{"salts":[` + strings.Repeat(e(v.Epoch)+",", 60) + e(v.Epoch) + `]}`, 0, true},
	} {
		s := &pcServer{t: t, replies: []reply{{200, tc.body}}}
		c := s.start("vault")
		got, err := c.PairCodeSalts(context.Background())
		if tc.fail != (err != nil) || !tc.fail && len(got) != tc.n {
			t.Errorf("%s: %d %v", name, len(got), err)
		}
	}
}

// A 404 (a relay without code claims) is an *Error with its code, after one
// attempt.
func TestPutPairCode404(t *testing.T) {
	v := loadPairCode(t)
	s := &pcServer{t: t, replies: []reply{{404, `{"code":"not_found","message":"x"}`}}}
	c := s.start("vault")
	_, err := c.PutPairCode(context.Background(), v.ClaimID, client.PairCodePut{SaltID: v.SaltID, Tag: make([]byte, 32), Salt: make([]byte, 16), Blob: []byte{1}})
	if !client.IsCode(err, "not_found") || s.calls.Load() != 1 {
		t.Fatalf("%v, %d requests", err, s.calls.Load())
	}
}
