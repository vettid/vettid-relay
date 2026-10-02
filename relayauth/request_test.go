package relayauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func signedHeaders(t testing.TB, priv ed25519.PrivateKey, method, path string, at time.Time, body []byte) http.Header {
	h := http.Header{}
	SetHeaders(h, priv, method, path, at, BodyHash(body))
	return h
}

func TestVerifyNegative(t *testing.T) {
	sender := vecKey(t, vecSenderSeed)
	other := vecKey(t, vecRecipientSeed)
	now := vecTime(t, vecTimestamp)
	body := []byte(vecBody)

	verify := func(h http.Header, method, path string, body []byte, now time.Time) error {
		sr, err := ParseHeaders(h)
		if err != nil {
			return err
		}
		return sr.Verify(method, path, BodyHash(body), now)
	}

	good := signedHeaders(t, sender, "POST", vecPath, now, body)
	if err := verify(good, "POST", vecPath, body, now); err != nil {
		t.Fatalf("good request: %v", err)
	}

	t.Run("tampered body", func(t *testing.T) {
		if err := verify(good, "POST", vecPath, []byte(`{"payload":"AAAA"}`), now); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("tampered path", func(t *testing.T) {
		if err := verify(good, "POST", "/v1/mailbox/ni4ahvpqlgicuhdnv66jxjdssi", body, now); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("tampered method", func(t *testing.T) {
		if err := verify(good, "DELETE", vecPath, body, now); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("sig/key mismatch", func(t *testing.T) {
		h := good.Clone()
		h.Set(HeaderKey, EncodeKey(other.Public().(ed25519.PublicKey)))
		if err := verify(h, "POST", vecPath, body, now); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("tampered timestamp", func(t *testing.T) {
		h := good.Clone()
		h.Set(HeaderTimestamp, "2026-06-10T12:00:01Z")
		if err := verify(h, "POST", vecPath, body, now); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("stale timestamp", func(t *testing.T) {
		for _, skew := range []time.Duration{91 * time.Second, -91 * time.Second, time.Hour} {
			if err := verify(good, "POST", vecPath, body, now.Add(skew)); !errors.Is(err, ErrTimestampStale) {
				t.Fatalf("skew %v: got %v", skew, err)
			}
		}
		for _, skew := range []time.Duration{90 * time.Second, -90 * time.Second} {
			if err := verify(good, "POST", vecPath, body, now.Add(skew)); err != nil {
				t.Fatalf("skew %v must be accepted: %v", skew, err)
			}
		}
	})
	t.Run("malformed headers", func(t *testing.T) {
		mut := []func(h http.Header){
			func(h http.Header) { h.Del(HeaderKey) },
			func(h http.Header) { h.Del(HeaderSig) },
			func(h http.Header) { h.Del(HeaderTimestamp) },
			func(h http.Header) { h.Add(HeaderSig, h.Get(HeaderSig)) },                         // duplicated
			func(h http.Header) { h.Set(HeaderKey, strings.TrimRight(h.Get(HeaderKey), "=")) }, // unpadded
			func(h http.Header) { h.Set(HeaderKey, "AAAA") },
			func(h http.Header) { h.Set(HeaderSig, h.Get(HeaderSig)[:80]) },
			func(h http.Header) { h.Set(HeaderTimestamp, "1749556800") },
			func(h http.Header) { h.Set(HeaderTimestamp, "2026-06-10 12:00:00") },
			func(h http.Header) { h.Set(HeaderKey, strings.NewReplacer("+", "-", "/", "_").Replace(vecSenderPub)) }, // url alphabet
		}
		for i, m := range mut {
			h := good.Clone()
			m(h)
			if err := verify(h, "POST", vecPath, body, now); !errors.Is(err, ErrSignatureInvalid) {
				t.Errorf("mutation %d: got %v", i, err)
			}
		}
	})
}

func TestReplayCache(t *testing.T) {
	sender := vecKey(t, vecSenderSeed)
	now := vecTime(t, vecTimestamp)
	sr, err := ParseHeaders(signedHeaders(t, sender, "GET", "/v1/mailbox", now, nil))
	if err != nil {
		t.Fatal(err)
	}
	c := NewReplayCache(1000)
	if err := c.Check(sr, now); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(sr, now.Add(10*time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed signature: got %v", err)
	}
	// Still rejected at the very end of the freshness window.
	if err := c.Check(sr, now.Add(FreshnessWindow)); !errors.Is(err, ErrReplay) {
		t.Fatalf("end of window: got %v", err)
	}
	// After the window the timestamp check rejects it anyway; the cache may forget.
	c.Sweep(now.Add(FreshnessWindow + 2*time.Second))
	if c.Len() != 0 {
		t.Fatalf("sweep left %d entries", c.Len())
	}
	// A different signature (new timestamp) is not a replay.
	sr2, _ := ParseHeaders(signedHeaders(t, sender, "GET", "/v1/mailbox", now.Add(time.Second), nil))
	if err := c.Check(sr2, now); err != nil {
		t.Fatal(err)
	}
}

func TestReplayCacheBounded(t *testing.T) {
	sender := vecKey(t, vecSenderSeed)
	now := vecTime(t, vecTimestamp)
	c := NewReplayCache(replayShards) // one entry per shard
	full := false
	for i := 0; i < 500 && !full; i++ {
		sr, _ := ParseHeaders(signedHeaders(t, sender, "GET", "/v1/mailbox", now.Add(time.Duration(i)*time.Second), nil))
		if err := c.Check(sr, now); errors.Is(err, ErrReplayCacheFull) {
			full = true
		}
	}
	if !full {
		t.Fatal("cache never reported full")
	}
	if c.Len() > replayShards {
		t.Fatalf("cache exceeded bound: %d", c.Len())
	}
	// Once entries expire, capacity returns.
	sr, _ := ParseHeaders(signedHeaders(t, sender, "GET", "/v1/x", now, nil))
	if err := c.Check(sr, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestReplayCacheConcurrent(t *testing.T) {
	sender := vecKey(t, vecSenderSeed)
	now := vecTime(t, vecTimestamp)
	sr, _ := ParseHeaders(signedHeaders(t, sender, "POST", "/v1/x", now, []byte("b")))
	c := NewReplayCache(1000)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.Check(sr, now) == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("same signature accepted %d times", accepted)
	}
}

func FuzzCanonical(f *testing.F) {
	f.Add("POST", "/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp", "2026-06-10T12:00:00Z", []byte(vecBody))
	f.Add("GET", "/v1/mailbox", "2026-06-10T12:00:00Z", []byte{})
	f.Add("delete", "/v1/mailbox/01J00000000000000000000000", "2026-06-10T12:00:00.123+02:00", []byte(nil))
	f.Add("PUT", "/v1/blob/x\n", "\n", []byte{0, 1, 2})
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	f.Fuzz(func(t *testing.T, method, path, ts string, body []byte) {
		bh := BodyHash(body)
		c := Canonical(method, path, ts, bh)
		// Structure: exactly the four fields when no field contains '\n'.
		if !strings.Contains(method+path+ts, "\n") {
			parts := bytes.Split(c, []byte("\n"))
			if len(parts) != 4 || string(parts[0]) != strings.ToUpper(method) ||
				string(parts[1]) != path || string(parts[2]) != ts || len(parts[3]) != 64 {
				t.Fatalf("bad canonical structure: %q", c)
			}
			for _, ch := range parts[3] {
				if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
					t.Fatalf("hash not lowercase hex: %q", parts[3])
				}
			}
		}
		// Digest is deterministic and signatures round-trip.
		d := Digest(method, path, ts, bh)
		if d != sha256.Sum256(c) {
			t.Fatal("digest is not SHA-256(canonical)")
		}
		sig := SignRequest(priv, method, path, ts, bh)
		if !ed25519.Verify(priv.Public().(ed25519.PublicKey), d[:], sig) {
			t.Fatal("sign/verify round trip failed")
		}
		// Any change to the body changes the digest.
		d2 := Digest(method, path, ts, BodyHash(append(append([]byte{}, body...), 'x')))
		if d == d2 {
			t.Fatal("body change did not change digest")
		}
	})
}

func FuzzVerifyRequest(f *testing.F) {
	f.Add(vecSenderPub, vecTimestamp, vecSigB64, "POST", vecPath, []byte(vecBody))
	f.Add("", "", "", "GET", "/", []byte{})
	f.Add("AAAA", "x", "====", "PUT", "/v1/blob/a", []byte("z"))
	now := vecTime(f, vecTimestamp)
	f.Fuzz(func(t *testing.T, key, ts, sig, method, path string, body []byte) {
		h := http.Header{}
		h.Set(HeaderKey, key)
		h.Set(HeaderTimestamp, ts)
		h.Set(HeaderSig, sig)
		sr, err := ParseHeaders(h)
		if err != nil {
			if !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("unexpected error type %v", err)
			}
			return
		}
		err = sr.Verify(method, path, BodyHash(body), now)
		if err == nil {
			// Only the genuine vector may verify.
			if key != vecSenderPub || sig != vecSigB64 || strings.ToUpper(method) != "POST" || path != vecPath || string(body) != vecBody {
				t.Fatalf("forged request verified: %q %q %q %q", key, ts, method, path)
			}
		} else if !errors.Is(err, ErrSignatureInvalid) && !errors.Is(err, ErrTimestampStale) {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

// Sub-second timestamps keep back-to-back identical requests distinct (the
// canonical string omits the query string and Ed25519 is deterministic).
func TestSubSecondTimestamps(t *testing.T) {
	sender := vecKey(t, vecSenderSeed)
	now := vecTime(t, vecTimestamp)
	h1 := signedHeaders(t, sender, "GET", "/v1/mailbox", now.Add(1*time.Millisecond), nil)
	h2 := signedHeaders(t, sender, "GET", "/v1/mailbox", now.Add(2*time.Millisecond), nil)
	if h1.Get(HeaderTimestamp) != "2026-06-10T12:00:00.001Z" || h1.Get(HeaderSig) == h2.Get(HeaderSig) {
		t.Fatalf("timestamps %q / %q", h1.Get(HeaderTimestamp), h2.Get(HeaderTimestamp))
	}
	c := NewReplayCache(100)
	for _, h := range []http.Header{h1, h2} {
		sr, err := ParseHeaders(h)
		if err != nil {
			t.Fatal(err)
		}
		if err := sr.Verify("GET", "/v1/mailbox", BodyHash(nil), now); err != nil {
			t.Fatal(err)
		}
		if err := c.Check(sr, now); err != nil {
			t.Fatalf("distinct requests flagged as replay: %v", err)
		}
	}
}

// Spec §4.1 (0.3.0): the canonical string uses X-VettID-Timestamp verbatim.
// Spellings that a parse/re-format round trip would change must verify as
// signed, and re-spelling the same instant must not.
func TestTimestampUsedVerbatim(t *testing.T) {
	sender := vecKey(t, vecSenderSeed)
	now := vecTime(t, vecTimestamp)
	for _, ts := range []string{"2026-06-10T12:00:00.120Z", "2026-06-10T12:00:00.000Z", "2026-06-10T12:00:00+00:00", "2026-06-10T14:00:00.5+02:00"} {
		bh := BodyHash([]byte("b"))
		h := http.Header{}
		h.Set(HeaderKey, EncodeKey(sender.Public().(ed25519.PublicKey)))
		h.Set(HeaderTimestamp, ts)
		h.Set(HeaderSig, b64.EncodeToString(SignRequest(sender, "POST", "/v1/x", ts, bh)))
		sr, err := ParseHeaders(h)
		if err != nil {
			t.Fatalf("%s: %v", ts, err)
		}
		if err := sr.Verify("POST", "/v1/x", bh, now); err != nil {
			t.Fatalf("%s: verbatim timestamp did not verify: %v", ts, err)
		}
		// Same instant, different spelling → signature no longer matches.
		h.Set(HeaderTimestamp, sr.Time.UTC().Format("2006-01-02T15:04:05.000000Z"))
		sr2, _ := ParseHeaders(h)
		if err := sr2.Verify("POST", "/v1/x", bh, now); !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("%s: re-spelled timestamp verified", ts)
		}
	}
}
