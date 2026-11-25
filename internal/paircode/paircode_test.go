package paircode

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"
)

// The shared vectors (vettid-vault testdata/vectors/pair-code.json, copied
// into relayclient/testdata).
type vectors struct {
	R        string `json:"r"`
	Epoch    int64  `json:"epoch"`
	NonceB64 string `json:"nonce_b64"`
	SRHex    string `json:"s_r_hex"`
	SaltID   string `json:"salt_id"`
	WithPort struct {
		R      string `json:"r"`
		SRHex  string `json:"s_r_hex"`
		SaltID string `json:"salt_id"`
	} `json:"with_port"`
	RelayForms []struct {
		Input   string `json:"input"`
		R       string `json:"r"`
		Refused bool   `json:"refused"`
	} `json:"relay_forms"`
}

func load(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("../../relayclient/testdata/pair-code.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.RelayForms) == 0 {
		t.Fatal("no relay_forms")
	}
	return v
}

func TestCanonicalRelayVectors(t *testing.T) {
	for _, f := range load(t).RelayForms {
		got, err := CanonicalRelay(f.Input)
		switch {
		case f.Refused && err == nil:
			t.Errorf("%q: accepted as %q, want refused", f.Input, got)
		case !f.Refused && (err != nil || got != f.R):
			t.Errorf("%q: %q %v, want %q", f.Input, got, err, f.R)
		}
	}
}

func TestSaltVectors(t *testing.T) {
	v := load(t)
	nonce, err := base64.StdEncoding.DecodeString(v.NonceB64)
	if err != nil || len(nonce) != NonceSize {
		t.Fatalf("nonce: %v", err)
	}
	for _, c := range []struct{ r, srHex, id string }{{v.R, v.SRHex, v.SaltID}, {v.WithPort.R, v.WithPort.SRHex, v.WithPort.SaltID}} {
		sr := SaltR(c.r, v.Epoch, nonce)
		if hex.EncodeToString(sr) != c.srHex || SaltID(sr) != c.id {
			t.Errorf("%s: s_r %x id %s, want %s %s", c.r, sr, SaltID(sr), c.srHex, c.id)
		}
	}
}

func TestListed(t *testing.T) {
	at := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	const e = 493044 // 2026-03-31T12:00:00Z
	if Epoch(at("2026-03-31T12:00:00Z")) != e || !Start(e).Equal(at("2026-03-31T12:00:00Z")) {
		t.Fatal("epoch")
	}
	for _, c := range []struct {
		now             string
		listed, creatbl []int64
	}{
		{"2026-03-31T12:30:00Z", []int64{e}, []int64{e}},
		{"2026-03-31T12:57:59Z", []int64{e}, []int64{e}},
		{"2026-03-31T12:58:00Z", []int64{e, e + 1}, []int64{e, e + 1}},
		{"2026-03-31T12:59:59Z", []int64{e, e + 1}, []int64{e, e + 1}},
		{"2026-03-31T12:00:00Z", []int64{e - 1, e}, []int64{e}},
		{"2026-03-31T12:09:59Z", []int64{e - 1, e}, []int64{e}},
		{"2026-03-31T12:10:00Z", []int64{e}, []int64{e}},
	} {
		now := at(c.now)
		if got := Listed(now); !slices.Equal(got, c.listed) {
			t.Errorf("%s: listed %v, want %v", c.now, got, c.listed)
		}
		if got := Creatable(now); !slices.Equal(got, c.creatbl) {
			t.Errorf("%s: creatable %v, want %v", c.now, got, c.creatbl)
		}
	}
}

func TestMACAndKeyID(t *testing.T) {
	k := make([]byte, KeySize)
	k2 := make([]byte, KeySize)
	k2[0] = 1
	tag := make([]byte, TagSize)
	if len(MAC(k, tag)) != MACSize || string(MAC(k, tag)) == string(MAC(k2, tag)) {
		t.Fatal("mac")
	}
	if len(KeyID(k)) != 16 || KeyID(k) == KeyID(k2) || KeyID(k) != KeyID(k) {
		t.Fatal("key id")
	}
}
