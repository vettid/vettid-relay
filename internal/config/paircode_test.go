package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPairCodeKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x6b}, 32)
	b64 := base64.StdEncoding.EncodeToString(key)
	dir := t.TempDir()
	file := filepath.Join(dir, "k")
	if err := os.WriteFile(file, []byte(b64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte(base64.StdEncoding.EncodeToString(key[:31])), 0o600)
	for _, c := range []struct {
		name    string
		env     map[string]string
		ok      bool
		problem string
	}{
		{"none", nil, false, "no RELAY_PAIR_CODE_KEY_FILE"},
		{"file", map[string]string{"RELAY_PAIR_CODE_KEY_FILE": file}, true, ""},
		{"env", map[string]string{"RELAY_PAIR_CODE_KEY": b64}, true, ""},
		{"the file wins", map[string]string{"RELAY_PAIR_CODE_KEY_FILE": file, "RELAY_PAIR_CODE_KEY": "x"}, true, ""},
		{"missing file", map[string]string{"RELAY_PAIR_CODE_KEY_FILE": filepath.Join(dir, "none")}, false, "RELAY_PAIR_CODE_KEY_FILE: the file can't be read"},
		{"31 bytes", map[string]string{"RELAY_PAIR_CODE_KEY_FILE": short}, false, "RELAY_PAIR_CODE_KEY_FILE: not a base64 key of 32 bytes"},
		{"not base64", map[string]string{"RELAY_PAIR_CODE_KEY": "not base64!"}, false, "RELAY_PAIR_CODE_KEY: not a base64 key of 32 bytes"},
	} {
		e := map[string]string{"RELAY_OPEN_TOKEN_MAX_LIFETIME": "660s"}
		for k, v := range c.env {
			e[k] = v
		}
		cfg, err := Load(env(e))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := bytes.Equal(cfg.PairCodeKey.Bytes(), key); got != c.ok || !strings.HasPrefix(cfg.PairCodeKeyProblem, c.problem) {
			t.Errorf("%s: key %v, problem %q", c.name, got, cfg.PairCodeKeyProblem)
		}
		if strings.Contains(cfg.PairCodeKeyProblem, b64) {
			t.Errorf("%s: the problem names the key", c.name)
		}
	}
}

// A key with an open-token limit under 660 s is set aside: a vault makes
// no code pairing toward such a relay, so the relay offers none, says
// why (naming the variable, never the key), and starts.
func TestPairCodeKeyNeedsOpenTokenLifetime(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, 32))
	for _, c := range []struct {
		life string
		ok   bool
	}{{"", false}, {"600s", false}, {"659s", false}, {"660s", true}, {"660.5s", true}, {"168h", true}} {
		e := map[string]string{"RELAY_PAIR_CODE_KEY": b64}
		if c.life != "" {
			e["RELAY_OPEN_TOKEN_MAX_LIFETIME"] = c.life
		}
		cfg, err := Load(env(e))
		if err != nil {
			t.Fatalf("%q: the relay doesn't start: %v", c.life, err)
		}
		if got := len(cfg.PairCodeKey.Bytes()) == 32; got != c.ok {
			t.Errorf("%q: key kept %v, want %v", c.life, got, c.ok)
		}
		if !c.ok && !strings.HasPrefix(cfg.PairCodeKeyProblem, "RELAY_OPEN_TOKEN_MAX_LIFETIME is ") {
			t.Errorf("%q: problem %q", c.life, cfg.PairCodeKeyProblem)
		}
		if c.ok && cfg.PairCodeKeyProblem != "" {
			t.Errorf("%q: problem %q with a kept key", c.life, cfg.PairCodeKeyProblem)
		}
		if strings.Contains(cfg.PairCodeKeyProblem, b64) {
			t.Errorf("%q: the problem names the key", c.life)
		}
	}
}

// A key that is no key keeps its own reason, whatever the limit.
func TestPairCodeBadKeyReasonWins(t *testing.T) {
	cfg, err := Load(env(map[string]string{"RELAY_PAIR_CODE_KEY": "not base64!"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PairCodeKeyProblem != "RELAY_PAIR_CODE_KEY: not a base64 key of 32 bytes" {
		t.Errorf("problem %q", cfg.PairCodeKeyProblem)
	}
}

// No print of a Config shows k_pc.
func TestPairCodeKeyNeverPrints(t *testing.T) {
	key := bytes.Repeat([]byte{0x6b}, 32)
	cfg, err := Load(env(map[string]string{"RELAY_PAIR_CODE_KEY": base64.StdEncoding.EncodeToString(key), "RELAY_OPEN_TOKEN_MAX_LIFETIME": "660s"}))
	if err != nil || cfg.PairCodeKey.Bytes() == nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "cfg", cfg, "key", cfg.PairCodeKey)
	slog.New(slog.NewTextHandler(&logs, nil)).Info("config", "cfg", cfg, "key", cfg.PairCodeKey)
	out := fmt.Sprintf("%v %+v %#v %s %v %d %x %q", cfg, cfg, cfg, cfg.PairCodeKey, cfg.PairCodeKey, cfg.PairCodeKey, cfg.PairCodeKey, cfg.PairCodeKey) + logs.String()
	for _, enc := range []string{base64.StdEncoding.EncodeToString(key), hex.EncodeToString(key), string(key), fmt.Sprint(key)} {
		if strings.Contains(out, enc) {
			t.Fatalf("k_pc printed: %s", out)
		}
	}
	if !strings.Contains(out, "[secret]") {
		t.Fatal("no [secret]")
	}
}
