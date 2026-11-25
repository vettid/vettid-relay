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
		cfg, err := Load(env(c.env))
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

// No print of a Config shows k_pc.
func TestPairCodeKeyNeverPrints(t *testing.T) {
	key := bytes.Repeat([]byte{0x6b}, 32)
	cfg, err := Load(env(map[string]string{"RELAY_PAIR_CODE_KEY": base64.StdEncoding.EncodeToString(key)}))
	if err != nil || cfg.PairCodeKey.Bytes() == nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "cfg", cfg, "key", cfg.PairCodeKey)
	slog.New(slog.NewTextHandler(&logs, nil)).Info("config", "cfg", cfg, "key", cfg.PairCodeKey)
	out := fmt.Sprintf("%v %+v %#v %s %v", cfg, cfg, cfg, cfg.PairCodeKey, cfg.PairCodeKey) + logs.String()
	for _, enc := range []string{base64.StdEncoding.EncodeToString(key), hex.EncodeToString(key), string(key), fmt.Sprint(key)} {
		if strings.Contains(out, enc) {
			t.Fatalf("k_pc printed: %s", out)
		}
	}
	if !strings.Contains(out, "[secret]") {
		t.Fatal("no [secret]")
	}
}
