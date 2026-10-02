package config

import (
	"testing"
	"time"
)

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestDefaultsValid(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxPayloadBytes != 262144 || c.MaxBlobBytes != 8388608 || c.VisibilityTimeout != 60*time.Second {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.MetricsAddr != "127.0.0.1:9090" {
		t.Fatalf("metrics must default to loopback, got %q", c.MetricsAddr)
	}
}

func TestLoadOverrides(t *testing.T) {
	c, err := Load(env(map[string]string{
		"RELAY_LISTEN_ADDR":        ":9999",
		"RELAY_BASE_URL":           "https://relay.vettid.org",
		"RELAY_DB_PATH":            "/data/relay.db",
		"RELAY_TRUST_PROXY":        "true",
		"RELAY_MESSAGE_TTL":        "3600",
		"RELAY_VISIBILITY_TIMEOUT": "90s",
		"RELAY_RATE_IP_RPS":        "2.5",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.TrustProxy || c.MessageTTL != time.Hour || c.VisibilityTimeout != 90*time.Second || c.RateIPPerSec != 2.5 {
		t.Fatalf("overrides not applied: %+v", c)
	}
	u, err := c.HealthcheckURL()
	if err != nil || u != "http://127.0.0.1:9999/healthz" {
		t.Fatalf("healthcheck url %q %v", u, err)
	}
}

func TestLoadRejects(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"trailing slash": {"RELAY_BASE_URL": "https://relay.vettid.org/"},
		"not a url":      {"RELAY_BASE_URL": "relay.vettid.org"},
		"bad bool":       {"RELAY_TRUST_PROXY": "yes please"},
		"bad dur":        {"RELAY_MESSAGE_TTL": "forever"},
		"neg int":        {"RELAY_MAX_PAYLOAD_BYTES": "-1"},
		"metrics==api":   {"RELAY_LISTEN_ADDR": ":8080", "RELAY_METRICS_ADDR": ":8080"},
		"log level":      {"RELAY_LOG_LEVEL": "loud"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLifetimePolicyConfig(t *testing.T) {
	c, err := Load(env(map[string]string{
		"RELAY_MAX_TOKEN_LIFETIME":      "34560000", // 400 days, integer seconds
		"RELAY_OPEN_TOKEN_MAX_LIFETIME": "168h",
		"RELAY_CLAIM_TTL":               "604800",
		"RELAY_MAX_CLAIM_BYTES":         "4096",
		"RELAY_RATE_CLAIM_GET_RPS":      "0.5",
		"RELAY_RATE_CLAIM_GET_BURST":    "3",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxTokenLifetime != 400*24*time.Hour || c.OpenTokenMaxLifetime != 7*24*time.Hour ||
		c.ClaimTTL != 7*24*time.Hour || c.MaxClaimBytes != 4096 || c.RateClaimPerSec != 0.5 || c.RateClaimBurst != 3 {
		t.Fatalf("%+v", c)
	}
	d := Defaults()
	if d.OpenTokenMaxLifetime != 600*time.Second || d.ClaimTTL != 900*time.Second || d.MaxClaimBytes != 16384 {
		t.Fatalf("0.3 defaults: %+v", d)
	}
	if _, err := Load(env(map[string]string{"RELAY_MAX_CLAIM_BYTES": "0"})); err == nil {
		t.Fatal("zero claim size accepted")
	}
}
