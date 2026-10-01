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
