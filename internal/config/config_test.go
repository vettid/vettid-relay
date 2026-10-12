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

func TestDynamoStoreConfig(t *testing.T) {
	base := map[string]string{
		"RELAY_STORE":             "dynamodb",
		"RELAY_DYNAMODB_TABLE":    "vettid-org-relay",
		"RELAY_BLOB_BUCKET":       "vettid-org-relay-blobs-123",
		"RELAY_VALKEY_ADDR":       "relay-abc.serverless.use1.cache.amazonaws.com:6379",
		"RELAY_VALKEY_TLS":        "true",
		"RELAY_VALKEY_IAM_USER":   "relay",
		"RELAY_VALKEY_CACHE_NAME": "vettid-org-relay",
	}
	c, err := Load(env(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.Store != "dynamodb" || !c.ValkeyTLS || !c.ValkeyServerless || c.ValkeyIAMUser != "relay" {
		t.Fatalf("%+v", c)
	}
	for name, mut := range map[string]func(m map[string]string){
		"no table":           func(m map[string]string) { delete(m, "RELAY_DYNAMODB_TABLE") },
		"no bucket":          func(m map[string]string) { delete(m, "RELAY_BLOB_BUCKET") },
		"no valkey":          func(m map[string]string) { delete(m, "RELAY_VALKEY_ADDR") },
		"payload over item":  func(m map[string]string) { m["RELAY_MAX_PAYLOAD_BYTES"] = "400000" },
		"iam without tls":    func(m map[string]string) { m["RELAY_VALKEY_TLS"] = "false" },
		"iam without cache":  func(m map[string]string) { delete(m, "RELAY_VALKEY_CACHE_NAME") },
		"unknown store kind": func(m map[string]string) { m["RELAY_STORE"] = "postgres" },
	} {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		mut(m)
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Blobs disabled: no bucket needed.
	m := map[string]string{"RELAY_BLOBS_ENABLED": "false"}
	for k, v := range base {
		if k != "RELAY_BLOB_BUCKET" {
			m[k] = v
		}
	}
	if _, err := Load(env(m)); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimitConfig(t *testing.T) {
	d := Defaults()
	if d.RateIPPerSec != 200 || d.RateIPBurst != 4000 || d.RateKeyPerSec != 20 || d.RateKeyBurst != 100 ||
		d.RateAuthFailPerSec != 1 || d.RateAuthFailBurst != 60 || d.AuthFailMaxPenalty != time.Minute ||
		d.RateTricklePerSec != 0.1 || d.RateTrickleBurst != 3 || d.MaxCollectors != 6000 || d.MaxCollectorsPerNetwork != 3000 ||
		d.MaxBodyBytes != 64<<20 || d.MaxBodyBytesPerNetwork != 16<<20 ||
		d.RateKeyFailPerSec != 1 || d.RateKeyFailBurst != 200 || d.RateVerifyPerSec != 1000 || d.RateVerifyBurst != 2000 ||
		d.RateRegisterPerSec != 1 || d.RateRegisterBurst != 100 || d.RateSenderPerSec != 5 || d.RateSenderBurst != 20 ||
		d.RateClaimPerSec != 1 || d.RateClaimBurst != 10 {
		t.Fatalf("defaults differ from docs/RELAY-PROTOCOL.md §7.2: %+v", d)
	}
	c, err := Load(env(map[string]string{
		"RELAY_RATE_IP_RPS":               "50",
		"RELAY_RATE_IP_BURST":             "500",
		"RELAY_RATE_KEY_RPS":              "2.5",
		"RELAY_RATE_KEY_BURST":            "30",
		"RELAY_RATE_AUTHFAIL_RPS":         "0.2",
		"RELAY_RATE_AUTHFAIL_BURST":       "10",
		"RELAY_RATE_AUTHFAIL_MAX_PENALTY": "5m",
		"RELAY_RATE_VERIFY_RPS":           "300",
		"RELAY_RATE_VERIFY_BURST":         "600",
		"RELAY_RATE_KEYFAIL_RPS":          "0.5",
		"RELAY_RATE_KEYFAIL_BURST":        "9",
		"RELAY_RATE_REGISTER_RPS":         "0.1",
		"RELAY_RATE_REGISTER_BURST":       "7",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.RateIPPerSec != 50 || c.RateIPBurst != 500 || c.RateKeyPerSec != 2.5 || c.RateKeyBurst != 30 ||
		c.RateAuthFailPerSec != 0.2 || c.RateAuthFailBurst != 10 || c.AuthFailMaxPenalty != 5*time.Minute ||
		c.RateRegisterPerSec != 0.1 || c.RateRegisterBurst != 7 || c.RateKeyFailPerSec != 0.5 || c.RateKeyFailBurst != 9 || c.RateVerifyPerSec != 300 || c.RateVerifyBurst != 600 {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []map[string]string{
		{"RELAY_RATE_KEY_RPS": "0"},
		{"RELAY_RATE_AUTHFAIL_RPS": "0"},
		{"RELAY_RATE_IP_RPS": "0"},
		{"RELAY_RATE_TRICKLE_RPS": "0"},
		{"RELAY_RATE_AUTHFAIL_MAX_PENALTY": "0"},
		{"RELAY_MAX_COLLECTORS": "0"},
		{"RELAY_MAX_INFLIGHT_BODY_BYTES_PER_NETWORK": "0"},
		{"RELAY_RATE_KEY_BURST": "0"},
		{"RELAY_RATE_AUTHFAIL_BURST": "-1"},
		{"RELAY_RATE_AUTHFAIL_MAX_PENALTY": "never"},
		{"RELAY_RATE_REGISTER_RPS": "x"},
	} {
		if _, err := Load(env(bad)); err == nil {
			t.Errorf("%v: expected an error", bad)
		}
	}
}
