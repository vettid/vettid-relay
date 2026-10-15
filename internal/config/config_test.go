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

func TestWebSocketSessionCapConfig(t *testing.T) {
	if d := Defaults(); d.MaxWebSocketSessions != 4000 {
		t.Fatalf("default %d", d.MaxWebSocketSessions)
	}
	c, err := Load(env(map[string]string{"RELAY_MAX_WS_SESSIONS": "5000"}))
	if err != nil || c.MaxWebSocketSessions != 5000 {
		t.Fatalf("%d %v", c.MaxWebSocketSessions, err)
	}
	// Per network: 1024, and a ceiling of 2000 that first sessions do not
	// pass. Per-network maximum <= ceiling <= process maximum.
	if d := Defaults(); d.MaxWebSocketSessionsPerNetworkHard != 2000 {
		t.Fatalf("default ceiling %d", d.MaxWebSocketSessionsPerNetworkHard)
	}
	c, err = Load(env(map[string]string{"RELAY_MAX_WS_SESSIONS": "150", "RELAY_MAX_WS_SESSIONS_PER_NETWORK": "40", "RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD": "150"}))
	if err != nil || c.MaxWebSocketSessions != 150 || c.MaxWebSocketSessionsPerNetwork != 40 || c.MaxWebSocketSessionsPerNetworkHard != 150 {
		t.Fatalf("%+v %v", c, err)
	}
	for name, bad := range map[string]map[string]string{
		"ceiling below the per-network maximum": {"RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD": "1000"},
		"ceiling above the process maximum":     {"RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD": "4001"},
		"process maximum below the ceiling":     {"RELAY_MAX_WS_SESSIONS": "1500"},
		"per-network maximum above the ceiling": {"RELAY_MAX_WS_SESSIONS_PER_NETWORK": "2001"},
		"ceiling zero":                          {"RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD": "0"},
	} {
		if _, err := Load(env(bad)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if d := Defaults(); d.MaxWebSocketSessionsPerNetwork != 1024 {
		t.Fatalf("default per network %d", d.MaxWebSocketSessionsPerNetwork)
	}
	c, err = Load(env(map[string]string{"RELAY_MAX_WS_SESSIONS_PER_NETWORK": "40"}))
	if err != nil || c.MaxWebSocketSessionsPerNetwork != 40 {
		t.Fatalf("%d %v", c.MaxWebSocketSessionsPerNetwork, err)
	}
	for _, name := range []string{"RELAY_MAX_WS_SESSIONS", "RELAY_MAX_WS_SESSIONS_PER_NETWORK"} {
		for _, bad := range []string{"0", "-1", "many"} {
			if _, err := Load(env(map[string]string{name: bad})); err == nil {
				t.Errorf("%s=%s: expected an error", name, bad)
			}
		}
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
	if d.RateIPPerSec != 100 || d.RateIPBurst != 300 || d.RateKeyPerSec != 20 || d.RateKeyBurst != 100 ||
		d.RateRegisterPerSec != 1 || d.RateRegisterBurst != 30 || d.RateSenderPerSec != 5 || d.RateSenderBurst != 20 ||
		d.RateClaimPerSec != 1 || d.RateClaimBurst != 10 {
		t.Fatalf("defaults differ from docs/RELAY-PROTOCOL.md §7.2: %+v", d)
	}
	c, err := Load(env(map[string]string{
		"RELAY_RATE_IP_RPS":         "50",
		"RELAY_RATE_IP_BURST":       "500",
		"RELAY_RATE_KEY_RPS":        "2.5",
		"RELAY_RATE_KEY_BURST":      "30",
		"RELAY_RATE_REGISTER_RPS":   "0.1",
		"RELAY_RATE_REGISTER_BURST": "7",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.RateIPPerSec != 50 || c.RateIPBurst != 500 || c.RateKeyPerSec != 2.5 || c.RateKeyBurst != 30 ||
		c.RateRegisterPerSec != 0.1 || c.RateRegisterBurst != 7 {
		t.Fatalf("%+v", c)
	}
	// Every rate and every burst must be greater than zero.
	for _, name := range []string{"IP", "KEY", "REGISTER", "SENDER", "CLAIM_GET", "WEB"} {
		for _, suffix := range []string{"_RPS", "_BURST"} {
			if _, err := Load(env(map[string]string{"RELAY_RATE_" + name + suffix: "0"})); err == nil {
				t.Errorf("RELAY_RATE_%s%s=0: expected an error", name, suffix)
			}
		}
	}
	for _, bad := range []map[string]string{{"RELAY_RATE_KEY_BURST": "-1"}, {"RELAY_RATE_REGISTER_RPS": "x"}} {
		if _, err := Load(env(bad)); err == nil {
			t.Errorf("%v: expected an error", bad)
		}
	}
}

// The resource limits: byte budgets per network, blob transfer slots and
// pace, the mailbox's stored-bytes cap and the log budget. Their defaults,
// their variables, and the start-up checks between related limits.
func TestResourceLimitConfig(t *testing.T) {
	d := Defaults()
	if d.RateKeyBytesPerSec != 64<<10 || d.RateKeyBytesBurst != 2<<20 || d.RateIPBytesPerSec != 1<<20 || d.RateIPBytesBurst != 32<<20 ||
		d.RateBlobKeyBytesPerSec != 1<<20 || d.RateBlobKeyBytesBurst != 32<<20 ||
		d.RateBlobBytesPerSec != 8<<20 || d.RateBlobBytesBurst != 256<<20 ||
		d.MaxBlobTransfersPerMailbox != 2 || d.MaxConcurrentBlobTransfers != 8 || d.BlobPaceBytes != 16<<10 ||
		d.MailboxMaxBytes != 32<<20 || d.LogInfoPerSec != 100 || d.LogInfoBurst != 1000 {
		t.Fatalf("defaults differ from README.md: %+v", d)
	}
	c, err := Load(env(map[string]string{
		"RELAY_RATE_KEY_BYTES_PER_SEC":         "131072",
		"RELAY_RATE_KEY_BYTES_BURST":           "4194304",
		"RELAY_RATE_IP_BYTES_PER_SEC":          "524288",
		"RELAY_RATE_IP_BYTES_BURST":            "16777216",
		"RELAY_RATE_BLOB_KEY_BYTES_PER_SEC":    "2097152",
		"RELAY_RATE_BLOB_KEY_BYTES_BURST":      "16777216",
		"RELAY_RATE_BLOB_BYTES_PER_SEC":        "16777216",
		"RELAY_RATE_BLOB_BYTES_BURST":          "134217728",
		"RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX": "3",
		"RELAY_BLOB_PACE_BYTES":                "65536",
		"RELAY_LOG_INFO_RPS":                   "50",
		"RELAY_LOG_INFO_BURST":                 "200",
		"RELAY_MAILBOX_MAX_BYTES":              "0",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.RateKeyBytesPerSec != 131072 || c.RateKeyBytesBurst != 4<<20 || c.RateIPBytesPerSec != 524288 || c.RateIPBytesBurst != 16<<20 || c.RateBlobKeyBytesPerSec != 2<<20 || c.RateBlobKeyBytesBurst != 16<<20 || c.RateBlobBytesPerSec != 16<<20 || c.RateBlobBytesBurst != 128<<20 ||
		c.MaxBlobTransfersPerMailbox != 3 || c.BlobPaceBytes != 65536 || c.LogInfoPerSec != 50 || c.LogInfoBurst != 200 || c.MailboxMaxBytes != 0 {
		t.Fatalf("%+v", c)
	}
	for _, bad := range []map[string]string{
		{"RELAY_RATE_IP_BYTES_PER_SEC": "0"},
		{"RELAY_RATE_BLOB_BYTES_PER_SEC": "0"},
		{"RELAY_LOG_INFO_RPS": "0"},
		{"RELAY_LOG_INFO_BURST": "0"},
		// The burst must hold the largest deposit body (about 350 KiB at the default payload size).
		{"RELAY_RATE_KEY_BYTES_BURST": "300000"},
		{"RELAY_RATE_KEY_BYTES_BURST": "0"},
		{"RELAY_RATE_KEY_BYTES_PER_SEC": "0"},
		// The network's ceiling at least a key's burst and rate.
		{"RELAY_RATE_IP_BYTES_BURST": "2097151"},
		{"RELAY_RATE_IP_BYTES_PER_SEC": "65535"},
		{"RELAY_RATE_IP_BYTES_BURST": "0"},
		// A key's blob burst must hold the largest blob, and the network's
		// ceiling at least a key's burst and rate.
		{"RELAY_RATE_BLOB_KEY_BYTES_BURST": "8388607"},
		{"RELAY_RATE_BLOB_KEY_BYTES_PER_SEC": "0"},
		{"RELAY_RATE_BLOB_BYTES_BURST": "33554431"},
		{"RELAY_RATE_BLOB_BYTES_PER_SEC": "1048575"},
		// Per-mailbox slots: at least 1, fewer than the process's.
		{"RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX": "0"},
		{"RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX": "9"},
		{"RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX": "8"}, // nothing left for downloads
		{"RELAY_BLOB_PACE_BYTES": "0"},
		// A mailbox cap below one message.
		{"RELAY_MAILBOX_MAX_BYTES": "1000"},
	} {
		if _, err := Load(env(bad)); err == nil {
			t.Errorf("%v: expected an error", bad)
		}
	}
	// With blobs off, how the blob limits relate is not checked; every
	// rate, burst and pace must still be greater than zero.
	if _, err := Load(env(map[string]string{"RELAY_BLOBS_ENABLED": "false", "RELAY_RATE_BLOB_BYTES_BURST": "1", "RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX": "0"})); err != nil {
		t.Fatalf("blobs off: %v", err)
	}
	for _, k := range []string{"RELAY_RATE_BLOB_BYTES_BURST", "RELAY_BLOB_PACE_BYTES"} {
		if _, err := Load(env(map[string]string{"RELAY_BLOBS_ENABLED": "false", k: "0"})); err == nil {
			t.Errorf("blobs off, %s=0: expected an error", k)
		}
	}
	if got := Defaults().DepositBodyLimit(); got != 4*((262144+2)/3)+1024 {
		t.Fatalf("deposit body limit %d", got)
	}
}

func TestBlobEvictMinAgeConfig(t *testing.T) {
	c, err := Load(env(map[string]string{"RELAY_BLOB_EVICT_MIN_AGE": "45s"}))
	if err != nil || c.BlobEvictMinAge != 45*time.Second {
		t.Fatalf("%v %v", c.BlobEvictMinAge, err)
	}
	if _, err := Load(env(map[string]string{"RELAY_BLOB_EVICT_MIN_AGE": "0"})); err == nil {
		t.Fatal("0: expected an error")
	}
}

// 0.9.2 (§6.8): a mailbox keeps one maximum blob's room for its owner's
// devices, and a sender's share is between one and two maximum blobs, in
// at least one blob.
func TestBlobShareConfig(t *testing.T) {
	d := Defaults()
	if d.MailboxMaxBlobBytes != 64<<20 || d.SenderBlobBytes() != 16<<20 || d.MaxSenderBlobs != 16 {
		t.Fatalf("defaults differ from README.md: %d %d %d", d.MailboxMaxBlobBytes, d.SenderBlobBytes(), d.MaxSenderBlobs)
	}
	c, err := Load(env(map[string]string{"RELAY_MAX_SENDER_BLOB_BYTES": "8388608", "RELAY_MAX_SENDER_BLOBS": "4", "RELAY_MAILBOX_MAX_BLOB_BYTES": "16777216"}))
	if err != nil || c.SenderBlobBytes() != 8<<20 || c.MaxSenderBlobs != 4 || c.MailboxMaxBlobBytes != 16<<20 {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := Load(env(map[string]string{"RELAY_MAX_BLOB_BYTES": "1000000"})); err != nil || c.SenderBlobBytes() != 2_000_000 {
		t.Fatalf("share follows the blob size: %v %v", c.SenderBlobBytes(), err)
	}
	for _, bad := range []map[string]string{
		{"RELAY_MAILBOX_MAX_BLOB_BYTES": "16777215"}, // less than two maximum blobs
		{"RELAY_MAILBOX_MAX_BLOB_BYTES": "0"},
		{"RELAY_MAX_SENDER_BLOB_BYTES": "8388607"},  // less than one blob
		{"RELAY_MAX_SENDER_BLOB_BYTES": "16777217"}, // more than two
		{"RELAY_MAX_SENDER_BLOB_BYTES": "-1"},
		{"RELAY_MAX_SENDER_BLOBS": "0"},
	} {
		if _, err := Load(env(bad)); err == nil {
			t.Errorf("%v: expected an error", bad)
		}
	}
	if _, err := Load(env(map[string]string{"RELAY_BLOBS_ENABLED": "false", "RELAY_MAILBOX_MAX_BLOB_BYTES": "0", "RELAY_MAX_SENDER_BLOBS": "0"})); err != nil {
		t.Fatalf("blobs off: %v", err)
	}
}
