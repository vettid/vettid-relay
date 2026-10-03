// Package config loads relay configuration from environment variables.
//
// The relay holds no long-term secrets, so nothing in here is sensitive.
// Every variable is documented in README.md; keep the two in sync.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the complete runtime configuration.
type Config struct {
	ListenAddr  string // RELAY_LISTEN_ADDR
	MetricsAddr string // RELAY_METRICS_ADDR ("" disables)
	BaseURL     string // RELAY_BASE_URL — exact-match `aud` for deposit tokens
	DBPath      string // RELAY_DB_PATH (store "sqlite")
	Store       string // RELAY_STORE: "sqlite" (default) or "dynamodb"

	// Store "dynamodb" (several relay processes on one shared store).
	DynamoTable    string // RELAY_DYNAMODB_TABLE
	BlobBucket     string // RELAY_BLOB_BUCKET (blob bodies, when blobs are enabled)
	DynamoEndpoint string // RELAY_DYNAMODB_ENDPOINT (development/tests only)
	S3Endpoint     string // RELAY_S3_ENDPOINT (development/tests only; path-style)

	// Valkey: shared replay cache, rate limits and wake-on-deposit.
	// Required with store "dynamodb".
	ValkeyAddr       string // RELAY_VALKEY_ADDR (host:port)
	ValkeyTLS        bool   // RELAY_VALKEY_TLS
	ValkeyIAMUser    string // RELAY_VALKEY_IAM_USER (ElastiCache IAM auth)
	ValkeyCacheName  string // RELAY_VALKEY_CACHE_NAME (for the IAM token)
	ValkeyServerless bool   // RELAY_VALKEY_SERVERLESS (IAM token resource type)
	ValkeyPrefix     string // RELAY_VALKEY_PREFIX (key/channel namespace; relays sharing it share state)
	TrustProxy       bool   // RELAY_TRUST_PROXY
	LogLevel         string // RELAY_LOG_LEVEL

	MaxPayloadBytes   int64         // RELAY_MAX_PAYLOAD_BYTES
	MessageTTL        time.Duration // RELAY_MESSAGE_TTL
	VisibilityTimeout time.Duration // RELAY_VISIBILITY_TIMEOUT

	BlobsEnabled               bool          // RELAY_BLOBS_ENABLED
	MaxBlobBytes               int64         // RELAY_MAX_BLOB_BYTES
	BlobTTL                    time.Duration // RELAY_BLOB_TTL
	MaxConcurrentBlobTransfers int           // RELAY_MAX_CONCURRENT_BLOB_TRANSFERS

	MailboxMaxMessages  int64 // RELAY_MAILBOX_MAX_MESSAGES
	MailboxMaxBytes     int64 // RELAY_MAILBOX_MAX_BYTES
	MailboxMaxBlobBytes int64 // RELAY_MAILBOX_MAX_BLOB_BYTES
	MailboxMaxDenylist  int64 // RELAY_MAILBOX_MAX_DENYLIST

	RotationGrace        time.Duration // RELAY_ROTATION_GRACE
	MaxTokenLifetime     time.Duration // RELAY_MAX_TOKEN_LIFETIME
	OpenTokenMaxLifetime time.Duration // RELAY_OPEN_TOKEN_MAX_LIFETIME

	MaxClaimBytes int64         // RELAY_MAX_CLAIM_BYTES
	ClaimTTL      time.Duration // RELAY_CLAIM_TTL (max TTL a creator may request)

	RateIPPerSec     float64 // RELAY_RATE_IP_RPS
	RateIPBurst      int     // RELAY_RATE_IP_BURST
	RateSenderPerSec float64 // RELAY_RATE_SENDER_RPS
	RateSenderBurst  int     // RELAY_RATE_SENDER_BURST
	RateClaimPerSec  float64 // RELAY_RATE_CLAIM_GET_RPS
	RateClaimBurst   int     // RELAY_RATE_CLAIM_GET_BURST

	MaxCollectorsPerMailbox int // RELAY_MAX_COLLECTORS_PER_MAILBOX
	ReplayCacheMax          int // RELAY_REPLAY_CACHE_MAX

	SweepInterval   time.Duration // RELAY_SWEEP_INTERVAL
	ShutdownTimeout time.Duration // RELAY_SHUTDOWN_TIMEOUT
}

// MaxDynamoPayloadBytes bounds max_payload_bytes for the DynamoDB store: a
// message item must stay under DynamoDB's 400 KB item limit with room for
// its keys and attributes. The protocol default (262,144) fits easily.
const MaxDynamoPayloadBytes = 380_000

// Defaults returns the documented default configuration.
func Defaults() Config {
	return Config{
		ListenAddr:  ":8080",
		MetricsAddr: "127.0.0.1:9090",
		BaseURL:     "http://localhost:8080",
		DBPath:      "relay.db",
		Store:       "sqlite",

		ValkeyServerless: true,
		ValkeyPrefix:     "relay",
		LogLevel:         "info",

		MaxPayloadBytes:   262144,
		MessageTTL:        14 * 24 * time.Hour,
		VisibilityTimeout: 60 * time.Second,

		BlobsEnabled:               true,
		MaxBlobBytes:               8388608,
		BlobTTL:                    7 * 24 * time.Hour,
		MaxConcurrentBlobTransfers: 8,

		MailboxMaxMessages:  10000,
		MailboxMaxBytes:     128 << 20,
		MailboxMaxBlobBytes: 64 << 20,
		MailboxMaxDenylist:  10000,

		RotationGrace:        7 * 24 * time.Hour,
		MaxTokenLifetime:     30 * 24 * time.Hour,
		OpenTokenMaxLifetime: 600 * time.Second,

		MaxClaimBytes: 16384,
		ClaimTTL:      900 * time.Second,

		RateIPPerSec:     20,
		RateIPBurst:      40,
		RateSenderPerSec: 5,
		RateSenderBurst:  20,
		RateClaimPerSec:  1,
		RateClaimBurst:   10,

		MaxCollectorsPerMailbox: 4,
		ReplayCacheMax:          1_000_000,

		SweepInterval:   60 * time.Second,
		ShutdownTimeout: 20 * time.Second,
	}
}

// FromEnv loads configuration from the process environment.
func FromEnv() (Config, error) { return Load(os.LookupEnv) }

// Load builds a Config from a lookup function (os.LookupEnv in production).
func Load(lookup func(string) (string, bool)) (Config, error) {
	c := Defaults()
	var errs []error
	str := func(key string, dst *string) {
		if v, ok := lookup(key); ok {
			*dst = strings.TrimSpace(v)
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			b, err := strconv.ParseBool(strings.TrimSpace(v))
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key, err))
				return
			}
			*dst = b
		}
	}
	i64 := func(key string, dst *int64) {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil || n < 0 {
				errs = append(errs, fmt.Errorf("%s: want a non-negative integer", key))
				return
			}
			*dst = n
		}
	}
	integer := func(key string, dst *int) {
		var n = int64(*dst)
		i64(key, &n)
		*dst = int(n)
	}
	f64 := func(key string, dst *float64) {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil || n <= 0 {
				errs = append(errs, fmt.Errorf("%s: want a positive number", key))
				return
			}
			*dst = n
		}
	}
	// Durations accept Go syntax ("90s", "336h") or a bare integer of seconds.
	dur := func(key string, dst *time.Duration) {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			v = strings.TrimSpace(v)
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				*dst = time.Duration(n) * time.Second
			} else if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			} else {
				errs = append(errs, fmt.Errorf("%s: want a duration like 60s or integer seconds", key))
				return
			}
			if *dst <= 0 {
				errs = append(errs, fmt.Errorf("%s: must be positive", key))
			}
		}
	}

	str("RELAY_LISTEN_ADDR", &c.ListenAddr)
	str("RELAY_METRICS_ADDR", &c.MetricsAddr)
	str("RELAY_BASE_URL", &c.BaseURL)
	str("RELAY_DB_PATH", &c.DBPath)
	str("RELAY_STORE", &c.Store)
	str("RELAY_DYNAMODB_TABLE", &c.DynamoTable)
	str("RELAY_BLOB_BUCKET", &c.BlobBucket)
	str("RELAY_DYNAMODB_ENDPOINT", &c.DynamoEndpoint)
	str("RELAY_S3_ENDPOINT", &c.S3Endpoint)
	str("RELAY_VALKEY_ADDR", &c.ValkeyAddr)
	boolean("RELAY_VALKEY_TLS", &c.ValkeyTLS)
	str("RELAY_VALKEY_IAM_USER", &c.ValkeyIAMUser)
	str("RELAY_VALKEY_CACHE_NAME", &c.ValkeyCacheName)
	boolean("RELAY_VALKEY_SERVERLESS", &c.ValkeyServerless)
	str("RELAY_VALKEY_PREFIX", &c.ValkeyPrefix)
	boolean("RELAY_TRUST_PROXY", &c.TrustProxy)
	str("RELAY_LOG_LEVEL", &c.LogLevel)

	i64("RELAY_MAX_PAYLOAD_BYTES", &c.MaxPayloadBytes)
	dur("RELAY_MESSAGE_TTL", &c.MessageTTL)
	dur("RELAY_VISIBILITY_TIMEOUT", &c.VisibilityTimeout)

	boolean("RELAY_BLOBS_ENABLED", &c.BlobsEnabled)
	i64("RELAY_MAX_BLOB_BYTES", &c.MaxBlobBytes)
	dur("RELAY_BLOB_TTL", &c.BlobTTL)
	integer("RELAY_MAX_CONCURRENT_BLOB_TRANSFERS", &c.MaxConcurrentBlobTransfers)

	i64("RELAY_MAILBOX_MAX_MESSAGES", &c.MailboxMaxMessages)
	i64("RELAY_MAILBOX_MAX_BYTES", &c.MailboxMaxBytes)
	i64("RELAY_MAILBOX_MAX_BLOB_BYTES", &c.MailboxMaxBlobBytes)
	i64("RELAY_MAILBOX_MAX_DENYLIST", &c.MailboxMaxDenylist)

	dur("RELAY_ROTATION_GRACE", &c.RotationGrace)
	dur("RELAY_MAX_TOKEN_LIFETIME", &c.MaxTokenLifetime)
	dur("RELAY_OPEN_TOKEN_MAX_LIFETIME", &c.OpenTokenMaxLifetime)
	i64("RELAY_MAX_CLAIM_BYTES", &c.MaxClaimBytes)
	dur("RELAY_CLAIM_TTL", &c.ClaimTTL)

	f64("RELAY_RATE_IP_RPS", &c.RateIPPerSec)
	integer("RELAY_RATE_IP_BURST", &c.RateIPBurst)
	f64("RELAY_RATE_SENDER_RPS", &c.RateSenderPerSec)
	integer("RELAY_RATE_SENDER_BURST", &c.RateSenderBurst)
	f64("RELAY_RATE_CLAIM_GET_RPS", &c.RateClaimPerSec)
	integer("RELAY_RATE_CLAIM_GET_BURST", &c.RateClaimBurst)

	integer("RELAY_MAX_COLLECTORS_PER_MAILBOX", &c.MaxCollectorsPerMailbox)
	integer("RELAY_REPLAY_CACHE_MAX", &c.ReplayCacheMax)

	dur("RELAY_SWEEP_INTERVAL", &c.SweepInterval)
	dur("RELAY_SHUTDOWN_TIMEOUT", &c.ShutdownTimeout)

	if err := c.Validate(); err != nil {
		errs = append(errs, err)
	}
	return c, errors.Join(errs...)
}

// Validate checks cross-field invariants.
func (c Config) Validate() error {
	var errs []error
	if c.ListenAddr == "" {
		errs = append(errs, errors.New("RELAY_LISTEN_ADDR must not be empty"))
	}
	switch c.Store {
	case "sqlite":
		if c.DBPath == "" {
			errs = append(errs, errors.New("RELAY_DB_PATH must not be empty"))
		}
	case "dynamodb":
		if c.DynamoTable == "" {
			errs = append(errs, errors.New("RELAY_DYNAMODB_TABLE is required with RELAY_STORE=dynamodb"))
		}
		if c.BlobsEnabled && c.BlobBucket == "" {
			errs = append(errs, errors.New("RELAY_BLOB_BUCKET is required with RELAY_STORE=dynamodb when blobs are enabled"))
		}
		// Several processes share the store, so they must share replay
		// detection, rate limits and wake-ups too.
		if c.ValkeyAddr == "" {
			errs = append(errs, errors.New("RELAY_VALKEY_ADDR is required with RELAY_STORE=dynamodb"))
		}
		// A message is one DynamoDB item (400 KB limit, ~1 KB attributes).
		if c.MaxPayloadBytes > MaxDynamoPayloadBytes {
			errs = append(errs, fmt.Errorf("RELAY_MAX_PAYLOAD_BYTES must be ≤ %d with RELAY_STORE=dynamodb", MaxDynamoPayloadBytes))
		}
	default:
		errs = append(errs, errors.New(`RELAY_STORE must be "sqlite" or "dynamodb"`))
	}
	if c.ValkeyIAMUser != "" && (c.ValkeyCacheName == "" || !c.ValkeyTLS) {
		errs = append(errs, errors.New("RELAY_VALKEY_IAM_USER needs RELAY_VALKEY_CACHE_NAME and RELAY_VALKEY_TLS=true"))
	}
	u, err := url.Parse(c.BaseURL)
	switch {
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "":
		errs = append(errs, errors.New("RELAY_BASE_URL must be an absolute http(s) URL"))
	case strings.HasSuffix(c.BaseURL, "/") || u.RawQuery != "" || u.Fragment != "":
		// `aud` is an exact string match (spec §5.3 step 4); a trailing slash
		// here would silently reject every correctly minted token.
		errs = append(errs, errors.New("RELAY_BASE_URL must not end with '/' or carry a query/fragment"))
	}
	if c.MetricsAddr != "" && c.MetricsAddr == c.ListenAddr {
		errs = append(errs, errors.New("RELAY_METRICS_ADDR must differ from RELAY_LISTEN_ADDR (metrics are never served on the public port)"))
	}
	if c.MaxTokenLifetime < time.Second || c.OpenTokenMaxLifetime < time.Second || c.ClaimTTL < time.Second {
		errs = append(errs, errors.New("token lifetimes and claim TTL must be at least 1s"))
	}
	if c.MaxClaimBytes <= 0 {
		errs = append(errs, errors.New("RELAY_MAX_CLAIM_BYTES must be > 0"))
	}
	if c.MaxPayloadBytes <= 0 {
		errs = append(errs, errors.New("RELAY_MAX_PAYLOAD_BYTES must be > 0"))
	}
	if c.BlobsEnabled && c.MaxBlobBytes <= 0 {
		errs = append(errs, errors.New("RELAY_MAX_BLOB_BYTES must be > 0 when blobs are enabled"))
	}
	if c.MaxConcurrentBlobTransfers <= 0 || c.MaxCollectorsPerMailbox <= 0 || c.ReplayCacheMax <= 0 ||
		c.RateIPBurst <= 0 || c.RateSenderBurst <= 0 || c.RateClaimBurst <= 0 {
		errs = append(errs, errors.New("concurrency, burst and cache limits must be > 0"))
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, errors.New("RELAY_LOG_LEVEL must be debug|info|warn|error"))
	}
	return errors.Join(errs...)
}

// HealthcheckURL derives the loopback /healthz URL from the listen address,
// used by `relay -healthcheck` inside distroless containers.
func (c Config) HealthcheckURL() (string, error) {
	_, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("RELAY_LISTEN_ADDR %q: %w", c.ListenAddr, err)
	}
	if port == "" {
		port = "80"
	}
	return "http://127.0.0.1:" + port + "/healthz", nil
}
