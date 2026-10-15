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

	// Log volume, per relay process: info lines beyond this budget are
	// dropped and counted (the per-minute "rate limits" line always gets
	// through and reports the count).
	LogInfoPerSec float64 // RELAY_LOG_INFO_RPS
	LogInfoBurst  int     // RELAY_LOG_INFO_BURST

	MaxPayloadBytes   int64         // RELAY_MAX_PAYLOAD_BYTES
	MessageTTL        time.Duration // RELAY_MESSAGE_TTL
	VisibilityTimeout time.Duration // RELAY_VISIBILITY_TIMEOUT

	BlobsEnabled               bool          // RELAY_BLOBS_ENABLED
	MaxBlobBytes               int64         // RELAY_MAX_BLOB_BYTES
	BlobTTL                    time.Duration // RELAY_BLOB_TTL
	MaxConcurrentBlobTransfers int           // RELAY_MAX_CONCURRENT_BLOB_TRANSFERS (per process)
	MaxBlobTransfersPerMailbox int           // RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX: uploads, and downloads, per mailbox
	// RELAY_BLOB_PACE_BYTES: a blob body (up or down) must move at least
	// this many bytes in every BlobPaceWindow, or the transfer is dropped.
	BlobPaceBytes int64
	// RELAY_BLOB_EVICT_MIN_AGE: when a new upload finds no upload slot
	// free, the slowest upload that has run at least this long is cut off
	// and the new one takes its slot.
	BlobEvictMinAge time.Duration

	MailboxMaxMessages  int64 // RELAY_MAILBOX_MAX_MESSAGES
	MailboxMaxBytes     int64 // RELAY_MAILBOX_MAX_BYTES
	MailboxMaxBlobBytes int64 // RELAY_MAILBOX_MAX_BLOB_BYTES
	// RELAY_MAX_SENDER_BLOB_BYTES (0.9.2, §6.8): one sender key's share
	// of a mailbox's blob storage, at most 2 × MaxBlobBytes; 0 (the
	// default) is 2 × MaxBlobBytes (SenderBlobBytes).
	MaxSenderBlobBytes int64
	MaxSenderBlobs     int64 // RELAY_MAX_SENDER_BLOBS: how many blobs one sender key may hold in one mailbox
	MailboxMaxDenylist int64 // RELAY_MAILBOX_MAX_DENYLIST

	RotationGrace        time.Duration // RELAY_ROTATION_GRACE
	MaxTokenLifetime     time.Duration // RELAY_MAX_TOKEN_LIFETIME
	OpenTokenMaxLifetime time.Duration // RELAY_OPEN_TOKEN_MAX_LIFETIME

	MaxClaimBytes int64         // RELAY_MAX_CLAIM_BYTES
	ClaimTTL      time.Duration // RELAY_CLAIM_TTL (max TTL a creator may request)

	// Rate limits (spec §7.2). Per client network (IPv4 address / IPv6 /64)
	// only before a request is authenticated; per key after.
	RateIPPerSec       float64 // RELAY_RATE_IP_RPS: flood guard on /v1/, per network (shared by all processes)
	RateIPBurst        int     // RELAY_RATE_IP_BURST
	RateKeyPerSec      float64 // RELAY_RATE_KEY_RPS: per authenticated key (owner routes, register, delete)
	RateKeyBurst       int     // RELAY_RATE_KEY_BURST
	RateRegisterPerSec float64 // RELAY_RATE_REGISTER_RPS: new mailboxes per network
	RateRegisterBurst  int     // RELAY_RATE_REGISTER_BURST
	RateSenderPerSec   float64 // RELAY_RATE_SENDER_RPS
	RateSenderBurst    int     // RELAY_RATE_SENDER_BURST
	RateClaimPerSec    float64 // RELAY_RATE_CLAIM_GET_RPS
	RateClaimBurst     int     // RELAY_RATE_CLAIM_GET_BURST
	RateWebPerSec      float64 // RELAY_RATE_WEB_RPS (everything outside /v1/ and /healthz)
	RateWebBurst       int     // RELAY_RATE_WEB_BURST

	// Byte budgets. Charged with a request's declared length before its
	// body is read. The per-key budgets are per relay process; the
	// network ceilings (RELAY_RATE_IP_BYTES_*, RELAY_RATE_BLOB_BYTES_*)
	// are relay-wide when the processes share Valkey (proposed 0.9.4).
	// Deposit and claim bytes, per authenticated key (the depositor's,
	// once its signature verified; a claim's creator) ...
	RateKeyBytesPerSec float64 // RELAY_RATE_KEY_BYTES_PER_SEC
	RateKeyBytesBurst  int     // RELAY_RATE_KEY_BYTES_BURST
	// ... and the ceiling over all keys of one network (relay-wide).
	RateIPBytesPerSec float64 // RELAY_RATE_IP_BYTES_PER_SEC
	RateIPBytesBurst  int     // RELAY_RATE_IP_BYTES_BURST
	// Blob bytes (uploads and downloads), per authenticated key: the
	// sender's for an upload, the mailbox owner's for a download. A vault
	// host's vaults each have their own.
	RateBlobKeyBytesPerSec float64 // RELAY_RATE_BLOB_KEY_BYTES_PER_SEC
	RateBlobKeyBytesBurst  int     // RELAY_RATE_BLOB_KEY_BYTES_BURST
	// The ceiling over all keys of one network (relay-wide).
	RateBlobBytesPerSec float64 // RELAY_RATE_BLOB_BYTES_PER_SEC
	RateBlobBytesBurst  int     // RELAY_RATE_BLOB_BYTES_BURST

	// Web endpoints (spec §6.11): /.well-known/assetlinks.json names the
	// Android app allowed to open this relay's /connect links. An empty
	// fingerprint list (RELAY_ANDROID_CERT_SHA256 set to "") turns
	// assetlinks.json off (404).
	AndroidPackage          string   // RELAY_ANDROID_PACKAGE
	AndroidCertFingerprints []string // RELAY_ANDROID_CERT_SHA256 (comma-separated)

	MaxCollectorsPerMailbox int // RELAY_MAX_COLLECTORS_PER_MAILBOX
	MaxWebSocketSessions    int // RELAY_MAX_WS_SESSIONS: open WebSocket collect sessions, per relay process
	// RELAY_MAX_WS_SESSIONS_PER_NETWORK: of those, per client network (IPv4
	// address / IPv6 /64); the first session of a mailbox is not refused by it.
	MaxWebSocketSessionsPerNetwork int
	// RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD: the most sessions of one
	// network per process, first sessions of mailboxes included. Between
	// the per-network maximum and the process maximum.
	MaxWebSocketSessionsPerNetworkHard int
	ReplayCacheMax                     int // RELAY_REPLAY_CACHE_MAX

	SweepInterval   time.Duration // RELAY_SWEEP_INTERVAL
	ShutdownTimeout time.Duration // RELAY_SHUTDOWN_TIMEOUT

	// Empty hints (with Valkey): collectors skip the store query for
	// mailboxes known to be empty, trusting one empty finding at most this
	// long (the worst-case delay if a deposit's hint update is lost).
	EmptyHints   bool          // RELAY_EMPTY_HINTS
	EmptySkipMax time.Duration // RELAY_EMPTY_SKIP_MAX
}

// MaxDynamoPayloadBytes bounds max_payload_bytes for the DynamoDB store: a
// message item must stay under DynamoDB's 400 KB item limit with room for
// its keys and attributes. The protocol default (262,144) fits easily.
const MaxDynamoPayloadBytes = 380_000

// BlobPaceWindow is the period of RELAY_BLOB_PACE_BYTES.
const BlobPaceWindow = 5 * time.Second

// SenderBlobBytes is one sender key's share of a mailbox's blob storage
// (max_sender_blob_bytes, §6.8): MaxSenderBlobBytes, or 2 ×
// MaxBlobBytes when that is 0.
func (c Config) SenderBlobBytes() int64 {
	if c.MaxSenderBlobBytes > 0 {
		return c.MaxSenderBlobBytes
	}
	return 2 * c.MaxBlobBytes
}

// DepositBodyLimit is the most a deposit's JSON body may be: base64 of
// the maximum payload plus headroom for {"payload":""} and whitespace.
func (c Config) DepositBodyLimit() int64 {
	return 4*((c.MaxPayloadBytes+2)/3) + 1024
}

// DefaultAndroidPackage is the VettID Android app.
const DefaultAndroidPackage = "com.vettid.app"

// DefaultAndroidCertFingerprints are the SHA-256 fingerprints of the
// certificates that sign the official VettID Android app, so that every
// relay, self-hosted ones included, lets the official app open its links.
var DefaultAndroidCertFingerprints = []string{
	// Production upload key.
	"31:A1:96:13:AA:10:F2:09:E0:89:45:F9:47:F9:4F:7C:E3:E6:E5:AC:34:24:57:FF:99:69:A6:79:86:92:8E:65",
	// Staging signers (staging builds also use relay.vettid.org).
	"BD:83:A0:75:3F:AA:6A:F6:F8:D8:1B:9F:76:A0:4A:C1:A4:99:EA:6C:7F:46:C6:F1:11:3D:4B:57:87:EC:B2:C4",
	"2F:ED:27:B7:27:46:79:7A:93:1F:D4:14:FF:3D:AC:4C:D9:69:FA:0C:2F:F3:62:09:AE:05:36:5F:58:00:14:F2",
}

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
		LogInfoPerSec:    100,
		LogInfoBurst:     1000,

		MaxPayloadBytes:   262144,
		MessageTTL:        14 * 24 * time.Hour,
		VisibilityTimeout: 60 * time.Second,

		BlobsEnabled:               true,
		MaxBlobBytes:               8388608,
		BlobTTL:                    7 * 24 * time.Hour,
		MaxConcurrentBlobTransfers: 8,
		MaxBlobTransfersPerMailbox: 2,
		BlobPaceBytes:              16 << 10,
		BlobEvictMinAge:            30 * time.Second,

		MailboxMaxMessages:  10000,
		MailboxMaxBytes:     32 << 20,
		MailboxMaxBlobBytes: 64 << 20,
		MaxSenderBlobs:      16,
		MailboxMaxDenylist:  10000,

		RotationGrace:        7 * 24 * time.Hour,
		MaxTokenLifetime:     30 * 24 * time.Hour,
		OpenTokenMaxLifetime: 600 * time.Second,

		MaxClaimBytes: 16384,
		ClaimTTL:      900 * time.Second,

		RateIPPerSec:       100,
		RateIPBurst:        300,
		RateKeyPerSec:      20,
		RateKeyBurst:       100,
		RateRegisterPerSec: 1,
		RateRegisterBurst:  30,
		RateSenderPerSec:   5,
		RateSenderBurst:    20,
		RateClaimPerSec:    1,
		RateClaimBurst:     10,
		RateWebPerSec:      2,
		RateWebBurst:       20,

		RateKeyBytesPerSec:     64 << 10,
		RateKeyBytesBurst:      2 << 20,
		RateIPBytesPerSec:      768 << 10,
		RateIPBytesBurst:       8 << 20,
		RateBlobKeyBytesPerSec: 1 << 20,
		RateBlobKeyBytesBurst:  32 << 20,
		RateBlobBytesPerSec:    8 << 20,
		RateBlobBytesBurst:     256 << 20,

		AndroidPackage:          DefaultAndroidPackage,
		AndroidCertFingerprints: append([]string(nil), DefaultAndroidCertFingerprints...),

		MaxCollectorsPerMailbox: 4,
		MaxWebSocketSessions:    4000,

		MaxWebSocketSessionsPerNetwork:     1024,
		MaxWebSocketSessionsPerNetworkHard: 2000,
		ReplayCacheMax:                     1_000_000,

		SweepInterval:   60 * time.Second,
		ShutdownTimeout: 20 * time.Second,

		EmptyHints:   true,
		EmptySkipMax: 5 * time.Minute,
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
	f64("RELAY_LOG_INFO_RPS", &c.LogInfoPerSec)
	integer("RELAY_LOG_INFO_BURST", &c.LogInfoBurst)

	i64("RELAY_MAX_PAYLOAD_BYTES", &c.MaxPayloadBytes)
	dur("RELAY_MESSAGE_TTL", &c.MessageTTL)
	dur("RELAY_VISIBILITY_TIMEOUT", &c.VisibilityTimeout)

	boolean("RELAY_BLOBS_ENABLED", &c.BlobsEnabled)
	i64("RELAY_MAX_BLOB_BYTES", &c.MaxBlobBytes)
	dur("RELAY_BLOB_TTL", &c.BlobTTL)
	integer("RELAY_MAX_CONCURRENT_BLOB_TRANSFERS", &c.MaxConcurrentBlobTransfers)
	integer("RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX", &c.MaxBlobTransfersPerMailbox)
	i64("RELAY_BLOB_PACE_BYTES", &c.BlobPaceBytes)
	dur("RELAY_BLOB_EVICT_MIN_AGE", &c.BlobEvictMinAge)

	i64("RELAY_MAILBOX_MAX_MESSAGES", &c.MailboxMaxMessages)
	i64("RELAY_MAILBOX_MAX_BYTES", &c.MailboxMaxBytes)
	i64("RELAY_MAILBOX_MAX_BLOB_BYTES", &c.MailboxMaxBlobBytes)
	i64("RELAY_MAX_SENDER_BLOB_BYTES", &c.MaxSenderBlobBytes)
	i64("RELAY_MAX_SENDER_BLOBS", &c.MaxSenderBlobs)
	i64("RELAY_MAILBOX_MAX_DENYLIST", &c.MailboxMaxDenylist)

	dur("RELAY_ROTATION_GRACE", &c.RotationGrace)
	dur("RELAY_MAX_TOKEN_LIFETIME", &c.MaxTokenLifetime)
	dur("RELAY_OPEN_TOKEN_MAX_LIFETIME", &c.OpenTokenMaxLifetime)
	i64("RELAY_MAX_CLAIM_BYTES", &c.MaxClaimBytes)
	dur("RELAY_CLAIM_TTL", &c.ClaimTTL)

	f64("RELAY_RATE_IP_RPS", &c.RateIPPerSec)
	integer("RELAY_RATE_IP_BURST", &c.RateIPBurst)
	f64("RELAY_RATE_KEY_RPS", &c.RateKeyPerSec)
	integer("RELAY_RATE_KEY_BURST", &c.RateKeyBurst)
	f64("RELAY_RATE_REGISTER_RPS", &c.RateRegisterPerSec)
	integer("RELAY_RATE_REGISTER_BURST", &c.RateRegisterBurst)
	f64("RELAY_RATE_SENDER_RPS", &c.RateSenderPerSec)
	integer("RELAY_RATE_SENDER_BURST", &c.RateSenderBurst)
	f64("RELAY_RATE_CLAIM_GET_RPS", &c.RateClaimPerSec)
	integer("RELAY_RATE_CLAIM_GET_BURST", &c.RateClaimBurst)
	f64("RELAY_RATE_WEB_RPS", &c.RateWebPerSec)
	integer("RELAY_RATE_WEB_BURST", &c.RateWebBurst)
	f64("RELAY_RATE_KEY_BYTES_PER_SEC", &c.RateKeyBytesPerSec)
	integer("RELAY_RATE_KEY_BYTES_BURST", &c.RateKeyBytesBurst)
	f64("RELAY_RATE_IP_BYTES_PER_SEC", &c.RateIPBytesPerSec)
	integer("RELAY_RATE_IP_BYTES_BURST", &c.RateIPBytesBurst)
	f64("RELAY_RATE_BLOB_KEY_BYTES_PER_SEC", &c.RateBlobKeyBytesPerSec)
	integer("RELAY_RATE_BLOB_KEY_BYTES_BURST", &c.RateBlobKeyBytesBurst)
	f64("RELAY_RATE_BLOB_BYTES_PER_SEC", &c.RateBlobBytesPerSec)
	integer("RELAY_RATE_BLOB_BYTES_BURST", &c.RateBlobBytesBurst)

	str("RELAY_ANDROID_PACKAGE", &c.AndroidPackage)
	if v, ok := lookup("RELAY_ANDROID_CERT_SHA256"); ok {
		fps, err := ParseCertFingerprints(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("RELAY_ANDROID_CERT_SHA256: %w", err))
		} else {
			c.AndroidCertFingerprints = fps
		}
	}

	integer("RELAY_MAX_COLLECTORS_PER_MAILBOX", &c.MaxCollectorsPerMailbox)
	integer("RELAY_MAX_WS_SESSIONS", &c.MaxWebSocketSessions)
	integer("RELAY_MAX_WS_SESSIONS_PER_NETWORK", &c.MaxWebSocketSessionsPerNetwork)
	integer("RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD", &c.MaxWebSocketSessionsPerNetworkHard)
	integer("RELAY_REPLAY_CACHE_MAX", &c.ReplayCacheMax)

	dur("RELAY_SWEEP_INTERVAL", &c.SweepInterval)
	dur("RELAY_SHUTDOWN_TIMEOUT", &c.ShutdownTimeout)
	boolean("RELAY_EMPTY_HINTS", &c.EmptyHints)
	dur("RELAY_EMPTY_SKIP_MAX", &c.EmptySkipMax)

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
	if c.MaxConcurrentBlobTransfers <= 0 || c.MaxCollectorsPerMailbox <= 0 || c.MaxWebSocketSessions <= 0 || c.MaxWebSocketSessionsPerNetwork <= 0 || c.ReplayCacheMax <= 0 ||
		c.RateIPBurst <= 0 || c.RateKeyBurst <= 0 || c.RateRegisterBurst <= 0 || c.RateSenderBurst <= 0 || c.RateClaimBurst <= 0 || c.RateWebBurst <= 0 {
		errs = append(errs, errors.New("concurrency, burst and cache limits must be > 0"))
	}
	// Byte budgets: the largest single request must fit in the burst, or
	// it could never be served.
	if c.RateKeyBytesBurst <= 0 || c.RateIPBytesBurst <= 0 || c.RateBlobKeyBytesBurst <= 0 || c.RateBlobBytesBurst <= 0 || c.LogInfoBurst <= 0 || c.BlobPaceBytes <= 0 {
		errs = append(errs, errors.New("RELAY_RATE_KEY_BYTES_BURST, RELAY_RATE_IP_BYTES_BURST, RELAY_RATE_BLOB_KEY_BYTES_BURST, RELAY_RATE_BLOB_BYTES_BURST, RELAY_LOG_INFO_BURST and RELAY_BLOB_PACE_BYTES must be > 0"))
	} else if int64(c.RateKeyBytesBurst) < max(c.DepositBodyLimit(), c.MaxClaimBytes) || c.RateIPBytesBurst < c.RateKeyBytesBurst || c.RateIPBytesPerSec < c.RateKeyBytesPerSec {
		errs = append(errs, fmt.Errorf("the largest deposit body (%d bytes for RELAY_MAX_PAYLOAD_BYTES) and RELAY_MAX_CLAIM_BYTES <= RELAY_RATE_KEY_BYTES_BURST <= RELAY_RATE_IP_BYTES_BURST, and RELAY_RATE_KEY_BYTES_PER_SEC <= RELAY_RATE_IP_BYTES_PER_SEC must hold", c.DepositBodyLimit()))
	}
	if c.BlobsEnabled {
		// A key's burst must hold the largest blob, and the network's
		// ceiling at least one key's burst and rate.
		if int64(c.RateBlobKeyBytesBurst) < c.MaxBlobBytes || c.RateBlobBytesBurst < c.RateBlobKeyBytesBurst || c.RateBlobBytesPerSec < c.RateBlobKeyBytesPerSec {
			errs = append(errs, errors.New("RELAY_MAX_BLOB_BYTES <= RELAY_RATE_BLOB_KEY_BYTES_BURST <= RELAY_RATE_BLOB_BYTES_BURST and RELAY_RATE_BLOB_KEY_BYTES_PER_SEC <= RELAY_RATE_BLOB_BYTES_PER_SEC must hold when blobs are enabled"))
		}
		// Uploads may use the process's transfers less one mailbox's worth,
		// which stay for downloads: so the per-mailbox number must be
		// smaller.
		if c.MaxBlobTransfersPerMailbox <= 0 || c.MaxBlobTransfersPerMailbox >= c.MaxConcurrentBlobTransfers {
			errs = append(errs, errors.New("0 < RELAY_MAX_BLOB_TRANSFERS_PER_MAILBOX < RELAY_MAX_CONCURRENT_BLOB_TRANSFERS must hold"))
		}
		// A mailbox keeps one maximum blob's room for its owner's devices
		// (§6.8): the cap must leave at least as much for everyone else.
		if c.MailboxMaxBlobBytes < 2*c.MaxBlobBytes {
			errs = append(errs, errors.New("RELAY_MAILBOX_MAX_BLOB_BYTES must be at least 2 × RELAY_MAX_BLOB_BYTES when blobs are enabled (one blob's room is kept for the owner's devices)"))
		}
		// A sender's share holds at least one blob of the maximum size and
		// at most two (§6.8), in at least one blob.
		if sb := c.SenderBlobBytes(); c.MaxSenderBlobBytes < 0 || sb < c.MaxBlobBytes || sb > 2*c.MaxBlobBytes || c.MaxSenderBlobs < 1 {
			errs = append(errs, errors.New("RELAY_MAX_BLOB_BYTES <= RELAY_MAX_SENDER_BLOB_BYTES <= 2 × RELAY_MAX_BLOB_BYTES (0: 2 × RELAY_MAX_BLOB_BYTES) and RELAY_MAX_SENDER_BLOBS >= 1 must hold when blobs are enabled"))
		}
	}
	// 0 is "no cap"; a cap below one message would refuse every deposit.
	if c.MailboxMaxBytes > 0 && c.MailboxMaxBytes < c.MaxPayloadBytes {
		errs = append(errs, errors.New("RELAY_MAILBOX_MAX_BYTES must be 0 (no cap) or at least RELAY_MAX_PAYLOAD_BYTES"))
	}
	if c.MaxWebSocketSessionsPerNetworkHard < c.MaxWebSocketSessionsPerNetwork || c.MaxWebSocketSessionsPerNetworkHard > c.MaxWebSocketSessions {
		errs = append(errs, errors.New("RELAY_MAX_WS_SESSIONS_PER_NETWORK <= RELAY_MAX_WS_SESSIONS_PER_NETWORK_HARD <= RELAY_MAX_WS_SESSIONS must hold (set all three when lowering one)"))
	}
	// A zero rate would silently turn a limit into "never refills".
	for _, r := range []float64{c.RateIPPerSec, c.RateKeyPerSec, c.RateRegisterPerSec, c.RateSenderPerSec, c.RateClaimPerSec, c.RateWebPerSec, c.LogInfoPerSec} {
		if !(r > 0) || r > 1e9 {
			errs = append(errs, errors.New("every RELAY_RATE_*_RPS and RELAY_LOG_INFO_RPS must be > 0"))
			break
		}
	}
	for _, r := range []float64{c.RateKeyBytesPerSec, c.RateIPBytesPerSec, c.RateBlobKeyBytesPerSec, c.RateBlobBytesPerSec} {
		if !(r > 0) || r > 1e12 {
			errs = append(errs, errors.New("every RELAY_RATE_*_BYTES_PER_SEC must be > 0"))
			break
		}
	}
	if len(c.AndroidCertFingerprints) > 0 && !validAndroidPackage(c.AndroidPackage) {
		errs = append(errs, errors.New("RELAY_ANDROID_PACKAGE must be an Android package name like com.vettid.app"))
	}
	for _, fp := range c.AndroidCertFingerprints {
		if n, err := ParseCertFingerprints(fp); err != nil || len(n) != 1 || n[0] != fp {
			errs = append(errs, errors.New("RELAY_ANDROID_CERT_SHA256: fingerprints must be uppercase colon-separated SHA-256"))
			break
		}
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

// maxCertFingerprints bounds RELAY_ANDROID_CERT_SHA256.
const maxCertFingerprints = 32

// ParseCertFingerprints parses a comma-separated list of SHA-256 certificate
// fingerprints, each either colon-separated ("31:A1:…") or plain hex
// ("31a1…"), in any case, and returns them in the uppercase colon form that
// Digital Asset Links uses, in order, without duplicates. Blank entries are
// skipped; an empty or blank list is valid and yields none.
func ParseCertFingerprints(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		hex := item
		if strings.Contains(item, ":") {
			parts := strings.Split(item, ":")
			if len(parts) != 32 {
				return nil, errors.New("want 32 colon-separated bytes per fingerprint")
			}
			for _, p := range parts {
				if len(p) != 2 {
					return nil, errors.New("want 32 colon-separated bytes per fingerprint")
				}
			}
			hex = strings.Join(parts, "")
		}
		if len(hex) != 64 {
			return nil, errors.New("want a SHA-256 fingerprint (64 hex digits)")
		}
		var b strings.Builder
		for i := 0; i < 64; i++ {
			ch := hex[i]
			switch {
			case ch >= '0' && ch <= '9', ch >= 'A' && ch <= 'F':
			case ch >= 'a' && ch <= 'f':
				ch -= 'a' - 'A'
			default:
				return nil, errors.New("fingerprints are hexadecimal")
			}
			if i > 0 && i%2 == 0 {
				b.WriteByte(':')
			}
			b.WriteByte(ch)
		}
		fp := b.String()
		if !seen[fp] {
			seen[fp] = true
			out = append(out, fp)
		}
		if len(out) > maxCertFingerprints {
			return nil, fmt.Errorf("at most %d fingerprints", maxCertFingerprints)
		}
	}
	return out, nil
}

// validAndroidPackage reports whether s is a valid Android application id:
// at least two dot-separated segments, each a letter followed by letters,
// digits or underscores.
func validAndroidPackage(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}
	segs := strings.Split(s, ".")
	if len(segs) < 2 {
		return false
	}
	for _, seg := range segs {
		if seg == "" {
			return false
		}
		for i := 0; i < len(seg); i++ {
			ch := seg[i]
			letter := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
			if i == 0 && !letter {
				return false
			}
			if !letter && !(ch >= '0' && ch <= '9') && ch != '_' {
				return false
			}
		}
	}
	return true
}
