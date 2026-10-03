// Package coord shares the relay's short-lived coordination state between
// relay processes through Valkey (ElastiCache Serverless in production):
//
//   - ReplayGuard: the §4.1 replay cache, SET NX PX per (key, signature)
//     for exactly as long as the timestamp stays fresh. If Valkey cannot be
//     reached the request is shed (429 rate_limited, retry_after 5), never
//     admitted unchecked.
//   - Limiter: §7.2 token buckets (GCRA in one Lua script, server clock), so
//     a client's limit is the same however the load balancer spreads it.
//     If Valkey cannot be reached a per-process bucket takes over (limits
//     are best-effort relay policy, availability matters more).
//   - WakeBus: wake-on-deposit across processes over sharded pub/sub. A lost
//     signal never loses a message: collectors re-check the store when a
//     long-poll ends, on every WebSocket ping, after any resubscription, and
//     every few seconds while Valkey is unreachable.
//
// Nothing here is durable or secret; Valkey holds only hashes, counters and
// mailbox ids, all expiring within minutes.
package coord

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/valkey-io/valkey-go"

	"github.com/vettid/vettid-relay/internal/metrics"
)

// Config locates Valkey.
type Config struct {
	Addr string // host:port
	TLS  bool

	// IAM authentication (ElastiCache): when IAMUser is set, every
	// connection authenticates as that user with a short-lived SigV4 token
	// for CacheName (lowercase), refreshed before the 15-minute expiry.
	IAMUser     string
	CacheName   string
	Serverless  bool
	Region      string
	Credentials aws.CredentialsProvider

	// Prefix namespaces keys and channels (default "relay").
	Prefix string
}

// Client is a connected Valkey client plus metrics.
type Client struct {
	vk     valkey.Client
	prefix string

	errors metrics.CounterVec
}

// Open connects to Valkey.
func Open(ctx context.Context, cfg Config, reg *metrics.Registry) (*Client, error) {
	if cfg.Addr == "" {
		return nil, errors.New("coord: address required")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "relay"
	}
	opt := valkey.ClientOption{
		InitAddress: []string{cfg.Addr},
		// ElastiCache Serverless does not support CLIENT TRACKING, and
		// nothing here benefits from client-side caching.
		DisableCache:     true,
		ConnWriteTimeout: 2 * time.Second,
		ClientName:       "vettid-relay",
	}
	if cfg.TLS {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: strings.Split(cfg.Addr, ":")[0]}
	}
	if cfg.IAMUser != "" {
		if cfg.CacheName == "" || cfg.Region == "" || cfg.Credentials == nil {
			return nil, errors.New("coord: IAM auth needs cache name, region and credentials")
		}
		opt.AuthCredentialsFn = func(valkey.AuthCredentialsContext) (valkey.AuthCredentials, error) {
			tok, err := iamToken(context.Background(), cfg, time.Now())
			if err != nil {
				return valkey.AuthCredentials{}, err
			}
			// Re-authenticate well before both the token's 15-minute expiry
			// matters and ElastiCache's 12-hour IAM connection limit.
			return valkey.AuthCredentials{Username: cfg.IAMUser, Password: tok, RefreshAfter: time.Now().Add(10 * time.Minute)}, nil
		}
	}
	vk, err := valkey.NewClient(opt)
	if err != nil {
		return nil, fmt.Errorf("coord: connect %s: %w", cfg.Addr, err)
	}
	c := &Client{vk: vk, prefix: cfg.Prefix, errors: reg.CounterVec("relay_coord_errors_total", "Valkey operations that failed, by operation.", "op")}
	for _, op := range []string{"replay", "ratelimit", "publish", "subscribe", "ping", "hint"} {
		c.errors.With(op)
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.Ping(pctx); err != nil {
		vk.Close()
		return nil, fmt.Errorf("coord: ping %s: %w", cfg.Addr, err)
	}
	return c, nil
}

// Ping checks connectivity.
func (c *Client) Ping(ctx context.Context) error {
	return c.vk.Do(ctx, c.vk.B().Ping().Build()).Error()
}

// Close closes the connection.
func (c *Client) Close() { c.vk.Close() }

// key builds a namespaced key.
func (c *Client) key(parts ...string) string { return c.prefix + ":" + strings.Join(parts, ":") }

// iamToken builds an ElastiCache IAM auth token: a SigV4-presigned
// "connect" request, without its scheme.
func iamToken(ctx context.Context, cfg Config, now time.Time) (string, error) {
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{"Action": {"connect"}, "User": {cfg.IAMUser}}
	if cfg.Serverless {
		q.Set("ResourceType", "ServerlessCache")
	}
	q.Set("X-Amz-Expires", "900")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+strings.ToLower(cfg.CacheName)+"/?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	empty := sha256.Sum256(nil)
	signed, _, err := v4.NewSigner().PresignHTTP(ctx, creds, req, hex.EncodeToString(empty[:]), "elasticache", cfg.Region, now)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(signed, "http://"), nil
}
