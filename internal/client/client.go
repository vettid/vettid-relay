// Package client is a small reference client for the VettID relay protocol,
// used by relayctl and the integration tests. It shows the client side of
// docs/RELAY-PROTOCOL.md: signing requests, minting deposit tokens,
// long-poll/WebSocket collect, acks, revocation and blobs. See
// docs/CLIENT-NOTES.md for guidance on production clients.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/vettid/vettid-relay/internal/auth"
)

// Client talks to one relay as one principal (one relay keypair).
type Client struct {
	BaseURL     string             // e.g. https://relay.vettid.org (no trailing slash)
	Key         ed25519.PrivateKey // this principal's relay key
	HTTP        *http.Client
	Now         func() time.Time
	MaxAttempts int // attempts for 429/5xx/network errors (≥1); each retry is freshly signed
}

// New returns a client with sane defaults.
func New(baseURL string, key ed25519.PrivateKey) *Client {
	return &Client{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		Key:         key,
		HTTP:        &http.Client{Timeout: 60 * time.Second},
		Now:         time.Now,
		MaxAttempts: 3,
	}
}

// PublicKey returns the raw public key.
func (c *Client) PublicKey() ed25519.PublicKey { return c.Key.Public().(ed25519.PublicKey) }

// PublicKeyB64 returns the canonical base64 public key (token `sub`).
func (c *Client) PublicKeyB64() string { return auth.EncodeKey(c.PublicKey()) }

// MailboxID returns this principal's mailbox id.
func (c *Client) MailboxID() string { return auth.MailboxID(c.PublicKey()) }

// Error is a relay error response (spec §7.1).
type Error struct {
	Status     int
	Code       string `json:"code"`
	Message    string `json:"message"`
	RetryAfter int    `json:"retry_after"`
}

func (e *Error) Error() string { return fmt.Sprintf("relay: %d %s: %s", e.Status, e.Code, e.Message) }

// IsCode reports whether err is a relay error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

type request struct {
	method, path, query string
	body                []byte
	token               string
	contentType         string
}

// do sends a signed request, retrying 429/5xx/transport errors with
// exponential backoff + jitter and honouring retry_after (spec §7.2).
func (c *Client) do(ctx context.Context, r request) (*http.Response, error) {
	attempts := max(c.MaxAttempts, 1)
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			wait := backoff(i)
			var e *Error
			if errors.As(lastErr, &e) && e.RetryAfter > 0 {
				wait = time.Duration(e.RetryAfter)*time.Second + jitter(250*time.Millisecond)
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		resp, err := c.once(ctx, r)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		var e *Error
		if errors.As(err, &e) && e.Status != http.StatusTooManyRequests && e.Status < 500 {
			return nil, err // client errors are not retried
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func backoff(attempt int) time.Duration {
	d := 250 * time.Millisecond << min(attempt, 6)
	return d/2 + jitter(d/2)
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d)))
}

func (c *Client) once(ctx context.Context, r request) (*http.Response, error) {
	u := c.BaseURL + r.path
	if r.query != "" {
		u += "?" + r.query
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u, bytes.NewReader(r.body))
	if err != nil {
		return nil, err
	}
	if r.body == nil {
		req.Body, req.ContentLength = http.NoBody, 0
	}
	auth.SetHeaders(req.Header, c.Key, r.method, req.URL.EscapedPath(), c.Now(), auth.BodyHash(r.body))
	if r.token != "" {
		req.Header.Set("Authorization", "VettID-Deposit "+r.token)
	}
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	} else if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		e := &Error{Status: resp.StatusCode}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(b, e) != nil || e.Code == "" {
			e.Code, e.Message = "http_"+strconv.Itoa(resp.StatusCode), strings.TrimSpace(string(b))
		}
		return nil, e
	}
	return resp, nil
}

func (c *Client) doJSON(ctx context.Context, r request, out any) (int, error) {
	resp, err := c.do(ctx, r)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// Limits are the relay limits returned at registration (spec §6.1).
type Limits struct {
	MaxPayloadBytes          int64  `json:"max_payload_bytes"`
	MessageTTLSeconds        int64  `json:"message_ttl_seconds"`
	VisibilityTimeoutSeconds int64  `json:"visibility_timeout_seconds"`
	MaxBlobBytes             *int64 `json:"max_blob_bytes,omitempty"`
	BlobTTLSeconds           *int64 `json:"blob_ttl_seconds,omitempty"`
}

// Registration is the register response.
type Registration struct {
	MailboxID string `json:"mailbox_id"`
	Limits    Limits `json:"limits"`
	Created   bool   `json:"-"`
}

// Register registers (idempotently) this principal's mailbox.
func (c *Client) Register(ctx context.Context) (Registration, error) {
	body, _ := json.Marshal(map[string]string{"pubkey": c.PublicKeyB64()})
	var reg Registration
	status, err := c.doJSON(ctx, request{method: "POST", path: "/v1/register", body: body}, &reg)
	reg.Created = status == http.StatusCreated
	return reg, err
}

// TokenOptions shape a minted deposit token.
type TokenOptions struct {
	TTL   time.Duration // default 30 days (spec: ≤ 30 d standing, ≤ 5 min one-shot)
	JTI   string        // default: random ULID-like id
	Quota *auth.Quota
}

// MintToken issues a deposit token for sender (base64 pubkey) to deposit
// into this principal's mailbox on the relay at audience.
func (c *Client) MintToken(senderB64, audience string, o TokenOptions) (string, error) {
	if o.TTL <= 0 {
		o.TTL = 30 * 24 * time.Hour
	}
	if o.JTI == "" {
		o.JTI = randomID()
	}
	now := c.Now().UTC().Truncate(time.Second)
	return auth.MintToken(c.Key, auth.Claims{
		Iss: c.MailboxID(), Sub: senderB64, Aud: audience,
		Iat: now, Exp: now.Add(o.TTL), Jti: o.JTI, Scope: "deposit", Quota: o.Quota,
	})
}

func randomID() string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	b := make([]byte, 26)
	for i := range b {
		b[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(b)
}

// Deposit deposits payload into mailboxID using token. Note: a retried
// deposit whose first attempt actually succeeded yields a second message
// with a new msg_id — dedupe at the E2E layer too (CLIENT-NOTES.md).
func (c *Client) Deposit(ctx context.Context, mailboxID, token string, payload []byte) (string, error) {
	body, _ := json.Marshal(map[string][]byte{"payload": payload})
	var out struct {
		MsgID string `json:"msg_id"`
	}
	_, err := c.doJSON(ctx, request{method: "POST", path: "/v1/mailbox/" + mailboxID, body: body, token: token}, &out)
	return out.MsgID, err
}

// Message is a collected message.
type Message struct {
	MsgID       string `json:"msg_id"`
	DepositedAt string `json:"deposited_at"`
	Sender      string `json:"sender"` // base64 relay key that signed the deposit
	Payload     []byte `json:"payload"`
}

// Collect long-polls this principal's mailbox (wait ≤ 25 s, max ≤ 100).
func (c *Client) Collect(ctx context.Context, wait time.Duration, max int) ([]Message, error) {
	q := url.Values{}
	q.Set("wait", strconv.Itoa(int(wait/time.Second)))
	if max > 0 {
		q.Set("max", strconv.Itoa(max))
	}
	var out struct {
		Messages []Message `json:"messages"`
	}
	_, err := c.doJSON(ctx, request{method: "GET", path: "/v1/mailbox", query: q.Encode()}, &out)
	return out.Messages, err
}

// Ack deletes a collected message (idempotent).
func (c *Client) Ack(ctx context.Context, msgID string) error {
	_, err := c.doJSON(ctx, request{method: "DELETE", path: "/v1/mailbox/" + msgID}, nil)
	return err
}

// Revocation is one denylist entry.
type Revocation struct {
	Kind  string `json:"kind"` // "jti" or "sub"
	Value string `json:"value"`
}

// Revoke adds entries to this mailbox's denylist.
func (c *Client) Revoke(ctx context.Context, entries ...Revocation) error {
	body, _ := json.Marshal(map[string][]Revocation{"revoke": entries})
	_, err := c.doJSON(ctx, request{method: "POST", path: "/v1/mailbox/denylist", body: body}, nil)
	return err
}

// Rotate moves this mailbox to newKey and returns the new mailbox id. The
// client keeps using the old key until the caller swaps c.Key.
func (c *Client) Rotate(ctx context.Context, newKey ed25519.PrivateKey) (string, error) {
	proof := ed25519.Sign(newKey, []byte(c.MailboxID()))
	body, _ := json.Marshal(map[string]any{
		"new_pubkey":    auth.EncodeKey(newKey.Public().(ed25519.PublicKey)),
		"new_key_proof": proof,
	})
	var out struct {
		MailboxID string `json:"mailbox_id"`
	}
	_, err := c.doJSON(ctx, request{method: "POST", path: "/v1/mailbox/rotate", body: body}, &out)
	return out.MailboxID, err
}

// PutBlob uploads ciphertext to mailboxID (claim-check, spec §6.8).
func (c *Client) PutBlob(ctx context.Context, mailboxID, token string, ciphertext []byte) (blobID string, expires time.Time, err error) {
	var out struct {
		BlobID    string `json:"blob_id"`
		ExpiresAt string `json:"expires_at"`
	}
	_, err = c.doJSON(ctx, request{method: "PUT", path: "/v1/blob/" + mailboxID, body: ciphertext,
		token: token, contentType: "application/octet-stream"}, &out)
	if err != nil {
		return "", time.Time{}, err
	}
	expires, _ = time.Parse(time.RFC3339, out.ExpiresAt)
	return out.BlobID, expires, nil
}

// GetBlob fetches a blob deposited to this principal's mailbox.
func (c *Client) GetBlob(ctx context.Context, blobID string) ([]byte, error) {
	resp, err := c.do(ctx, request{method: "GET", path: "/v1/blob/" + blobID})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// DeleteBlob deletes a blob (idempotent).
func (c *Client) DeleteBlob(ctx context.Context, blobID string) error {
	_, err := c.doJSON(ctx, request{method: "DELETE", path: "/v1/blob/" + blobID}, nil)
	return err
}

// Stream is an open WebSocket collect session (spec §6.4).
type Stream struct{ conn *websocket.Conn }

// OpenStream opens a WebSocket collect session (owner-signed at upgrade).
func (c *Client) OpenStream(ctx context.Context) (*Stream, error) {
	const path = "/v1/mailbox/ws"
	h := http.Header{}
	auth.SetHeaders(h, c.Key, "GET", path, c.Now(), auth.BodyHash(nil))
	u := c.BaseURL + path
	switch {
	case strings.HasPrefix(u, "https://"):
		u = "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		u = "ws://" + strings.TrimPrefix(u, "http://")
	}
	conn, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: h, HTTPClient: c.HTTP})
	if err != nil {
		if resp != nil {
			return nil, &Error{Status: resp.StatusCode, Code: "http_" + strconv.Itoa(resp.StatusCode), Message: err.Error()}
		}
		return nil, err
	}
	conn.SetReadLimit(1 << 20)
	return &Stream{conn: conn}, nil
}

// Next blocks for the next pushed message.
func (s *Stream) Next(ctx context.Context) (Message, error) {
	_, data, err := s.conn.Read(ctx)
	if err != nil {
		return Message{}, err
	}
	var m Message
	return m, json.Unmarshal(data, &m)
}

// Ack acknowledges a message over the socket.
func (s *Stream) Ack(ctx context.Context, msgID string) error {
	b, _ := json.Marshal(map[string]string{"ack": msgID})
	return s.conn.Write(ctx, websocket.MessageText, b)
}

// Close closes the session.
func (s *Stream) Close() error { return s.conn.Close(websocket.StatusNormalClosure, "") }
