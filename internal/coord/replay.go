package coord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"

	auth "github.com/vettid/vettid-relay/relayauth"
)

// ReplayGuard is the cross-process §4.1 replay cache.
type ReplayGuard struct {
	c       *Client
	timeout time.Duration
}

// ReplayGuard returns the shared replay cache.
func (c *Client) ReplayGuard() *ReplayGuard { return &ReplayGuard{c: c, timeout: time.Second} }

// Check records (key, signature) until its timestamp can no longer pass the
// freshness check; a second Check of the same pair in that time — on any
// process — returns auth.ErrReplay. Valkey errors return a wrapped
// auth.ErrReplayCacheFull so the request is shed, not admitted.
func (g *ReplayGuard) Check(sr auth.SignedRequest, now time.Time) error {
	h := sha256.New()
	h.Write(sr.Key)
	h.Write(sr.Sig)
	k := g.c.key("rp", hex.EncodeToString(h.Sum(nil)))
	ttl := sr.Time.Add(auth.FreshnessWindow + time.Second).Sub(now)
	if ttl < time.Second {
		ttl = time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	err := g.c.vk.Do(ctx, g.c.vk.B().Set().Key(k).Value("1").Nx().PxMilliseconds(ttl.Milliseconds()).Build()).Error()
	switch {
	case err == nil:
		return nil
	case valkey.IsValkeyNil(err): // NX refused: already recorded
		return auth.ErrReplay
	default:
		g.c.errors.With("replay").Inc()
		return fmt.Errorf("%w (valkey: %v)", auth.ErrReplayCacheFull, err)
	}
}
