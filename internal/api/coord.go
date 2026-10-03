package api

import (
	"time"

	auth "github.com/vettid/vettid-relay/relayauth"
)

// The relay keeps three kinds of short-lived coordination state outside the
// store: the signature replay cache (§4.1), rate-limit buckets (§7.2) and
// wake-on-deposit signals (§6.2). One relay process keeps them in memory (the
// defaults). Several processes sharing one store must share them too, or a
// request replayed to another process would pass, limits would multiply by
// the process count, and a collector parked on one process would not wake
// for a deposit taken by another. internal/coord implements them on Valkey.

// ReplayGuard records a verified signed request and rejects a duplicate
// (auth.ErrReplay). auth.ErrReplayCacheFull means "cannot record right now":
// the request is shed with 429 rate_limited rather than admitted unchecked.
type ReplayGuard interface {
	Check(sr auth.SignedRequest, now time.Time) error
}

// RateLimiter is a keyed token bucket: Allow consumes one token, or reports
// how long until one is available.
type RateLimiter interface {
	Allow(key string, now time.Time) (bool, time.Duration)
}

// WakeBus carries wake-on-deposit signals between relay processes. Publish
// must not block on the network for long; a lost signal only delays
// delivery (collectors re-check the store on every wake-up, at the end of
// each long-poll and periodically on WebSockets), it never loses a message.
type WakeBus interface {
	Publish(mailbox string)
}

// WithReplayGuard replaces the in-memory replay cache.
func WithReplayGuard(g ReplayGuard) Option { return func(s *Server) { s.replay = g } }

// WithRateLimiters replaces the in-memory per-IP, per-sender and claim-GET
// limiters (nil keeps the default for that one).
func WithRateLimiters(ip, sender, claim RateLimiter) Option {
	return func(s *Server) {
		if ip != nil {
			s.ipLimit = ip
		}
		if sender != nil {
			s.subLimit = sender
		}
		if claim != nil {
			s.claimLimit = claim
		}
	}
}

// WithWakeBus publishes every deposit's mailbox to other relay processes.
// Signals they publish are delivered here through Server.Wake.
func WithWakeBus(b WakeBus) Option { return func(s *Server) { s.bus = b } }

// Wake wakes collectors parked on mailbox in this process (called for wake
// signals received from other processes).
func (s *Server) Wake(mailbox string) { s.hub.notify(mailbox) }

// WakeAll wakes every collector parked in this process so each re-checks the
// store. Called when cross-process signals may have been missed (the bus
// reconnected) and periodically while the bus is down.
func (s *Server) WakeAll() { s.hub.notifyAll() }

// notifyDeposit wakes local collectors immediately and tells other processes.
func (s *Server) notifyDeposit(mailbox string) {
	s.hub.notify(mailbox)
	if s.bus != nil {
		s.bus.Publish(mailbox)
	}
}
