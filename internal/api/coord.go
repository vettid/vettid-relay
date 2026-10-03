package api

import (
	"context"
	"time"

	"github.com/vettid/vettid-relay/internal/store"

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

// EmptyHints lets collectors skip the store query for mailboxes known to be
// empty (internal/coord.EmptyHints documents the invariant). The API keeps
// its side of the contract: Bump after every committed deposit and before
// its wake signal; register for wake-ups before Check; MarkEmpty only with
// the version Check returned before the store query; force a real query
// after any WakeAll.
type EmptyHints interface {
	Bump(ctx context.Context, mailbox string) error
	Check(ctx context.Context, mailbox string) (version string, emptyFor time.Duration, err error)
	MarkEmpty(ctx context.Context, mailbox, version string, validFor time.Duration)
	Clear(ctx context.Context, mailbox string)
}

// WithEmptyHints enables skipping store queries for known-empty mailboxes.
func WithEmptyHints(h EmptyHints) Option { return func(s *Server) { s.hints = h } }

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
func (s *Server) WakeAll() {
	s.forceGen.Add(1) // every woken collector queries the store for real
	s.hub.notifyAll()
}

// notifyDeposit records a committed deposit for the empty hints, then wakes
// local collectors immediately and tells other processes (in that order: a
// woken collector must see the new version).
func (s *Server) notifyDeposit(ctx context.Context, mailbox string) {
	if s.hints != nil {
		if err := s.hints.Bump(context.WithoutCancel(ctx), mailbox); err != nil {
			s.log.Warn("empty-hint bump failed; collectors may skip this deposit until their hint expires", "err", err)
		}
	}
	s.hub.notify(mailbox)
	if s.bus != nil {
		s.bus.Publish(mailbox)
	}
}

// collectOnce is one collect attempt for a registered collector (it must
// have obtained its hub wait channel first). Unless force is set, a mailbox
// the hints know to be empty is not queried: it returns no messages and the
// time at which the hint expires, so the caller re-checks then. Otherwise it
// queries the store and updates the hint.
func (s *Server) collectOnce(ctx context.Context, mailbox string, max int, force bool) ([]store.Message, time.Time, error) {
	version, haveVersion := "", false
	if s.hints != nil {
		v, emptyFor, err := s.hints.Check(ctx, mailbox)
		if err == nil {
			if emptyFor > 0 && !force {
				s.m.storeSkips.Inc()
				return nil, s.now().Add(emptyFor), nil
			}
			version, haveVersion = v, true
		}
	}
	s.m.storeQueries.Inc()
	msgs, next, err := s.st.Collect(ctx, mailbox, max, s.cfg.VisibilityTimeout)
	if err != nil || !haveVersion {
		return msgs, next, err
	}
	switch {
	case len(msgs) > 0:
		s.hints.Clear(ctx, mailbox)
	case next.IsZero():
		s.hints.MarkEmpty(ctx, mailbox, version, s.cfg.EmptySkipMax)
	default: // trust the finding only until a leased message can reappear
		s.hints.MarkEmpty(ctx, mailbox, version, next.Sub(s.now()))
	}
	return msgs, next, nil
}
