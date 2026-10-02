// Package sweep runs the relay's periodic TTL sweeper: expired messages,
// blobs, denylist rows and token counters are deleted, stale leases are
// released and rotated mailboxes past their grace period are removed — one
// batched transaction per pass (store.Sweep).
package sweep

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/vettid/vettid-relay/internal/metrics"
	"github.com/vettid/vettid-relay/internal/store"
)

// Store is the subset of the store the sweeper needs.
type Store interface {
	Sweep(ctx context.Context) (store.SweepStats, error)
}

// Sweeper periodically calls Store.Sweep.
type Sweeper struct {
	st       Store
	interval time.Duration
	log      *slog.Logger

	runs    metrics.Counter
	errs    metrics.Counter
	deleted metrics.CounterVec
}

// New builds a sweeper running every interval.
func New(st Store, interval time.Duration, log *slog.Logger, reg *metrics.Registry) *Sweeper {
	s := &Sweeper{
		st: st, interval: interval, log: log,
		runs:    reg.Counter("relay_sweep_runs_total", "Sweeper passes completed."),
		errs:    reg.Counter("relay_sweep_errors_total", "Sweeper passes that failed."),
		deleted: reg.CounterVec("relay_sweep_removed_total", "Rows removed or released by the sweeper.", "kind"),
	}
	for _, k := range []string{"messages", "leases", "denylist", "blobs", "token_usage", "mailboxes", "consumed_tokens", "claims"} {
		s.deleted.With(k)
	}
	return s
}

// Run sweeps until ctx is cancelled. The first pass starts after a random
// delay in [0, interval) so restarts do not synchronise sweeps.
func (s *Sweeper) Run(ctx context.Context) {
	first := time.Duration(rand.Int64N(int64(s.interval)))
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.Once(ctx)
		t.Reset(s.interval)
	}
}

// Once performs a single sweep pass.
func (s *Sweeper) Once(ctx context.Context) {
	start := time.Now()
	st, err := s.st.Sweep(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.errs.Inc()
			s.log.Error("sweep failed", "err", err)
		}
		return
	}
	s.runs.Inc()
	s.deleted.With("messages").Add(st.Messages)
	s.deleted.With("leases").Add(st.Leases)
	s.deleted.With("denylist").Add(st.Denylist)
	s.deleted.With("blobs").Add(st.Blobs)
	s.deleted.With("token_usage").Add(st.TokenUsage)
	s.deleted.With("mailboxes").Add(st.Mailboxes)
	s.deleted.With("consumed_tokens").Add(st.ConsumedTokens)
	s.deleted.With("claims").Add(st.Claims)
	if st != (store.SweepStats{}) {
		s.log.Info("sweep", "messages", st.Messages, "leases", st.Leases, "denylist", st.Denylist,
			"blobs", st.Blobs, "token_usage", st.TokenUsage, "mailboxes", st.Mailboxes,
			"consumed_tokens", st.ConsumedTokens, "claims", st.Claims,
			"dur", time.Since(start))
	}
}
