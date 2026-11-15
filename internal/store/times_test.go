package store

import (
	"testing"
	"time"
)

// The tombstone's not-before is the removal plus the margin, rounded up to
// the whole second: what registration reports (§6.1) is what is stored.
func TestTombstoneTimesWholeSecond(t *testing.T) {
	p := TombstonePolicy{Margin: 90 * time.Second, Retention: time.Hour}
	base := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	for _, frac := range []time.Duration{0, time.Nanosecond, 500 * time.Microsecond, 999 * time.Millisecond} {
		nb, keep := p.Times(base.Add(frac))
		want := base.Add(90 * time.Second)
		if frac > 0 {
			want = want.Add(time.Second)
		}
		if !nb.Equal(want) || !keep.Equal(want.Add(time.Hour)) {
			t.Errorf("at +%s: not-before %v keep %v, want %v", frac, nb, keep, want)
		}
	}
}
