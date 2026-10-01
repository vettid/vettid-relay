package metrics

import (
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	r.Counter("relay_deposits_total", "Deposits.").Add(3)
	g := r.Gauge("relay_parked", "Parked.")
	g.Inc()
	g.Inc()
	g.Dec()
	v := r.CounterVec("relay_errors_total", "Errors.", "code")
	v.With("token_invalid").Inc()
	v.With("rate_limited").Add(2)
	r.GaugeFunc("relay_fn", "Fn.", func() int64 { return 7 })
	var b strings.Builder
	r.WriteTo(&b)
	out := b.String()
	for _, want := range []string{
		"# TYPE relay_deposits_total counter\nrelay_deposits_total 3\n",
		"relay_parked 1\n",
		`relay_errors_total{code="rate_limited"} 2`,
		`relay_errors_total{code="token_invalid"} 1`,
		"relay_fn 7\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Re-registering returns the same series.
	r.Counter("relay_deposits_total", "Deposits.").Inc()
	b.Reset()
	r.WriteTo(&b)
	if !strings.Contains(b.String(), "relay_deposits_total 4\n") {
		t.Fatal("re-registration must share the series")
	}
}
