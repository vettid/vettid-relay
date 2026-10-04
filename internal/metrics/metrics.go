// Package metrics is a tiny, dependency-free Prometheus text-format exporter.
//
// Only counters and gauges with at most one label are supported, which is all
// the relay needs. Label values are always from closed sets (error codes,
// route names, sweep kinds) — never ids, keys or payload-derived values.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds metric families.
type Registry struct {
	mu       sync.Mutex
	families map[string]*family
}

type family struct {
	name, help, typ, label string
	mu                     sync.Mutex
	series                 map[string]*atomic.Int64 // label value → value
	fn                     func() int64             // gauge func, if set
}

// New returns an empty registry.
func New() *Registry { return &Registry{families: map[string]*family{}} }

func (r *Registry) family(name, help, typ, label string) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.families[name]; ok {
		return f
	}
	f := &family{name: name, help: help, typ: typ, label: label, series: map[string]*atomic.Int64{}}
	r.families[name] = f
	return f
}

func (f *family) get(v string) *atomic.Int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.series[v]
	if !ok {
		c = new(atomic.Int64)
		f.series[v] = c
	}
	return c
}

// Counter is a monotonically increasing value.
type Counter struct{ v *atomic.Int64 }

// Inc adds one.
func (c Counter) Inc() { c.v.Add(1) }

// Add adds n (n ≥ 0).
func (c Counter) Add(n int64) { c.v.Add(n) }

// Value returns the current count.
func (c Counter) Value() int64 { return c.v.Load() }

// Gauge is a value that can go up and down.
type Gauge struct{ v *atomic.Int64 }

// Inc adds one.
func (g Gauge) Inc() { g.v.Add(1) }

// Dec subtracts one.
func (g Gauge) Dec() { g.v.Add(-1) }

// Value returns the current value.
func (g Gauge) Value() int64 { return g.v.Load() }

// Counter registers (or returns) an unlabelled counter.
func (r *Registry) Counter(name, help string) Counter {
	return Counter{r.family(name, help, "counter", "").get("")}
}

// Gauge registers (or returns) an unlabelled gauge.
func (r *Registry) Gauge(name, help string) Gauge {
	return Gauge{r.family(name, help, "gauge", "").get("")}
}

// GaugeFunc registers a gauge whose value is computed at scrape time.
func (r *Registry) GaugeFunc(name, help string, fn func() int64) {
	f := r.family(name, help, "gauge", "")
	f.fn = fn
}

// CounterVec is a counter family with one label.
type CounterVec struct{ f *family }

// CounterVec registers a counter family keyed by one label.
func (r *Registry) CounterVec(name, help, label string) CounterVec {
	return CounterVec{r.family(name, help, "counter", label)}
}

// With returns the counter for a label value (must come from a closed set).
func (v CounterVec) With(value string) Counter { return Counter{v.f.get(value)} }

// WriteTo writes all families in Prometheus text exposition format 0.0.4.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	names := make([]string, 0, len(r.families))
	for n := range r.families {
		names = append(names, n)
	}
	r.mu.Unlock()
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		r.mu.Lock()
		f := r.families[n]
		r.mu.Unlock()
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.typ)
		if f.fn != nil {
			fmt.Fprintf(&b, "%s %d\n", f.name, f.fn())
			continue
		}
		f.mu.Lock()
		vals := make([]string, 0, len(f.series))
		for v := range f.series {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		for _, v := range vals {
			if f.label == "" {
				fmt.Fprintf(&b, "%s %d\n", f.name, f.series[v].Load())
			} else {
				fmt.Fprintf(&b, "%s{%s=%q} %d\n", f.name, f.label, v, f.series[v].Load())
			}
		}
		f.mu.Unlock()
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// Handler serves the registry.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.WriteTo(w)
	})
}
