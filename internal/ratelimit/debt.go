package ratelimit

import (
	"sync"
	"time"
)

// Debt is a keyed budget that is only ever charged after the fact: Charge
// records one event (a failed authentication), Wait says whether the key has
// used its budget up and for how long. Unlike Limiter, a charge is never
// refused: events beyond the budget run up a debt that has to refill first,
// so the average rate of events a key gets away with stays at the refill
// rate however they are timed. The debt is capped (maxPenalty), so a key is
// never shut out for longer than that after its last event.
//
// Keys are client networks (an IPv4 address, an IPv6 /64); they are never
// logged by this package.
type Debt struct {
	per        time.Duration // refill time of one unit
	burst      int
	maxPenalty time.Duration
	maxKeys    int

	mu   sync.Mutex
	tat  map[string]time.Time // theoretical arrival time: when the budget is full again
	peak float64
}

// NewDebt returns a budget of burst events refilling at rate per second,
// whose debt never exceeds maxPenalty of waiting.
func NewDebt(rate float64, burst int, maxPenalty time.Duration, maxKeys int) *Debt {
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &Debt{per: time.Duration(float64(time.Second) / rate), burst: burst, maxPenalty: maxPenalty, maxKeys: maxKeys, tat: map[string]time.Time{}}
}

// allowance is how far ahead of now a key's arrival time may run while it
// still has one whole unit left.
func (d *Debt) allowance() time.Duration { return time.Duration(d.burst-1) * d.per }

// Charge records one event for key. It reports whether the key had its
// full budget before (its first event for a while). A key that goes
// untracked because the table is full is never reported as first: what
// cannot be remembered must not be charged to anyone else again and again.
func (d *Debt) Charge(key string, now time.Time) (first bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.tat[key]
	if !ok && len(d.tat) >= d.maxKeys {
		d.pruneLocked(now)
		if len(d.tat) >= d.maxKeys {
			return false // table full of live keys: this one goes untracked
		}
	}
	first = !t.After(now)
	if t.Before(now) {
		t = now
	}
	t = t.Add(d.per)
	if limit := now.Add(d.allowance() + d.maxPenalty); t.After(limit) {
		t = limit
	}
	d.tat[key] = t
	if used := float64(t.Sub(now)) / float64(time.Duration(d.burst)*d.per); used > d.peak {
		d.peak = min(used, 1)
	}
	return first
}

// Wait returns 0 while key has budget left, otherwise how long until one
// unit has refilled.
func (d *Debt) Wait(key string, now time.Time) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.tat[key]
	if !ok {
		return 0
	}
	if w := t.Sub(now) - d.allowance(); w > 0 {
		return w
	}
	return 0
}

// Exhausted returns the number of keys currently out of budget.
func (d *Debt) Exhausted(now time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, t := range d.tat {
		if t.Sub(now) > d.allowance() {
			n++
		}
	}
	return n
}

// Peak returns the highest fraction (0..1) of its budget any one key had
// used since the previous call, and resets it.
func (d *Debt) Peak() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.peak
	d.peak = 0
	return p
}

func (d *Debt) pruneLocked(now time.Time) {
	for k, t := range d.tat {
		if !t.After(now) {
			delete(d.tat, k)
		}
	}
}

// Prune drops keys whose budget is full again; run periodically.
func (d *Debt) Prune(now time.Time) {
	d.mu.Lock()
	d.pruneLocked(now)
	d.mu.Unlock()
}

// Len returns the number of tracked keys.
func (d *Debt) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.tat)
}

// Recent is a bounded set of strings that expire a fixed time after they
// were last added. The relay uses it to remember which keys authenticated
// from which client network lately.
type Recent struct {
	ttl time.Duration
	max int

	mu sync.Mutex
	m  map[string]time.Time // → expiry
}

// NewRecent returns a set whose entries live for ttl and which holds at
// most max of them.
func NewRecent(ttl time.Duration, max int) *Recent {
	return &Recent{ttl: ttl, max: max, m: map[string]time.Time{}}
}

// Add inserts or refreshes k. With fresh false only an entry that is
// already present is refreshed. A full set takes no new entries.
func (r *Recent) Add(k string, now time.Time, fresh bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.m[k]; !ok || !e.After(now) {
		if !fresh {
			return
		}
		if !ok && len(r.m) >= r.max {
			r.pruneLocked(now)
			if len(r.m) >= r.max {
				return
			}
		}
	}
	r.m[k] = now.Add(r.ttl)
}

// Has reports whether k is present and not expired.
func (r *Recent) Has(k string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.m[k]
	return ok && e.After(now)
}

// Remove deletes k.
func (r *Recent) Remove(k string) {
	r.mu.Lock()
	delete(r.m, k)
	r.mu.Unlock()
}

func (r *Recent) pruneLocked(now time.Time) {
	for k, e := range r.m {
		if !e.After(now) {
			delete(r.m, k)
		}
	}
}

// Prune drops expired entries; run periodically.
func (r *Recent) Prune(now time.Time) {
	r.mu.Lock()
	r.pruneLocked(now)
	r.mu.Unlock()
}

// Len returns the number of entries (expired ones not yet pruned included).
func (r *Recent) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// Hold is a bounded negative cache with a growing penalty: each Fail for a
// key holds it for twice as long as the one before (base, 2×base, … max),
// and Wait says how long a key is still held. The relay uses it for keys
// that sign correctly but turned out to have no mailbox: whoever keeps
// asking is answered from this table instead of from the store, less and
// less often. An entry is forgotten max after its hold ended.
type Hold struct {
	base, max time.Duration
	maxKeys   int

	mu sync.Mutex
	m  map[string]holdEntry
}

type holdEntry struct {
	until   time.Time
	streak  int
	checked time.Time // last Recheck
}

// NewHold returns a table holding at most maxKeys keys.
func NewHold(base, max time.Duration, maxKeys int) *Hold {
	return &Hold{base: base, max: max, maxKeys: maxKeys, m: map[string]holdEntry{}}
}

// Fail records one failure of key and holds it. It reports whether the key
// was new to the table: true once per key for as long as it keeps failing.
// If the table is full of live keys the key goes untracked: it is not
// held, and never reported as first (what cannot be remembered must not be
// charged to anyone else again and again).
func (h *Hold) Fail(key string, now time.Time) (first bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.m[key]
	if ok && now.After(e.until.Add(h.max)) {
		ok = false
	}
	if !ok {
		if _, present := h.m[key]; !present && len(h.m) >= h.maxKeys {
			h.pruneLocked(now)
			if len(h.m) >= h.maxKeys {
				return false
			}
		}
		e = holdEntry{}
	}
	e.streak++
	d := h.base
	for i := 1; i < e.streak && d < h.max; i++ {
		d *= 2
	}
	e.until = now.Add(min(d, h.max))
	h.m[key] = e
	return !ok
}

// Wait returns how long key is still held (0: not held).
func (h *Hold) Wait(key string, now time.Time) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.m[key]; ok && e.until.After(now) {
		return e.until.Sub(now)
	}
	return 0
}

// Recheck reports whether it is time to look again at whether a held key
// still deserves its hold: true at most once per `every` for each key.
func (h *Hold) Recheck(key string, now time.Time, every time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.m[key]
	if !ok || now.Sub(e.checked) < every {
		return false
	}
	e.checked = now
	h.m[key] = e
	return true
}

// Clear forgets key.
func (h *Hold) Clear(key string) {
	h.mu.Lock()
	delete(h.m, key)
	h.mu.Unlock()
}

func (h *Hold) pruneLocked(now time.Time) {
	for k, e := range h.m {
		if now.After(e.until.Add(h.max)) {
			delete(h.m, k)
		}
	}
}

// Prune drops forgotten keys; run periodically.
func (h *Hold) Prune(now time.Time) {
	h.mu.Lock()
	h.pruneLocked(now)
	h.mu.Unlock()
}

// Len returns the number of keys in the table.
func (h *Hold) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.m)
}
