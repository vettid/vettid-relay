package api

import "sync"

// hub wakes parked collectors (long-poll and WebSocket) of a mailbox as soon
// as a deposit commits — no polling loop sits on the delivery path (spec
// §6.2 wake-on-deposit). It also caps concurrent collectors per mailbox.
type hub struct {
	mu    sync.Mutex
	boxes map[string]*hubEntry
	total int
}

type hubEntry struct {
	ch         chan struct{} // closed (and replaced) on deposit
	collectors int
}

func newHub() *hub { return &hub{boxes: map[string]*hubEntry{}} }

// acquire registers a collector for mailbox; false if max are already active.
func (h *hub) acquire(mailbox string, max int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.boxes[mailbox]
	if !ok {
		e = &hubEntry{ch: make(chan struct{})}
		h.boxes[mailbox] = e
	}
	if e.collectors >= max {
		return false
	}
	e.collectors++
	h.total++
	return true
}

// release unregisters a collector acquired with acquire.
func (h *hub) release(mailbox string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.boxes[mailbox]
	if !ok {
		return
	}
	e.collectors--
	h.total--
	if e.collectors <= 0 {
		delete(h.boxes, mailbox)
	}
}

// wait returns a channel that is closed by the next notify for mailbox.
// Callers must obtain it BEFORE checking the store, so a deposit that commits
// between the check and the park is never missed. Only valid while the
// caller holds a collector slot.
func (h *hub) wait(mailbox string) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.boxes[mailbox]; ok {
		return e.ch
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

// notify wakes every collector parked on mailbox.
func (h *hub) notify(mailbox string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.boxes[mailbox]; ok {
		close(e.ch)
		e.ch = make(chan struct{})
	}
}

// notifyAll wakes every parked collector (each re-checks the store).
func (h *hub) notifyAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.boxes {
		close(e.ch)
		e.ch = make(chan struct{})
	}
}

// collectors returns the number of active collectors across all mailboxes.
func (h *hub) collectors() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.total
}
