package api

import "sync"

// hub wakes parked collectors (long-poll and WebSocket) of a mailbox as soon
// as a deposit commits — no polling loop sits on the delivery path (spec
// §6.2 wake-on-deposit). It also caps concurrent collectors per mailbox.
type hub struct {
	mu    sync.Mutex
	boxes map[string]*hubEntry
	total int
	nets  map[string]int // WebSocket sessions per client network
}

type hubEntry struct {
	ch         chan struct{} // closed (and replaced) on deposit
	gone       chan struct{} // closed (and replaced) when the mailbox is deleted
	collectors int
	sessions   int // of collectors: WebSocket sessions
}

func newHub() *hub { return &hub{boxes: map[string]*hubEntry{}, nets: map[string]int{}} }

// wsAdmission is the outcome of acquireWS.
type wsAdmission int

const (
	wsAdmitted       wsAdmission = iota
	wsMailboxFull                // the mailbox has its maximum of collectors
	wsNetworkFull                // the network has its maximum of sessions, and the mailbox already has one
	wsNetworkCeiling             // the network has as many sessions as any network may have
)

// acquireWS registers a WebSocket session for mailbox, opened from
// network. Like acquire it holds one of the mailbox's collector slots
// (max). It also counts the session against its network, which may hold
// netMax of them on this process, with one exception: a mailbox that has
// no WebSocket session here is always admitted. So whoever fills a
// network's allowance (a network is shared: a vault host, a carrier NAT)
// keeps nobody else behind that network from its first session, and what
// a network can hold beyond netMax is one session per mailbox. That
// exception ends at netCeiling, which no network passes: one network
// cannot take every session the process has.
func (h *hub) acquireWS(mailbox string, max int, network string, netMax, netCeiling int) wsAdmission {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.boxes[mailbox]
	switch {
	case ok && e.collectors >= max:
		return wsMailboxFull
	case h.nets[network] >= netCeiling:
		return wsNetworkCeiling
	case ok && e.sessions > 0 && h.nets[network] >= netMax:
		return wsNetworkFull
	case !ok:
		e = &hubEntry{ch: make(chan struct{}), gone: make(chan struct{})}
		h.boxes[mailbox] = e
	}
	e.collectors++
	e.sessions++
	h.total++
	h.nets[network]++
	return wsAdmitted
}

// releaseWS unregisters a session acquired with acquireWS.
func (h *hub) releaseWS(mailbox, network string) {
	h.mu.Lock()
	if e, ok := h.boxes[mailbox]; ok {
		e.sessions--
	}
	if h.nets[network]--; h.nets[network] <= 0 {
		delete(h.nets, network)
	}
	h.mu.Unlock()
	h.release(mailbox)
}

// acquire registers a collector for mailbox; false if max are already active.
func (h *hub) acquire(mailbox string, max int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.boxes[mailbox]
	if !ok {
		e = &hubEntry{ch: make(chan struct{}), gone: make(chan struct{})}
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

// goneCh returns a channel closed when mailbox is deleted. Only valid
// while the caller holds a collector slot; collectors take it right after
// acquire and then re-check the mailbox, so no deletion is missed.
func (h *hub) goneCh(mailbox string) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.boxes[mailbox]; ok {
		return e.gone
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

// kill ends every collector of a deleted mailbox. Collectors that register
// later (a new registration of the key) get a fresh channel.
func (h *hub) kill(mailbox string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok := h.boxes[mailbox]; ok {
		close(e.gone)
		e.gone = make(chan struct{})
	}
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
