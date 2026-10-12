package api

import "sync"

// hub wakes parked collectors (long-poll and WebSocket) of a mailbox as soon
// as a deposit commits — no polling loop sits on the delivery path (spec
// §6.2 wake-on-deposit). It also caps concurrent collectors per mailbox.
type hub struct {
	mu     sync.Mutex
	boxes  map[string]*hubEntry
	perNet map[string]int // collectors per client network
	total  int
}

type hubEntry struct {
	ch         chan struct{} // closed (and replaced) on deposit
	gone       chan struct{} // closed (and replaced) when the mailbox is deleted
	collectors int
}

func newHub() *hub { return &hub{boxes: map[string]*hubEntry{}, perNet: map[string]int{}} }

// Why a collector was not admitted.
const (
	fullMailbox = "mailbox" // the mailbox has its maximum of collectors
	fullNetwork = "network" // its client network has
	fullProcess = "process" // this process has
)

// acquire registers a collector for mailbox, from client network net. It
// returns "" or which cap was reached: collectors per mailbox, per network,
// or in this process altogether (each parked collector holds a connection
// and a goroutine: the caps bound that memory).
func (h *hub) acquire(mailbox, net string, maxMailbox, maxNet, maxTotal int) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.total >= maxTotal {
		return fullProcess
	}
	if net != "" && h.perNet[net] >= maxNet {
		return fullNetwork
	}
	e, ok := h.boxes[mailbox]
	if ok && e.collectors >= maxMailbox {
		return fullMailbox
	}
	if !ok {
		e = &hubEntry{ch: make(chan struct{}), gone: make(chan struct{})}
		h.boxes[mailbox] = e
	}
	e.collectors++
	h.total++
	if net != "" {
		h.perNet[net]++
	}
	return ""
}

// release unregisters a collector acquired with acquire.
func (h *hub) release(mailbox, net string) {
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
	if net != "" {
		if h.perNet[net]--; h.perNet[net] <= 0 {
			delete(h.perNet, net)
		}
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
