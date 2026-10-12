package api

import "sync"

// hub wakes parked collectors (long-poll and WebSocket) of a mailbox as soon
// as a deposit commits — no polling loop sits on the delivery path (spec
// §6.2 wake-on-deposit). It also bounds how many collectors are parked
// (each holds a connection and a goroutine), in a way that nobody can use
// to shut a mailbox out (spec §7.2 item 8):
//
//   - a collect that does not park (wait=0) is never refused by a cap on
//     parked collectors;
//   - a mailbox's first collector is always admitted. If the process is
//     full, room is made by shedding one collector of the network that
//     holds the most (it gets an empty answer and comes back), unless that
//     network is the newcomer's own;
//   - the process cap refuses only a mailbox's second and later
//     collectors, and newcomers of the heaviest network.
type hub struct {
	mu    sync.Mutex
	boxes map[string]*hubEntry
	nets  map[string]map[*collector]struct{} // parked collectors per client network
	total int                                // parked collectors counted against the process cap
}

type hubEntry struct {
	ch         chan struct{} // closed (and replaced) on deposit
	gone       chan struct{} // closed (and replaced) when the mailbox is deleted
	collectors int
}

// collector is one admitted collect or WebSocket session.
type collector struct {
	net     string
	shed    chan struct{} // closed when the collector has to give its place up
	counted bool          // in nets and total
}

func newHub() *hub {
	return &hub{boxes: map[string]*hubEntry{}, nets: map[string]map[*collector]struct{}{}}
}

// Why a collector was not admitted.
const (
	fullMailbox = "mailbox" // the mailbox has its maximum of collectors
	fullNetwork = "network" // its client network has
	fullProcess = "process" // this process has
)

// acquire registers a collector for mailbox, from client network net;
// parked says whether it may wait (a long-poll with wait>0, a WebSocket).
// It returns the collector, or which cap refused it.
func (h *hub) acquire(mailbox, net string, parked bool, maxMailbox, maxNet, maxTotal int) (*collector, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.boxes[mailbox]
	if ok && e.collectors >= maxMailbox {
		return nil, fullMailbox
	}
	c := &collector{net: net, shed: make(chan struct{})}
	if parked {
		if len(h.nets[net]) >= maxNet {
			return nil, fullNetwork
		}
		if h.total >= maxTotal {
			heavy, n := "", 0
			for name, set := range h.nets {
				if len(set) > n {
					heavy, n = name, len(set)
				}
			}
			// Only a mailbox's first collector is worth someone else's
			// place, and never the place of a network no heavier than
			// the newcomer's own.
			if (ok && e.collectors > 0) || n <= len(h.nets[net])+1 {
				return nil, fullProcess
			}
			for victim := range h.nets[heavy] {
				h.uncount(victim)
				close(victim.shed)
				break
			}
		}
		if h.nets[net] == nil {
			h.nets[net] = map[*collector]struct{}{}
		}
		h.nets[net][c] = struct{}{}
		h.total++
		c.counted = true
	}
	if !ok {
		e = &hubEntry{ch: make(chan struct{}), gone: make(chan struct{})}
		h.boxes[mailbox] = e
	}
	e.collectors++
	return c, ""
}

func (h *hub) uncount(c *collector) {
	if !c.counted {
		return
	}
	c.counted = false
	h.total--
	if set := h.nets[c.net]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(h.nets, c.net)
		}
	}
}

// release unregisters a collector acquired with acquire.
func (h *hub) release(mailbox string, c *collector) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.uncount(c)
	e, ok := h.boxes[mailbox]
	if !ok {
		return
	}
	e.collectors--
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
