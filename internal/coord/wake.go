package coord

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/vettid/vettid-relay/internal/metrics"
)

// Waker is what the bus wakes in this process (api.Server implements it).
type Waker interface {
	Wake(mailbox string)
	WakeAll()
	// MailboxGone is called for a mailbox another process deleted.
	MailboxGone(mailbox string)
}

// goneSuffix marks a deletion signal: "<process>|<mailbox>|gone". A
// process from before protocol 0.5.0 reads it as a wake for a mailbox id
// that does not exist, which is harmless (rolling deploys).

// WakeBus carries wake-on-deposit signals between relay processes on one
// sharded pub/sub channel. Every process receives every signal and wakes the
// collectors it holds for that mailbox (if any); a process ignores its own
// signals (it already woke them locally).
//
// Volume: one small message (process id + 26-char mailbox id) per deposit
// per process — at 1,000 deposits/s and 6 processes, 6,000 deliveries/s of
// ~60 bytes, well within one Valkey shard.
type WakeBus struct {
	c       *Client
	channel string
	self    string // this process's id
	w       Waker

	out    chan string
	up     atomic.Bool
	cancel context.CancelFunc
	wg     sync.WaitGroup

	published, received, dropped metrics.Counter

	// DegradedInterval: while Valkey is unreachable, wake every local
	// collector this often so deposits taken by other processes are still
	// picked up (each wake costs one store query per collector).
	DegradedInterval time.Duration
}

// NewWakeBus creates the bus; call Start once the Waker exists.
func (c *Client) NewWakeBus(reg *metrics.Registry) *WakeBus {
	id := make([]byte, 8)
	rand.Read(id)
	b := &WakeBus{
		c: c, channel: c.key("wake"), self: hex.EncodeToString(id),
		out:              make(chan string, 4096),
		published:        reg.Counter("relay_wake_published_total", "Wake-on-deposit signals published to other relay processes."),
		received:         reg.Counter("relay_wake_received_total", "Wake-on-deposit signals received from other relay processes."),
		dropped:          reg.Counter("relay_wake_dropped_total", "Wake-on-deposit signals not published (queue full or Valkey error)."),
		DegradedInterval: 5 * time.Second,
	}
	reg.GaugeFunc("relay_wake_bus_up", "1 while subscribed to cross-process wake signals.", func() int64 {
		if b.up.Load() {
			return 1
		}
		return 0
	})
	return b
}

// Publish implements api.WakeBus. It never blocks: signals are queued and
// sent in order by a background goroutine; when the queue is full the
// signal is dropped (counted) and collectors find the message on their next
// re-check.
func (b *WakeBus) Publish(mailbox string) {
	select {
	case b.out <- mailbox:
	default:
		b.dropped.Inc()
	}
}

// PublishGone implements api.GoneBus: other processes drop the mailbox
// from their caches and end its parked collectors. Never blocks; a dropped
// signal is counted.
func (b *WakeBus) PublishGone(mailbox string) { b.Publish(mailbox + goneSuffix) }

const goneSuffix = "|gone"

// Start subscribes and starts publishing; it returns once the first
// subscription is confirmed or ctx ends (the bus keeps retrying either way).
func (b *WakeBus) Start(ctx context.Context, w Waker) {
	b.w = w
	runCtx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	subscribed := make(chan struct{})
	var once sync.Once
	b.wg.Add(3)
	go func() { defer b.wg.Done(); b.subscribeLoop(runCtx, func() { once.Do(func() { close(subscribed) }) }) }()
	go func() { defer b.wg.Done(); b.publishLoop(runCtx) }()
	go func() { defer b.wg.Done(); b.healthLoop(runCtx) }()
	select {
	case <-subscribed:
	case <-ctx.Done():
	}
}

// Stop stops the bus (after the HTTP server has drained).
func (b *WakeBus) Stop() {
	if b.cancel != nil {
		b.cancel()
		b.wg.Wait()
	}
}

func (b *WakeBus) subscribeLoop(ctx context.Context, first func()) {
	hctx := valkey.WithOnSubscriptionHook(ctx, func(s valkey.PubSubSubscription) {
		if s.Kind == "ssubscribe" {
			b.up.Store(true)
			first()
			// (Re)subscribed: signals sent while we were not may be lost,
			// so every local collector re-checks the store once.
			go b.w.WakeAll()
		}
	})
	for attempt := 0; ctx.Err() == nil; attempt++ {
		err := b.c.vk.Receive(hctx, b.c.vk.B().Ssubscribe().Channel(b.channel).Build(), func(m valkey.PubSubMessage) {
			from, mailbox, ok := strings.Cut(m.Message, "|")
			if !ok || from == b.self || mailbox == "" {
				return
			}
			b.received.Inc()
			if id, gone := strings.CutSuffix(mailbox, goneSuffix); gone {
				b.w.MailboxGone(id)
				return
			}
			b.w.Wake(mailbox)
		})
		b.up.Store(false)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			b.c.errors.With("subscribe").Inc()
		}
		t := time.NewTimer(min(time.Duration(attempt+1)*200*time.Millisecond, 5*time.Second))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func (b *WakeBus) publishLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case mb := <-b.out:
			pctx, cancel := context.WithTimeout(ctx, time.Second)
			err := b.c.vk.Do(pctx, b.c.vk.B().Spublish().Channel(b.channel).Message(b.self+"|"+mb).Build()).Error()
			cancel()
			if err != nil {
				b.dropped.Inc()
				b.c.errors.With("publish").Inc()
				continue
			}
			b.published.Inc()
		}
	}
}

// healthLoop pings Valkey; while it is unreachable, local collectors are
// woken every DegradedInterval so cross-process deposits are not missed for
// a whole long-poll.
func (b *WakeBus) healthLoop(ctx context.Context) {
	t := time.NewTicker(b.DegradedInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, time.Second)
		err := b.c.Ping(pctx)
		cancel()
		if err != nil || !b.up.Load() {
			if err != nil {
				b.c.errors.With("ping").Inc()
			}
			b.w.WakeAll()
		}
	}
}
