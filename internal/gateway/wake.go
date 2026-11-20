package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/wakesock"
)

// Bounds of the wake (see waker).
const (
	maxWakes      = 4                // wakes in flight on the node
	maxAsks       = 6                // wake requests a minute per (source, ref)
	askWindow     = time.Minute      //
	idleEvery     = 30 * time.Second // idle reports
	activePolling = 25 * time.Millisecond
)

// waker asks the daemon, over the wake socket, to wake asleep projects, and
// reports the idle ones. The zero value is ready and asks for nothing until
// SetWake gives it a client; without the socket file nothing is sent.
//
// A wake is asked by a request that passed every check before the proxy.
// Requests for a ref whose wake is in flight wait on that one, at most the
// project's in-flight cap of them (the asker included), so at most
// 4 × 128 requests are held on the gateway; at most four wakes are in
// flight; a source (an IPv6 /64 is one) asks at most six wakes a minute
// per ref. A wake that failed or ran out of the hold backs
// the ref off: for wakesock.Backoff its requests are answered at once. Every
// refusal is 503 project_restarting, the answer of a draining project.
type waker struct {
	c     *wakesock.Client
	bound time.Duration    // the hold; 0: wakesock.WakeBound
	now   func() time.Time // the back-off's and the window's clock; nil: time.Now

	mu        sync.Mutex
	flights   map[string]*flight
	backoff   map[string]time.Time // ref → end of its back-off
	asks      map[askKey][]time.Time
	sweep     int                  // asks' size at which a new key sweeps it next
	last      map[string]time.Time // ref → its last request
	wasActive map[string]bool      // the refs active at the last idle report
	holding   map[string]int       // requests in awake per ref, until they leave it
}

type askKey struct {
	src netip.Prefix
	ref string
}

type flight struct {
	done   chan struct{}
	err    error // set before done is closed
	joined int   // requests waiting on it besides the one that asked
}

// SetWake gives the gateway the wake socket's client; call it before serving.
func (g *Gateway) SetWake(c *wakesock.Client) {
	g.wake.c = c
}

func (k *waker) clock() time.Time {
	if k.now != nil {
		return k.now()
	}
	return time.Now()
}

func (k *waker) hold() time.Duration {
	if k.bound > 0 {
		return k.bound
	}
	return wakesock.WakeBound
}

// awake is the request's last check before the in-flight caps. An entry that
// is not asleep is noted as busy and passes; for an asleep one the request
// asks for a wake or joins the one in flight, and waits at most the hold for
// it to succeed and for the table to show the project active. It returns the
// entry to forward to, or false once it has answered.
func (g *Gateway) awake(w http.ResponseWriter, r *http.Request, ref string, p *project) (*project, bool) {
	k := &g.wake
	if !p.asleep {
		k.mu.Lock()
		if k.last == nil {
			k.last = map[string]time.Time{}
		}
		k.last[ref] = k.clock()
		k.mu.Unlock()
		return p, true
	}
	ctx, cancel := context.WithTimeout(r.Context(), k.hold())
	defer cancel()
	f, ask := k.join(ref, r.RemoteAddr, g.projectCap)
	if f == nil {
		fail(w, http.StatusServiceUnavailable, "project_restarting")
		return nil, false
	}
	defer k.leave(ref)
	if ask {
		k.run(ref, f)
	}
	select {
	case <-f.done:
	case <-ctx.Done():
	}
	if ctx.Err() != nil || f.err != nil {
		fail(w, http.StatusServiceUnavailable, "project_restarting")
		return nil, false
	}
	tick := time.NewTicker(activePolling)
	defer tick.Stop()
	for {
		if tb := g.table.cur.Load(); tb != nil {
			if np := tb.projects[ref]; np != nil && !np.asleep && !np.draining && !np.stopped {
				return g.awake(w, r, ref, np) // noted as busy
			}
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			fail(w, http.StatusServiceUnavailable, "project_restarting")
			return nil, false
		}
	}
}

// join returns the flight a request for ref waits on, and whether it must
// ask for it itself; nil when the back-off or a wake limit refuses it. held
// is the most requests one flight holds, its asker included.
func (k *waker) join(ref, remote string, held int) (*flight, bool) {
	if k.c == nil {
		return nil, false
	}
	now := k.clock()
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.asks == nil {
		k.flights, k.backoff, k.asks, k.holding = map[string]*flight{}, map[string]time.Time{}, map[askKey][]time.Time{}, map[string]int{}
	}
	if until, ok := k.backoff[ref]; ok {
		if now.Before(until) {
			return nil, false
		}
		delete(k.backoff, ref)
	}
	if k.holding[ref] >= held {
		return nil, false
	}
	if f := k.flights[ref]; f != nil {
		f.joined++
		k.holding[ref]++
		return f, false
	}
	if len(k.flights) >= maxWakes || len(k.holding) >= maxWakes && k.holding[ref] == 0 {
		return nil, false
	}
	// Only a request that asks for a wake spends one of its source's six.
	ap, _ := netip.ParseAddrPort(remote) // unparsable: one shared zero source
	key := askKey{source(ap.Addr()), ref}
	stamps := k.asks[key]
	for len(stamps) > 0 && now.Sub(stamps[0]) >= askWindow {
		stamps = stamps[1:]
	}
	if len(stamps) >= maxAsks {
		return nil, false
	}
	if stamps == nil && len(k.asks) >= k.sweep { // a new key: drop the expired ones
		for kk, s := range k.asks {
			if now.Sub(s[len(s)-1]) >= askWindow {
				delete(k.asks, kk)
			}
		}
		k.sweep = 2 * len(k.asks)
	}
	k.asks[key] = append(stamps, now)
	f := &flight{done: make(chan struct{})}
	k.flights[ref] = f
	k.holding[ref]++
	return f, true
}

// run asks for ref's wake, bounded by the hold whatever the asking request
// does, and ends its flight.
func (k *waker) run(ref string, f *flight) {
	ctx, cancel := context.WithTimeout(context.Background(), k.hold())
	err := k.c.Wake(ctx, ref)
	cancel()
	k.mu.Lock()
	delete(k.flights, ref)
	if errors.Is(err, wakesock.ErrFailed) || errors.Is(err, context.DeadlineExceeded) {
		k.backoff[ref] = k.clock().Add(wakesock.Backoff)
	}
	f.err = err
	k.mu.Unlock()
	close(f.done)
}

// ReportIdle reports the idle projects every 30 s until ctx ends.
func (g *Gateway) ReportIdle(ctx context.Context) {
	tick := time.NewTicker(idleEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		g.reportIdle(ctx)
	}
}

// reportIdle sends Idle with the refs that are active, have no request in
// flight and had none for the table's idle_stop_s, and forgets what it keeps
// of refs no longer in the table.
func (g *Gateway) reportIdle(ctx context.Context) {
	k := &g.wake
	tb := g.table.cur.Load()
	if tb == nil || k.c == nil {
		return
	}
	now := k.clock()
	var idle []string
	g.mu.Lock()
	k.mu.Lock()
	for ref := range k.last {
		if tb.projects[ref] == nil {
			delete(k.last, ref)
		}
	}
	for ref, until := range k.backoff {
		if tb.projects[ref] == nil || !now.Before(until) {
			delete(k.backoff, ref)
		}
	}
	if k.last == nil {
		k.last = map[string]time.Time{}
	}
	active := make(map[string]bool, len(tb.projects))
	for ref, p := range tb.projects {
		if p.asleep || p.draining || p.stopped {
			continue
		}
		active[ref] = true
		if !k.wasActive[ref] { // new, started or woken since the last report: quiet from now
			k.last[ref] = now
			continue
		}
		if tb.idleStop > 0 && g.byProject[ref] == 0 && now.Sub(k.last[ref]) >= time.Duration(tb.idleStop)*time.Second {
			idle = append(idle, ref)
		}
	}
	k.wasActive = active
	k.mu.Unlock()
	g.mu.Unlock()
	slices.Sort(idle)
	for c := range slices.Chunk(idle, wakesock.MaxIdleRefs) {
		k.c.Idle(ctx, c) // a report that fails is sent again next round
	}
}

// leave ends a request's hold.
func (k *waker) leave(ref string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.holding[ref]--; k.holding[ref] <= 0 {
		delete(k.holding, ref)
	}
}
