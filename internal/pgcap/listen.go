package pgcap

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Where a slice's cluster and the proxy sit in the slice, and the cluster's
// port. sliceAddrs is their one user.
const (
	clusterHost = 2
	proxyHost   = 4
	clusterPort = 5432
)

// sliceAddrs returns, for slice i of the table's block, the proxy's address on
// the slice's network (every dial's source) and the cluster's (its target).
// Nothing else computes either: routing is by the port a client connected to.
func sliceAddrs(t *Table, i int) (from netip.Addr, to netip.AddrPort) {
	b := t.ProjectBlock.Addr().As4()
	base := binary.BigEndian.Uint32(b[:]) + uint32(i)<<(32-t.SlicePrefix)
	return addr4(base + proxyHost), netip.AddrPortFrom(addr4(base+clusterHost), clusterPort)
}

func addr4(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, n)))
}

// member is a placed slice's place in one class: one listening socket.
type member struct {
	index int
	class string
}

// classState is what the proxy keeps per class across reloads.
type classState struct {
	c                      Class // the caps in force: a reload replaces them
	refusals               int   // places of the class's pool held
	peerConns, peerCancels map[netip.Addr]int
}

// slot is one member's listening socket, its context and its counters. It lives
// as long as the member is in the table.
type slot struct {
	m       member
	ln      net.Listener
	from    netip.Addr
	to      netip.AddrPort
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup // the accept loop and every socket it accepted
	streams StreamSlots
	// under proxy.mu
	allowance, conns, cancels int
	tokens                    float64
	last                      time.Time
}

// proxy is the running program: the table in use, one slot per member, and the
// node-wide and per-class counters.
type proxy struct {
	log     *logger
	mu      sync.Mutex
	tb      Table
	units   int // of the node-wide ceiling
	classes map[string]*classState
	slots   map[member]*slot
	seen    stamp // the version of the file in use; the watcher's own
}

// take spends one token of the slot's connection rate, refilled at the class's
// rate up to its burst.
func (s *slot) take(now time.Time, c Class) bool {
	s.tokens = min(float64(c.ConnsBurst), s.tokens+now.Sub(s.last).Seconds()*float64(c.ConnsPerSecond))
	s.last = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

// listen opens member m's listening socket at the class's port for the slice,
// with the class's socket buffers, which every accepted socket inherits.
func (p *proxy) listen(m member, c Class) (*slot, error) {
	ap := netip.AddrPortFrom(p.tb.Listen, uint16(c.PortBase+m.index))
	ln, err := (&net.ListenConfig{Control: socketBuffers(c.SockBufBytes)}).Listen(context.Background(), "tcp4", ap.String())
	if err != nil {
		return nil, err
	}
	s := &slot{m: m, ln: ln, tokens: float64(c.ConnsBurst), last: time.Now()}
	s.from, s.to = sliceAddrs(&p.tb, m.index)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s, nil
}

// serve accepts the slot's sockets until its listening socket is closed.
func (p *proxy) serve(s *slot) {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond) // out of descriptors: a pause, not a spin
			continue
		}
		p.accept(s, c.(*net.TCPConn), time.Now())
	}
}
