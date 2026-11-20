package pgcap

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/Amphoze/supapace/internal/pgwire"
)

// peerCheck is the check of a socket's two addresses; a test build with the tag
// nopeer turns it off.
var peerCheck = true

// requestFamily is the high half of every request code that is not a protocol
// version: the encryption requests' and the cancel's.
const requestFamily = 1234

// accept decides, before anything is read, whether socket c accepted on s's
// listening socket is kept: its two addresses, the node-wide ceiling and the
// pool of its class's refusals in flight. A kept socket holds a unit of the
// ceiling until it is closed, and a place of the pool until it is admitted as a
// connection or a cancel, or closed: every unit belongs to one of the terms.
func (p *proxy) accept(s *slot, c *net.TCPConn, at time.Time) {
	remote, local := addrOf(c.RemoteAddr()), addrOf(c.LocalAddr())
	p.mu.Lock()
	cs := p.classes[s.m.class]
	preamble := ms(p.tb.PreambleMS)
	var why string
	switch {
	case peerCheck && (local != p.tb.Listen || !slices.Contains(cs.c.Peers, remote)):
		why = "not a peer of the class" // holds nothing
	case p.units >= p.tb.MaxConns:
		why = "node-wide ceiling reached"
	case cs.refusals >= cs.c.RefusalsMax:
		why = "the class's refusals in flight at their cap"
	default:
		p.units++
		cs.refusals++
	}
	p.mu.Unlock()
	if why != "" {
		c.Close()
		p.log.conn(s.m, why)
		return
	}
	s.wg.Add(1)
	go p.handle(s, c, remote, at, at.Add(preamble))
}

func addrOf(a net.Addr) netip.Addr {
	ap, _ := netip.ParseAddrPort(a.String())
	return ap.Addr()
}

// conn is one socket from its classification on: what it holds, released when
// it ends.
type conn struct {
	p      *proxy
	s      *slot
	c      *net.TCPConn
	peer   netip.Addr
	placed bool // holds a place of the class's pool
}

// handle reads the socket's first eight bytes under the preamble deadline and
// acts on them: an encryption request is declined, a cancel forwarded, a
// request code in another form closed unanswered, and anything else is a
// startup, relayed or refused. Closing the slice closes the socket.
func (p *proxy) handle(s *slot, c *net.TCPConn, peer netip.Addr, at, deadline time.Time) {
	k := &conn{p: p, s: s, c: c, peer: peer, placed: true}
	defer s.wg.Done()
	defer func() {
		p.mu.Lock()
		p.units--
		if k.placed {
			p.classes[s.m.class].refusals--
		}
		p.mu.Unlock()
	}()
	relayed := false
	defer func() {
		if f := recover(); f != nil {
			p.log.conn(s.m, fmt.Sprintf("fault: %v", f))
		}
		if !relayed {
			c.Close()
		}
	}()
	stop := afterFunc(s, c)
	defer stop() // whatever the socket's end: nothing stays registered with the slice's context
	c.SetDeadline(deadline)
	var first [8]byte
	var tls, gss bool
	for {
		if _, err := io.ReadFull(c, first[:]); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				p.log.conn(s.m, "preamble deadline")
			}
			return
		}
		t, g := pgwire.EncryptionRequest(first[:])
		if !t && !g {
			break
		}
		if t && tls || g && gss {
			p.log.conn(s.m, "encryption requested twice")
			return
		}
		tls, gss = tls || t, gss || g
		if _, err := c.Write([]byte{'N'}); err != nil {
			return
		}
	}
	switch {
	case pgwire.CancelRequest(first[:]):
		k.cancel(first)
	case binary.BigEndian.Uint32(first[4:])>>16 == requestFamily:
		p.log.conn(s.m, "a request code in another form")
	default:
		relayed = k.startup(first, at)
	}
}

// afterFunc closes c when the slot's context ends; the returned function stops
// that, and tells whether it had not happened.
func afterFunc(s *slot, c net.Conn) func() bool {
	return context.AfterFunc(s.ctx, func() { c.Close() })
}

// startup admits a startup packet against the slice's allowance, the peer's cap
// and the slice's rate, and relays it; otherwise it answers the refusal a
// client can read. It tells whether the socket went to Relay, which closes it.
func (k *conn) startup(first [8]byte, at time.Time) bool {
	p, s := k.p, k.s
	p.mu.Lock()
	cs := p.classes[s.m.class]
	c := cs.c
	var why string
	switch {
	case s.conns >= s.allowance:
		why = "the project's allowance"
	case c.ConnsPerPeer > 0 && cs.peerConns[k.peer] >= c.ConnsPerPeer:
		why = "the peer's cap"
	case !s.take(time.Now(), c):
		why = "the project's connection rate"
	default:
		s.conns++
		cs.peerConns[k.peer]++
		if k.placed {
			cs.refusals--
			k.placed = false
		}
	}
	p.mu.Unlock()
	if why != "" {
		k.refuse(first, why) // a refusal in flight keeps its place
		return false
	}
	defer func() {
		p.mu.Lock()
		s.conns--
		if cs.peerConns[k.peer]--; cs.peerConns[k.peer] == 0 {
			delete(cs.peerConns, k.peer)
		}
		p.mu.Unlock()
	}()
	k.c.SetDeadline(time.Time{})
	err := Relay(s.ctx, Conn{Class: c, Client: k.c, First: first[:], From: s.from, To: s.to, Accepted: at, Streams: &s.streams})
	if err != nil {
		p.log.conn(s.m, err.Error())
	}
	return true
}

// refuse reads the rest of the startup packet under what remains of the
// preamble deadline, dials nothing, and answers "too many connections".
func (k *conn) refuse(first [8]byte, why string) {
	n, ok := pgwire.StartupLength(first[:])
	if !ok {
		k.p.log.conn(k.s.m, "refused, its startup length out of range: "+why)
		return
	}
	if _, err := io.CopyN(io.Discard, k.c, int64(n-8)); err != nil {
		k.p.log.conn(k.s.m, "refused, its startup packet not read: "+why)
		return
	}
	k.c.Write(pgwire.TooManyConnections())
	k.p.log.conn(k.s.m, "too many connections: "+why)
}

// logger writes one JSON line per event, at most one a second per class and
// slice index, with the count of the lines it did not print.
type logger struct {
	mu   sync.Mutex
	w    io.Writer
	now  func() time.Time
	last map[member]*logged
}

type logged struct {
	at      time.Time
	dropped int
}

func newLogger(w io.Writer) *logger {
	return &logger{w: w, now: time.Now, last: map[member]*logged{}}
}

func (l *logger) conn(m member, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	g := l.last[m]
	if g != nil && now.Sub(g.at) < time.Second {
		g.dropped++
		return
	}
	if g == nil {
		g = &logged{}
		l.last[m] = g
	}
	b, _ := json.Marshal(struct {
		Class   string `json:"class"`
		Index   int    `json:"index"`
		Reason  string `json:"reason"`
		Dropped int    `json:"not_printed,omitempty"`
	}{m.class, m.index, reason, g.dropped})
	l.w.Write(append(b, '\n'))
	g.at, g.dropped = now, 0
}

// table logs an event of the table: one line each, never rate-limited — the
// loader logs once per change of the file.
func (l *logger) table(reason string) {
	b, _ := json.Marshal(struct {
		Table string `json:"table"`
	}{reason})
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Write(append(b, '\n'))
}
