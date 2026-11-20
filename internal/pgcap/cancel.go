package pgcap

import (
	"context"
	"io"
	"net"
	"time"
)

// cancel forwards a cancel request outside the connection cap, under the
// slice's and the peer's cancel allowances: it reads the request's other eight
// bytes, dials the slice's cluster and writes exactly the sixteen bytes, all
// within the class's cancel deadline, then closes both sides. Nothing after the
// sixteenth byte is read, and nothing is read back. Over an allowance the socket
// is closed unanswered.
func (k *conn) cancel(first [8]byte) {
	p, s := k.p, k.s
	p.mu.Lock()
	cs := p.classes[s.m.class]
	c := cs.c
	ok := s.cancels < c.CancelsPerProject && (c.CancelsPerPeer == 0 || cs.peerCancels[k.peer] < c.CancelsPerPeer)
	if ok {
		s.cancels++
		cs.peerCancels[k.peer]++
		if k.placed {
			cs.refusals--
			k.placed = false
		}
	}
	p.mu.Unlock()
	if !ok {
		p.log.conn(s.m, "cancel over its allowance")
		return
	}
	defer func() {
		p.mu.Lock()
		s.cancels--
		if cs.peerCancels[k.peer]--; cs.peerCancels[k.peer] == 0 {
			delete(cs.peerCancels, k.peer)
		}
		p.mu.Unlock()
	}()
	deadline := time.Now().Add(ms(c.CancelMS))
	k.c.SetDeadline(deadline)
	req := append(first[:], make([]byte, 8)...)
	if _, err := io.ReadFull(k.c, req[8:]); err != nil {
		p.log.conn(s.m, "cancel: "+err.Error())
		return
	}
	ctx, done := context.WithDeadline(s.ctx, deadline)
	defer done()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: s.from.AsSlice()}, Control: socketBuffers(c.SockBufBytes)}
	srv, err := d.DialContext(ctx, "tcp4", s.to.String())
	if err != nil {
		p.log.conn(s.m, "cancel: dial: "+err.Error())
		return
	}
	defer srv.Close()
	stop := context.AfterFunc(ctx, func() { srv.Close() })
	defer stop()
	srv.SetDeadline(deadline)
	if _, err := srv.Write(req); err != nil {
		p.log.conn(s.m, "cancel: "+err.Error())
	}
}
