package pgcap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/pgwire"
)

// Conn is one admitted connection, handed to Relay by the owner of the
// listening sockets.
type Conn struct {
	Class  Class
	Client net.Conn // the accepted socket, its buffers set by its listening socket
	// First is what was read from the client to classify it (its first eight
	// bytes at least); it is relayed before anything else.
	First []byte
	// From is the proxy's address on the slice's network, To the cluster.
	From     netip.Addr
	To       netip.AddrPort
	Accepted time.Time    // every clock of the connection starts here
	Streams  *StreamSlots // the slice's places in the stream state; needed when the class has a stream window
}

var (
	errPeerClosed   = errors.New("closed by a peer")
	errAuthDeadline = breach("authentication-ok not within the class's deadline")
	errWallClock    = breach("the class's wall clock reached")
)

// faultHook sees every server message type before it is judged; a test build
// makes it fail on a marker.
var faultHook = func(typ byte) {}

// newBuffer allocates a direction's copy buffer: one per direction and
// connection, never grown.
var newBuffer = func(n int) []byte { return make([]byte, n) }

type relay struct {
	c      *Conn
	ctx    context.Context
	stop   context.CancelCauseFunc
	server net.Conn
	buf    []byte
	st     state
	authed atomic.Bool
}

// Relay runs one connection to its end: it dials the cluster from From within
// the class's dial deadline, relays the client's bytes unread, and streams the
// server's messages to the client through one fixed buffer, judging each
// header before its body by the class's rules. A breach, a deadline, a fault
// (a panic included) or the end of ctx closes both sides of this connection and
// nothing else. Cancelling ctx is how the owner closes the connection from
// outside, for instance every connection of a slice that left the table.
//
// It returns nil when a peer closed the connection, and otherwise the reason
// it was closed.
func Relay(ctx context.Context, c Conn) error {
	ctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	r := &relay{c: &c, ctx: ctx, stop: stop, st: state{c: &c.Class, slots: c.Streams}}
	var mu sync.Mutex
	closed := false
	closeAll := func() {
		mu.Lock()
		defer mu.Unlock()
		closed = true
		c.Client.Close()
		if r.server != nil {
			r.server.Close()
		}
	}
	context.AfterFunc(ctx, closeAll)
	defer closeAll() // both sockets are closed when Relay returns, whatever the timing of the above
	defer func() {
		if r.st.phase == phStream {
			r.st.slots.release()
		}
	}()
	t := time.AfterFunc(time.Until(c.Accepted.Add(ms(c.Class.AuthMS))), func() {
		if !r.authed.Load() {
			stop(errAuthDeadline)
		}
	})
	defer t.Stop()
	if c.Class.WallMS > 0 {
		w := time.AfterFunc(time.Until(c.Accepted.Add(ms(c.Class.WallMS))), func() { stop(errWallClock) })
		defer w.Stop()
	}

	if !c.From.Is4() { // never the kernel's choice of source
		stop(errors.New("dial: no IPv4 source address"))
		return context.Cause(ctx)
	}
	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: c.From.AsSlice()},
		Deadline:  c.Accepted.Add(ms(c.Class.DialMS)),
		Control:   socketBuffers(c.Class.SockBufBytes),
	}
	server, err := d.DialContext(ctx, "tcp4", c.To.String())
	if err != nil {
		stop(fmt.Errorf("dial: %w", err))
		return context.Cause(ctx)
	}
	mu.Lock()
	r.server = server
	if closed {
		server.Close()
	}
	mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer r.recoverFault()
		if _, err := server.Write(c.First); err == nil {
			buf := newBuffer(c.Class.CopyBufBytes)
			// Wrapped so that the copy goes through buf, not a splice.
			io.CopyBuffer(struct{ io.Writer }{server}, struct{ io.Reader }{c.Client}, buf)
		}
		stop(errPeerClosed)
	}()
	func() {
		defer r.recoverFault()
		r.buf = newBuffer(c.Class.CopyBufBytes)
		stop(r.fromServer())
	}()
	wg.Wait()
	if err := context.Cause(ctx); !errors.Is(err, errPeerClosed) {
		return err
	}
	return nil
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func (r *relay) recoverFault() {
	if p := recover(); p != nil {
		r.stop(fmt.Errorf("fault: %v", p))
	}
}

// socketBuffers sets a dialled socket's send and receive buffers before it
// connects.
func socketBuffers(n int) func(string, string, syscall.RawConn) error {
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, n); serr == nil {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, n)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// fromServer relays the server's messages until a breach or a closed side,
// through the one buffer r.buf, scanned in place:
//   - a read fills the buffer behind the bytes not yet judged;
//   - the headers that lie complete in it are judged in order, each before any
//     byte of its body is forwarded; buf[w:p] is what they admitted, buf[p:e]
//     what is not judged yet;
//   - the admitted bytes are written to the client in one write before the
//     next read, before a dropped message is skipped, and before a breach
//     returns — so the client never receives a byte of a refused message;
//   - what cannot be judged yet (a partial header, or an authentication
//     request or the start of a row description not yet whole) moves to the
//     buffer's start before the next read; a body longer than the buffer
//     streams through it.
func (r *relay) fromServer() error {
	buf := r.buf
	var w, p, e int // buf[w:p] admitted and not written; buf[p:e] not judged
	var rem int     // bytes of the current message's body still to pass or drop
	var drop bool   // the current body is discarded
	var held bool   // the header at p is judged and waits for need bytes
	var act action
	var n, need int
	flush := func() error {
		if p > w {
			if _, err := r.c.Client.Write(buf[w:p]); err != nil {
				return errPeerClosed
			}
		}
		w = p
		return nil
	}
	refuse := func(err error) error {
		flush() // what was admitted before the refused message
		return err
	}
	defer func() { // a fault, too, leaves the client every message admitted before it
		if f := recover(); f != nil {
			flush()
			panic(f)
		}
	}()
	for {
		switch {
		case rem > 0 && p < e:
			k := min(rem, e-p)
			p, rem = p+k, rem-k
			if drop {
				w = p
			}
			continue
		case rem == 0 && !held && e-p >= 5:
			typ, ln, err := pgwire.Header([5]byte(buf[p : p+5]))
			faultHook(typ)
			if err != nil {
				return refuse(breach("message length below 4"))
			}
			was := r.st.phase
			if act, err = r.st.header(typ, ln); err != nil {
				return refuse(err)
			}
			if was != phStream && r.st.phase == phStream {
				// What was read beyond the copy-both counts in the first interval.
				r.st.allowance(time.Now())
				r.st.took(e - p - 5)
			}
			n = ln
			switch act {
			case actAuth:
				held, need = true, 5+n
			case actFields:
				if n < 2 {
					return refuse(breach("malformed row description"))
				}
				held, need = true, 7
			case actDrop:
				if err := flush(); err != nil {
					return err
				}
				p += 5
				w, rem, drop = p, n, true
			default:
				p += 5
				rem, drop = n, false
			}
			continue
		case held && e-p >= need:
			var err error
			if act == actAuth {
				err = r.st.auth(buf[p+5 : p+need])
				r.authed.Store(r.st.authed())
			} else {
				err = r.st.rowFields(buf[p+5 : p+need])
			}
			if err != nil {
				return refuse(err)
			}
			p += need
			rem, drop, held = n-(need-5), false, false
			continue
		}
		if err := flush(); err != nil {
			return err
		}
		e = copy(buf, buf[p:e])
		p, w = 0, 0
		m, err := r.read(buf[e:])
		if err != nil {
			return err
		}
		e += m
	}
}

// read reads from the server; in the stream state no more than the interval's
// allowance, waiting for the next interval when it is spent.
func (r *relay) read(p []byte) (int, error) {
	if r.st.phase == phStream {
		for {
			left, wait := r.st.allowance(time.Now())
			if left > 0 {
				p = p[:min(int64(len(p)), left)]
				break
			}
			t := time.NewTimer(wait)
			select {
			case <-r.ctx.Done():
				t.Stop()
				return 0, errPeerClosed
			case <-t.C:
			}
		}
	}
	n, _ := r.server.Read(p)
	if r.st.phase == phStream {
		r.st.allowance(time.Now()) // bytes that arrive in a new interval are counted in it
		r.st.took(n)
	}
	if n > 0 {
		return n, nil
	}
	return 0, errPeerClosed
}
