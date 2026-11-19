package pgcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The pacing rule alone, with a clock the test owns: an interval gives its
// budget once, what is left is what was not taken, the wait is what remains of
// the interval, a new interval starts where the clock is and brings no more than
// one budget however long the gap, and it starts the count caps again.
func TestStream_AllowanceIsTheRate(t *testing.T) {
	c := streamClass()
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = 1000, 50
	s := state{c: &c, phase: phStream}
	t0 := time.Unix(1000, 0)
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	if left, wait := s.allowance(t0); left != 1000 || wait != 0 {
		t.Fatalf("first read: %d %v", left, wait)
	}
	s.took(400)
	if left, wait := s.allowance(at(10 * time.Millisecond)); left != 600 || wait != 0 {
		t.Fatalf("after 400 bytes: %d %v", left, wait)
	}
	s.took(600)
	s.params = 7
	if left, wait := s.allowance(at(20 * time.Millisecond)); left != 0 || wait != 30*time.Millisecond {
		t.Fatalf("budget spent at 20 ms: %d %v, want a wait of 30 ms", left, wait)
	}
	if s.params != 7 {
		t.Fatal("the count caps started again inside an interval")
	}
	if left, wait := s.allowance(at(50*time.Millisecond - 1)); left != 0 || wait != 1 {
		t.Fatalf("one nanosecond before the interval's end: %d %v", left, wait)
	}
	if left, wait := s.allowance(at(50 * time.Millisecond)); left != 1000 || wait != 0 {
		t.Fatalf("next interval: %d %v", left, wait)
	}
	if s.params != 0 {
		t.Fatal("a new interval did not start the count caps again")
	}
	s.took(1000)
	// Ten intervals without a read bring one budget, not ten.
	if left, _ := s.allowance(at(600 * time.Millisecond)); left != 1000 {
		t.Fatalf("after an idle gap: %d, want one interval's budget", left)
	}
	s.took(1000)
	if left, wait := s.allowance(at(610 * time.Millisecond)); left != 0 || wait != 40*time.Millisecond {
		t.Fatalf("the interval after the gap starts at the read: %d %v", left, wait)
	}
}

// bufListener listens with the given socket buffer sizes, which accepted
// sockets inherit — what the owner of the listening sockets does for a class.
func bufListener(t *testing.T, n int) net.Listener {
	t.Helper()
	l, err := (&net.ListenConfig{Control: socketBuffers(n)}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

// blast writes to c until no byte has been taken for half a second, and returns
// how many bytes the path took.
func blast(c net.Conn, head []byte) int {
	total := 0
	chunk := make([]byte, 4<<10)
	if head != nil {
		chunk = head
	}
	for {
		c.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Write(chunk)
		total += n
		if err != nil {
			return total
		}
		if head != nil {
			chunk, head = make([]byte, 4<<10), nil
		}
	}
}

// The two fixed buffers and the socket buffers are all a connection holds: with
// a peer that sends as fast as it can and a peer on the other side that never
// reads, what the path takes is at most one copy buffer and the four socket
// buffers of that direction, each at the twice its size the kernel accounts —
// in both directions, over many connections at once. Nothing else (a kernel
// pipe of a zero-copy path, with its two descriptors, or a grown buffer) may
// stand between the two sockets.
func TestBuffers_BoundWhatAStalledPeerHolds(t *testing.T) {
	for _, sizes := range [][2]int{{16 << 10, 16 << 10}, {64 << 10, 32 << 10}} { // the default sizes; the dashboard class's
		for _, dir := range []string{"client sends, the cluster never reads", "the cluster sends, the client never reads"} {
			t.Run(fmt.Sprintf("%d and %d KiB: %s", sizes[0]>>10, sizes[1]>>10, dir), func(t *testing.T) {
				stalledPeer(t, sizes[0], sizes[1], strings.HasPrefix(dir, "the cluster"))
			})
		}
	}
}

func stalledPeer(t *testing.T, copyBuf, sockBuf int, fromCluster bool) {
	c := noneClass() // no byte window: only the buffers bound it
	c.CopyBufBytes, c.SockBufBytes = copyBuf, sockBuf
	// One direction: the relay's copy buffer and two of its socket buffers, and
	// the test's own two sockets, set to the same size.
	bound := c.CopyBufBytes + 4*2*c.SockBufBytes
	if int64(bound) > c.ConnBytes() {
		t.Fatal("helper: one direction above the class's figure for a connection")
	}
	const conns = 48
	{
		{
			cluster, front := bufListener(t, c.SockBufBytes), bufListener(t, c.SockBufBytes)
			took := make(chan int, conns)
			hold := make(chan struct{})
			var wg sync.WaitGroup
			defer wg.Wait()
			defer close(hold)
			go func() {
				for {
					s, err := cluster.Accept()
					if err != nil {
						return
					}
					go func() {
						defer s.Close()
						if fromCluster {
							io.ReadFull(s, make([]byte, 8))
							// One endless message after the login.
							took <- blast(s, cat(login, binary.BigEndian.AppendUint32([]byte{'D'}, 0xffffffff))) - len(login) - 5
						}
						<-hold // never reads
					}()
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			files := openFiles(t)
			for range conns {
				client, err := (&net.Dialer{Control: socketBuffers(c.SockBufBytes)}).Dial("tcp4", front.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				acc, err := front.Accept()
				if err != nil {
					t.Fatal(err)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					Relay(ctx, Conn{Class: c, Client: acc, First: startupPacket(""), From: netip.MustParseAddr("127.0.0.1"),
						To: netip.MustParseAddrPort(cluster.Addr().String()), Accepted: time.Now()})
				}()
				if !fromCluster {
					go func() { took <- blast(client, nil) }()
				}
			}
			sum, worst := 0, 0
			for range conns {
				select {
				case n := <-took:
					sum, worst = sum+n, max(worst, n)
				case <-time.After(60 * time.Second):
					t.Fatal("a sender never stalled")
				}
			}
			t.Logf("%d connections held %d bytes in all, %d at most each; the bound is %d each (the class's figure for a whole connection: %d)",
				conns, sum, worst, bound, c.ConnBytes())
			// Two sockets of the relay's and two of the test's a connection, and no
			// other descriptor: the open-file limit is counted from that.
			if got := openFiles(t) - files; got > 4*conns {
				t.Fatalf("%d descriptors for %d stalled connections, want two of the relay's and two of the test's each", got, conns)
			}
			// A socket may take one write past its size: one socket buffer of slack.
			if limit := bound + 2*c.SockBufBytes; worst > limit {
				t.Fatalf("one connection took %d bytes from a sender whose peer never reads, want at most %d", worst, limit)
			}
			if worst < c.CopyBufBytes {
				t.Fatalf("one connection took only %d bytes: the measurement measures nothing", worst)
			}
			cancel()
		}
	}
}

// Every clock starts at the accept, not when the relay is given the connection:
// a connection accepted most of a deadline ago has only the rest of it.
func TestDeadlines_CountFromTheAccept(t *testing.T) {
	late := func(by time.Duration) opts {
		return opts{edit: func(c *Conn) { c.Accepted = time.Now().Add(-by) }}
	}
	t.Run("authentication", func(t *testing.T) {
		c := metaClass() // 10 s
		c.DialMS = c.AuthMS
		start := time.Now()
		p := relayTo(t, c, func(s net.Conn) { write(s, rSASL) }, late(ms(c.AuthMS)-300*time.Millisecond))
		if err := p.closed(t, rSASL); err != errAuthDeadline {
			t.Fatalf("relay: %v", err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("ended after %v: the deadline ran from the hand-over", d)
		}
	})
	t.Run("wall clock", func(t *testing.T) {
		c := metaClass() // 55 s
		c.DialMS, c.AuthMS = c.WallMS, c.WallMS
		start := time.Now()
		p := relayTo(t, c, func(s net.Conn) { write(s, login) }, late(ms(c.WallMS)-300*time.Millisecond))
		if err := p.closed(t, login); err != errWallClock {
			t.Fatalf("relay: %v", err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("ended after %v", d)
		}
	})
	t.Run("dial", func(t *testing.T) {
		c := metaClass() // 3 s
		start := time.Now()
		p := relayTo(t, c, nil, opts{to: silentListener(t), edit: func(c *Conn) { c.Accepted = time.Now().Add(-ms(c.Class.DialMS) + 300*time.Millisecond) }})
		if err := p.closed(t, nil); !strings.Contains(err.Error(), "dial") {
			t.Fatalf("relay: %v", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("ended after %v: the dial deadline ran from the hand-over", d)
		}
	})
	t.Run("a deadline already passed ends it at once", func(t *testing.T) {
		p := relayTo(t, metaClass(), func(s net.Conn) { write(s, login) }, late(time.Hour))
		if err := p.closed(t, nil); err == nil {
			t.Fatal("no reason")
		}
	})
	t.Run("no accept time is a deadline already passed", func(t *testing.T) {
		p := relayTo(t, metaClass(), func(s net.Conn) { write(s, login) }, opts{edit: func(c *Conn) { c.Accepted = time.Time{} }})
		if err := p.closed(t, nil); err == nil {
			t.Fatal("no reason")
		}
	})
}

// A client that answers nothing, or reads nothing, cannot hold a connection
// past its deadlines either.
func TestDeadlines_ASlowClientIsNoException(t *testing.T) {
	t.Run("a client that never answers the exchange ends at the authentication deadline", func(t *testing.T) {
		c := metaClass()
		c.AuthMS = 300
		p := relayTo(t, c, func(s net.Conn) { write(s, rSASL); io.Copy(io.Discard, s) })
		if err := p.result(t); err != errAuthDeadline {
			t.Fatalf("relay: %v", err)
		}
	})
	t.Run("a client that never reads ends at the wall clock, the relay blocked in its write", func(t *testing.T) {
		c := metaClass()
		c.WallMS, c.WindowBytes = 500, 1<<40
		p := relayTo(t, c, func(s net.Conn) {
			write(s, login)
			for write(s, dataRow(8<<10)) {
			}
		})
		if err := p.result(t); err != errWallClock {
			t.Fatalf("relay: %v", err)
		}
	})
}

// What the caller hands over: more than the first eight bytes, nothing at all,
// no stream places for a class that streams.
func TestRelay_WhatTheCallerHandsOver(t *testing.T) {
	t.Run("more than the first eight bytes is relayed first, in order", func(t *testing.T) {
		whole := startupPacket("user\x00u\x00database\x00postgres\x00\x00")
		extra := ms4('p', "x")
		p := relayTo(t, metaClass(), nil, opts{edit: func(c *Conn) {
			// The harness's client has sent the packet whole; the caller read all of it and more of its own.
			rest := make([]byte, len(whole)-8)
			io.ReadFull(c.Client, rest)
			c.First = cat(c.First, rest, extra)
		}})
		after := ms4('Q', "select 1\x00")
		write(p.client, after)
		p.client.(*net.TCPConn).CloseWrite()
		// The scripted cluster consumed the startup packet; what follows is extra, then the client's next bytes.
		if got := <-p.cluster; !bytes.Equal(got, cat(extra, after)) {
			t.Fatalf("cluster received %q", got)
		}
	})
	t.Run("nothing read by the caller", func(t *testing.T) {
		run, ch := script(t, login)
		p := relayTo(t, metaClass(), run, opts{edit: func(c *Conn) {
			l, _ := net.Listen("tcp4", "127.0.0.1:0")
			defer l.Close()
			cl, _ := net.Dial("tcp4", l.Addr().String())
			c.Client, _ = l.Accept()
			c.First = nil
			go func() {
				cl.Write(startupPacket("user\x00u\x00\x00"))
				io.Copy(io.Discard, cl)
			}()
		}})
		<-ch
		p.cancel()
		if err := p.result(t); !errors.Is(err, context.Canceled) {
			t.Fatalf("relay: %v", err)
		}
	})
	t.Run("a class that streams without stream places refuses the copy-both", func(t *testing.T) {
		w := m('W', make([]byte, 3))
		p := relayTo(t, streamClass(), func(s net.Conn) { write(s, login, w, copyData(64)) })
		if err := p.closed(t, login); !strings.Contains(err.Error(), "copy-both") {
			t.Fatalf("relay: %v", err)
		}
	})
}

// Encryption cannot come about through the relay, whatever the caller let
// through: a server's one-byte answer to an encryption request is no message,
// so it never reaches the client, and what a server sends after it is judged as
// any message before authentication-ok.
func TestRelay_NoEncryptionAnswerPasses(t *testing.T) {
	for _, code := range []uint32{80877103, 80877104} {
		for _, answer := range []string{"S", "G", "N"} {
			t.Run(answer, func(t *testing.T) {
				c := metaClass()
				c.AuthMS = 400
				req := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 8), code)
				cl, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer cl.Close()
				go func() {
					s, err := cl.Accept()
					if err != nil {
						return
					}
					defer s.Close()
					io.ReadFull(s, make([]byte, 8))
					write(s, []byte(answer), []byte{0x16, 0x03, 0x03, 0x00, 0x20}, make([]byte, 0x20)) // and a record after it
					io.Copy(io.Discard, s)
				}()
				p := relayTo(t, c, nil, opts{to: netip.MustParseAddrPort(cl.Addr().String()), edit: func(c *Conn) { c.First = req }})
				if err := p.closed(t, nil); err == nil {
					t.Fatal("no reason")
				}
			})
		}
	}
}

// A message type the relay does not know: before authentication-ok it closes
// the connection like any other (a protocol-version negotiation among them);
// after it, it is relayed under the class's caps like a row.
func TestUnknownMessageType(t *testing.T) {
	negotiate := m('v', binary.BigEndian.AppendUint32(nil, 196608), binary.BigEndian.AppendUint32(nil, 0))
	for _, msg := range [][]byte{negotiate, ms4('?', "x"), ms4(0, "x"), ms4(0xff, "x"), ms4('p', "x")} {
		t.Run("before", func(t *testing.T) {
			p := relayTo(t, metaClass(), func(s net.Conn) { write(s, msg, login) })
			if err := p.closed(t, nil); !strings.Contains(err.Error(), "before authentication-ok") {
				t.Fatalf("relay: %v", err)
			}
		})
		t.Run("after", func(t *testing.T) {
			run, ch := script(t, login, msg)
			p := relayTo(t, metaClass(), run)
			if got := p.read(t, len(login)+len(msg)); !bytes.Equal(got, cat(login, msg)) {
				t.Fatalf("got %q", got[len(login):])
			}
			p.open(t, <-ch)
		})
	}
	t.Run("after, over the message cap", func(t *testing.T) {
		c := responseClass() // 256 KiB a message
		p := relayTo(t, c, func(s net.Conn) {
			write(s, login, binary.BigEndian.AppendUint32([]byte{'?'}, uint32(c.MessageBytes)+1), make([]byte, 1024))
		})
		p.closed(t, login)
	})
}

// A header's stated length is never trusted with memory: the largest length
// there is, with no cap in the class, is streamed through the one buffer.
func TestHeader_LargestLengthAllocatesNothing(t *testing.T) {
	before := totalAlloc()
	run, ch := script(t, login, binary.BigEndian.AppendUint32([]byte{'D'}, 0xffffffff), make([]byte, 1<<20))
	p := relayTo(t, noneClass(), run)
	p.read(t, len(login)+5+1<<20)
	<-ch
	if grew := totalAlloc() - before; grew > 4<<20 {
		t.Fatalf("a header announcing 4 GiB allocated %d bytes", grew)
	}
}

// panicConn fails like a defect in the handler would: its write, or its read,
// panics.
type panicConn struct {
	net.Conn
	onWrite, onRead bool
}

func (p panicConn) Write(b []byte) (int, error) {
	if p.onWrite {
		panic("write failed badly")
	}
	return p.Conn.Write(b)
}

func (p panicConn) Read(b []byte) (int, error) {
	if p.onRead {
		panic("read failed badly")
	}
	return p.Conn.Read(b)
}

// A panic that no hook planted, in either direction of a connection, ends that
// connection with both sides closed and leaves another one relaying.
func TestFault_APanicInEitherDirection(t *testing.T) {
	runB, chB := script(t, login)
	b := relayTo(t, metaClass(), runB)
	b.read(t, len(login))
	sB := <-chB
	for _, dir := range []string{"server to client", "client to server"} {
		t.Run(dir, func(t *testing.T) {
			ended := make(chan struct{})
			a := relayTo(t, metaClass(), func(s net.Conn) {
				write(s, login)
				io.Copy(io.Discard, s)
				close(ended)
			}, opts{edit: func(c *Conn) {
				c.Client = panicConn{Conn: c.Client, onWrite: dir == "server to client", onRead: dir != "server to client"}
			}})
			if err := a.result(t); err == nil || !strings.Contains(err.Error(), "fault") {
				t.Fatalf("relay: %v", err)
			}
			a.drain(t)
			select {
			case <-ended:
			case <-time.After(30 * time.Second):
				t.Fatal("the cluster's side is still open")
			}
			b.open(t, sB)
		})
	}
}

// In the stream state a client that stops reading stops the relay's reads from
// the server; when it reads again the relay takes the rate from the server,
// never the budget of the intervals the client sat out.
func TestStream_AClientThatStopsReadingGetsNoBurst(t *testing.T) {
	c := streamClass()
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = 32<<10, 100
	w := m('W', make([]byte, 3))
	wrote := &atomic.Int64{}
	p := relayTo(t, c, func(s net.Conn) {
		s.(*net.TCPConn).SetWriteBuffer(c.SockBufBytes) // fixed, so that what it wrote is what the relay took
		write(s, login, w)
		chunk := copyData(4 << 10)
		for {
			n, err := s.Write(chunk)
			wrote.Add(int64(n))
			if err != nil {
				return
			}
		}
	}, opts{streams: &StreamSlots{}, edit: func(conn *Conn) {
		conn.Client.(*net.TCPConn).SetWriteBuffer(c.SockBufBytes) // as its listening socket would have set it
	}})
	p.read(t, len(login)+len(w))
	time.Sleep(2 * time.Second) // twenty intervals unread
	stalled := wrote.Load()
	time.Sleep(500 * time.Millisecond)
	if more := wrote.Load() - stalled; more > 64<<10 {
		t.Fatalf("the cluster wrote %d more bytes while the client read nothing", more)
	}
	base := wrote.Load()
	go io.Copy(io.Discard, p.client)
	time.Sleep(time.Second)
	// Ten intervals, half as much again for a late clock, and the two socket buffers between.
	got, lim := wrote.Load()-base, 15*c.Stream.BytesPerInterval+int64(4*c.SockBufBytes)
	if got > lim {
		t.Fatalf("in the second after the stall the relay took %d bytes, want at most %d", got, lim)
	}
	if got < c.Stream.BytesPerInterval {
		t.Fatalf("in the second after the stall the relay took %d bytes: the stream did not go on", got)
	}
	select {
	case err := <-p.done:
		t.Fatalf("relay ended: %v", err)
	default:
	}
}

func openFiles(t *testing.T) int {
	t.Helper()
	d, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(d)
}

// settle waits until f is at most want.
func settle(want int, f func() int) int {
	got := f()
	for deadline := time.Now().Add(20 * time.Second); got > want && time.Now().Before(deadline); got = f() {
		time.Sleep(20 * time.Millisecond)
	}
	return got
}

// Thousands of connections, ended in every way a connection ends, leave
// nothing behind: when Relay has returned its client socket is closed and the
// cluster's side sees the end; afterwards no goroutine, no descriptor and no
// stream place remains.
func TestRelay_EveryEndingLeavesNothingBehind(t *testing.T) {
	if testing.Short() {
		t.Skip("thousands of connections")
	}
	const each, parallel = 300, 48
	w := m('W', make([]byte, 3))
	slots := &StreamSlots{}
	meta, stream := metaClass(), streamClass()
	stream.Stream.ConnsPerProject = 1 << 20
	short := func(c Class, auth, wall int) Class { c.AuthMS, c.WallMS = auth, wall; return c }
	isBreach := func(err error) bool {
		var b breach
		return errors.As(err, &b) && err != errAuthDeadline && err != errWallClock
	}
	has := func(s string) func(error) bool {
		return func(err error) bool { return err != nil && strings.Contains(err.Error(), s) }
	}
	silent := silentListener(t)
	// A port that refuses: bound, not listening, and held so that no listener of this test gets it.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	sa, _ := syscall.Getsockname(fd)
	refused := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(sa.(*syscall.SockaddrInet4).Port))
	type way struct {
		name    string
		class   Class
		sends   []byte                                   // what the cluster sends after the startup packet
		then    func(s net.Conn)                         // what the cluster does next (nil: reads to the end)
		client  func(c net.Conn, cancel func(), n int64) // what the test's client does once it has read n bytes
		reads   int                                      // how many bytes the client reads first
		edit    func(*Conn)
		want    func(error) bool
		inSlots bool
	}
	closeIt := func(c net.Conn, _ func(), _ int64) { c.Close() }
	wait := func(net.Conn, func(), int64) {}
	ways := []way{
		{name: "the client closes", class: meta, sends: login, reads: len(login), client: closeIt, want: func(err error) bool { return err == nil }},
		{name: "the cluster closes", class: meta, sends: login, then: func(s net.Conn) { s.Close() }, reads: len(login), client: wait,
			want: func(err error) bool { return err == nil }},
		{name: "the client closes in the stream state", class: stream, sends: cat(login, w, copyData(512)), reads: len(login) + len(w) + 512,
			client: closeIt, want: func(err error) bool { return err == nil }, inSlots: true},
		{name: "cancelled mid-message in the stream state", class: stream,
			sends: cat(login, w, binary.BigEndian.AppendUint32([]byte{'d'}, 4+64<<10), make([]byte, 100)), reads: len(login) + len(w) + 5 + 100,
			client: func(_ net.Conn, cancel func(), _ int64) { cancel() }, want: func(err error) bool { return errors.Is(err, context.Canceled) }, inSlots: true},
		{name: "cancelled in the dial", class: meta, client: func(_ net.Conn, cancel func(), _ int64) { time.Sleep(5 * time.Millisecond); cancel() },
			edit: func(c *Conn) { c.To = silent }, want: func(err error) bool { return errors.Is(err, context.Canceled) }},
		{name: "the dial deadline", class: meta, client: wait,
			edit: func(c *Conn) { c.To, c.Class.DialMS = silent, 40 }, want: has("dial")},
		{name: "the authentication deadline", class: short(meta, 60, 0), sends: cat(rSASL, rCont), client: wait,
			want: func(err error) bool { return err == errAuthDeadline }},
		{name: "the wall clock", class: short(meta, 10000, 80), sends: login, client: wait,
			want: func(err error) bool { return err == errWallClock }},
		{name: "the dial refused", class: meta, client: wait, edit: func(c *Conn) { c.To = refused }, want: has("dial")},
		{name: "a breach", class: meta, sends: cat(rSASL, authReq(3, "")), reads: len(rSASL), client: wait, want: isBreach},
		{name: "a breach in the stream state", class: stream, sends: cat(login, w, m('R', make([]byte, 4))), reads: len(login) + len(w), client: wait,
			want: isBreach, inSlots: true},
		{name: "a fault", class: meta, sends: login, client: wait, want: has("fault"),
			edit: func(c *Conn) { c.Client = panicConn{Conn: c.Client, onWrite: true} }},
		{name: "a fault in the stream state", class: stream, sends: cat(login, w, copyData(64), ms4('!', "x")), reads: len(login) + len(w) + 64, client: wait,
			want: has("fault"), inSlots: true},
	}
	old := faultHook
	faultHook = func(typ byte) {
		if typ == '!' {
			panic("marker")
		}
	}
	defer func() { faultHook = old }()

	front, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	runtime.GC()
	goroutines, files := runtime.NumGoroutine(), openFiles(t)

	var failed atomic.Int64
	fail := func(format string, a ...any) {
		if failed.Add(1) <= 10 {
			t.Errorf(format, a...)
		}
	}
	one := func(wy way) {
		cl, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			fail("%v", err)
			return
		}
		defer cl.Close()
		clusterEnd := make(chan struct{})
		go func() {
			defer close(clusterEnd)
			s, err := cl.Accept()
			if err != nil {
				return
			}
			defer s.Close()
			s.SetDeadline(time.Now().Add(60 * time.Second))
			if _, err := io.ReadFull(s, make([]byte, 8)); err != nil {
				return
			}
			write(s, wy.sends)
			if wy.then != nil {
				wy.then(s)
				return
			}
			io.Copy(io.Discard, s) // to the end the relay gives it
		}()
		// front is shared: dial and accept as one step, so each worker keeps its own pair.
		frontMu.Lock()
		client, err := net.Dial("tcp4", front.Addr().String())
		var acc net.Conn
		if err == nil {
			acc, err = front.Accept()
		}
		frontMu.Unlock()
		if err != nil {
			fail("%v", err)
			return
		}
		defer client.Close()
		client.SetDeadline(time.Now().Add(60 * time.Second))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		conn := Conn{Class: wy.class, First: startupPacket(""), From: netip.MustParseAddr("127.0.0.1"),
			To: netip.MustParseAddrPort(cl.Addr().String()), Accepted: time.Now()}
		if wy.inSlots {
			conn.Streams = slots
		}
		conn.Client = acc
		if wy.edit != nil {
			wy.edit(&conn)
		}
		done := make(chan error, 1)
		go func() { done <- Relay(ctx, conn) }()
		if wy.reads > 0 {
			if _, err := io.CopyN(io.Discard, client, int64(wy.reads)); err != nil {
				fail("%s: client: %v", wy.name, err)
			}
		}
		wy.client(client, cancel, int64(wy.reads))
		select {
		case err := <-done:
			if !wy.want(err) {
				fail("%s: relay returned %v", wy.name, err)
			}
		case <-time.After(20 * time.Second): // well before the scripted cluster gives up
			fail("%s: the relay did not return", wy.name)
			return
		}
		// Returned: the client socket it was given is closed, now.
		if _, err := acc.Write([]byte{0}); !errors.Is(err, net.ErrClosed) {
			fail("%s: the client socket is not closed when Relay has returned: %v", wy.name, err)
		}
		cl.Close() // a cluster never dialled still waits in its accept
		select {
		case <-clusterEnd:
		case <-time.After(60 * time.Second):
			fail("%s: the cluster's side did not see the end", wy.name)
		}
	}
	work := make(chan way)
	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for wy := range work {
				one(wy)
			}
		}()
	}
	for range each {
		for _, wy := range ways {
			work <- wy
		}
	}
	close(work)
	wg.Wait()
	t.Logf("%d connections, %d ways", each*len(ways), len(ways))
	if n := slots.n.Load(); n != 0 {
		t.Errorf("%d stream places still held", n)
	}
	if got := settle(goroutines, runtime.NumGoroutine); got > goroutines {
		buf := make([]byte, 1<<20)
		t.Errorf("%d goroutines, %d before:\n%s", got, goroutines, buf[:runtime.Stack(buf, true)])
	}
	if got := settle(files, func() int { return openFiles(t) }); got > files {
		t.Errorf("%d open files, %d before", got, files)
	}
}

var frontMu sync.Mutex

// A length below the four bytes of the length itself closes the connection at
// that header, before authentication-ok and after it; nothing of it is relayed.
func TestHeader_LengthBelowFourCloses(t *testing.T) {
	for _, length := range []uint32{0, 3} {
		bad := binary.BigEndian.AppendUint32([]byte{'D'}, length)
		p := relayTo(t, noneClass(), func(s net.Conn) { write(s, login, bad, readyMsg) })
		if err := p.closed(t, login); !strings.Contains(err.Error(), "length below 4") {
			t.Fatalf("after authentication-ok: %v", err)
		}
		bad[0] = 'E'
		q := relayTo(t, noneClass(), func(s net.Conn) { write(s, rSASL, bad, readyMsg) })
		if err := q.closed(t, rSASL); !strings.Contains(err.Error(), "length below 4") {
			t.Fatalf("before authentication-ok: %v", err)
		}
	}
}

// The dial leaves from the address the caller names, whatever the route would
// have chosen.
func TestDial_FromTheGivenAddress(t *testing.T) {
	cl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	from := make(chan string, 1)
	go func() {
		s, err := cl.Accept()
		if err != nil {
			return
		}
		from <- s.RemoteAddr().(*net.TCPAddr).IP.String()
		s.Close()
	}()
	p := relayTo(t, metaClass(), nil, opts{to: netip.MustParseAddrPort(cl.Addr().String()),
		edit: func(c *Conn) { c.From = netip.MustParseAddr("127.0.0.2") }})
	select {
	case got := <-from:
		if got != "127.0.0.2" {
			t.Fatalf("the cluster saw %s", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no dial")
	}
	p.result(t)
}

// Every cap and bound of a class that the strict reading names, one member at
// a time, and the exact edges of the ceiling and of the slice count.
func TestTable_Strict_EveryMember(t *testing.T) {
	good := metaJSON(metaSlices) // terms 10 + 4 + 16
	two := strings.Replace(good, `"drop_notices":true}]`, `"drop_notices":true},`+replica+`]`, 1)
	for _, c := range []struct {
		name, base, from, to string
		ok                   bool
	}{
		{"max_conns equal to the terms", good, `"max_conns":64`, `"max_conns":30`, true},
		{"max_conns one below the terms", good, `"max_conns":64`, `"max_conns":29`, false},
		{"negative conns_per_peer", good, `"conns_per_peer":16`, `"conns_per_peer":-1`, false},
		{"negative cancels_per_project", good, `"cancels_per_project":2`, `"cancels_per_project":-1`, false},
		{"negative cancels_per_peer", good, `"cancels_per_peer":8`, `"cancels_per_peer":-1`, false},
		{"negative param_status_max", good, `"param_status_max":64`, `"param_status_max":-1`, false},
		{"negative row_fields_max", good, `"row_fields_max":1664`, `"row_fields_max":-1`, false},
		{"negative window_bytes without a window", two, `"window":"response","window_bytes":8388608`, `"window":"none","window_bytes":-1`, false},
		{"no window and no window_bytes", two, `"window":"response","window_bytes":8388608`, `"window":"none","window_bytes":0`, true},
		{"port_base 0", good, `"port_base":20000`, `"port_base":0`, false},
		{"the last port is 65535", good, `"port_base":20000`, `"port_base":64512`, true},
		{"the last port is 65536", good, `"port_base":20000`, `"port_base":64513`, false},
		{"port ranges that touch", two, `"port_base":30000`, `"port_base":21024`, true},
		{"port ranges that share one port", two, `"port_base":30000`, `"port_base":21023`, false},
		{"port ranges that share one port, the other way", two, `"port_base":30000`, `"port_base":18977`, false},
		{"the last slice of the block", good, `"7":{`, `"1023":{`, true},
		{"a stream interval of 10 ms", two, `"interval_ms":100`, `"interval_ms":10`, true},
		{"a stream interval of 1000 ms", two, `"interval_ms":100`, `"interval_ms":1000`, true},
		{"a negative stream rate", two, `"bytes_per_interval":1048576`, `"bytes_per_interval":-1`, false},
		{"buffers of 4 KiB", good, `"copy_buf_bytes":65536,"sock_buf_bytes":32768`, `"copy_buf_bytes":4096,"sock_buf_bytes":4096`, true},
		{"buffers of 1 MiB", good, `"copy_buf_bytes":65536,"sock_buf_bytes":32768`, `"copy_buf_bytes":1048576,"sock_buf_bytes":1048576`, true},
		{"an iteration cap of 0", good, `"scram_iter_min":4096,"scram_iter_max":4096`, `"scram_iter_min":1,"scram_iter_max":0`, false},
		{"a slice of eight addresses", good, `"slice_prefix":26`, `"slice_prefix":29`, true},
		{"a slice prefix equal to the block's", metaJSON(`{"0":{"meta":5}}`), `"slice_prefix":26`, `"slice_prefix":16`, false},
		{"an empty class name that a slice uses", metaJSON(`{"3":{"":5}}`), `"name":"meta"`, `"name":""`, false},
		{"a number with a fraction", good, `"max_conns":64`, `"max_conns":64.0`, false},
		{"a number past the integers", good, `"max_conns":64`, `"max_conns":9223372036854775808`, false},
		{"a text where a number belongs", good, `"max_conns":64`, `"max_conns":"64"`, false},
		{"no classes and no slices", good, good, `{"listen":"10.212.0.6","project_block":"10.213.0.0/16","slice_prefix":26,"max_conns":0,"preamble_ms":2000,"classes":[],"slices":{}}`, true},
		{"empty", good, good, ``, false},
		{"two documents", good, good, good + good, false},
	} {
		if !strings.Contains(c.base, c.from) {
			t.Fatalf("%s: %q not in the table", c.name, c.from)
		}
		if _, err := ParseTable([]byte(strings.Replace(c.base, c.from, c.to, 1))); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// The caps at their edges, where the committed cases leave room: one field
// over the cap closes; notices before authentication-ok are counted like any
// other.
func TestCountCaps_Edges(t *testing.T) {
	p := relayTo(t, metaClass(), func(s net.Conn) { write(s, login, rowDesc(1665)) })
	if err := p.closed(t, login); !strings.Contains(err.Error(), "row description") {
		t.Fatalf("1,665 fields: %v", err)
	}
	c := responseClass()
	c.NoticesMax = 3
	q := relayTo(t, c, func(s net.Conn) { write(s, rSASL, repeat(notice, 4), rCont) })
	if err := q.closed(t, cat(rSASL, repeat(notice, 3))); !strings.Contains(err.Error(), "notices") {
		t.Fatalf("four notices before authentication-ok: %v", err)
	}
	// A copy-both inside the stream state takes no second place.
	w := m('W', make([]byte, 3))
	run, ch := script(t, login, w, w, copyData(64))
	r := relayTo(t, streamClass(), run, opts{streams: &StreamSlots{}}) // one place a project
	r.read(t, len(login)+2*len(w)+64)
	<-ch
}

// A connection refused at its copy-both holds no place: when the project's one
// streaming connection leaves the stream state, the next one enters.
func TestStream_ARefusedConnectionHoldsNoPlace(t *testing.T) {
	w := m('W', make([]byte, 3))
	slots := &StreamSlots{}
	run1, ch1 := script(t, login, w)
	first := relayTo(t, streamClass(), run1, opts{streams: slots})
	first.read(t, len(login)+len(w))
	s1 := <-ch1
	for range 3 {
		refused := relayTo(t, streamClass(), func(s net.Conn) { write(s, login, w) }, opts{streams: slots})
		refused.closed(t, login)
	}
	write(s1, readyMsg) // the first leaves the stream state
	first.read(t, len(readyMsg))
	run2, ch2 := script(t, login, w, copyData(64))
	next := relayTo(t, streamClass(), run2, opts{streams: slots})
	next.read(t, len(login)+len(w)+64)
	<-ch2
	if n := slots.n.Load(); n != 1 {
		t.Fatalf("%d places held, want the one of the connection that streams", n)
	}
}

// An authentication request too short to carry a subtype closes the connection
// at every step of the exchange — it is never read as authentication-ok.
func TestAuth_RequestWithoutASubtypeCloses(t *testing.T) {
	steps := [][]byte{nil, rSASL, cat(rSASL, rCont), cat(rSASL, rCont, rFinal)}
	for _, before := range steps {
		for size := range 4 {
			p := relayTo(t, metaClass(), func(s net.Conn) { write(s, before, m('R', make([]byte, size)), greeting) })
			if err := p.closed(t, before); !strings.Contains(err.Error(), "malformed authentication request") {
				t.Fatalf("after %d bytes of the exchange, a request body of %d bytes: %v", len(before), size, err)
			}
		}
	}
}
