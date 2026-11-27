package pgcap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The classes the relay is tested with: the dashboard's shape, a long-lived
// shape with a response window, the same with a stream window, and one with no
// window — the shapes of the later classes.
func metaClass() Class {
	tb, err := ParseTable([]byte(metaJSON(metaSlices)))
	if err != nil {
		panic(err)
	}
	return tb.Classes[0]
}

func responseClass() Class {
	c := metaClass()
	c.Name, c.Window, c.WindowBytes, c.MessageBytes = "response", WindowResponse, 1<<20, 256<<10
	c.CopyBufBytes, c.SockBufBytes = 16<<10, 16<<10
	c.WallMS, c.ScramIterMin, c.ScramIterMax, c.NoticesMax, c.DropNotices = 0, 4096, 4096, 1000, false
	return c
}

func streamClass() Class {
	c := responseClass()
	c.Name = "stream"
	c.Stream = &Stream{ConnsPerProject: 1, BytesPerInterval: 256 << 10, IntervalMS: 50}
	return c
}

func noneClass() Class {
	c := responseClass()
	c.Name, c.Window, c.WindowBytes, c.MessageBytes, c.NoticesMax = "none", WindowNone, 0, 0, 0
	c.CopyBufBytes = 64 << 10
	c.ScramIterMin, c.ScramIterMax = 1, 32768
	return c
}

// Backend messages.
func m(typ byte, body ...[]byte) []byte {
	b := bytes.Join(body, nil)
	return append(binary.BigEndian.AppendUint32([]byte{typ}, uint32(4+len(b))), b...)
}

func ms4(typ byte, s string) []byte { return m(typ, []byte(s)) }

func authReq(code uint32, data string) []byte {
	return m('R', binary.BigEndian.AppendUint32(nil, code), []byte(data))
}

func cont(iter int) []byte { return authReq(11, "r=abcdef,s=c2FsdHNhbHQ=,i="+strconv.Itoa(iter)) }

var (
	rSASL    = authReq(10, "SCRAM-SHA-256\x00\x00")
	rCont    = cont(4096)
	rFinal   = authReq(12, "v=c2lnbmF0dXJl")
	rOK      = authReq(0, "")
	readyMsg = ms4('Z', "I")
	paramMsg = ms4('S', "client_encoding\x00UTF8\x00")
	notice   = ms4('N', "SNOTICE\x00C00000\x00Mnote\x00\x00")
	greeting = bytes.Join([][]byte{paramMsg, paramMsg, m('K', make([]byte, 8)), readyMsg}, nil)
	login    = bytes.Join([][]byte{rSASL, rCont, rFinal, rOK, greeting}, nil)
)

func dataRow(size int) []byte { return m('D', make([]byte, size-5)) } // a message of size bytes in all

func rowDesc(fields int) []byte {
	return m('T', binary.BigEndian.AppendUint16(nil, uint16(fields)), make([]byte, 16))
}

func startupPacket(params string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(8+len(params)))
	return append(binary.BigEndian.AppendUint32(b, 196608), params...)
}

// pair is one relayed connection: the test's client, what the scripted cluster
// received after the startup packet (sent once its side is closed), and the
// relay's result.
type pair struct {
	client  net.Conn
	cluster chan []byte
	done    chan error
	cancel  context.CancelFunc
}

type opts struct {
	streams *StreamSlots
	to      netip.AddrPort // a cluster address other than the scripted one
	edit    func(*Conn)    // changes the connection handed to Relay
}

// relayTo starts a scripted cluster, a client that sends a startup packet, and
// the relay between them. The script gets the cluster's socket after the
// startup packet has been read; when it returns, the cluster reads until its
// side is closed.
func relayTo(t *testing.T, c Class, script func(net.Conn), o ...opts) *pair {
	t.Helper()
	var op opts
	if len(o) > 0 {
		op = o[0]
	}
	cl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	p := &pair{cluster: make(chan []byte, 1), done: make(chan error, 1)}
	go func() {
		s, err := cl.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		s.SetDeadline(time.Now().Add(30 * time.Second))
		var h [8]byte
		if _, err := io.ReadFull(s, h[:]); err != nil {
			p.cluster <- nil
			return
		}
		io.CopyN(io.Discard, s, int64(binary.BigEndian.Uint32(h[:]))-8)
		if script != nil {
			script(s)
		}
		b, _ := io.ReadAll(s)
		p.cluster <- b
	}()
	front, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	client, err := net.Dial("tcp4", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := client.Write(startupPacket("user\x00u\x00database\x00postgres\x00\x00")); err != nil {
		t.Fatal(err)
	}
	acc, err := front.Accept()
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 8)
	if _, err := io.ReadFull(acc, first); err != nil {
		t.Fatal(err)
	}
	to := netip.MustParseAddrPort(cl.Addr().String())
	if op.to.IsValid() {
		to = op.to
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	conn := Conn{Class: c, Client: acc, First: first, From: netip.MustParseAddr("127.0.0.1"), To: to,
		Accepted: time.Now(), Streams: op.streams}
	if op.edit != nil {
		op.edit(&conn)
	}
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		p.done <- Relay(ctx, conn)
	}()
	// The relay ends before the test does: one left running reads the
	// package's hooks (faultHook, newBuffer) while the next test sets them.
	t.Cleanup(func() {
		cancel()
		select {
		case <-ended:
		case <-time.After(30 * time.Second):
			t.Error("the relay did not end 30 s after its context")
		}
	})
	p.client = client
	return p
}

func write(c net.Conn, bs ...[]byte) bool {
	for _, b := range bs {
		if _, err := c.Write(b); err != nil {
			return false
		}
	}
	return true
}

// drain reads what the client receives until the relay closes it.
func (p *pair) drain(t *testing.T) []byte {
	t.Helper()
	b, err := io.ReadAll(p.client)
	if errors.Is(err, syscall.ECONNRESET) { // closed with client bytes unread
		return b
	}
	if err != nil {
		t.Fatalf("client: %v after %d bytes, want the connection closed", err, len(b))
	}
	return b
}

// read reads exactly n bytes at the client.
func (p *pair) read(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if k, err := io.ReadFull(p.client, b); err != nil {
		t.Fatalf("client: %v after %d of %d bytes", err, k, n)
	}
	return b
}

func (p *pair) result(t *testing.T) error {
	t.Helper()
	select {
	case err := <-p.done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("the relay did not end")
		return nil
	}
}

// closed checks that the client received exactly want and then the end, and
// that the relay reports a reason.
func (p *pair) closed(t *testing.T, want []byte) error {
	t.Helper()
	if got := p.drain(t); !bytes.Equal(got, want) {
		t.Fatalf("client received %d bytes %q…, want exactly %d", len(got), got[:min(len(got), 64)], len(want))
	}
	err := p.result(t)
	if err == nil {
		t.Fatal("relay ended without a reason")
	}
	return err
}

// open checks that the connection still relays: the cluster's next message
// reaches the client.
func (p *pair) open(t *testing.T, server net.Conn) {
	t.Helper()
	if !write(server, readyMsg) {
		t.Fatal("cluster side closed")
	}
	if b := p.read(t, len(readyMsg)); !bytes.Equal(b, readyMsg) {
		t.Fatalf("got %q", b)
	}
}

// script sends bs and hands the cluster's socket to the test.
func script(t *testing.T, bs ...[]byte) (func(net.Conn), chan net.Conn) {
	ch, release := make(chan net.Conn, 1), make(chan struct{})
	t.Cleanup(func() { close(release) }) // after the client has closed
	return func(s net.Conn) {
		write(s, bs...)
		ch <- s
		<-release // the test reads and writes the socket meanwhile
	}, ch
}

func cat(bs ...[]byte) []byte { return bytes.Join(bs, nil) }

func TestAuth_OnlySASLPasses(t *testing.T) {
	for _, req := range [][]byte{authReq(3, ""), authReq(5, "salt"), authReq(7, ""), authReq(9, ""), authReq(2, ""), authReq(99, "")} {
		code := binary.BigEndian.Uint32(req[5:])
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			p := relayTo(t, metaClass(), func(s net.Conn) { write(s, req) })
			// A client that answers any request with a password, would it see one.
			go func() {
				var b [5]byte
				if _, err := io.ReadFull(p.client, b[:]); err == nil {
					p.client.Write(ms4('p', "secret\x00"))
				}
			}()
			if err := p.result(t); err == nil || !strings.Contains(err.Error(), "authentication request") {
				t.Fatalf("relay: %v", err)
			}
			if got := <-p.cluster; len(got) != 0 {
				t.Fatalf("cluster received %q", got)
			}
		})
	}
	t.Run("control: SASL", func(t *testing.T) {
		p := relayTo(t, metaClass(), func(s net.Conn) { write(s, rSASL) })
		if b := p.read(t, len(rSASL)); !bytes.Equal(b, rSASL) {
			t.Fatalf("got %q", b)
		}
	})
}

func TestAuth_OkOnlyAfterACompletedExchange(t *testing.T) {
	sasl2 := cat(rSASL, rSASL)
	for _, c := range []struct {
		name       string
		sent, seen []byte // what the cluster sends; what the client must see before the close
	}{
		{"ok first", rOK, nil},
		{"ok after SASL", cat(rSASL, rOK), rSASL},
		{"ok after continue", cat(rSASL, rCont, rOK), cat(rSASL, rCont)},
		{"a second SASL request", sasl2, rSASL},
		{"final without continue", cat(rSASL, rFinal), rSASL},
		{"continue repeated", cat(rSASL, rCont, rCont), cat(rSASL, rCont)},
		{"final repeated", cat(rSASL, rCont, rFinal, rFinal), cat(rSASL, rCont, rFinal)},
		{"continue first", rCont, nil},
		{"ok after the exchange, then ok", cat(login, rOK), login},
		{"ok after the exchange, then SASL", cat(login, rSASL), login},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := relayTo(t, metaClass(), func(s net.Conn) { write(s, c.sent) })
			p.closed(t, c.seen)
		})
	}
	t.Run("control: the exact sequence", func(t *testing.T) {
		run, ch := script(t, login)
		p := relayTo(t, metaClass(), run)
		if b := p.read(t, len(login)); !bytes.Equal(b, login) {
			t.Fatalf("got %q", b)
		}
		p.open(t, <-ch)
	})
}

func TestAuth_OnlyErrorsAndNoticesBeforeOk(t *testing.T) {
	for _, msg := range [][]byte{readyMsg, rowDesc(1), dataRow(16), paramMsg, m('K', make([]byte, 8)), ms4('C', "SELECT 1\x00"), m('W', make([]byte, 3))} {
		t.Run(string(msg[0]), func(t *testing.T) {
			p := relayTo(t, metaClass(), func(s net.Conn) { write(s, rSASL, msg) })
			p.closed(t, rSASL)
		})
	}
	t.Run("an error is relayed", func(t *testing.T) {
		e := ms4('E', "SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")
		p := relayTo(t, metaClass(), func(s net.Conn) { write(s, rSASL, rCont, e); s.Close() })
		if got := p.drain(t); !bytes.Equal(got, cat(rSASL, rCont, e)) {
			t.Fatalf("got %q", got)
		}
		if err := p.result(t); err != nil {
			t.Fatalf("relay: %v, want a close by the cluster", err)
		}
	})
	t.Run("a notice is relayed where the class relays notices", func(t *testing.T) {
		run, ch := script(t, rSASL, notice, rCont)
		p := relayTo(t, responseClass(), run)
		if got := p.read(t, len(rSASL)+len(notice)+len(rCont)); !bytes.Equal(got, cat(rSASL, notice, rCont)) {
			t.Fatalf("got %q", got)
		}
		<-ch
	})
}

func TestAuth_IterationFloorAndCap(t *testing.T) {
	capOnly := noneClass() // floor 1, cap 32768
	for _, c := range []struct {
		name  string
		class Class
		iter  int
		pass  bool
	}{
		{"above the cap", metaClass(), 4097, false},
		{"below the floor", metaClass(), 4095, false},
		{"equal to both", metaClass(), 4096, true},
		{"cap alone: a low count", capOnly, 10, true},
		{"cap alone: above the cap", capOnly, 32769, false},
		{"cap alone: a huge count", capOnly, 10000000, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			run, ch := script(t, rSASL, cont(c.iter))
			p := relayTo(t, c.class, run)
			if !c.pass {
				p.closed(t, rSASL)
				return
			}
			want := cat(rSASL, cont(c.iter))
			if got := p.read(t, len(want)); !bytes.Equal(got, want) {
				t.Fatalf("got %q", got)
			}
			<-ch
		})
	}
}

func totalAlloc() uint64 {
	var s runtime.MemStats
	runtime.ReadMemStats(&s)
	return s.TotalAlloc
}

// streamN writes a header announcing size bytes of body, then the body.
func streamN(s net.Conn, typ byte, size int) {
	chunk := make([]byte, 64<<10)
	if !write(s, binary.BigEndian.AppendUint32([]byte{typ}, uint32(4+size))) {
		return
	}
	for size > 0 {
		n := min(size, len(chunk))
		if _, err := s.Write(chunk[:n]); err != nil {
			return
		}
		size -= n
	}
}

func TestStreams_NeverHoldsAMessage(t *testing.T) {
	const size = 256 << 20 // four times the container's memory limit
	t.Run("relayed", func(t *testing.T) {
		before := totalAlloc()
		p := relayTo(t, noneClass(), func(s net.Conn) { write(s, login); streamN(s, 'D', size) })
		p.read(t, len(login)+5)
		if n, err := io.CopyN(io.Discard, p.client, size); err != nil {
			t.Fatalf("after %d bytes: %v", n, err)
		}
		if grew := totalAlloc() - before; grew > 1<<20 {
			t.Fatalf("relaying %d bytes allocated %d bytes", size, grew)
		}
	})
	t.Run("dropped", func(t *testing.T) {
		c := noneClass()
		c.DropNotices = true
		before := totalAlloc()
		p := relayTo(t, c, func(s net.Conn) { write(s, login); streamN(s, 'N', size); write(s, readyMsg) })
		if got := p.read(t, len(login)+len(readyMsg)); !bytes.Equal(got, cat(login, readyMsg)) {
			t.Fatalf("got %q", got[len(login):])
		}
		if grew := totalAlloc() - before; grew > 1<<20 {
			t.Fatalf("dropping %d bytes allocated %d bytes", size, grew)
		}
	})
}

func TestWindow_HeaderJudgedBeforeTheBody(t *testing.T) {
	const size = 64 << 20
	written := make(chan int, 1)
	p := relayTo(t, metaClass(), func(s net.Conn) {
		write(s, login)
		n := 0
		if write(s, binary.BigEndian.AppendUint32([]byte{'D'}, uint32(4+size))) {
			chunk := make([]byte, 16<<10)
			for n < size {
				k, err := s.Write(chunk)
				n += k
				if err != nil {
					break
				}
			}
		}
		written <- n
	})
	p.closed(t, login)
	if n := <-written; n >= size/4 {
		t.Fatalf("the cluster wrote %d of the body's %d bytes", n, size)
	}
}

func TestCopyBuffer_IsTheClassSize(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	old := newBuffer
	newBuffer = func(n int) []byte { mu.Lock(); sizes = append(sizes, n); mu.Unlock(); return old(n) }
	defer func() { newBuffer = old }()
	c := responseClass()
	c.CopyBufBytes, c.WindowBytes = 8<<10, 64<<20
	up := make([]byte, 4<<20)
	rand.Read(up)
	got := make(chan []byte, 1)
	p := relayTo(t, c, func(s net.Conn) {
		write(s, login)
		for range 100 {
			write(s, dataRow(100<<10))
		}
		b := make([]byte, len(up))
		io.ReadFull(s, b)
		got <- b
	})
	go p.client.Write(up)
	if _, err := io.CopyN(io.Discard, p.client, int64(len(login)+100*(100<<10))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(<-got, up) {
		t.Fatal("client bytes changed on the way")
	}
	p.client.Close()
	p.result(t)
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 2 || sizes[0] != c.CopyBufBytes || sizes[1] != c.CopyBufBytes {
		t.Fatalf("buffers %v, want two of %d", sizes, c.CopyBufBytes)
	}
}

func TestFault_EndsOnlyItsOwnConnection(t *testing.T) {
	old := faultHook
	faultHook = func(typ byte) {
		if typ == '!' {
			panic("marker")
		}
	}
	t.Cleanup(func() { faultHook = old }) // after relay B, which outlives the test's body, has ended
	runB, chB := script(t, login)
	b := relayTo(t, metaClass(), runB) // another project's connection, opened before
	b.read(t, len(login))
	sB := <-chB
	a := relayTo(t, metaClass(), func(s net.Conn) { write(s, login, ms4('!', "x")) })
	if err := a.closed(t, login); !strings.Contains(err.Error(), "fault") {
		t.Fatalf("relay: %v", err)
	}
	b.open(t, sB)
	if !write(b.client, ms4('Q', "select 1\x00")) {
		t.Fatal("client B closed")
	}
	got := make([]byte, 14)
	if _, err := io.ReadFull(sB, got); err != nil || got[0] != 'Q' {
		t.Fatalf("cluster B: %q %v", got, err)
	}
}

func TestBreach_ClosesBothSides(t *testing.T) {
	p := relayTo(t, metaClass(), func(s net.Conn) { write(s, authReq(3, "")) })
	select { // the cluster's side ends while the client has not closed its own
	case <-p.cluster:
	case <-time.After(30 * time.Second):
		t.Fatal("cluster side still open")
	}
	p.closed(t, nil)
}

func TestCopyBoth_ClassWithoutAStreamWindowRefuses(t *testing.T) {
	for _, c := range []Class{metaClass(), responseClass(), noneClass()} {
		t.Run(c.Name, func(t *testing.T) {
			p := relayTo(t, c, func(s net.Conn) { write(s, login, m('W', make([]byte, 3)), dataRow(16)) })
			p.closed(t, login)
		})
	}
}

// copyData is a copy-data message of size bytes in all.
func copyData(size int) []byte { return m('d', make([]byte, size-5)) }

func TestCopyBoth_SwitchesToTheStreamWindow(t *testing.T) {
	c := streamClass() // response window 1 MiB, stream 256 KiB per 50 ms
	w := m('W', make([]byte, 3))
	const n = 160 // 160 × 8 KiB = 1.25 MiB, over the response window
	p := relayTo(t, c, func(s net.Conn) {
		write(s, login, w)
		for range n {
			if !write(s, copyData(8<<10)) {
				return
			}
		}
		write(s, readyMsg)
		for { // after the stream, the response window again
			if !write(s, dataRow(64<<10)) {
				return
			}
		}
	}, opts{streams: &StreamSlots{}})
	p.read(t, len(login)+len(w))
	start := time.Now()
	p.read(t, n*(8<<10))
	// The rate, not the response window: five intervals' budget, paced.
	if d := time.Since(start); d < 3*50*time.Millisecond {
		t.Fatalf("1.25 MiB in %v, faster than the rate", d)
	}
	p.read(t, len(readyMsg))
	got := p.drain(t)
	if len(got) > 1<<20 {
		t.Fatalf("%d bytes in the response after the stream", len(got))
	}
	if err := p.result(t); err == nil || !strings.Contains(err.Error(), "byte window") {
		t.Fatalf("relay: %v", err)
	}
}

func TestStream_SecondConnectionOfAProjectRefused(t *testing.T) {
	w := m('W', make([]byte, 3))
	sliceA, sliceB := &StreamSlots{}, &StreamSlots{}
	run1, ch1 := script(t, login, w)
	a1 := relayTo(t, streamClass(), run1, opts{streams: sliceA})
	a1.read(t, len(login)+len(w))
	<-ch1
	a2 := relayTo(t, streamClass(), func(s net.Conn) { write(s, login, w) }, opts{streams: sliceA})
	a2.closed(t, login)
	runB, chB := script(t, login, w)
	b1 := relayTo(t, streamClass(), runB, opts{streams: sliceB})
	b1.read(t, len(login)+len(w))
	<-chB
}

func TestStream_ExcessIsPacedNotCut(t *testing.T) {
	c := streamClass()
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = 64<<10, 50
	w := m('W', make([]byte, 3))
	p := relayTo(t, c, func(s net.Conn) {
		write(s, login, w)
		for { // far more than the rate: as fast as the relay reads
			if !write(s, copyData(4<<10)) {
				return
			}
		}
	}, opts{streams: &StreamSlots{}})
	p.read(t, len(login)+len(w))
	budget := int(c.Stream.BytesPerInterval)
	p.read(t, 1)
	start := time.Now()
	p.read(t, 10*budget-1)
	d := time.Since(start)
	// Ten intervals' budget never arrives faster than the rate allows (nine
	// interval boundaries); a slower machine only reads it later.
	if d < 9*50*time.Millisecond || d > 20*time.Second {
		t.Fatalf("ten intervals' budget in %v", d)
	}
	p.read(t, budget) // still open: paced, not cut
	select {
	case err := <-p.done:
		t.Fatalf("relay ended: %v", err)
	default:
	}
}

func TestStream_EndsAtReadyForQuery(t *testing.T) {
	w := m('W', make([]byte, 3))
	slots := &StreamSlots{}
	run1, ch1 := script(t, login, w, copyData(1024), readyMsg)
	a1 := relayTo(t, streamClass(), run1, opts{streams: slots})
	a1.read(t, len(login)+len(w)+1024+len(readyMsg))
	s1 := <-ch1
	// The project's one place is free again: its next connection enters.
	run2, ch2 := script(t, login, w)
	a2 := relayTo(t, streamClass(), run2, opts{streams: slots})
	a2.read(t, len(login)+len(w))
	<-ch2
	// The first connection is in a response window again (1 MiB).
	go func() {
		for write(s1, dataRow(64<<10)) {
		}
	}()
	if got := a1.drain(t); len(got) > 1<<20 {
		t.Fatalf("%d bytes after the stream", len(got))
	}
}

func repeat(b []byte, n int) []byte { return bytes.Repeat(b, n) }

func TestCountCaps_PerWindow(t *testing.T) {
	t.Run("connection: the 65th parameter status of its life", func(t *testing.T) {
		run, ch := script(t, login, repeat(paramMsg, 62), readyMsg) // 2 in the greeting + 62
		p := relayTo(t, metaClass(), run)
		p.read(t, len(login)+62*len(paramMsg)+len(readyMsg))
		s := <-ch
		write(s, paramMsg)
		p.closed(t, nil)
	})
	t.Run("response: 64 in each of 1000 responses, closed at 65 in one", func(t *testing.T) {
		resp := cat(repeat(paramMsg, 64), readyMsg)
		run, ch := script(t, login)
		p := relayTo(t, responseClass(), run)
		p.read(t, len(login))
		s := <-ch
		go func() {
			for range 1000 {
				write(s, resp)
			}
			write(s, repeat(paramMsg, 65))
		}()
		if got := p.drain(t); len(got) != 1000*len(resp)+64*len(paramMsg) {
			t.Fatalf("received %d bytes", len(got))
		}
	})
	t.Run("none: counted in the startup only", func(t *testing.T) {
		run, ch := script(t, login, repeat(paramMsg, 10000), readyMsg)
		p := relayTo(t, noneClass(), run)
		p.read(t, len(login)+10000*len(paramMsg)+len(readyMsg))
		<-ch
		big := cat(rSASL, rCont, rFinal, rOK, repeat(paramMsg, 65))
		q := relayTo(t, noneClass(), func(s net.Conn) { write(s, big, readyMsg) })
		q.closed(t, big[:len(big)-len(paramMsg)])
	})
}

func TestWindow_BytesPerConnection(t *testing.T) {
	c := metaClass()
	c.WindowBytes = 256 << 10
	rest := int(c.WindowBytes) - len(login) - len(readyMsg)
	exact := cat(dataRow(rest-100<<10), dataRow(100<<10), readyMsg)
	t.Run("exactly the budget passes", func(t *testing.T) {
		run, ch := script(t, login, exact)
		p := relayTo(t, c, run)
		p.read(t, len(login)+len(exact))
		s := <-ch
		write(s, readyMsg) // one byte past it is not
		p.closed(t, nil)
	})
	t.Run("one byte over the budget is closed at that header", func(t *testing.T) {
		rows := cat(dataRow(rest-100<<10), dataRow(100<<10+1)) // the ReadyForQuery after them is one byte over
		p := relayTo(t, c, func(s net.Conn) { write(s, login, rows, readyMsg) })
		p.closed(t, cat(login, rows))
	})
	t.Run("endless rows end at the budget", func(t *testing.T) {
		p := relayTo(t, c, func(s net.Conn) {
			write(s, login)
			for write(s, dataRow(1024)) {
			}
		})
		got := p.drain(t)
		if len(got) > int(c.WindowBytes) || len(got) < int(c.WindowBytes)-1024 {
			t.Fatalf("received %d bytes, window %d", len(got), c.WindowBytes)
		}
	})
}

func TestWindow_BytesPerResponse(t *testing.T) {
	c := responseClass()
	c.WindowBytes = 128 << 10
	resp := cat(dataRow(int(c.WindowBytes)-len(readyMsg)), readyMsg) // exactly the budget
	run, ch := script(t, login)
	p := relayTo(t, c, run)
	p.read(t, len(login))
	s := <-ch
	go func() {
		for range 3 {
			write(s, resp)
		}
		for write(s, dataRow(1024)) {
		}
	}()
	got := p.drain(t)
	if n := len(got) - 3*len(resp); n < 0 || n > int(c.WindowBytes) || n < int(c.WindowBytes)-1024 {
		t.Fatalf("received %d bytes after three full responses", n)
	}
}

func TestMessageCap_WhenSet(t *testing.T) {
	c := responseClass()
	c.MessageBytes, c.WindowBytes = 256<<10, 64<<20
	ok, over := dataRow(256<<10+1), dataRow(256<<10+2) // lengths 256 KiB and one more
	run, ch := script(t, login, ok)
	p := relayTo(t, c, run)
	p.read(t, len(login)+len(ok))
	s := <-ch
	write(s, over)
	p.closed(t, nil)
	t.Run("none when 0", func(t *testing.T) {
		big := dataRow(8 << 20)
		run, ch := script(t, login, big)
		p := relayTo(t, noneClass(), run)
		p.read(t, len(login)+len(big))
		<-ch
	})
}

func TestRowDescription_FieldCap(t *testing.T) {
	run, ch := script(t, login, rowDesc(1664))
	p := relayTo(t, metaClass(), run)
	p.read(t, len(login)+len(rowDesc(1664)))
	<-ch
	q := relayTo(t, metaClass(), func(s net.Conn) { write(s, login, rowDesc(32767)) })
	q.closed(t, login)
	r := relayTo(t, metaClass(), func(s net.Conn) { write(s, login, m('T', []byte{1})) }) // one byte: malformed
	r.closed(t, login)
}

func TestNotices_CountedAndDropped(t *testing.T) {
	notify := ms4('A', "\x00\x00\x00\x01chan\x00payload\x00")
	run, ch := script(t, login, repeat(notice, 100), notify, readyMsg)
	p := relayTo(t, metaClass(), run) // drops, no cap
	if got := p.read(t, len(login)+len(readyMsg)); !bytes.Equal(got, cat(login, readyMsg)) {
		t.Fatalf("got %q", got[len(login):])
	}
	<-ch
	c := metaClass()
	c.NoticesMax = 3
	q := relayTo(t, c, func(s net.Conn) { write(s, login, repeat(notice, 3), readyMsg, notice) })
	q.closed(t, cat(login, readyMsg))
}

func TestNotices_RelayedWhenTheClassSaysSo(t *testing.T) {
	notify := ms4('A', "\x00\x00\x00\x01chan\x00payload\x00")
	want := cat(login, notice, notify, readyMsg)
	run, ch := script(t, want)
	p := relayTo(t, responseClass(), run)
	if got := p.read(t, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	<-ch
}

// silentListener is a TCP port that never completes a handshake: its accept
// queue (backlog 0) is held full by one connection, so a new SYN is dropped.
func silentListener(t *testing.T) netip.AddrPort {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	sa, _ := syscall.Getsockname(fd)
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(sa.(*syscall.SockaddrInet4).Port))
	held, err := net.DialTimeout("tcp4", ap.String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { held.Close() })
	probe, err := net.DialTimeout("tcp4", ap.String(), 200*time.Millisecond)
	if err == nil {
		probe.Close()
		t.Skip("this kernel completes handshakes over a full accept queue")
	}
	return ap
}

func TestDial_Deadline(t *testing.T) {
	c := metaClass()
	c.DialMS = 300
	start := time.Now()
	p := relayTo(t, c, nil, opts{to: silentListener(t)})
	if err := p.closed(t, nil); !strings.Contains(err.Error(), "dial") {
		t.Fatalf("relay: %v", err)
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("closed after %v, before the dial deadline", d)
	}
}

func TestAuth_Deadline(t *testing.T) {
	c := metaClass()
	c.AuthMS = 300
	start := time.Now()
	p := relayTo(t, c, func(s net.Conn) { write(s, rSASL, rCont, rFinal) }) // never the ok
	if err := p.closed(t, cat(rSASL, rCont, rFinal)); err != errAuthDeadline {
		t.Fatalf("relay: %v", err)
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("closed after %v", d)
	}
	t.Run("control: an ok in time holds past the deadline", func(t *testing.T) {
		run, ch := script(t, login)
		p := relayTo(t, c, run)
		p.read(t, len(login))
		s := <-ch
		time.Sleep(600 * time.Millisecond)
		p.open(t, s)
	})
}

func TestWallClock_OnlyWhenSet(t *testing.T) {
	ticking := func(s net.Conn) {
		write(s, login)
		for write(s, readyMsg) {
			time.Sleep(20 * time.Millisecond)
		}
	}
	c := metaClass()
	c.WallMS = 400
	start := time.Now()
	p := relayTo(t, c, ticking)
	p.drain(t)
	if err := p.result(t); err != errWallClock || time.Since(start) < 400*time.Millisecond {
		t.Fatalf("relay: %v after %v", err, time.Since(start))
	}
	c.WallMS = 0
	q := relayTo(t, c, ticking)
	q.read(t, len(login))
	time.Sleep(800 * time.Millisecond)
	q.read(t, len(readyMsg))
	select {
	case err := <-q.done:
		t.Fatalf("relay ended without a wall clock: %v", err)
	default:
	}
}

func TestStallAndTrickle_EndAtTheWallClock(t *testing.T) {
	c := metaClass()
	c.WallMS = 400
	for name, run := range map[string]func(net.Conn){
		"stall": func(s net.Conn) { write(s, login) },
		"trickle": func(s net.Conn) {
			write(s, login, binary.BigEndian.AppendUint32([]byte{'D'}, 1<<20))
			for write(s, []byte{0}) {
				time.Sleep(20 * time.Millisecond)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			p := relayTo(t, c, run)
			p.drain(t)
			if err := p.result(t); err != errWallClock || time.Since(start) < 400*time.Millisecond {
				t.Fatalf("relay: %v after %v", err, time.Since(start))
			}
		})
	}
}

func TestClientBytes_RelayedUnread(t *testing.T) {
	// The relay saw only the first eight bytes of the test's startup packet;
	// what follows — the rest of it, a replication startup, messages a server
	// would refuse, random bytes — reaches the cluster as sent.
	junk := make([]byte, 1<<20)
	rand.Read(junk)
	sent := cat(startupPacket("user\x00u\x00replication\x00database\x00\x00"), authReq(3, ""), m('Q', make([]byte, 1<<16)),
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff}, junk)
	p := relayTo(t, metaClass(), nil)
	write(p.client, sent)
	p.client.(*net.TCPConn).CloseWrite()
	got := <-p.cluster
	if !bytes.Equal(got, sent) {
		t.Fatalf("cluster received %d bytes, client sent %d", len(got), len(sent))
	}
}

// The owner of the listening sockets closes a connection from outside by
// cancelling the context it gave Relay — how every connection of a slice that
// left the table is cut. Mid-message, in the stream state: both sides close,
// Relay returns (its goroutines with it), the slice's place in the stream
// state is free again; another connection beside it is untouched.
func TestRelay_CloseFromOutsideEndsThatConnectionOnly(t *testing.T) {
	w := m('W', make([]byte, 3))
	slots := &StreamSlots{}
	runA, chA := script(t, login, w, binary.BigEndian.AppendUint32([]byte{'d'}, 4+200<<10), make([]byte, 64<<10)) // under the message cap
	a := relayTo(t, streamClass(), runA, opts{streams: slots})
	a.read(t, len(login)+len(w)+5+64<<10)
	sA := <-chA
	runB, chB := script(t, login)
	b := relayTo(t, metaClass(), runB)
	b.read(t, len(login))
	sB := <-chB
	a.cancel()
	if err := a.closed(t, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("relay: %v", err)
	}
	if n, err := sA.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("cluster side: %d %v, want its end", n, err)
	}
	runC, chC := script(t, login, w)
	c := relayTo(t, streamClass(), runC, opts{streams: slots})
	c.read(t, len(login)+len(w))
	<-chC
	b.open(t, sB)
}

func TestDial_SocketBuffersSetBeforeConnect(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	d := net.Dialer{Control: socketBuffers(8 << 10)}
	c, err := d.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rc, _ := c.(*net.TCPConn).SyscallConn()
	rc.Control(func(fd uintptr) {
		for _, opt := range []int{syscall.SO_RCVBUF, syscall.SO_SNDBUF} {
			if v, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt); err != nil || v != 16<<10 {
				t.Errorf("option %d: %d %v, want twice 8 KiB", opt, v, err)
			}
		}
	})
}

// The one message read whole is an authentication request of at most 1 KiB.
func TestAuth_RequestReadWholeIsBounded(t *testing.T) {
	pad := func(length int) []byte { // a SASL request of the given length
		return authReq(10, "SCRAM-SHA-256\x00"+strings.Repeat("x", length-4-4-14-1)+"\x00")
	}
	if len(pad(1024)) != 1025 {
		t.Fatal("helper")
	}
	p := relayTo(t, metaClass(), func(s net.Conn) { write(s, pad(1025)) })
	if err := p.closed(t, nil); !strings.Contains(err.Error(), "authentication request of 1025 bytes") {
		t.Fatalf("relay: %v", err)
	}
	run, ch := script(t, pad(1024))
	q := relayTo(t, metaClass(), run)
	q.read(t, 1025)
	<-ch
}

// In the stream state the count caps apply per interval: sixty-four
// parameter-status messages in each of two intervals pass, sixty-five in one
// close the connection.
func TestCountCaps_PerStreamInterval(t *testing.T) {
	w := m('W', make([]byte, 3))
	run, ch := script(t, login, w, repeat(paramMsg, 64))
	p := relayTo(t, streamClass(), run, opts{streams: &StreamSlots{}}) // interval 50 ms
	p.read(t, len(login)+len(w)+64*len(paramMsg))
	s := <-ch
	time.Sleep(300 * time.Millisecond) // a later interval
	write(s, repeat(paramMsg, 64))
	p.read(t, 64*len(paramMsg))
	q := relayTo(t, streamClass(), func(s net.Conn) { write(s, login, w, repeat(paramMsg, 65)) }, opts{streams: &StreamSlots{}})
	q.closed(t, cat(login, w, repeat(paramMsg, 64)))
}

// A connection handed over without a source address is refused before any
// dial: the kernel never picks the source.
func TestDial_NoSourceAddressRefused(t *testing.T) {
	p := relayTo(t, metaClass(), nil, opts{edit: func(c *Conn) { c.From = netip.Addr{} }})
	if err := p.closed(t, nil); !strings.Contains(err.Error(), "no IPv4 source address") {
		t.Fatalf("relay: %v", err)
	}
}
