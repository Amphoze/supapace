package pgcap

import (
	"bytes"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/pgwire"
)

// first8 is the start of a packet: its length and its code.
func first8(length, code uint32) []byte {
	return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, length), code)
}

const (
	codeTLS    = 80877103
	codeGSS    = 80877104
	codeCancel = 80877102
	proto30    = 196608
)

// A first eight bytes with a code of the request family in any form but the
// three exact ones is closed unanswered and nothing is dialled; a startup of
// protocol 3.0 is relayed.
func TestPreamble_RequestCodeInAnotherFormIsNotAStartup(t *testing.T) {
	r := newRig(t, nil)
	f := r.cluster(3)
	for name, b := range map[string][]byte{
		"an encryption request of length 12": append(first8(12, codeTLS), 0, 0, 0, 0),
		"a GSS request of length 12":         append(first8(12, codeGSS), 0, 0, 0, 0),
		"a cancel of length 8":               first8(8, codeCancel),
		"a cancel of length 20":              append(first8(20, codeCancel), make([]byte, 12)...),
		"an unknown code of the family":      first8(8, 1234<<16|5678),
		"another unknown code, length 16":    append(first8(16, 1234<<16|1), make([]byte, 8)...),
	} {
		c := r.mustDial(peerA1, "a", 3)
		c.Write(b)
		t.Run(name, func(t *testing.T) { unanswered(t, c) })
	}
	if f.count() != 0 {
		t.Fatalf("the cluster was dialled %d times", f.count())
	}
	r.served(peerA1, "a", 3) // control
	if f.count() != 1 {
		t.Fatalf("the control: %d dials", f.count())
	}
}

// An encryption request is answered N and not forwarded: the cluster's first
// bytes are the startup packet that follows.
func TestEncryptionRequest_AnsweredAndNotForwarded(t *testing.T) {
	r := newRig(t, nil)
	f := r.cluster(3)
	for n, reqs := range [][]uint32{{codeTLS}, {codeGSS}, {codeTLS, codeGSS}, {codeGSS, codeTLS}} {
		c := r.mustDial(peerA1, "a", 3)
		for _, code := range reqs {
			c.Write(first8(8, code))
			if b := make([]byte, 1); !readAll(c, b) || b[0] != 'N' {
				t.Fatalf("%v: got %q, want N", reqs, b)
			}
		}
		c.Write(rigStartup)
		if b := make([]byte, len(login)); !readAll(c, b) || !bytes.Equal(b, login) {
			t.Fatalf("%v: the startup after it was not relayed", reqs)
		}
		f.mu.Lock()
		got := f.firsts[n]
		f.mu.Unlock()
		if !bytes.Equal(got, rigStartup[:8]) {
			t.Fatalf("%v: the cluster's first bytes %q, want the startup packet's", reqs, got)
		}
	}
}

// A second TLS request, a second GSS request and a third request of any kind
// each close the connection; nothing is dialled.
func TestEncryptionRequest_AtMostOneOfEachKind(t *testing.T) {
	r := newRig(t, nil)
	f := r.cluster(3)
	for _, reqs := range [][]uint32{{codeTLS, codeTLS}, {codeGSS, codeGSS}, {codeTLS, codeGSS, codeTLS}, {codeGSS, codeTLS, codeGSS}} {
		c := r.mustDial(peerA1, "a", 3)
		for _, code := range reqs[:len(reqs)-1] {
			c.Write(first8(8, code))
			if b := make([]byte, 1); !readAll(c, b) || b[0] != 'N' {
				t.Fatalf("%v: got %q, want N", reqs, b)
			}
		}
		c.Write(first8(8, reqs[len(reqs)-1]))
		unanswered(t, c)
	}
	if f.count() != 0 {
		t.Fatalf("the cluster was dialled %d times", f.count())
	}
}

// A socket from an address outside the class's list, or from another class's
// peer, is closed unanswered and holds no unit of the ceiling and no place of
// the pool; with the tag nopeer it is served. A socket whose local address is
// not the table's listen (a table that listens on every address) is closed.
func TestAccept_PeerAndLocalAddress(t *testing.T) {
	r := newRig(t, withB)
	r.cluster(3)
	for _, from := range []byte{stranger, peerB} {
		if !peerCheck {
			r.served(from, "a", 3).Close()
			continue
		}
		c := r.mustDial(from, "a", 3)
		unanswered(t, c)
		if u, pool := r.counts("a"); u != 0 || pool != 0 {
			t.Fatalf(".%d: %d units and %d places held by a refused peer", from, u, pool)
		}
	}
	// Control: the class's peer holds a unit and a place while it is silent.
	r.mustDial(peerA1, "a", 3)
	until(t, "a silent peer holds a unit and a place", func() bool { u, p := r.counts("a"); return u == 1 && p == 1 })

	if !peerCheck {
		return
	}
	// A socket whose local address is not the table's: accepted on another
	// address of this host and handed to the proxy as its accept loop would.
	client, acc := handed(t, r, peerA2, 7, rigStartup)
	r.p.mu.Lock()
	s := r.p.slots[member{3, "a"}]
	r.p.mu.Unlock()
	r.p.accept(s, acc, time.Now())
	unanswered(t, client)
	if u, pool := r.counts("a"); u != 1 || pool != 1 {
		t.Fatalf("%d units and %d places held, want the silent peer's alone", u, pool)
	}
}

// handed returns a connection from the rig's address .from to its address
// .local, with sent already queued at the accepted end: a socket for the
// proxy's accept, which the test calls as the accept loop would.
func handed(t *testing.T, r *rig, from, local byte, sent []byte) (net.Conn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp4", r.addr(local).String()+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: r.addr(from).AsSlice()}}).Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(60 * time.Second))
	client.Write(sent)
	a, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	acc := a.(*net.TCPConn)
	if len(sent) >= 8 {
		until(t, "the bytes queued", func() bool {
			n := 0
			rc, _ := acc.SyscallConn()
			rc.Control(func(fd uintptr) {
				n, _, _ = syscall.Recvfrom(int(fd), make([]byte, len(sent)), syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
			})
			return n == len(sent)
		})
	}
	return client, acc
}

// With max_conns units held the next socket is closed without a byte; a flood
// of them leaves the process's open files and heap where they were.
func TestCeiling_NodeWide_ClosedUnanswered(t *testing.T) {
	r := newRig(t, nil)
	r.cluster(3)
	r.p.mu.Lock()
	r.p.units = r.p.tb.MaxConns // what every term at its cap holds; no table reaches it but in passing
	r.p.mu.Unlock()
	c := r.mustDial(peerA1, "a", 3)
	c.Write(rigStartup)
	unanswered(t, c)
	files := openFiles(t)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: r.addr(peerA1).AsSlice()}}
	for range 2000 {
		c, err := d.Dial("tcp4", netip.AddrPortFrom(r.addr(1), uint16(r.port("a", 3))).String())
		if err != nil {
			t.Fatal(err)
		}
		io.ReadAll(c)
		c.Close()
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if got := settle(files, func() int { return openFiles(t) }); got > files {
		t.Errorf("%d open files after the flood, %d before", got, files)
	}
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 1<<20 {
		t.Errorf("the heap grew by %d bytes over 2,000 refused sockets", grew)
	}
	r.p.mu.Lock()
	r.p.units -= r.p.tb.MaxConns
	r.p.mu.Unlock()
	if u, _ := r.counts("a"); u != 0 {
		t.Fatalf("%d units held after the flood", u)
	}
	r.served(peerA1, "a", 3) // control
}

// Sockets silent in the preamble each hold a unit of the ceiling and a place of
// their class's pool: the seventeenth on a class's ports is closed unanswered
// while another class's port still accepts; both are released at preamble_ms.
func TestCeiling_EveryAcceptedSocketCounts(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		withB(tb)
		tb.PreambleMS = 1500
		tb.Slices["3"]["b"] = 5
	})
	var silent []net.Conn
	t0 := time.Now()
	for i := range 16 {
		silent = append(silent, r.mustDial(peerA1+byte(i%2), "a", []int{3, 7}[i%2]))
	}
	until(t, "sixteen silent sockets hold sixteen units and places", func() bool {
		u, p := r.counts("a")
		return u == 16 && p == 16
	})
	unanswered(t, r.mustDial(peerA2, "a", 7))
	b := r.mustDial(peerB, "b", 3)
	until(t, "class b's socket is held", func() bool {
		u, p := r.counts("b")
		return u == 17 && p == 1
	})
	for _, c := range append(silent, b) {
		unanswered(t, c)
	}
	if d := time.Since(t0); d < 1500*time.Millisecond {
		t.Fatalf("silent sockets closed after %v, before preamble_ms", d)
	}
	until(t, "all released", func() bool {
		u, pa := r.counts("a")
		_, pb := r.counts("b")
		return u == 0 && pa == 0 && pb == 0
	})
}

// The sixth connection of a project reads FATAL 53300 "too many connections"
// after its startup packet has been read, with nothing dialled, while another
// project's first is served.
func TestConnCap_PerProject_ClientReadsTooManyConnections(t *testing.T) {
	r := newRig(t, nil)
	f := r.cluster(3)
	r.cluster(7)
	for range 5 {
		r.served(peerA1, "a", 3)
	}
	c := r.mustDial(peerA2, "a", 3)
	c.Write(rigStartup[:12])
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("answered before the startup packet was whole")
	}
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Write(rigStartup[12:])
	if got, err := io.ReadAll(c); !bytes.Equal(got, pgwire.TooManyConnections()) || err != nil {
		t.Fatalf("got %q (%v)", got, err)
	}
	if f.count() != 5 {
		t.Fatalf("%d dials for six connections", f.count())
	}
	r.served(peerA2, "a", 7)
	if !strings.Contains(r.logs.String(), "the project's allowance") {
		t.Fatalf("log: %s", r.logs)
	}
}

// The seventeenth connection from one peer is refused; the other peer's first
// is served.
func TestConnCap_PerPeer(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.Slices["9"], tb.Slices["11"] = map[string]int{"a": 5}, map[string]int{"a": 5} })
	for _, i := range []int{3, 7, 9, 11} {
		r.cluster(i)
	}
	for n := range 16 {
		r.served(peerA1, "a", []int{3, 7, 9, 11}[n/5])
	}
	refused(t, r.mustDial(peerA1, "a", 11))
	r.served(peerA2, "a", 11)
	if !strings.Contains(r.logs.String(), "the peer's cap") {
		t.Fatalf("log: %s", r.logs)
	}
}

// A refused client that states a length of 10,001 or of 4 is closed
// unanswered; one that sends half a packet and then nothing is closed
// unanswered at preamble_ms. Control: a whole packet reads the refusal.
func TestRefusal_StartupReadIsBounded(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.PreambleMS = 800; tb.Slices["3"]["a"] = 0 })
	for _, n := range []uint32{10001, 4} {
		c := r.mustDial(peerA1, "a", 3)
		c.Write(first8(n, proto30))
		unanswered(t, c)
	}
	c := r.mustDial(peerA1, "a", 3)
	t0 := time.Now()
	c.Write(rigStartup[:len(rigStartup)/2])
	unanswered(t, c)
	if d := time.Since(t0); d < 700*time.Millisecond {
		t.Fatalf("closed after %v, before preamble_ms", d)
	}
	refused(t, r.mustDial(peerA1, "a", 3))
}

// With a class's refusals_max refusals held open by slow clients, the next
// over-cap connection of that class is closed unanswered, and a second class's
// over-cap connection is still answered 53300.
func TestRefusalsInFlight_CappedThenUnanswered(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		withB(tb)
		tb.Classes[0].RefusalsMax, tb.Classes[1].RefusalsMax = 4, 4
		tb.PreambleMS = 20000
		tb.Slices["3"] = map[string]int{"a": 0, "b": 0}
	})
	for range 4 {
		c := r.mustDial(peerA1, "a", 3)
		c.Write(first8(100, proto30)) // the rest never comes
	}
	until(t, "four refusals in flight", func() bool { _, p := r.counts("a"); return p == 4 })
	c := r.mustDial(peerA2, "a", 3)
	c.Write(rigStartup)
	unanswered(t, c)
	refused(t, r.mustDial(peerB, "b", 3))
}

// Both peers open their sixteen connections at the same instant, each sending
// its startup at once, a hundred times over. At the class's pool of sixteen the
// number of runs in which one was not admitted is recorded: a socket accepted
// before its first eight bytes have arrived waits, and holds a place, so it
// depends on how the clients are scheduled. With a pool of the two peers'
// caps — every honest connection of the class waiting at once — all thirty-two
// are admitted in every run.
func TestRefusalPool_ThirtyTwoHonestConnectsAtOnce(t *testing.T) {
	runs := 100
	if testing.Short() {
		runs = 10
	}
	for _, pool := range []int{16, 32} {
		r := newRig(t, func(tb *Table) {
			tb.Slices = map[string]map[string]int{}
			for i := range 8 {
				tb.Slices[strconv.Itoa(i)] = map[string]int{"a": 5}
			}
			// The test is of the pool: the rate is set out of the way, and so are
			// the deadlines a loaded machine with few processors could meet.
			tb.Classes[0].ConnsPerSecond, tb.Classes[0].ConnsBurst = 1<<20, 1<<20
			tb.Classes[0].DialMS, tb.Classes[0].AuthMS, tb.Classes[0].WallMS, tb.PreambleMS = 60000, 60000, 0, 60000
			tb.Classes[0].RefusalsMax = pool
		})
		for i := range 8 {
			r.cluster(i)
		}
		failed := 0
		for range runs {
			start := make(chan struct{})
			var wg sync.WaitGroup
			var refused atomic.Int32
			for n := range 32 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, err := r.dial0(byte(peerA1+n%2), n%8, start)
					if err != nil {
						refused.Add(1)
						return
					}
					defer c.Close()
					if b := make([]byte, len(login)); !readAll(c, b) || !bytes.Equal(b, login) {
						refused.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			if refused.Load() > 0 {
				failed++
			}
			until(t, "every unit released", func() bool { u, p := r.counts("a"); return u == 0 && p == 0 })
		}
		t.Logf("pool %d: %d of %d runs had a connection not admitted", pool, failed, runs)
		if pool == 32 && failed > 0 {
			t.Fatalf("pool %d: %d runs refused an honest connection (log: %s)", pool, failed, r.logs)
		}
	}
}

// Every clock of an admitted connection runs from the accept: a client that
// waits in the preamble before its startup has that time counted against the
// authentication deadline.
func TestAccept_ClocksRunFromTheAccept(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.Classes[0].AuthMS = 2000; tb.PreambleMS = 10000 })
	r.cluster(3).mute.Store(true)
	c := r.mustDial(peerA1, "a", 3)
	t0 := time.Now()
	time.Sleep(1800 * time.Millisecond) // the client's own pause before its startup
	c.Write(rigStartup)
	unanswered(t, c)
	if d := time.Since(t0); d < 1900*time.Millisecond || d > 3200*time.Millisecond {
		t.Fatalf("closed %v after the accept, want the authentication deadline of 2 s from the accept, not from the startup", d)
	}
}

// dial0 waits for start, then connects and writes its startup at once.
func (r *rig) dial0(from byte, i int, start chan struct{}) (net.Conn, error) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: r.addr(from).AsSlice()}, Timeout: 30 * time.Second}
	to := netip.AddrPortFrom(r.addr(1), uint16(r.port("a", i))).String()
	<-start
	c, err := d.Dial("tcp4", to)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(60 * time.Second))
	_, err = c.Write(rigStartup)
	return c, err
}

// Reconnects of one slice faster than its rate beyond the burst are refused and
// dial nothing, while another slice's connections at the same moment are
// admitted; after a second the first slice is admitted again.
func TestConnRate_PerProject(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.Classes[0].ConnsPerSecond, tb.Classes[0].ConnsBurst = 1, 2 })
	f := r.cluster(3)
	r.cluster(7)
	t0 := time.Now()
	r.served(peerA1, "a", 3).Close()
	r.served(peerA1, "a", 3).Close()
	refused(t, r.mustDial(peerA1, "a", 3))
	if d := time.Since(t0); d > 900*time.Millisecond {
		t.Skipf("the three connects took %v: too slow a machine to tell the rate from its refill", d)
	}
	r.served(peerA1, "a", 7)
	r.served(peerA1, "a", 7)
	if f.count() != 2 {
		t.Fatalf("slice 3's cluster dialled %d times", f.count())
	}
	time.Sleep(time.Until(t0.Add(1100 * time.Millisecond))) // the time the rate refills one token in
	r.served(peerA1, "a", 3)
	if !strings.Contains(r.logs.String(), "connection rate") {
		t.Fatalf("log: %s", r.logs)
	}
}

// One line a second per class and slice index, with the count of what was not
// printed; another index or class has its own.
func TestLog_RateLimitedPerClassAndIndex(t *testing.T) {
	var out lockedBuf
	l := newLogger(&out)
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	for range 100 {
		l.conn(member{3, "a"}, "x")
	}
	l.conn(member{7, "a"}, "y")
	l.conn(member{3, "b"}, "z")
	now = now.Add(999 * time.Millisecond)
	l.conn(member{3, "a"}, "x")
	now = now.Add(time.Millisecond)
	l.conn(member{3, "a"}, "w")
	want := `{"class":"a","index":3,"reason":"x"}
{"class":"a","index":7,"reason":"y"}
{"class":"b","index":3,"reason":"z"}
{"class":"a","index":3,"reason":"w","not_printed":100}
`
	if out.String() != want {
		t.Fatalf("got\n%s", out.String())
	}
}

// A table with a second class of other ports, peers, window kind, buffers,
// rate and caps is served by the same program: the second class streams where
// the first refuses a copy-both.
func TestSecondClass_IsATableRow(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		withB(tb)
		b := &tb.Classes[1]
		b.Window, b.WindowBytes, b.MessageBytes, b.WallMS = WindowResponse, 1<<20, 256<<10, 0
		b.CopyBufBytes, b.SockBufBytes, b.ConnsPerSecond, b.ConnsBurst = 16<<10, 16<<10, 50, 20
		b.ConnsPerPeer, b.CancelsPerPeer, b.NoticesMax, b.DropNotices = 0, 0, 100, false
		b.Stream = &Stream{ConnsPerProject: 1, BytesPerInterval: 1 << 20, IntervalMS: 100}
		tb.Slices["3"]["b"] = 3
	})
	r.cluster(3)
	a := r.served(peerA1, "a", 3)
	b := r.served(peerB, "b", 3)
	query(t, a)
	query(t, b)
	for _, c := range []net.Conn{a, b} {
		c.Write(m('Q', []byte("copy\x00")))
	}
	if got, _ := io.ReadAll(a); len(got) != 0 {
		t.Fatalf("class a received %q of a copy-both its class refuses", got)
	}
	if want := cat(m('W', []byte{0, 0, 0}), copyData(100)); !readAll(b, make([]byte, len(want))) {
		t.Fatal("class b's copy-both was not relayed")
	}
	until(t, "the breach logged", func() bool {
		return strings.Contains(r.logs.String(), `"class":"a","index":3,"reason":"copy-both refused by the class"`)
	})
}

// No class name and no figure of a class is written in the program: a class is
// a row of the table.
func TestSecondClass_NoClassInTheProgram(t *testing.T) {
	figures := map[string]bool{}
	for _, v := range []string{"20000", "2000", "3000", "10000", "55000", "4096", "1664", "65536", "32768", "12582912", "64"} {
		figures[v] = true
	}
	for _, dir := range []string{".", "../../cmd/pgcap"} {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
		if err != nil || len(pkgs) == 0 {
			t.Fatalf("%s: %v", dir, err)
		}
		for _, p := range pkgs {
			for name, f := range p.Files {
				ast.Inspect(f, func(n ast.Node) bool {
					if l, ok := n.(*ast.BasicLit); ok && (figures[l.Value] || strings.Contains(strings.ToLower(l.Value), "meta")) {
						t.Errorf("%s: %s %s", filepath.Base(name), fset.Position(l.Pos()), l.Value)
					}
					return true
				})
			}
		}
	}
}

// The preamble deadline bounds the preamble only: an admitted connection is
// relayed past it.
func TestAccept_PreambleDeadlineEndsAtAdmission(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.PreambleMS = 300 })
	r.cluster(3)
	c := r.served(peerA1, "a", 3)
	time.Sleep(time.Second) // past the preamble deadline
	query(t, c)
}

// The bucket refills at the class's rate and saves no more than its burst: a
// slice idle for a minute has the burst, not a minute's worth.
func TestConnRate_BurstCapsWhatAnIdleSliceSaves(t *testing.T) {
	c := Class{ConnsPerSecond: 2, ConnsBurst: 3}
	t0 := time.Unix(1000, 0)
	s := &slot{tokens: 3, last: t0}
	took := 0
	for s.take(t0.Add(time.Minute), c) {
		took++
	}
	if took != 3 {
		t.Fatalf("after a minute idle %d connections at once, want the burst of 3", took)
	}
	if s.take(t0.Add(time.Minute+400*time.Millisecond), c) || !s.take(t0.Add(time.Minute+500*time.Millisecond), c) {
		t.Fatal("one token refills in half a second at two a second")
	}
}
