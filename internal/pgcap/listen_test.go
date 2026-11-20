package pgcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/pgwire"
)

// rig is one proxy on loopback addresses of its own: it listens on 127.X.0.1;
// class "a" has the peers 127.X.0.2 and .3, a second class "b" the peer .9, and
// .8 is a stranger; the block 127.X.4.0/22 is cut into sixteen slices of /26, so
// slice i's cluster is at 127.X.4.(64i+2) port 5432 and the proxy dials from
// .(64i+4). Every table it serves is written with Marshal, by rename.
type rig struct {
	t    *testing.T
	x    byte
	path string
	p    *proxy
	logs *lockedBuf
}

var rigSeq atomic.Uint32

// rigOctet claims a second octet X for the rig, across processes too: it holds a
// socket bound to 127.X.255.254 port 65000 until the test ends, and takes the
// next X while another holds it.
func rigOctet(t *testing.T) byte {
	t.Helper()
	for range 224 {
		x := byte(16 + (rigSeq.Add(1)+uint32(os.Getpid()))%224)
		if l, err := net.Listen("tcp4", netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, x, 255, 254}), 65000).String()); err == nil {
			t.Cleanup(func() { l.Close() })
			return x
		}
	}
	t.Fatal("no loopback block free for the rig")
	return 0
}

const (
	peerA1, peerA2, stranger, peerB = 2, 3, 8, 9
)

// rigClass is the dashboard's class shape on the rig's addresses.
func rigClass(x byte, name string, portBase int, peers ...byte) Class {
	c := metaClass()
	c.Name, c.PortBase, c.Peers = name, portBase, nil
	for _, p := range peers {
		c.Peers = append(c.Peers, netip.AddrFrom4([4]byte{127, x, 0, p}))
	}
	return c
}

// rigTable is a table of class "a" with slices 3 and 7, five each.
func rigTable(x byte) Table {
	base := 20000 + 64*rand.IntN(150)
	return Table{
		Listen: netip.AddrFrom4([4]byte{127, x, 0, 1}), ProjectBlock: netip.PrefixFrom(netip.AddrFrom4([4]byte{127, x, 4, 0}), 22),
		SlicePrefix: 26, PreambleMS: 2000,
		Classes: []Class{rigClass(x, "a", base, peerA1, peerA2)},
		Slices:  map[string]map[string]int{"3": {"a": 5}, "7": {"a": 5}},
	}
}

// withB adds class "b", the dashboard's shape on the next ports with the peer .9.
func withB(tb *Table) {
	tb.Classes = append(tb.Classes, rigClass(tb.Listen.As4()[1], "b", tb.Classes[0].PortBase+16, peerB))
}

// ceiling sets max_conns to the sum of the terms plus spare.
func ceiling(tb *Table, spare int) {
	a, b, r := tb.Terms()
	tb.MaxConns = a + b + r + spare
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// newRig serves the table that edit makes of rigTable (max_conns, when left 0,
// the sum of the terms plus 64) until the test ends.
func newRig(t *testing.T, edit func(*Table)) *rig {
	t.Helper()
	x := rigOctet(t)
	tb := rigTable(x)
	if edit != nil {
		edit(&tb)
	}
	if tb.MaxConns == 0 {
		ceiling(&tb, 64)
	}
	r := &rig{t: t, x: x, path: filepath.Join(t.TempDir(), "pgcap.json"), logs: &lockedBuf{}}
	r.write(tb)
	p, err := open(r.path, r.logs)
	if err != nil {
		t.Fatal(err)
	}
	r.p = p
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.watch(ctx, r.path); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return r
}

// write replaces the table's file with tb in Marshal's form.
func (r *rig) write(tb Table) {
	r.t.Helper()
	b, err := tb.Marshal()
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := ParseTable(b); err != nil {
		r.t.Fatalf("the rig wrote a table the proxy refuses: %v", err)
	}
	r.writeBytes(b)
}

func (r *rig) writeBytes(b []byte) {
	r.t.Helper()
	tmp := r.path + ".new"
	if err := os.WriteFile(tmp, b, 0o444); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Rename(tmp, r.path); err != nil {
		r.t.Fatal(err)
	}
}

// table returns the table in use.
func (r *rig) table() Table {
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	return r.p.tb
}

func (r *rig) addr(last byte) netip.Addr { return netip.AddrFrom4([4]byte{127, r.x, 0, last}) }

func (r *rig) port(class string, i int) int {
	for _, c := range r.table().Classes {
		if c.Name == class {
			return c.PortBase + i
		}
	}
	r.t.Fatalf("no class %q", class)
	return 0
}

// dial connects from 127.X.0.from to class's port of slice i.
func (r *rig) dial(from byte, class string, i int) (*net.TCPConn, error) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: r.addr(from).AsSlice()}, Timeout: 30 * time.Second}
	c, err := d.Dial("tcp4", netip.AddrPortFrom(r.addr(1), uint16(r.port(class, i))).String())
	if err != nil {
		return nil, err
	}
	r.t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(60 * time.Second))
	return c.(*net.TCPConn), nil
}

func (r *rig) mustDial(from byte, class string, i int) *net.TCPConn {
	r.t.Helper()
	c, err := r.dial(from, class, i)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

var rigStartup = startupPacket("user\x00u\x00database\x00postgres\x00\x00")

// served opens a connection whose startup is relayed to slice i's cluster,
// which logs it in: the client has read the whole login.
func (r *rig) served(from byte, class string, i int) *net.TCPConn {
	r.t.Helper()
	c := r.mustDial(from, class, i)
	if _, err := c.Write(rigStartup); err != nil {
		r.t.Fatal(err)
	}
	if b := make([]byte, len(login)); !readAll(c, b) || !bytes.Equal(b, login) {
		r.t.Fatalf("%s/%d from .%d: not served (%q)", class, i, from, b)
	}
	return c
}

func readAll(c net.Conn, b []byte) bool {
	_, err := io.ReadFull(c, b)
	return err == nil
}

// refused sends a whole startup packet and expects the refusal a client reads,
// then the end.
func refused(t *testing.T, c net.Conn) {
	t.Helper()
	c.Write(rigStartup)
	got, err := io.ReadAll(c)
	if !bytes.Equal(got, pgwire.TooManyConnections()) || err != nil {
		t.Fatalf("got %q (%v), want the too-many-connections error and an orderly close", got, err)
	}
}

// unanswered expects the proxy to close c without writing a byte.
func unanswered(t *testing.T, c net.Conn) {
	t.Helper()
	got, err := io.ReadAll(c)
	if len(got) != 0 || err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("got %q (%v), want the socket closed unanswered", got, err)
	}
}

// query sends a statement on a served connection and reads its answer.
func query(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write(m('Q', []byte("select 1\x00"))); err != nil {
		t.Fatal(err)
	}
	want := cat(commandOK, readyMsg)
	if b := make([]byte, len(want)); !readAll(c, b) || !bytes.Equal(b, want) {
		t.Fatalf("statement: got %q", b)
	}
}

var commandOK = ms4('C', "SELECT 1\x00")

// fakeCluster is slice i's cluster: it logs every startup in and answers each
// statement; a cancel request it records whole, until the proxy closes.
type fakeCluster struct {
	mu       sync.Mutex
	accepted int
	sources  []netip.Addr
	cancels  [][]byte
	firsts   [][]byte // the first eight bytes of each connection
	ln       net.Listener
	mute     atomic.Bool // answers no startup: a server that never authenticates
}

func (r *rig) cluster(i int) *fakeCluster {
	r.t.Helper()
	tb := r.table()
	_, to := sliceAddrs(&tb, i)
	ln, err := net.Listen("tcp4", to.String())
	if err != nil {
		r.t.Fatalf("the slice's cluster address %v: %v (a server on port %d of every address?)", to, err, to.Port())
	}
	f := &fakeCluster{ln: ln}
	r.t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			s, err := ln.Accept()
			if err != nil {
				return
			}
			r.t.Cleanup(func() { s.Close() })
			go f.serve(s)
		}
	}()
	return f
}

func (f *fakeCluster) serve(s net.Conn) {
	defer s.Close()
	s.SetDeadline(time.Now().Add(120 * time.Second))
	h := make([]byte, 8)
	_, err := io.ReadFull(s, h)
	f.mu.Lock()
	f.accepted++
	f.sources = append(f.sources, addrOf(s.RemoteAddr()))
	f.firsts = append(f.firsts, h)
	f.mu.Unlock()
	if err != nil {
		return
	}
	n := binary.BigEndian.Uint32(h)
	if n == 16 && binary.BigEndian.Uint32(h[4:]) == 80877102 {
		rest, _ := io.ReadAll(s)
		f.mu.Lock()
		f.cancels = append(f.cancels, append(h, rest...))
		f.mu.Unlock()
		return
	}
	if n < 8 || n > 10000 {
		return
	}
	io.CopyN(io.Discard, s, int64(n)-8)
	if f.mute.Load() {
		io.Copy(io.Discard, s)
		return
	}
	s.Write(login)
	for {
		var hdr [5]byte
		if !readAll(s, hdr[:]) {
			return
		}
		body := make([]byte, min(binary.BigEndian.Uint32(hdr[1:])-4, 1<<16))
		if !readAll(s, body) {
			return
		}
		switch {
		case hdr[0] == 'Q' && bytes.HasPrefix(body, []byte("copy")):
			s.Write(cat(m('W', []byte{0, 0, 0}), copyData(100)))
		case hdr[0] == 'Q':
			s.Write(cat(commandOK, readyMsg))
		case hdr[0] == 'X':
			return
		}
	}
}

func (f *fakeCluster) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted
}

// silentCluster stands at slice i's cluster address and never completes a
// handshake: its accept queue (backlog 0) is held full.
func (r *rig) silentCluster(i int) {
	r.t.Helper()
	tb := r.table()
	_, to := sliceAddrs(&tb, i)
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { syscall.Close(fd) })
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: to.Addr().As4(), Port: int(to.Port())}); err != nil {
		r.t.Fatal(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		r.t.Fatal(err)
	}
	held, err := net.DialTimeout("tcp4", to.String(), 5*time.Second)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { held.Close() })
	if probe, err := net.DialTimeout("tcp4", to.String(), 200*time.Millisecond); err == nil {
		probe.Close()
		r.t.Skip("this kernel completes handshakes over a full accept queue")
	}
}

// counts reads the node-wide units and a class's pool under the proxy's lock.
func (r *rig) counts(class string) (units, pool int) {
	r.p.mu.Lock()
	defer r.p.mu.Unlock()
	return r.p.units, r.p.classes[class].refusals
}

// until waits, up to 30 s, for cond.
func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not within 30 s: %s", what)
		}
	}
}

// refusedByKernel tells whether a connect to class's port of slice i is
// refused by the kernel: no listening socket there.
func (r *rig) refusedByKernel(class string, i int) bool {
	_, err := r.dial(peerA1, class, i)
	return errors.Is(err, syscall.ECONNREFUSED)
}

func TestListeners_OnlyForSlicesInTheTable(t *testing.T) {
	r := newRig(t, nil)
	r.cluster(3)
	r.cluster(7)
	r.served(peerA1, "a", 3)
	r.served(peerA1, "a", 7)
	for _, i := range []int{0, 4, 15} {
		if !r.refusedByKernel("a", i) {
			t.Errorf("slice %d, not in the table: its port was not refused by the kernel", i)
		}
	}
}

// A flood at one slice's port does not hold up the accept of another's: each
// slice has its own listening socket, accept queue and accept loop.
func TestListeners_OneAcceptQueuePerSlice(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.Classes[0].ConnsPerSecond, tb.Classes[0].ConnsBurst = 1000, 1000 })
	r.cluster(7)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var flood atomic.Int64
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if c, err := r.dial(stranger, "a", 3); err == nil {
					io.ReadAll(c) // closed at accept
					c.Close()
					flood.Add(1)
				}
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	until(t, "the flood is under way", func() bool { return flood.Load() > 100 })
	var worst time.Duration
	for range 20 {
		t0 := time.Now()
		r.served(peerA1, "a", 7).Close()
		worst = max(worst, time.Since(t0))
	}
	t.Logf("%d flood connections; the slowest of 20 accepts at slice 7 took %v", flood.Load(), worst)
	if worst > 5*time.Second {
		t.Fatalf("an accept at slice 7 took %v during a flood at slice 3", worst)
	}
}

func TestDial_FromTheProxyAddress(t *testing.T) {
	r := newRig(t, nil)
	f := r.cluster(3)
	r.served(peerA1, "a", 3)
	if want := netip.AddrFrom4([4]byte{127, r.x, 4, 64*3 + 4}); len(f.sources) != 1 || f.sources[0] != want {
		t.Fatalf("the cluster saw %v, want the proxy's address on slice 3, %v", f.sources, want)
	}
	// The default table's layout: the last slice of the /16 block.
	tb, err := ParseTable([]byte(metaJSON(metaSlices)))
	if err != nil {
		t.Fatal(err)
	}
	from, to := sliceAddrs(&tb, 1023)
	if from.String() != "10.213.255.196" || to.String() != "10.213.255.194:5432" {
		t.Fatalf("slice 1023: from %v to %v", from, to)
	}
}

// One function computes From and To: the two host offsets and the cluster's
// port are used in sliceAddrs and nowhere else in the package.
func TestDial_OneFunctionComputesTheAddresses(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	uses := map[string][]string{}
	for _, f := range pkgs["pgcap"].Files {
		for _, d := range f.Decls {
			fn, _ := d.(*ast.FuncDecl)
			ast.Inspect(d, func(n ast.Node) bool {
				where := "a declaration"
				if fn != nil {
					where = fn.Name.Name
				}
				switch n := n.(type) {
				case *ast.Ident:
					if n.Name == "clusterHost" || n.Name == "proxyHost" || n.Name == "clusterPort" {
						uses[n.Name] = append(uses[n.Name], where)
					}
				case *ast.BasicLit:
					if n.Value == "5432" {
						uses["5432"] = append(uses["5432"], where)
					}
				}
				return true
			})
		}
	}
	for _, name := range []string{"clusterHost", "proxyHost", "clusterPort"} {
		if got := strings.Join(uses[name], ","); got != "a declaration,sliceAddrs" {
			t.Errorf("%s used in: %s", name, got)
		}
	}
	if got := strings.Join(uses["5432"], ","); got != "a declaration" {
		t.Errorf("5432 written in: %s", got)
	}
}

// A slice that is not in the table has no listening socket, so nothing can
// reach its cluster through the proxy.
func TestDial_UnplacedSliceHasNoListener(t *testing.T) {
	r := newRig(t, nil)
	f := r.cluster(5)
	if !r.refusedByKernel("a", 5) {
		t.Fatal("slice 5 is not in the table and its port accepted")
	}
	r.cluster(3)
	r.served(peerA1, "a", 3) // control
	if f.count() != 0 {
		t.Fatalf("slice 5's cluster was dialled %d times", f.count())
	}
}

// getsockopt on the proxy's two sockets of a relayed connection — the accepted
// one and the dialled one, found among the process's descriptors by their
// addresses — reads twice the class's socket buffer size, for two classes with
// different sizes.
func TestSockets_FixedBuffersOnBothSides(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		withB(tb)
		tb.Classes[1].CopyBufBytes, tb.Classes[1].SockBufBytes = 16<<10, 16<<10
		tb.Slices["3"]["b"] = 5
	})
	r.cluster(3)
	for _, c := range []struct {
		class string
		peer  byte
		size  int
	}{{"a", peerA1, 32 << 10}, {"b", peerB, 16 << 10}} {
		client := r.served(c.peer, c.class, 3)
		tb := r.table()
		from, to := sliceAddrs(&tb, 3)
		accepted := findSocket(t, netip.MustParseAddrPort(client.RemoteAddr().String()), netip.MustParseAddrPort(client.LocalAddr().String()))
		dialled := findSocket(t, netip.AddrPortFrom(from, 0), to)
		for name, fd := range map[string]int{"accepted": accepted, "dialled": dialled} {
			for _, opt := range []int{syscall.SO_RCVBUF, syscall.SO_SNDBUF} {
				if v, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, opt); err != nil || v != 2*c.size {
					t.Errorf("class %s, %s socket, option %d: %d %v, want %d", c.class, name, opt, v, err, 2*c.size)
				}
			}
		}
		client.Close()
		// The next class's dialled socket has the same two addresses: this one's must be gone first.
		until(t, "the connection ended", func() bool { u, _ := r.counts(c.class); return u == 0 })
	}
}

// findSocket returns the descriptor of this process whose socket has the local
// and remote addresses given (a local port of 0 matches any).
func findSocket(t *testing.T, local, remote netip.AddrPort) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	ap := func(sa syscall.Sockaddr) netip.AddrPort {
		if s, ok := sa.(*syscall.SockaddrInet4); ok {
			return netip.AddrPortFrom(netip.AddrFrom4(s.Addr), uint16(s.Port))
		}
		return netip.AddrPort{}
	}
	for _, e := range ents {
		fd, _ := strconv.Atoi(e.Name())
		sa, err := syscall.Getsockname(fd)
		if err != nil {
			continue
		}
		pa, err := syscall.Getpeername(fd)
		if l := ap(sa); err != nil || l.Addr() != local.Addr() || local.Port() != 0 && l.Port() != local.Port() || ap(pa) != remote {
			continue
		}
		return fd
	}
	t.Fatalf("no socket %v → %v", local, remote)
	return -1
}
