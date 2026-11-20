package pgcap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// A class never holds more units of the node-wide ceiling than its own terms
// — its connections, its cancels, its pool — whatever its peers send and
// however fast: what it does not hold is another class's. With every term of
// class a held, a burst of sockets from a's peers whose first eight bytes come
// with them is closed, each at its accept, and class b's share stays free.
func TestCeiling_AClassHoldsNoMoreThanItsTerms(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		withB(tb)
		tb.Slices = map[string]map[string]int{}
		for i := range 8 {
			tb.Slices[strconv.Itoa(i)] = map[string]int{"a": 5, "b": 5}
		}
		for i := range tb.Classes {
			tb.Classes[i].ConnsPerSecond, tb.Classes[i].ConnsBurst = 1<<20, 1<<20
		}
		tb.PreambleMS = 60000
		tb.Classes[0].CancelMS = 60000
		ceiling(tb, 0) // exactly the terms, as a full node's table has it
	})
	for i := range 8 {
		r.cluster(i)
	}
	tb := r.table()
	var a Table = tb
	a.Classes = tb.Classes[:1]
	conns, cancels, pool := a.Terms()
	termsA := conns + cancels + pool
	for n := range conns {
		r.served(byte(peerA1+n%2), "a", n%8)
	}
	for n := range cancels {
		r.mustDial(byte(peerA1+n%2), "a", n%8).Write(first8(16, codeCancel))
	}
	until(t, "the cancels admitted", func() bool { u, _ := r.counts("a"); return u == conns+cancels })
	for n := range pool {
		r.mustDial(byte(peerA1+n%2), "a", n%8)
	}
	until(t, "every term of class a held", func() bool { u, p := r.counts("a"); return u == termsA && p == pool })

	// The burst: more sockets than class b's whole share, each with a startup's
	// first eight bytes already queued.
	burst := tb.MaxConns - termsA + 8
	var accs []*net.TCPConn
	for n := range burst {
		_, acc := handed(t, r, byte(peerA1+n%2), 1, first8(100, proto30))
		accs = append(accs, acc)
	}
	r.p.mu.Lock()
	s := r.p.slots[member{0, "a"}]
	r.p.mu.Unlock()
	// One thread: nothing the proxy starts for a socket runs before the burst
	// is through, so the count below is what the accepts themselves left held.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	now := time.Now()
	for _, acc := range accs {
		r.p.accept(s, acc, now)
	}
	held, _ := r.counts("a")
	if held > termsA {
		t.Fatalf("class a holds %d units of the ceiling's %d after a burst of %d sockets; its terms are %d — the rest is class b's (%d)",
			held, tb.MaxConns, burst, termsA, tb.MaxConns-termsA)
	}
}

// When a table removes one slice and adds another, the new slice's listening
// socket opens only after every socket of the removed one has ended and given
// back what it held: at the first moment the new port accepts, nothing of the
// old slice is counted.
func TestTable_NewSliceOpensAfterTheRemovedOneHasEnded(t *testing.T) {
	const silent = 1500
	r := newRig(t, func(tb *Table) {
		tb.PreambleMS = 60000
		tb.Classes[0].RefusalsMax = silent
		ceiling(tb, 64)
	})
	for range silent {
		c, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: r.addr(peerA1).AsSlice()}}).Dial("tcp4",
			netip.AddrPortFrom(r.addr(1), uint16(r.port("a", 3))).String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	until(t, "every silent socket held", func() bool { u, _ := r.counts("a"); return u == silent })
	tb := r.table()
	delete(tb.Slices, "3")
	tb.Slices["9"] = map[string]int{"a": 5}
	// Watch for the moment slice 9's place appears, and read the count in that
	// same moment, under the proxy's lock.
	seen := make(chan int, 1)
	go func() {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); runtime.Gosched() {
			r.p.mu.Lock()
			_, ok := r.p.slots[member{9, "a"}]
			u := r.p.units
			r.p.mu.Unlock()
			if ok {
				seen <- u
				return
			}
		}
		seen <- -1
	}()
	r.write(tb)
	switch u := <-seen; {
	case u < 0:
		t.Fatal("slice 9 did not enter the table within 30 s")
	case u > 0:
		t.Fatalf("slice 9's listening socket opened while %d sockets of the removed slice were still counted", u)
	}
}

// A path that holds something other than a regular file — here a FIFO, whose
// open or read would never return — is not read: the table in use is kept, the
// next good file is applied, and the proxy still ends when it is told to.
func TestTable_AFileThatIsNotRegularIsNotRead(t *testing.T) {
	r := newRig(t, nil)
	r.cluster(3)
	r.cluster(9)
	fifo := filepath.Join(filepath.Dir(r.path), "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("no FIFO here:", err)
	}
	// Held open for writing by the test, so that a reader, were there one, is
	// released when the test ends and not left in the kernel for ever.
	hold, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hold.Close() })
	if err := os.Rename(fifo, r.path); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond) // two looks at the file
	r.served(peerA1, "a", 3).Close()    // the table in use is kept
	tb := r.table()
	tb.Slices["9"] = map[string]int{"a": 5}
	r.write(tb)
	deadline := time.Now().Add(5 * time.Second)
	for r.refusedByKernel("a", 9) {
		if time.Now().After(deadline) {
			t.Fatal("the file after the FIFO was not applied within 5 s: the proxy is still reading the FIFO")
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.served(peerA1, "a", 9)
}

// A table's listening address is one address: the unspecified address would
// open the class's ports on every network the proxy is attached to.
func TestTable_Strict_ListenIsOneAddress(t *testing.T) {
	good := metaJSON(metaSlices)
	if _, err := ParseTable([]byte(good)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTable([]byte(strings.Replace(good, `"listen":"10.212.0.6"`, `"listen":"0.0.0.0"`, 1))); err == nil {
		t.Fatal("a table that listens on the unspecified address was accepted")
	}
}

// Run serves until its context ends and then returns nil, with every listening
// socket closed and every connection cut.
func TestRun_ServesUntilTheContextEnds(t *testing.T) {
	x := rigOctet(t)
	tb := rigTable(x)
	ceiling(&tb, 0)
	b, err := tb.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pgcap.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	logs := &lockedBuf{}
	go func() { done <- Run(ctx, path, logs) }()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, x, 0, peerA1)}, Timeout: 5 * time.Second}
	to := netip.AddrPortFrom(tb.Listen, uint16(tb.Classes[0].PortBase+3)).String()
	var c net.Conn
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if c, err = d.Dial("tcp4", to); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
	if got, err := io.ReadAll(c); len(got) != 0 || err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("the open socket: %q %v, want it closed", got, err)
	}
	if _, err := d.Dial("tcp4", to); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("after Run returned the port answers: %v", err)
	}
	// A table that cannot be served is an error at once, with nothing left open.
	for i := range 12 {
		tb.Slices[strconv.Itoa(i)] = map[string]int{"a": 1}
	}
	ceiling(&tb, 0)
	if b, err = tb.Marshal(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", to) // slice 3's port is taken
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	if err := Run(ctx2, path, logs); err == nil {
		t.Fatal("Run served a table one of whose ports is taken")
	}
	for i := range 12 {
		if i == 3 {
			continue
		}
		other := netip.AddrPortFrom(tb.Listen, uint16(tb.Classes[0].PortBase+i)).String()
		if _, err := d.Dial("tcp4", other); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("after a failed start slice %d's port answers: %v", i, err)
		}
	}
}

// A refused connection spends none of its slice's rate: with one connection
// open at an allowance of one, ten refused attempts leave the tokens where
// they were.
func TestConnRate_ARefusalSpendsNoToken(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		tb.Classes[0].ConnsPerSecond, tb.Classes[0].ConnsBurst = 1, 3
		tb.Slices["3"]["a"] = 1
	})
	f := r.cluster(3)
	held := r.served(peerA1, "a", 3)
	for range 10 {
		refused(t, r.mustDial(peerA2, "a", 3))
	}
	held.Close()
	until(t, "the connection ended", func() bool { u, _ := r.counts("a"); return u == 0 })
	t0 := time.Now()
	for range 2 { // the two tokens left of the burst of three
		c := r.served(peerA1, "a", 3)
		c.Close()
		until(t, "the connection ended", func() bool { u, _ := r.counts("a"); return u == 0 })
	}
	if d := time.Since(t0); d > 900*time.Millisecond {
		t.Skipf("the machine took %v for two connections: the rate has refilled meanwhile", d)
	}
	if f.count() != 3 {
		t.Fatalf("the cluster was dialled %d times, want the three admitted", f.count())
	}
}

// A cancel request whose other eight bytes never come holds one unit of its
// slice's cancel allowance — not a place of the pool — until the class's cancel
// deadline, and dials nothing.
func TestCancel_AHalfRequestEndsAtTheDeadline(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.Classes[0].CancelMS = 700; tb.PreambleMS = 60000 })
	f := r.cluster(3)
	c := r.mustDial(peerA1, "a", 3)
	t0 := time.Now()
	c.Write(cancelReq(1)[:8])
	until(t, "the cancel admitted", func() bool {
		r.p.mu.Lock()
		defer r.p.mu.Unlock()
		return r.p.slots[member{3, "a"}].cancels == 1 && r.p.classes["a"].refusals == 0
	})
	unanswered(t, c)
	if d := time.Since(t0); d < 700*time.Millisecond || d > 20*time.Second {
		t.Fatalf("closed after %v, want the cancel deadline of 700 ms", d)
	}
	until(t, "released", func() bool { u, _ := r.counts("a"); return u == 0 })
	if f.count() != 0 {
		t.Fatalf("the cluster was dialled %d times for half a cancel", f.count())
	}
}

// A class that leaves a slice's row has that slice's sockets of the class cut;
// the slice's sockets of the class that stays are kept, and so is the leaving
// class on its other slices.
func TestTable_AClassLeavesASlice(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		withB(tb)
		tb.Slices["3"]["b"] = 5
		tb.Slices["7"]["b"] = 5
	})
	r.cluster(3)
	r.cluster(7)
	a3, b3, b7 := r.served(peerA1, "a", 3), r.served(peerB, "b", 3), r.served(peerB, "b", 7)
	tb := r.table()
	tb.Slices = map[string]map[string]int{"3": {"a": 5}, "7": {"a": 5, "b": 5}}
	r.write(tb)
	unanswered(t, b3)
	until(t, "class b's port of slice 3 closed", func() bool {
		_, err := r.dial(peerB, "b", 3)
		return errors.Is(err, syscall.ECONNREFUSED)
	})
	query(t, a3)
	query(t, b7)
}

// A flood of sockets of every kind the proxy closes — strangers, peers that
// say nothing and leave, a part of a preamble, request codes in other forms,
// encryption asked twice, cancels over their allowance, startups over the
// allowance whole, cut short and with a length out of range — leaves nothing
// behind: no unit, no place, no goroutine, no descriptor, and no memory — a
// slice's row lives for months, so a byte kept per refused socket is a leak.
func TestFlood_EveryRefusedSocketLeavesNothingBehind(t *testing.T) {
	if testing.Short() {
		t.Skip("thousands of sockets")
	}
	r := newRig(t, func(tb *Table) {
		tb.PreambleMS = 100
		tb.Classes[0].CancelsPerProject = 0
		tb.Slices["3"]["a"] = 0
	})
	f := r.cluster(3)
	kinds := []struct {
		from byte
		send [][]byte
	}{
		{stranger, [][]byte{rigStartup}},
		{peerA1, nil},
		{peerA1, [][]byte{{0, 0, 0}}},
		{peerA2, [][]byte{first8(12, codeTLS)}},
		{peerA2, [][]byte{first8(8, codeTLS), first8(8, codeTLS)}},
		{peerA1, [][]byte{first8(8, codeGSS), first8(8, codeTLS), first8(8, codeGSS)}},
		{peerA1, [][]byte{cancelReq(7)}},
		{peerA2, [][]byte{rigStartup}},
		{peerA2, [][]byte{first8(100, proto30)}},
		{peerA1, [][]byte{first8(10001, proto30), bytes.Repeat([]byte{'x'}, 4000)}},
		{peerA1, [][]byte{first8(4, proto30)}},
	}
	to := netip.AddrPortFrom(r.addr(1), uint16(r.port("a", 3))).String()
	one := func(n int) {
		k := kinds[n%len(kinds)]
		c, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: r.addr(k.from).AsSlice()}}).Dial("tcp4", to)
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		for _, b := range k.send {
			c.Write(b)
		}
		if n%3 != 0 { // two in three wait for the proxy's close; the third leaves first
			io.Copy(io.Discard, c)
		}
	}
	for n := range 200 { // warm: pools, the log's map
		one(n)
	}
	until(t, "the warm-up released", func() bool { u, p := r.counts("a"); return u == 0 && p == 0 })
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	goroutines, files := runtime.NumGoroutine(), openFiles(t)
	const total, parallel = 8000, 24
	var wg sync.WaitGroup
	for w := range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := w; n < total; n += parallel {
				one(n)
			}
		}()
	}
	wg.Wait()
	until(t, "every unit and place released", func() bool { u, p := r.counts("a"); return u == 0 && p == 0 })
	if got := settle(goroutines, runtime.NumGoroutine); got > goroutines {
		t.Errorf("%d goroutines after the flood, %d before", got, goroutines)
	}
	if got := settle(files, func() int { return openFiles(t) }); got > files {
		t.Errorf("%d open files after the flood, %d before", got, files)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 1<<20 {
		t.Errorf("the heap grew by %d bytes over %d refused sockets (%d a socket)", grew, total, grew/total)
	}
	if f.count() != 0 {
		t.Errorf("the cluster was dialled %d times", f.count())
	}
	// What a peer chose appears in no log line: every reason is one of the fixed texts.
	for _, line := range strings.Split(strings.TrimSpace(r.logs.String()), "\n") {
		if !strings.HasPrefix(line, `{"class":"a","index":3,"reason":"`) {
			t.Fatalf("log line %q", line)
		}
		reason, _, _ := strings.Cut(strings.TrimPrefix(line, `{"class":"a","index":3,"reason":"`), `"`)
		switch {
		case reason == "not a peer of the class", reason == "preamble deadline", reason == "encryption requested twice",
			reason == "a request code in another form", reason == "cancel over its allowance",
			reason == "the class's refusals in flight at their cap",
			strings.HasPrefix(reason, "too many connections: the project's allowance"),
			strings.HasPrefix(reason, "refused, its startup length out of range: the project's allowance"),
			strings.HasPrefix(reason, "refused, its startup packet not read: the project's allowance"):
		default:
			t.Fatalf("log reason %q is none of the fixed texts", reason)
		}
	}
}

// FuzzKeepShape gives the reload any next table made from the one in use by
// changing its figures, its classes and its slices: what comes back, when
// anything does, has the shape of the table in use to the member, passes every
// rule of a table, and carries of the new file only what a reload may take —
// the slices and allowances of the classes that exist, and the other figures.
func FuzzKeepShape(f *testing.F) {
	f.Add(uint8(0), uint16(0), uint8(0), uint8(0), uint16(0xffff), uint8(5), int32(0))
	f.Add(uint8(1), uint16(64), uint8(1), uint8(3), uint16(0x0088), uint8(1), int32(1))
	f.Add(uint8(0x3f), uint16(7), uint8(2), uint8(200), uint16(1), uint8(0), int32(-3))
	f.Fuzz(func(t *testing.T, what uint8, port uint16, peers, pool uint8, slices uint16, allowance uint8, ceil int32) {
		cur := rigTable(77)
		withB(&cur)
		cur.Slices["3"]["b"] = 2
		ceiling(&cur, 64)
		b, err := cur.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if cur, err = ParseTable(b); err != nil {
			t.Fatal(err)
		}
		next := cur
		next.Classes = append([]Class(nil), cur.Classes...)
		c := &next.Classes[0]
		if what&1 != 0 {
			c.PortBase += int(port)
		}
		if what&2 != 0 {
			c.Peers = c.Peers[:int(peers)%3]
		}
		if what&4 != 0 {
			c.RefusalsMax = int(pool) + 1
		}
		if what&8 != 0 {
			c.CopyBufBytes, c.SockBufBytes = 8<<10, 8<<10
		}
		if what&16 != 0 {
			next.Classes = next.Classes[:1] // class b gone
		}
		if what&32 != 0 {
			extra := rigClass(77, "c", cur.Classes[0].PortBase+64, 11)
			next.Classes = append(next.Classes, extra)
		}
		if what&64 != 0 {
			next.SlicePrefix = 27
		}
		c.ConnsBurst, c.ConnsPerSecond = int(pool)+1, int(peers)+1
		next.Slices = map[string]map[string]int{}
		for i := range 16 {
			if slices&(1<<i) != 0 {
				m := map[string]int{}
				for j, cl := range next.Classes {
					if (i+j)%3 != 0 {
						m[cl.Name] = int(allowance) % 9
					}
				}
				next.Slices[strconv.Itoa(i)] = m
			}
		}
		a, cn, r := next.Terms()
		next.MaxConns = a + cn + r + int(ceil%100)
		nb, err := next.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if next, err = ParseTable(nb); err != nil {
			return // not a table an agent could have written
		}
		out, changed, err := keepShape(cur, next)
		if err != nil {
			return // kept whole
		}
		if out.Listen != cur.Listen || out.ProjectBlock != cur.ProjectBlock || out.SlicePrefix != cur.SlicePrefix ||
			out.MaxConns != cur.MaxConns || len(out.Classes) != len(cur.Classes) {
			t.Fatalf("the shape changed: %+v", out)
		}
		for i, oc := range out.Classes {
			cc := cur.Classes[i]
			if oc.Name != cc.Name || oc.PortBase != cc.PortBase || !slicesEqual(oc.Peers, cc.Peers) || oc.RefusalsMax != cc.RefusalsMax ||
				oc.CopyBufBytes != cc.CopyBufBytes || oc.SockBufBytes != cc.SockBufBytes {
				t.Fatalf("class %q changed its shape: %+v", cc.Name, oc)
			}
		}
		if err := out.check(); err != nil {
			t.Fatalf("the table to apply breaks a rule: %v", err)
		}
		if x, y, z := out.Terms(); x+y+z > out.MaxConns {
			t.Fatal("terms above the ceiling in use")
		}
		for k, m := range out.Slices {
			for name, al := range m {
				if got, ok := next.Slices[k][name]; !ok || got != al {
					t.Fatalf("slice %s class %s: allowance %d is not the new file's", k, name, al)
				}
			}
		}
		if !changed {
			if ob, _ := out.Marshal(); !bytes.Equal(ob, nb) {
				t.Fatal("told unchanged, and the table is not the new file's")
			}
		}
	})
}

func slicesEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A file whose listening address or project block differs from the table in
// use names other sockets and other clusters by the same slice indexes: it is
// kept out whole — nothing of it is applied, not even a removed slice.
func TestTable_AnotherAddressOrBlockKeepsTheWholeTable(t *testing.T) {
	for name, edit := range map[string]func(*rig, *Table){
		"listening address": func(r *rig, tb *Table) { tb.Listen = r.addr(7) },
		"project block": func(r *rig, tb *Table) {
			tb.ProjectBlock = netip.PrefixFrom(netip.AddrFrom4([4]byte{127, r.x, 8, 0}), 22)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			f := r.cluster(3)
			old := r.table()
			tb := r.table()
			tb.Slices = map[string]map[string]int{"7": {"a": 5}, "9": {"a": 5}}
			edit(r, &tb)
			r.write(tb)
			until(t, "the file looked at and kept out", func() bool { return strings.Contains(r.logs.String(), "kept the table in use") })
			if got := r.table(); got.Listen != old.Listen || got.ProjectBlock != old.ProjectBlock || len(got.Slices) != 2 || got.Slices["3"] == nil {
				t.Fatalf("the table in use changed: %+v", got)
			}
			r.served(peerA1, "a", 3) // the slice the file dropped is still served, at the old address, to the old cluster
			if f.count() != 1 {
				t.Fatalf("slice 3's cluster was dialled %d times", f.count())
			}
			if !r.refusedByKernel("a", 9) {
				t.Fatal("a slice of the file that was kept out got a listening socket")
			}
		})
	}
}

// For a class without per-peer caps 0 means "none", for connections and for
// cancels: its one peer is held by the slice's allowances alone.
func TestCaps_NoPerPeerCapMeansNone(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		tb.Classes[0].ConnsPerPeer, tb.Classes[0].CancelsPerPeer = 0, 0
		tb.Classes[0].CancelMS = 60000
		ceiling(tb, 64)
	})
	f := r.cluster(3)
	for range 5 {
		r.served(peerA1, "a", 3)
	}
	refused(t, r.mustDial(peerA1, "a", 3)) // the slice's allowance, still
	c := r.mustDial(peerA1, "a", 3)
	c.Write(cancelReq(3))
	until(t, "the cancel forwarded", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.cancels) == 1
	})
}

// A slice's connections of one class share one set of stream places, through
// the proxy as through the relay alone: with one place a project, the second
// connection of the slice is closed at its copy-both, another slice's is not,
// and a reload that keeps the slice keeps the count.
func TestStream_OneSetOfPlacesPerSliceAndClass(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		c := &tb.Classes[0]
		c.Window, c.WindowBytes, c.WallMS = WindowResponse, 1<<20, 0
		c.Stream = &Stream{ConnsPerProject: 1, BytesPerInterval: 1 << 20, IntervalMS: 100}
	})
	r.cluster(3)
	r.cluster(7)
	copyBoth := m('Q', []byte("copy\x00"))
	stream := cat(m('W', []byte{0, 0, 0}), copyData(100))
	enters := func(c net.Conn) bool {
		c.Write(copyBoth)
		b := make([]byte, len(stream))
		return readAll(c, b) && bytes.Equal(b, stream)
	}
	first := r.served(peerA1, "a", 3)
	if !enters(first) {
		t.Fatal("the slice's first connection did not enter the stream state")
	}
	if enters(r.served(peerA2, "a", 3)) {
		t.Fatal("a second connection of the slice entered the stream state: its places are not shared")
	}
	if !enters(r.served(peerA1, "a", 7)) {
		t.Fatal("another slice's first connection was refused the stream state")
	}
	tb := r.table()
	tb.Slices = map[string]map[string]int{"3": {"a": 4}, "7": {"a": 5}}
	r.write(tb)
	until(t, "the new allowance in use", func() bool { return r.table().Slices["3"]["a"] == 4 })
	if enters(r.served(peerA2, "a", 3)) {
		t.Fatal("after a reload a second connection of the slice entered the stream state: the count started again")
	}
}

// A cancel gives its allowance back when it ends, leaves from the proxy's
// address on the slice, and brings nothing back to the client, whatever the
// cluster answers.
func TestCancel_AllowanceGivenBack_SourceAndNoAnswer(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.Classes[0].CancelsPerProject, tb.Classes[0].CancelsPerPeer = 2, 3 })
	tb := r.table()
	from, to := sliceAddrs(&tb, 3)
	ln, err := net.Listen("tcp4", to.String())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var got [][]byte
	var sources []netip.Addr
	go func() { // a cluster that answers every cancel with bytes of its own
		for {
			s, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer s.Close()
				s.SetDeadline(time.Now().Add(30 * time.Second))
				b := make([]byte, 16)
				io.ReadFull(s, b)
				mu.Lock()
				got, sources = append(got, b), append(sources, addrOf(s.RemoteAddr()))
				mu.Unlock()
				s.Write([]byte("an answer nobody asked for"))
				io.Copy(io.Discard, s)
			}()
		}
	}()
	r.cluster(7)
	for n := range 7 { // more, one after the other, than either allowance
		c := r.mustDial(peerA1, "a", 3)
		c.Write(cancelReq(byte(n)))
		unanswered(t, c)
		until(t, "the cancel's unit released", func() bool { u, _ := r.counts("a"); return u == 0 })
		until(t, "cancel "+strconv.Itoa(n+1)+" at the cluster: an allowance given back", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(got) == n+1
		})
	}
	mu.Lock()
	defer mu.Unlock()
	for i, b := range got {
		if !bytes.Equal(b, cancelReq(b[11])) || sources[i] != from {
			t.Fatalf("cancel %d: %x from %v, want the request from %v", i, b, sources[i], from)
		}
	}
}

// A file that changes the shape and whose other figures no longer fit the
// shape in use — here more slices than the ceiling in use covers — is kept out
// whole: nothing of it is applied.
func TestTable_ShapeKeptAndTheRestMustStillFit(t *testing.T) {
	r := newRig(t, func(tb *Table) { ceiling(tb, 0) }) // exactly the terms of two slices
	r.cluster(3)
	tb := r.table()
	tb.Slices = map[string]map[string]int{}
	for i := range 12 {
		tb.Slices[strconv.Itoa(i)] = map[string]int{"a": 5}
	}
	ceiling(&tb, 0) // the new file's own ceiling covers them; the one in use does not
	r.write(tb)
	until(t, "the file kept out", func() bool { return strings.Contains(r.logs.String(), "kept the table in use") })
	if got := r.table(); len(got.Slices) != 2 {
		t.Fatalf("the table in use has %d slices: a table above the ceiling in use was applied", len(got.Slices))
	}
	if !r.refusedByKernel("a", 9) {
		t.Fatal("a slice of the file that was kept out got a listening socket")
	}
	r.served(peerA1, "a", 3)
}

// A reload's caps apply to sockets accepted after it: with the per-peer cap
// lowered to one, a peer's second connection is refused, while a connection
// open across the reload stays.
func TestTable_NewCapsApplyToNewSockets(t *testing.T) {
	r := newRig(t, nil)
	r.cluster(3)
	r.cluster(7)
	open := r.served(peerA1, "a", 3)
	r.served(peerA1, "a", 7).Close() // two at once from one peer: fine under the old cap
	tb := r.table()
	tb.Classes = append([]Class(nil), tb.Classes...)
	tb.Classes[0].ConnsPerPeer = 1
	ceiling(&tb, 0)
	tb.MaxConns = r.table().MaxConns // the shape stays
	r.write(tb)
	until(t, "the new cap in use", func() bool { return r.table().Classes[0].ConnsPerPeer == 1 })
	refused(t, r.mustDial(peerA1, "a", 7))
	query(t, open)
	r.served(peerA2, "a", 7)
}

// A slice whose port cannot be opened at a reload is logged and left out; the
// other slices of the same file are opened all the same.
func TestTable_OnePortThatCannotOpenStopsNoOther(t *testing.T) {
	r := newRig(t, func(tb *Table) { ceiling(tb, 200) })
	taken, err := net.Listen("tcp4", netip.AddrPortFrom(r.addr(1), uint16(r.port("a", 9))).String())
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	tb := r.table()
	others := []int{0, 1, 2, 4, 5, 6, 8, 10, 11, 12, 13, 14, 15}
	for _, i := range append(others, 9) {
		tb.Slices[strconv.Itoa(i)] = map[string]int{"a": 1}
	}
	r.write(tb)
	until(t, "the failure logged", func() bool { return strings.Contains(r.logs.String(), `"index":9,"reason":"listen: `) })
	for _, i := range others {
		until(t, "slice "+strconv.Itoa(i)+" listening", func() bool { return !r.refusedByKernel("a", i) })
	}
}
