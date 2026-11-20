package pgcap

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// A reload that removes slice 3 and adds slice 9 closes slice 3's listening
// socket and every open socket of it — a relayed connection on both sides, a
// cancel and a refusal in flight — within the poll period; slice 7's
// connection, open across the same reload, completes its statement; slice 9's
// port listens after it.
func TestTable_SliceRemoved_ItsConnectionsCut_OthersKept(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		tb.PreambleMS = 60000
		tb.Classes[0].CancelMS = 60000
		tb.Slices["3"]["a"] = 1
	})
	r.cluster(3)
	r.cluster(7)
	r.cluster(9)
	relayed := r.served(peerA1, "a", 3)
	kept := r.served(peerA1, "a", 7)
	cancel := r.mustDial(peerA1, "a", 3)
	cancel.Write(cancelReq(1)[:8]) // the rest never comes
	refusal := r.mustDial(peerA2, "a", 3)
	refusal.Write(first8(100, proto30)) // over the allowance; the rest never comes
	until(t, "four sockets held", func() bool { u, _ := r.counts("a"); return u == 4 })

	tb := r.table()
	delete(tb.Slices, "3")
	tb.Slices["9"] = map[string]int{"a": 5}
	t0 := time.Now()
	r.write(tb)
	for name, c := range map[string]net.Conn{"relayed": relayed, "cancel": cancel, "refusal": refusal} {
		unanswered(t, c)
		t.Logf("%s connection closed after %v", name, time.Since(t0))
	}
	if d := time.Since(t0); d > 10*time.Second {
		t.Fatalf("cut after %v, poll period %v", d, pollEvery)
	}
	if !r.refusedByKernel("a", 3) {
		t.Fatal("slice 3's port still accepts")
	}
	query(t, kept)
	// apply opens slice 9's socket only after the removed slice's sockets
	// have ended: the cut seen by the client does not mean it listens yet.
	until(t, "slice 9 listening", func() bool {
		r.p.mu.Lock()
		defer r.p.mu.Unlock()
		return r.p.slots[member{9, "a"}] != nil
	})
	r.served(peerA2, "a", 9)
	if u, _ := r.counts("a"); u != 2 {
		t.Fatalf("%d units held, want slice 7's and slice 9's", u)
	}
}

// Five open, the allowance lowered to two: none is cut; a sixth is refused
// while two or more are open, and admitted once one is left.
func TestTable_LoweredAllowanceReachedAsConnectionsEnd(t *testing.T) {
	r := newRig(t, nil)
	r.cluster(3)
	var open []net.Conn
	for range 5 {
		open = append(open, r.served(peerA1, "a", 3))
	}
	tb := r.table()
	tb.Slices["3"]["a"] = 2
	r.write(tb)
	until(t, "the lowered allowance in use", func() bool {
		r.p.mu.Lock()
		defer r.p.mu.Unlock()
		return r.p.slots[member{3, "a"}].allowance == 2
	})
	for _, c := range open {
		query(t, c)
	}
	conns := func() int {
		r.p.mu.Lock()
		defer r.p.mu.Unlock()
		return r.p.slots[member{3, "a"}].conns
	}
	for len(open) > 1 {
		refused(t, r.mustDial(peerA2, "a", 3))
		open[0].Close()
		open = open[1:]
		until(t, "a connection ended", func() bool { return conns() == len(open) })
	}
	r.served(peerA2, "a", 3)
}

// A file that does not parse — here a valid table with one byte of white space
// after it — keeps the table in use; the same table in Marshal's form is
// applied.
func TestTable_BadFileKeepsTheLastGood(t *testing.T) {
	r := newRig(t, nil)
	r.cluster(3)
	tb := r.table()
	delete(tb.Slices, "3")
	b, _ := tb.Marshal()
	r.writeBytes(append(b, '\n'))
	until(t, "the bad file read", func() bool { return strings.Contains(r.logs.String(), "kept the table in use") })
	r.served(peerA1, "a", 3)
	r.write(tb)
	until(t, "the good file applied", func() bool { return r.refusedByKernel("a", 3) })
}

// A change of the shape — another port base, peer list, buffer size, pool or
// ceiling, or a class added — is logged and not applied; the rest of the file
// (here slice 7's allowance) is. A change of the slice layout keeps the whole
// table in use.
func TestTable_ShapeChangeIsNotReloaded(t *testing.T) {
	for name, edit := range map[string]func(*Table){
		"port base":   func(tb *Table) { tb.Classes[0].PortBase += 32 },
		"peer list":   func(tb *Table) { tb.Classes[0].Peers = tb.Classes[0].Peers[:1] },
		"buffer size": func(tb *Table) { tb.Classes[0].SockBufBytes = 16 << 10 },
		"pool":        func(tb *Table) { tb.Classes[0].RefusalsMax = 32; ceiling(tb, 64) },
		"ceiling":     func(tb *Table) { tb.MaxConns++ },
		"class added": func(tb *Table) { withB(tb); tb.Slices["3"]["b"] = 5; ceiling(tb, 64) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			r.cluster(3)
			r.cluster(7)
			old := r.table()
			tb := r.table()
			tb.Classes = append([]Class(nil), tb.Classes...)
			tb.Slices = map[string]map[string]int{"3": {"a": 5}, "7": {"a": 1}}
			edit(&tb)
			r.write(tb)
			until(t, "the change logged", func() bool { return strings.Contains(r.logs.String(), "shape changed") })
			// The change is logged before the rest is applied.
			until(t, "slice 7's new allowance in use", func() bool {
				r.p.mu.Lock()
				defer r.p.mu.Unlock()
				return r.p.slots[member{7, "a"}].allowance == 1
			})
			got := r.table()
			if got.MaxConns != old.MaxConns || len(got.Classes) != 1 || got.Classes[0].PortBase != old.Classes[0].PortBase ||
				len(got.Classes[0].Peers) != 2 || got.Classes[0].SockBufBytes != old.Classes[0].SockBufBytes ||
				got.Classes[0].RefusalsMax != old.Classes[0].RefusalsMax {
				t.Fatalf("the shape changed: %+v", got)
			}
			r.served(peerA2, "a", 3) // the old port, from the old peers
			r.served(peerA2, "a", 7)
			refused(t, r.mustDial(peerA2, "a", 7)) // the new allowance
		})
	}
	t.Run("slice layout", func(t *testing.T) {
		r := newRig(t, nil)
		r.cluster(3)
		tb := r.table()
		tb.SlicePrefix = 27
		tb.Slices = map[string]map[string]int{"7": {"a": 5}}
		r.write(tb)
		until(t, "the change logged", func() bool { return strings.Contains(r.logs.String(), "slice layout") })
		r.served(peerA1, "a", 3)
	})
}

// A slice whose listening socket cannot be opened at a reload is logged and
// tried again at the next look at the file, without another change of it.
func TestTable_ASliceThatDidNotOpenIsTriedAgain(t *testing.T) {
	r := newRig(t, nil)
	r.cluster(9)
	held, err := net.Listen("tcp4", netip.AddrPortFrom(r.addr(1), uint16(r.port("a", 9))).String())
	if err != nil {
		t.Fatal(err)
	}
	tb := r.table()
	tb.Slices["9"] = map[string]int{"a": 5}
	r.write(tb)
	until(t, "the failed listen logged", func() bool { return strings.Contains(r.logs.String(), `"index":9,"reason":"listen: `) })
	held.Close()
	until(t, "slice 9 listening", func() bool {
		r.p.mu.Lock()
		defer r.p.mu.Unlock()
		return r.p.slots[member{9, "a"}] != nil
	})
	r.served(peerA1, "a", 9)
}

// A look at the file that fails is logged once, not at every look.
func TestTable_AFailedLookIsLoggedOnce(t *testing.T) {
	r := newRig(t, nil)
	if err := os.Remove(r.path); err != nil {
		t.Fatal(err)
	}
	until(t, "the failed look logged", func() bool { return strings.Contains(r.logs.String(), "cannot look at the table") })
	time.Sleep(3 * pollEvery) // three more looks at the missing file
	if n := strings.Count(r.logs.String(), "cannot look at the table"); n != 1 {
		t.Fatalf("logged %d times: %s", n, r.logs)
	}
}

// After a good look the next failed one is logged again: the log tells each
// change of state, not only the first.
func TestTable_AFailedLookIsLoggedAgainAfterAGoodOne(t *testing.T) {
	r := newRig(t, nil)
	tb := r.table()
	failed := func() int { return strings.Count(r.logs.String(), "cannot look at the table") }
	if err := os.Remove(r.path); err != nil {
		t.Fatal(err)
	}
	until(t, "the first failed look logged", func() bool { return failed() == 1 })
	r.write(tb)
	time.Sleep(2*pollEvery + pollEvery/2) // two good looks
	if err := os.Remove(r.path); err != nil {
		t.Fatal(err)
	}
	until(t, "the failed look after a good one logged", func() bool { return failed() == 2 })
}

// A file over the size bound is not read at all: it is told as a file that
// cannot be looked at, not as one that does not parse.
func TestTable_AFileOverTheSizeBoundIsNotRead(t *testing.T) {
	r := newRig(t, nil)
	r.cluster(3)
	r.writeBytes(make([]byte, maxTable+1))
	until(t, "the file told", func() bool {
		return strings.Contains(r.logs.String(), "cannot look at the table") || strings.Contains(r.logs.String(), "kept the table in use")
	})
	if logs := r.logs.String(); !strings.Contains(logs, "cannot look at the table") || strings.Contains(logs, "kept the table in use") {
		t.Fatalf("a file of %d bytes was read: %s", maxTable+1, logs)
	}
	r.served(peerA1, "a", 3) // the table in use is kept
}
