package pgcap

import (
	"bytes"
	"testing"
	"time"
)

// cancelReq is a cancel request with the given key.
func cancelReq(key byte) []byte {
	return append(first8(16, codeCancel), 0, 0, 0, key, 0, 0, 0, key)
}

// With a project at its allowance a cancel request still reaches the cluster
// of its slice.
func TestCancel_AdmittedOutsideTheCap(t *testing.T) {
	r := newRig(t, nil)
	f := r.cluster(3)
	for range 5 {
		r.served(peerA1, "a", 3)
	}
	refused(t, r.mustDial(peerA1, "a", 3))
	c := r.mustDial(peerA2, "a", 3)
	c.Write(cancelReq(7))
	unanswered(t, c)
	until(t, "the cancel reached the cluster", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.cancels) == 1
	})
	if !bytes.Equal(f.cancels[0], cancelReq(7)) {
		t.Fatalf("the cluster received %q", f.cancels[0])
	}
}

// The cluster receives the request's sixteen bytes and nothing of what the
// client sent after them; what the cluster answers is not read back.
func TestCancel_ExactlySixteenBytes(t *testing.T) {
	r := newRig(t, nil)
	f := r.cluster(3)
	c := r.mustDial(peerA1, "a", 3)
	c.Write(append(cancelReq(9), bytes.Repeat([]byte{'x'}, 100)...))
	unanswered(t, c)
	until(t, "the cancel reached the cluster", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.cancels) == 1
	})
	if got := f.cancels[0]; !bytes.Equal(got, cancelReq(9)) {
		t.Fatalf("the cluster received %d bytes %q, want exactly the sixteen of the request", len(got), got)
	}
}

// The third simultaneous cancel of a project and the ninth from one peer are
// closed unanswered; held cancels wait on a cluster that never accepts.
func TestCancel_OverItsAllowanceClosedUnanswered(t *testing.T) {
	r := newRig(t, func(tb *Table) {
		tb.Classes[0].CancelMS = 20000
		for _, i := range []string{"4", "5", "6"} {
			tb.Slices[i] = map[string]int{"a": 5}
		}
	})
	for _, i := range []int{3, 4, 5, 6, 7} {
		r.silentCluster(i)
	}
	held := func(peer byte, i int) {
		c := r.mustDial(peer, "a", i)
		c.Write(cancelReq(1))
	}
	cancels := func() int {
		r.p.mu.Lock()
		defer r.p.mu.Unlock()
		return r.p.classes["a"].peerCancels[r.addr(peerA1)] + r.p.classes["a"].peerCancels[r.addr(peerA2)]
	}
	held(peerA1, 3)
	held(peerA2, 3)
	until(t, "two cancels of slice 3 in flight", func() bool { return cancels() == 2 })
	c := r.mustDial(peerA2, "a", 3)
	c.Write(cancelReq(1))
	unanswered(t, c)

	for _, i := range []int{4, 4, 5, 5, 6, 6} {
		held(peerA1, i)
	}
	held(peerA1, 7)
	until(t, "nine cancels in flight, eight from .2", func() bool { return cancels() == 9 })
	c = r.mustDial(peerA1, "a", 7)
	c.Write(cancelReq(1))
	unanswered(t, c) // the ninth from .2
	held(peerA2, 7)  // the other peer's first, with room in its slice
	until(t, "the other peer's cancel admitted", func() bool { return cancels() == 10 })
}

// A cluster that never accepts: the cancel is closed at cancel_ms.
func TestCancel_Deadline(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.Classes[0].CancelMS = 600 })
	r.silentCluster(3)
	c := r.mustDial(peerA1, "a", 3)
	t0 := time.Now()
	c.Write(cancelReq(1))
	unanswered(t, c)
	if d := time.Since(t0); d < 550*time.Millisecond {
		t.Fatalf("closed after %v, before cancel_ms", d)
	}
	until(t, "released", func() bool { u, _ := r.counts("a"); return u == 0 })
}

// A cancel whose dial is in flight when its slice leaves the table ends then,
// not at cancel_ms: nothing of a slice outlives its row.
func TestCancel_CutWithItsSlice(t *testing.T) {
	r := newRig(t, func(tb *Table) { tb.Classes[0].CancelMS = 60000 })
	r.silentCluster(3)
	c := r.mustDial(peerA1, "a", 3)
	c.Write(cancelReq(1))
	until(t, "the cancel dialling", func() bool {
		r.p.mu.Lock()
		defer r.p.mu.Unlock()
		return r.p.slots[member{3, "a"}].cancels == 1
	})
	tb := r.table()
	delete(tb.Slices, "3")
	t0 := time.Now()
	r.write(tb)
	unanswered(t, c)
	until(t, "its unit released", func() bool { u, _ := r.counts("a"); return u == 0 })
	if d := time.Since(t0); d > 10*time.Second {
		t.Fatalf("released after %v", d)
	}
}
