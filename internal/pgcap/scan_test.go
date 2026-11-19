package pgcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/pgwire"
)

// straight is the relay's server side written the plain way, over bytes that
// are all there: one message after the other, each judged by the same state
// machine, with no buffer and no batching. It returns what the client must
// have received and how the connection must have ended.
func straight(c Class, slots *StreamSlots, in []byte) ([]byte, string) {
	st := state{c: &c, slots: slots}
	defer func() {
		if st.phase == phStream {
			slots.release()
		}
	}()
	var out []byte
	for o := 0; ; {
		if len(in)-o < 5 {
			return out, errPeerClosed.Error()
		}
		typ, n, err := pgwire.Header([5]byte(in[o : o+5]))
		if err != nil {
			return out, "message length below 4"
		}
		act, err := st.header(typ, n)
		if err != nil {
			return out, err.Error()
		}
		switch act {
		case actAuth:
			if len(in)-o < 5+n {
				return out, errPeerClosed.Error()
			}
			if err := st.auth(in[o+5 : o+5+n]); err != nil {
				return out, err.Error()
			}
		case actFields:
			if n < 2 {
				return out, "malformed row description"
			}
			if len(in)-o < 7 {
				return out, errPeerClosed.Error()
			}
			if err := st.rowFields(in[o+5 : o+7]); err != nil {
				return out, err.Error()
			}
		}
		end := min(o+5+n, len(in))
		if act != actDrop {
			out = append(out, in[o:end]...)
		}
		if end < o+5+n {
			return out, errPeerClosed.Error()
		}
		o = end
	}
}

// watched runs the relay's server side over in, read as plan says, and checks
// at every read — the moments the relay may block — that the client holds
// exactly what the plain scan gives for the bytes read so far: nothing of a
// message not yet judged, nothing of a refused or dropped one, and everything
// that was admitted. It returns the client's bytes and the relay's verdict.
type watched struct {
	net.Conn
	t        *testing.T
	c        Class
	slots    func() *StreamSlots
	sent     []byte
	consumed int
	plan     func(consumed, room int) int
	out      bytes.Buffer
	reads    int
	every    int // check at every every-th read
	fail     string
}

func (w *watched) check(when string) {
	want, _ := straight(w.c, w.slots(), w.sent[:w.consumed])
	if w.fail == "" && !bytes.Equal(w.out.Bytes(), want) {
		w.fail = fmt.Sprintf("%s, %d of %d bytes read: the client holds %d bytes, the plain scan gives %d", when, w.consumed, len(w.sent), w.out.Len(), len(want))
	}
}

func (w *watched) Read(p []byte) (int, error) {
	if len(p) == 0 && w.fail == "" {
		w.fail = fmt.Sprintf("a read of no bytes after %d", w.consumed)
	}
	if w.reads++; w.reads%w.every == 0 {
		w.check("at a read")
	}
	if w.consumed == len(w.sent) {
		return 0, nil // the end, as a closed socket gives it to the relay
	}
	n := max(1, min(len(p), len(w.sent)-w.consumed, w.plan(w.consumed, len(p))))
	copy(p, w.sent[w.consumed:w.consumed+n])
	w.consumed += n
	return n, nil
}

func (w *watched) Write(p []byte) (int, error) { return w.out.Write(p) }

func scan(t *testing.T, c Class, slots func() *StreamSlots, in []byte, every int, plan func(consumed, room int) int) ([]byte, string, string) {
	w := &watched{t: t, c: c, slots: slots, sent: in, plan: plan, every: max(1, every)}
	r := &relay{c: &Conn{Class: c, Client: w}, st: state{c: &c, slots: slots()}, buf: make([]byte, c.CopyBufBytes), server: w}
	err := r.fromServer()
	return w.out.Bytes(), err.Error(), w.fail
}

func freshSlots() *StreamSlots { return &StreamSlots{} }

// quiet makes a class's stream state wait for nothing, so that only the scan
// is under test.
func quiet(c Class) Class {
	if c.Stream != nil {
		s := *c.Stream
		s.BytesPerInterval, s.IntervalMS = 1<<40, 1<<30
		c.Stream = &s
	}
	return c
}

// agree runs in through the relay under plan and compares with the plain scan.
func agree(t *testing.T, name string, c Class, slots func() *StreamSlots, in []byte, every int, plan func(consumed, room int) int) {
	t.Helper()
	want, verdict := straight(c, slots(), in)
	got, gerr, fail := scan(t, c, slots, in, every, plan)
	if fail != "" {
		t.Fatalf("%s: %s", name, fail)
	}
	if !bytes.Equal(got, want) || gerr != verdict {
		t.Fatalf("%s: client received %d bytes and %q; the plain scan gives %d bytes and %q", name, len(got), gerr, len(want), verdict)
	}
}

func whole(_, room int) int { return room }
func oneByte(_, _ int) int  { return 1 }

// cutAt reads up to i bytes first and then whatever is asked.
func cutAt(i int) func(consumed, room int) int {
	return func(consumed, room int) int {
		if consumed < i {
			return i - consumed
		}
		return room
	}
}

// refusals are server streams that end in a refusal of every kind the relay
// has, each after traffic it admits (and, where the class drops, traffic it
// drops), and streams that are admitted to their end.
func refusals() []struct {
	name  string
	class Class
	slots func() *StreamSlots
	sent  []byte
	want  string // part of the verdict
} {
	meta, resp, stream, none := metaClass(), responseClass(), quiet(streamClass()), noneClass()
	small := metaClass()
	small.WindowBytes = 2048
	noisy := responseClass()
	noisy.NoticesMax = 3
	full := func() *StreamSlots { s := &StreamSlots{}; s.acquire(1); return s } // the slice's one place is taken
	w := m('W', make([]byte, 3))
	rows := cat(dataRow(30), dataRow(5), notice, rowDesc(7), dataRow(200), ms4('C', "SELECT 3\x00"), readyMsg)
	after := cat(dataRow(40), readyMsg, rSASL) // what must never follow a refusal
	type R = struct {
		name  string
		class Class
		slots func() *StreamSlots
		sent  []byte
		want  string
	}
	return []R{
		{"a length of 3", meta, freshSlots, cat(login, rows, []byte{'D', 0, 0, 0, 3}, after), "length below 4"},
		{"a length of 0 before authentication-ok", meta, freshSlots, cat(rSASL, []byte{'E', 0, 0, 0, 0}, after), "length below 4"},
		{"a message over the cap", resp, freshSlots, cat(login, rows, binary.BigEndian.AppendUint32([]byte{'D'}, 1<<20), make([]byte, 64), after), "over the cap"},
		{"a message over what is left of the window", small, freshSlots, cat(login, rows, dataRow(900), dataRow(900), after), "byte window"},
		{"a row before authentication-ok", meta, freshSlots, cat(rSASL, notice, rCont, dataRow(9), after), "before authentication-ok"},
		{"ready-for-query before authentication-ok", resp, freshSlots, cat(rSASL, notice, readyMsg, after), "before authentication-ok"},
		{"an authentication request after authentication-ok", meta, freshSlots, cat(login, rows, rOK, after), "after authentication-ok"},
		{"final without continue", meta, freshSlots, cat(rSASL, rFinal, after), "refused after step"},
		{"ok without an exchange", resp, freshSlots, cat(notice, rOK, after), "refused after step"},
		{"cleartext", meta, freshSlots, cat(authReq(3, ""), after), "refused after step"},
		{"an authentication request of 1,025 bytes", meta, freshSlots, cat(rSASL, authReq(11, strings.Repeat("x", 1017)), after), "authentication request of 1025 bytes"},
		{"an authentication request of two bytes", meta, freshSlots, cat(rSASL, rCont, m('R', []byte{0, 0}), after), "malformed authentication request"},
		{"an iteration count under the floor", meta, freshSlots, cat(rSASL, cont(5), after), "iteration count"},
		{"a challenge that is no challenge", meta, freshSlots, cat(rSASL, authReq(11, "r=a,s=b"), after), "malformed SCRAM challenge"},
		{"a row description one field over", meta, freshSlots, cat(login, rows, rowDesc(1665), after), "row description fields"},
		{"a row description of one byte", meta, freshSlots, cat(login, rows, m('T', []byte{1}), after), "malformed row description"},
		{"a copy-both without a stream window", resp, freshSlots, cat(login, rows, w, copyData(64), after), "copy-both refused"},
		{"a copy-both with the slice's place taken", stream, full, cat(login, rows, w, copyData(64), after), "copy-both over"},
		{"a copy-both without places", stream, func() *StreamSlots { return nil }, cat(login, w, copyData(64), after), "copy-both over"},
		{"the 65th parameter status", meta, freshSlots, cat(login, repeat(paramMsg, 62), dataRow(20), paramMsg, after), "parameter-status"},
		{"the fourth notice", noisy, freshSlots, cat(rSASL, notice, rCont, notice, rFinal, rOK, notice, paramMsg, notice, after), "notices over the cap"},
		{"a refusal in the stream state", stream, freshSlots, cat(login, w, copyData(64), binary.BigEndian.AppendUint32([]byte{'d'}, 1<<20), after), "over the cap"},
		{"a stream, left and entered again, then a refusal", stream, freshSlots, cat(login, w, copyData(64), readyMsg, dataRow(8), w, w, copyData(9), readyMsg, rOK, after), "after authentication-ok"},
		{"admitted to the end, dropping", meta, freshSlots, cat(login, notice, rows, ms4('A', "\x00\x00\x00\x01c\x00p\x00"), rows, ms4('N', strings.Repeat("n", 700)), dataRow(5)), "closed by a peer"},
		{"admitted to the end, no window", none, freshSlots, cat(login, rows, ms4('?', "x"), m('T', []byte{0, 1, 9}), rows, m(0), m(0xff)), "closed by a peer"},
		{"an error and the end before authentication-ok", meta, freshSlots, cat(rSASL, rCont, ms4('E', "SFATAL\x00C28P01\x00Mno\x00\x00")), "closed by a peer"},
	}
}

// Every refusal, with the server's bytes cut at every single position, read a
// byte at a time, and ended early at every position: the client receives every
// message admitted before the refused one and no byte of it or after it, and
// at every read holds exactly what was admitted of the bytes read so far.
func TestBatch_EveryRefusalAtEverySplit(t *testing.T) {
	for _, r := range refusals() {
		for _, size := range []int{minBuf, 64 << 10} {
			c := r.class
			c.CopyBufBytes = size
			t.Run(fmt.Sprintf("%s, a buffer of %d", r.name, size), func(t *testing.T) {
				want, verdict := straight(c, r.slots(), r.sent)
				if !strings.Contains(verdict, r.want) {
					t.Fatalf("the plain scan ends with %q, want %q: the case tests nothing", verdict, r.want)
				}
				if bytes.Contains(want, []byte("SELECT 3")) != bytes.Contains(r.sent, []byte("SELECT 3")) {
					t.Fatal("the admitted traffic before the refusal did not pass")
				}
				agree(t, "in one piece", c, r.slots, r.sent, 1, whole)
				agree(t, "a byte at a time", c, r.slots, r.sent, 1, oneByte)
				for i := 1; i < len(r.sent); i++ {
					agree(t, fmt.Sprintf("cut at %d", i), c, r.slots, r.sent, 1, cutAt(i))
					if size == minBuf {
						agree(t, fmt.Sprintf("ended at %d", i), c, r.slots, r.sent[:i], 1, whole)
					}
				}
			})
		}
	}
}

// A message that is held until it is whole — each authentication request, the
// start of a row description — and a refused one, at every offset around the
// end of the buffer: behind a filler that is relayed, and behind one that is
// dropped. The buffer's end and the move to its start never let a part of a
// held or refused message out, and never lose a byte of an admitted one.
func TestBatch_HeldAndRefusedMessagesAcrossTheBufferEnd(t *testing.T) {
	relays, drops := responseClass(), responseClass()
	relays.CopyBufBytes, relays.MessageBytes, relays.WindowBytes = minBuf, 0, 1<<30
	drops.CopyBufBytes, drops.MessageBytes, drops.WindowBytes, drops.DropNotices = minBuf, 0, 1<<30, true
	tail := cat(dataRow(33), rowDesc(12), dataRow(700), rowDesc(1), readyMsg)
	for _, c := range []Class{relays, drops} {
		for _, end := range []struct {
			name string
			sent []byte
		}{
			{"a login, admitted", cat(login, tail)},
			{"a refused challenge", cat(rSASL, cont(5), tail)},
			{"a refused request after the exchange", cat(login, tail, rSASL, tail)},
			{"a row description over the cap", cat(login, dataRow(33), rowDesc(1665), tail)},
		} {
			for _, buffers := range []int{1, 2, 3} {
				if buffers > 1 && len(end.sent) > 400 && !c.DropNotices {
					continue // the long endings once more only behind a dropped filler
				}
				for fill := buffers*minBuf - len(end.sent) - 8; fill <= buffers*minBuf+8; fill++ {
					// One notice before authentication-ok, as long as it takes to put the rest there.
					in := cat(ms4('N', strings.Repeat("n", fill-5)), end.sent)
					name := fmt.Sprintf("%s, dropping %v, behind %d bytes", end.name, c.DropNotices, fill)
					agree(t, name, c, freshSlots, in, 1, whole)
					agree(t, name+", the buffer never full", c, freshSlots, in, 1, func(_, room int) int { return room - 1 })
					agree(t, name+", in reads of 1,000", c, freshSlots, in, 1, func(_, _ int) int { return 1000 })
				}
			}
		}
	}
}

// A body many times the buffer is streamed through it — never held, never
// grown — whether relayed or dropped, with a header split behind it.
func TestBatch_LongBodiesStreamThroughTheBuffer(t *testing.T) {
	c := noneClass()
	c.CopyBufBytes, c.DropNotices = minBuf, true
	long, dropped := dataRow(40*minBuf+3), ms4('N', strings.Repeat("n", 33*minBuf+1))
	in := cat(login, long, dataRow(6), dropped, dataRow(7), dropped, long, readyMsg)
	for _, plan := range []func(int, int) int{whole, func(_, room int) int { return room - 3 }, func(c, _ int) int { return 1 + c%4099 }} {
		agree(t, "long bodies", c, freshSlots, in, 16, plan)
	}
	// And nothing is allocated for a body: the one buffer is all there is.
	w := &watched{t: t, c: c, slots: freshSlots, sent: in, plan: whole, every: 1 << 30}
	r := &relay{c: &Conn{Class: c, Client: w}, st: state{c: &c, slots: freshSlots()}, buf: make([]byte, c.CopyBufBytes), server: w}
	w.out.Grow(len(in))
	before := totalAlloc()
	r.fromServer()
	if grew := totalAlloc() - before; grew > 64<<10 {
		t.Fatalf("relaying %d bytes through a %d-byte buffer allocated %d bytes", len(in), c.CopyBufBytes, grew)
	}
}

// A fault in the middle of a read's worth of messages leaves the client every
// message admitted before it and nothing after, at every split.
func TestBatch_FaultLeavesWhatWasAdmitted(t *testing.T) {
	old := faultHook
	faultHook = func(typ byte) {
		if typ == 0x7f {
			panic("marker")
		}
	}
	defer func() { faultHook = old }()
	c := metaClass() // drops notices
	before := cat(login, dataRow(30), notice, rowDesc(3), dataRow(9))
	in := cat(before, m(0x7f, []byte("xyz")), dataRow(40), readyMsg)
	want, _ := straight(c, freshSlots(), before)
	for i := 0; i <= len(in); i++ {
		w := &watched{t: t, c: c, slots: freshSlots, sent: in, plan: cutAt(i), every: 1 << 30}
		r := &relay{c: &Conn{Class: c, Client: w}, st: state{c: &c, slots: freshSlots()}, buf: make([]byte, c.CopyBufBytes), server: w}
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("cut at %d: no fault", i)
				}
			}()
			r.fromServer()
		}()
		if !bytes.Equal(w.out.Bytes(), want) {
			t.Fatalf("cut at %d: the client holds %d bytes after the fault, want the %d admitted before it", i, w.out.Len(), len(want))
		}
	}
}

// FuzzScanAgainstThePlainScan gives any server bytes to the relay in one
// piece, a byte at a time, cut once anywhere, in random sizes and with a
// small buffer, and to the plain scan: the same client bytes, the same
// verdict, and at every read exactly what was admitted so far.
func FuzzScanAgainstThePlainScan(f *testing.F) {
	for i, r := range refusals() {
		f.Add(byte(i), uint64(i), uint16(len(r.sent)/2), r.sent)
	}
	f.Add(byte(1), uint64(9), uint16(7), cat(login, m('W', make([]byte, 3)), copyData(64), readyMsg, rowDesc(3)))
	f.Add(byte(13), uint64(7), uint16(4090), cat(login, repeat(dataRow(30), 300), dataRow(5000), readyMsg))
	f.Fuzz(func(t *testing.T, which byte, seed uint64, cut uint16, in []byte) {
		if len(in) > 12<<10 {
			return
		}
		classes := []Class{metaClass(), quiet(streamClass()), responseClass(), noneClass()}
		c := classes[int(which)%len(classes)]
		c.WindowBytes = min(c.WindowBytes, 16<<10)
		if c.Window == WindowNone {
			c.WindowBytes = 0
		}
		c.DropNotices = which&4 != 0
		if which&8 != 0 {
			c.CopyBufBytes = minBuf
		}
		if which&16 != 0 {
			c.NoticesMax, c.ParamStatusMax, c.RowFieldsMax = 2, 3, 4
		}
		rng := rand.New(rand.NewPCG(seed, 1))
		agree(t, "in one piece", c, freshSlots, in, 1, whole)
		agree(t, "a byte at a time", c, freshSlots, in, 7, oneByte)
		agree(t, "cut once", c, freshSlots, in, 1, cutAt(int(cut)%(len(in)+1)))
		agree(t, "random", c, freshSlots, in, 1, func(_, _ int) int { return 1 + rng.IntN(700) })
		agree(t, "random, small", c, freshSlots, in, 3, func(_, _ int) int { return 1 + rng.IntN(9) })
	})
}

// The pacing rule under any schedule, on a clock the test owns: with a debt of
// d bytes at the start, what has been taken by the end of the k-th interval is
// never more than the larger of d and k+1 budgets — over any stretch the rate
// holds, the entry's own bytes apart — and a server that always has bytes for
// a relay that is always on time gets exactly one budget an interval once the
// debt is paid: the debt neither raises the rate nor lowers it for good.
func TestStream_DebtAndRateUnderAnySchedule(t *testing.T) {
	const budget, iv = 1000, 50 * time.Millisecond
	c := streamClass()
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = budget, int(iv/time.Millisecond)
	rng := rand.New(rand.NewPCG(1, 2))
	t0 := time.Unix(5000, 0)
	for run := range 2000 {
		debt := []int{0, 1, 999, 1000, 1001, 2500, 65531, 1 << 20}[run%8]
		s := state{c: &c, phase: phStream}
		s.allowance(t0) // the entry
		s.took(debt)
		taken, now := int64(debt), t0
		onTime := run%2 == 0
		var paidAt time.Duration = -1
		for step := 0; step < 2400 && now.Sub(t0) < 3000*iv; step++ {
			left, wait := s.allowance(now)
			if left < 0 || left > budget || left == 0 && wait <= 0 || left > 0 && wait != 0 {
				t.Fatalf("debt %d at %v: allowance %d, wait %v", debt, now.Sub(t0), left, wait)
			}
			if left == 0 {
				if wait > iv {
					t.Fatalf("debt %d: a wait of %v, longer than an interval", debt, wait)
				}
				now = now.Add(wait)
				if !onTime {
					now = now.Add(time.Duration(rng.IntN(3)) * iv / 2) // a late clock, an idle server
				}
				continue
			}
			if paidAt < 0 {
				paidAt = now.Sub(t0)
			}
			n := int(left)
			if !onTime {
				n = 1 + rng.IntN(int(left))
				now = now.Add(time.Duration(rng.IntN(int(iv) * 3 / 2))) // the read blocks
			}
			s.allowance(now) // as the relay does after a read
			s.took(n)
			taken += int64(n)
			k := int64(now.Sub(t0) / iv)
			if most := max(int64(debt), (k+1)*budget); taken > most {
				t.Fatalf("debt %d: %d bytes taken %v after the entry, more than %d", debt, taken, now.Sub(t0), most)
			}
		}
		if paidAt < 0 {
			t.Fatalf("debt %d: nothing was ever read again", debt)
		}
		if onTime {
			// Paid in exactly the intervals the debt is worth, then one budget an interval.
			if want := time.Duration(debt/budget) * iv; paidAt != want {
				t.Fatalf("debt %d: the first read after it at %v, want %v", debt, paidAt, want)
			}
			k := int64(now.Sub(t0) / iv)
			if taken != max(int64(debt), k*budget) && taken != (k+1)*budget {
				t.Fatalf("debt %d: %d bytes after %d intervals on time, want one budget an interval", debt, taken, k)
			}
		}
	}
}

// In the stream state the relay never asks the server for no bytes and never
// for more than the interval has left, down to a budget of one byte; what a
// read brought is with the client before the relay waits for the next
// interval; and a debt larger than the buffer is not possible.
func TestStream_ReadsAreCutToTheAllowance(t *testing.T) {
	c := streamClass()
	c.CopyBufBytes = minBuf
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = 1, 10
	wmsg := m('W', make([]byte, 3))
	in := cat(login, wmsg, copyData(12), readyMsg)
	entry := len(login) + len(wmsg)
	var sizes []int
	w := &watched{t: t, c: c, slots: freshSlots, sent: in, every: 1}
	w.plan = func(consumed, room int) int {
		if consumed < entry {
			return entry - consumed // the copy-both ends its read: its three body bytes are the only debt
		}
		sizes = append(sizes, room)
		return room
	}
	r := &relay{c: &Conn{Class: c, Client: w}, ctx: t.Context(), st: state{c: &c, slots: freshSlots()}, buf: make([]byte, c.CopyBufBytes), server: w}
	start := time.Now()
	if err := r.fromServer(); err != errPeerClosed {
		t.Fatalf("relay: %v", err)
	}
	if w.fail != "" {
		t.Fatal(w.fail)
	}
	if !bytes.Equal(w.out.Bytes(), in) {
		t.Fatalf("relayed %d of %d bytes", w.out.Len(), len(in))
	}
	// Twelve bytes of copy data and the header of the ready-for-query, a byte
	// an interval; the byte after that header is read outside the state.
	if len(sizes) != 18 || sizes[17] <= 1 {
		t.Fatalf("reads after the copy-both: %v", sizes)
	}
	for i, n := range sizes[:17] {
		if n != 1 {
			t.Fatalf("read %d in the stream state asked for %d bytes at one byte an interval", i, n)
		}
	}
	if d := time.Since(start); d < 16*10*time.Millisecond {
		t.Fatalf("17 bytes at one byte per 10 ms in %v", d)
	}
}

// The field cap applies where the count caps apply: for a class without a
// window, in the startup only — there one field over the cap closes the
// connection, and after the first ready-for-query any count passes.
func TestRowDescription_FieldCapOnlyWhereCountsApply(t *testing.T) {
	c := noneClass()
	startup := cat(rSASL, cont(4096), rFinal, rOK)
	p := relayTo(t, c, func(s net.Conn) { write(s, startup, rowDesc(1665), readyMsg) })
	if err := p.closed(t, startup); !strings.Contains(err.Error(), "row description fields") {
		t.Fatalf("in the startup: %v", err)
	}
	wide := rowDesc(40000)
	run, ch := script(t, login, wide)
	q := relayTo(t, c, run)
	if got := q.read(t, len(login)+len(wide)); !bytes.Equal(got, cat(login, wide)) {
		t.Fatal("after the startup a wide row description did not pass unchanged")
	}
	q.open(t, <-ch)
}

// Each stay in the stream state has its own interval: when a server ends the
// state and starts it again, the new stay is charged what was read beyond its
// own copy-both and nothing of the stay before — no byte is charged twice.
func TestStream_ANewStayStartsANewInterval(t *testing.T) {
	c := quiet(streamClass())
	w := m('W', make([]byte, 3))
	in := cat(login, w, copyData(1000), readyMsg, dataRow(8), w, copyData(300))
	out := &bytes.Buffer{}
	r := &relay{c: &Conn{Class: c, Client: clientBytes{w: out}}, st: state{c: &c, slots: &StreamSlots{}},
		buf: make([]byte, c.CopyBufBytes), server: &splitReader{rest: in, sizes: func() int { return len(in) }}}
	if err := r.fromServer(); err != errPeerClosed {
		t.Fatalf("relay: %v", err)
	}
	if !bytes.Equal(out.Bytes(), in) || r.st.ivUsed != 3+300 {
		t.Fatalf("relayed %d of %d bytes; the second stay is charged %d bytes, want %d", out.Len(), len(in), r.st.ivUsed, 3+300)
	}
}

// A connection that is paying off what it read with its copy-both — reading
// nothing for many intervals — is still closed at once from outside.
func TestStream_ClosedFromOutsideWhilePayingTheEntryDebt(t *testing.T) {
	c := streamClass()
	c.CopyBufBytes = 16 << 10
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = 1, 1000 // a full buffer is hours of debt
	w := m('W', make([]byte, 3))
	p := relayTo(t, c, func(s net.Conn) { write(s, cat(login, w, repeat(copyData(1024), 15))) }, opts{streams: &StreamSlots{}})
	p.read(t, len(login)+len(w))
	time.Sleep(100 * time.Millisecond) // the relay now waits for its allowance, however the bytes were read
	start := time.Now()
	p.cancel()
	if err := p.result(t); !errors.Is(err, context.Canceled) {
		t.Fatalf("relay: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("closed from outside after %v", d)
	}
}
