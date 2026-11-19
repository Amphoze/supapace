package pgcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// trickle writes b in pieces cut at the given offsets, pausing between them so
// that each piece reaches the relay in a read of its own.
func trickle(s net.Conn, b []byte, cuts ...int) {
	at := 0
	for _, c := range append(cuts, len(b)) {
		if !write(s, b[at:c]) {
			return
		}
		at = c
		time.Sleep(30 * time.Millisecond)
	}
}

// nothingFor checks that no byte reaches the client for a while.
func nothingFor(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(make([]byte, 1))
	var ne net.Error
	if n != 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read %d bytes (%v) while the rest of a message was pending", n, err)
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
}

// A header, an authentication request or the start of a row description split
// across reads is judged once it is whole, and no part of it is forwarded
// before; a header split that way and refused is not forwarded at all.
func TestBatch_SplitMessagesJudgedWhole(t *testing.T) {
	row := dataRow(64)
	for _, c := range []struct {
		name string
		msg  []byte
		cuts []int
	}{
		{"a header", row, []int{2}},
		{"a header one byte at a time", row, []int{1, 2, 3, 4}},
		{"a row description", rowDesc(10), []int{5, 6}},
	} {
		t.Run(c.name, func(t *testing.T) {
			run, ch := script(t, login)
			p := relayTo(t, metaClass(), run)
			p.read(t, len(login))
			s := <-ch
			go trickle(s, c.msg, c.cuts...)
			if c.cuts[0] < 5 {
				nothingFor(t, p.client, 25*time.Millisecond)
			}
			if got := p.read(t, len(c.msg)); !bytes.Equal(got, c.msg) {
				t.Fatalf("got %q", got)
			}
		})
	}
	t.Run("an authentication request", func(t *testing.T) {
		run, ch := script(t)
		p := relayTo(t, metaClass(), run)
		s := <-ch
		go trickle(s, login, 3, 9, len(rSASL)+7)
		if got := p.read(t, len(login)); !bytes.Equal(got, login) {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("a refused header", func(t *testing.T) {
		c := responseClass() // message cap 256 KiB
		over := binary.BigEndian.AppendUint32([]byte{'D'}, 1<<20)
		p := relayTo(t, c, func(s net.Conn) { write(s, login); trickle(s, append(over, make([]byte, 64)...), 2) })
		p.closed(t, login)
	})
	t.Run("a refused authentication request", func(t *testing.T) {
		p := relayTo(t, metaClass(), func(s net.Conn) { trickle(s, cat(rSASL, cont(5)), len(rSASL)+3, len(rSASL)+12) })
		p.closed(t, rSASL)
	})
}

// Messages admitted before a refused one, in the same read, reach the client;
// nothing of the refused one does.
func TestBatch_BreachMidBufferFlushesWhatCameBefore(t *testing.T) {
	c := responseClass()
	rows := repeat(dataRow(40), 50)
	over := cat(binary.BigEndian.AppendUint32([]byte{'D'}, 1<<20), make([]byte, 100))
	p := relayTo(t, c, func(s net.Conn) { write(s, cat(login, rows, over)) })
	p.closed(t, cat(login, rows))
	q := relayTo(t, metaClass(), func(s net.Conn) { write(s, cat(login, rows, authReq(0, ""), rows)) })
	q.closed(t, cat(login, rows))
}

// A dropped message is skipped inside the buffer, also when it is longer than
// the buffer and spans reads; what surrounds it passes.
func TestBatch_DroppedMessageSpanningReads(t *testing.T) {
	c := metaClass() // drops notices
	c.CopyBufBytes = minBuf
	row := dataRow(100)
	long := ms4('N', string(make([]byte, 3*minBuf)))
	want := cat(login, row, row, readyMsg)
	t.Run("one write", func(t *testing.T) {
		run, ch := script(t, login, row, long, notice, row, readyMsg)
		p := relayTo(t, c, run)
		if got := p.read(t, len(want)); !bytes.Equal(got, want) {
			t.Fatalf("got %d bytes", len(got))
		}
		<-ch
	})
	t.Run("in pieces", func(t *testing.T) {
		run, ch := script(t)
		p := relayTo(t, c, run)
		s := <-ch
		all := cat(login, row, long, notice, row, readyMsg)
		o := len(login) + len(row)
		go trickle(s, all, o+2, o+700, o+len(long)-1, o+len(long)+3)
		if got := p.read(t, len(want)); !bytes.Equal(got, want) {
			t.Fatalf("got %d bytes", len(got))
		}
	})
}

// What was read beyond a copy-both in the same read counts in the stream
// state's first interval: a full buffer at the switch is no burst.
func TestBatch_StreamEntryDoesNotBurst(t *testing.T) {
	c := streamClass()
	c.CopyBufBytes = 16 << 10
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = 1<<10, 50
	w := m('W', make([]byte, 3))
	data := repeat(copyData(1024), 96)
	p := relayTo(t, c, func(s net.Conn) { write(s, cat(login, w, data)) }, opts{streams: &StreamSlots{}})
	p.read(t, len(login)+len(w))
	start := time.Now()
	p.read(t, 20<<10) // the first buffer (about sixteen budgets) and four more
	// The sixteen budgets read with the copy-both are paid off before more is
	// read: about twenty intervals in all, never under fourteen (without the
	// debt, five). A loaded machine is only slower.
	if d := time.Since(start); d < 14*50*time.Millisecond {
		t.Fatalf("twenty budgets in %v", d)
	}
}

// In the stream state a read takes no more than what is left of the
// interval's allowance, however much the buffer could hold: a full buffer is
// no burst.
func TestBatch_StreamReadsAtMostTheAllowance(t *testing.T) {
	c := streamClass()
	c.CopyBufBytes = 16 << 10
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = 1<<10, 50
	w := m('W', make([]byte, 3))
	run, ch := script(t, login, w)
	p := relayTo(t, c, run, opts{streams: &StreamSlots{}})
	p.read(t, len(login)+len(w))
	s := <-ch
	time.Sleep(100 * time.Millisecond) // nothing read beyond the copy-both
	go write(s, repeat(copyData(1024), 64))
	first := p.read(t, 1)
	_ = first
	start := time.Now()
	p.client.SetReadDeadline(start.Add(120 * time.Millisecond))
	got := 1
	buf := make([]byte, 64<<10)
	for {
		n, err := p.client.Read(buf)
		got += n
		if err != nil {
			break
		}
	}
	p.client.SetReadDeadline(time.Now().Add(30 * time.Second))
	// At most three intervals begin within 120 ms of the first byte.
	if got > 3<<10 {
		t.Fatalf("%d bytes within 120 ms at 1 KiB per 50 ms", got)
	}
}

// Exactly the bytes read beyond the copy-both's header in its read (its own
// body included) are counted in the stream state's first interval.
func TestBatch_StreamEntryCountsWhatWasReadAlready(t *testing.T) {
	c := streamClass()
	c.Stream.BytesPerInterval, c.Stream.IntervalMS = 1<<40, 1<<30 // no wait, no new interval
	after := cat(copyData(1000), copyData(300))
	in := cat(login, m('W', make([]byte, 3)), after)
	out := &bytes.Buffer{}
	r := &relay{c: &Conn{Class: c, Client: clientBytes{w: out}}, st: state{c: &c, slots: &StreamSlots{}},
		buf: make([]byte, c.CopyBufBytes), server: &splitReader{rest: in, sizes: func() int { return len(in) }}}
	if err := r.fromServer(); err != errPeerClosed {
		t.Fatalf("relay: %v", err)
	}
	if !bytes.Equal(out.Bytes(), in) || r.st.ivUsed != int64(3+len(after)) {
		t.Fatalf("relayed %d of %d bytes; counted %d in the first interval, want %d", out.Len(), len(in), r.st.ivUsed, 3+len(after))
	}
}
