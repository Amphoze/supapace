package main

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// held is one chunk the relay waits to deliver: when it is due, and the
// channel that lets it go.
type held struct {
	due     time.Time
	release chan time.Time
}

// tDelayer is a relay whose clock stands still at t0 and whose waits are
// released by the test, one by one, through asked.
func tDelayer(to string, rtt time.Duration) (d *delayer, t0 time.Time, asked chan held) {
	t0 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	asked = make(chan held, 1024)
	d = &delayer{to: to, half: rtt / 2, now: func() time.Time { return t0 },
		wait: func(due time.Time) <-chan time.Time {
			h := held{due, make(chan time.Time, 1)}
			asked <- h
			return h.release
		}}
	return d, t0, asked
}

func next(t *testing.T, asked chan held, what string) held {
	t.Helper()
	select {
	case h := <-asked:
		return h
	case <-time.After(20 * time.Second):
		t.Fatalf("%s: the relay never waited", what)
	}
	return held{}
}

// readInto reads conn in the background; got receives what each read returned.
func readInto(c net.Conn) chan []byte {
	got := make(chan []byte, 1024)
	go func() {
		defer close(got)
		for {
			b := make([]byte, 64<<10)
			n, err := c.Read(b)
			if n > 0 {
				got <- b[:n]
			}
			if err != nil {
				return
			}
		}
	}()
	return got
}

func recv(t *testing.T, got chan []byte, what string) []byte {
	t.Helper()
	select {
	case b, ok := <-got:
		if !ok {
			t.Fatalf("%s: the connection ended", what)
		}
		return b
	case <-time.After(20 * time.Second):
		t.Fatalf("%s: nothing arrived", what)
	}
	return nil
}

func TestDelay_HalfTheRoundTripEachWay_BoundedBuffers(t *testing.T) {
	const rtt = 100 * time.Millisecond

	t.Run("each_way", func(t *testing.T) {
		// An upstream that echoes; what it receives is also seen by the test.
		up, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		atUp := make(chan []byte, 16)
		go func() {
			c, err := up.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			for b := range readInto(c) {
				atUp <- b
				c.Write(b)
			}
		}()
		d, t0, asked := tDelayer(up.Addr().String(), rtt)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go d.serve(ln)
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		back := readInto(c)

		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		h := next(t, asked, "towards the upstream")
		if want := t0.Add(rtt / 2); !h.due.Equal(want) {
			t.Errorf("towards the upstream: due %v, want half the round trip after it was read, %v", h.due, want)
		}
		// The relay is blocked in its wait: nothing has gone on.
		select {
		case b := <-atUp:
			t.Fatalf("the upstream received %q before its half of the round trip", b)
		default:
		}
		h.release <- h.due
		if b := recv(t, atUp, "upstream"); string(b) != "ping" {
			t.Fatalf("the upstream received %q", b)
		}
		h = next(t, asked, "back to the client")
		if want := t0.Add(rtt / 2); !h.due.Equal(want) {
			t.Errorf("back to the client: due %v, want %v", h.due, want)
		}
		select {
		case b := <-back:
			t.Fatalf("the client received %q before the answer's half of the round trip", b)
		default:
		}
		h.release <- h.due
		if b := recv(t, back, "client"); string(b) != "ping" {
			t.Fatalf("the client received %q", b)
		}
	})

	t.Run("bounded", func(t *testing.T) {
		// A pipe has no buffer of its own: a write returns once the relay has
		// read it, so the bytes accepted are exactly what the relay holds.
		if delayChunk != 32<<10 {
			t.Fatalf("buffers of %d bytes, want 32 KiB", delayChunk)
		}
		srcW, srcR := net.Pipe()
		dstW, dstR := net.Pipe()
		d, _, asked := tDelayer("", rtt)
		go d.pipe(dstW, srcR)
		const chunks = 64
		var accepted atomic.Int64
		payload := make([]byte, chunks*delayChunk)
		for i := range payload {
			payload[i] = byte(i / delayChunk)
		}
		go func() {
			for i := range chunks {
				if _, err := srcW.Write(payload[i*delayChunk : (i+1)*delayChunk]); err != nil {
					return
				}
				accepted.Add(1)
			}
			srcW.Close()
		}()
		first := next(t, asked, "first chunk")
		// One chunk waits to be written, delayQueue wait in the queue and one
		// more is read and waits for room: nothing else is accepted.
		want := int64(delayQueue + 2)
		wait := func(n int64) {
			t.Helper()
			deadline := time.Now().Add(20 * time.Second)
			for accepted.Load() != n {
				if got := accepted.Load(); got > n || time.Now().After(deadline) {
					t.Fatalf("%d chunks accepted, want %d (one %d-byte chunk being written, %d queued, one read)",
						got, n, delayChunk, delayQueue)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		wait(want)
		// Control: one chunk released makes room for exactly one more.
		got := readInto(dstR)
		first.release <- first.due
		if b := recv(t, got, "first chunk"); len(b) != delayChunk || !bytes.Equal(b, payload[:delayChunk]) {
			t.Fatalf("first chunk: %d bytes", len(b))
		}
		wait(want + 1)
		// Release the rest; every write is one chunk of at most 32 KiB, in order.
		go func() {
			for h := range asked {
				h.release <- h.due
			}
		}()
		all := append([]byte(nil), payload[:delayChunk]...)
		for len(all) < len(payload) {
			b := recv(t, got, "the rest")
			if len(b) > delayChunk {
				t.Fatalf("a write of %d bytes, above the %d-byte buffer", len(b), delayChunk)
			}
			all = append(all, b...)
		}
		if !bytes.Equal(all, payload) {
			t.Fatal("the bytes arrived changed or out of order")
		}
		if _, ok := <-got; ok {
			t.Fatal("bytes after the end")
		}
	})
}

func TestDelay_EndsBothWays(t *testing.T) {
	// The client half-closes: the upstream sees the end, answers, closes, and
	// the client gets the answer and then the end.
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		b, _ := io.ReadAll(c)
		c.Write(append([]byte("got "), b...))
		c.Close()
	}()
	d, _, asked := tDelayer(up.Addr().String(), time.Second)
	go func() {
		for h := range asked {
			h.release <- h.due
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go d.serve(ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))
	c.Write([]byte("x"))
	c.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "got x" {
		t.Fatalf("answer %q, %v", b, err)
	}
}

func TestDelay_RealWaitHonoursTheDueTime(t *testing.T) {
	select {
	case <-realWait(time.Now().Add(time.Hour)):
		t.Fatal("a wait due in an hour ended at once")
	default:
	}
	select {
	case <-realWait(time.Now().Add(-time.Second)):
	case <-time.After(20 * time.Second):
		t.Fatal("a wait already due did not end")
	}
}

func TestDelay_Usage(t *testing.T) {
	d, listen, code := parseDelay([]string{"--listen", "127.0.0.1:0", "--to", "127.0.0.1:1", "--rtt", "100ms"}, io.Discard)
	if code != 0 || listen != "127.0.0.1:0" || d.to != "127.0.0.1:1" || d.half != 50*time.Millisecond {
		t.Fatalf("parse: %d %q %+v", code, listen, d)
	}
	for _, args := range [][]string{
		{"delay"},
		{"delay", "--listen", "127.0.0.1:0", "--to", "127.0.0.1:1"},
		{"delay", "--listen", "127.0.0.1:0", "--to", "127.0.0.1:1", "--rtt", "0s"},
		{"delay", "--listen", "127.0.0.1:0", "--to", "127.0.0.1:1", "--rtt", "-1s"},
		{"delay", "--listen", "127.0.0.1:0", "--rtt", "1s"},
		{"delay", "--to", "127.0.0.1:1", "--rtt", "1s"},
		{"delay", "--listen", "127.0.0.1:0", "--to", "127.0.0.1:1", "--rtt", "1s", "extra"},
	} {
		// parseDelay, not the command: a usage that were accepted would serve.
		if _, _, code := parseDelay(args[1:], io.Discard); code != 2 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
	if code, out, _ := runOut("delay"); code != 2 || out != "" {
		t.Errorf("delay: exit %d, stdout %q", code, out)
	}
}

// Each chunk is held half the round trip from when it was read, not from when
// the chunk before it was written: a burst that the relay reads as many chunks
// arrives about half the round trip after it was sent, not that times the
// number of chunks.
func TestDelay_ABurstIsHeldOnceNotPerChunk(t *testing.T) {
	const half = 500 * time.Millisecond
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	got := make(chan int, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer c.Close()
		n, _ := io.Copy(io.Discard, c)
		got <- int(n)
	}()
	d := &delayer{to: up.Addr().String(), half: half, now: time.Now, wait: realWait}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go d.serve(ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Ten chunks at least: no read returns more than one chunk's bytes.
	burst := bytes.Repeat([]byte("x"), 10*delayChunk)
	start := time.Now()
	if _, err := c.Write(burst); err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).CloseWrite()
	select {
	case n := <-got:
		el := time.Since(start)
		if n != len(burst) {
			t.Fatalf("the upstream received %d bytes, want %d", n, len(burst))
		}
		// Held per chunk in turn, the burst would take ten halves (5 s).
		if el < half || el > 3*time.Second {
			t.Fatalf("the burst arrived after %v, want about %v", el, half)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the burst did not arrive")
	}
}
