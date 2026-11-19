package pgcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
)

type clientBytes struct {
	net.Conn
	w *bytes.Buffer
}

func (c clientBytes) Write(p []byte) (int, error) { return c.w.Write(p) }

// splitReader hands the server's bytes over in the read sizes of a plan: the
// relay must not be able to tell one plan from another.
type splitReader struct {
	net.Conn
	rest  []byte
	sizes func() int
}

func (s *splitReader) Read(p []byte) (int, error) {
	if len(s.rest) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), len(s.rest), max(1, s.sizes()))
	copy(p, s.rest[:n])
	s.rest = s.rest[n:]
	return n, nil
}

// boundaries are the offsets at which a message of in begins, as far as its
// headers can be followed.
func boundaries(in []byte) []int {
	var b []int
	for o := 0; o+5 <= len(in); {
		b = append(b, o)
		n := int(binary.BigEndian.Uint32(in[o+1 : o+5]))
		if n < 4 || o+1+n > len(in) {
			break
		}
		o += 1 + n
	}
	return b
}

// fuzzRelay runs the relay's server side over in, read in the sizes given.
func fuzzRelay(c Class, in []byte, sizes func() int) ([]byte, error) {
	out := &bytes.Buffer{}
	r := &relay{c: &Conn{Class: c, Client: clientBytes{w: out}}, st: state{c: &c, slots: &StreamSlots{}},
		buf: make([]byte, c.CopyBufBytes), server: &splitReader{rest: in, sizes: sizes}}
	return out.Bytes(), r.fromServer()
}

// FuzzFromServer runs the relay's server side — the startup, the
// authentication order, the windows, the count caps, the drop and the stream
// state — over any byte sequence a server sends, read in one piece and in
// other splits: one byte, five bytes, cut around every message boundary, and
// random sizes. Every split must give the client the same bytes and the relay
// the same verdict. The relay must not panic, must end with a breach or the end
// of the bytes, must send the client only a prefix of what the server sent
// (with a class that drops nothing), and must pass nothing but an error or a
// notice before a completed exchange.
func FuzzFromServer(f *testing.F) {
	f.Add(byte(0), uint64(1), login)
	f.Add(byte(1), uint64(2), cat(login, m('W', make([]byte, 3)), copyData(64), readyMsg, rowDesc(3)))
	f.Add(byte(2), uint64(3), cat(rSASL, rOK, readyMsg))
	f.Add(byte(3), uint64(4), cat(rSASL, cont(1), rFinal, rOK, repeat(paramMsg, 70), readyMsg))
	f.Add(byte(0), uint64(5), cat(login, rowDesc(40000)))
	f.Add(byte(4), uint64(6), cat(login, notice, dataRow(9000), notice, readyMsg, ms4('N', strings.Repeat("n", 9000)), readyMsg))
	f.Add(byte(13), uint64(7), cat(login, repeat(dataRow(30), 300), dataRow(5000), readyMsg))
	f.Fuzz(func(t *testing.T, which byte, seed uint64, in []byte) {
		classes := []Class{metaClass(), streamClass(), responseClass(), noneClass()}
		c := classes[int(which)%len(classes)]
		c.WindowBytes = min(c.WindowBytes, 16<<10)
		if c.Window == WindowNone {
			c.WindowBytes = 0
		}
		if c.Stream != nil {
			c.Stream.BytesPerInterval = 1 << 40 // never waits
			c.Stream.IntervalMS = 1 << 30       // and no interval ends during a run
		}
		c.DropNotices = which&4 != 0
		if which&8 != 0 {
			c.CopyBufBytes = minBuf
		}
		whole, err := fuzzRelay(c, in, func() int { return len(in) })
		var b breach
		if !errors.As(err, &b) && err != errPeerClosed {
			t.Fatalf("ended with %v", err)
		}
		cuts := map[int]bool{}
		for _, o := range boundaries(in) {
			cuts[o-1], cuts[o], cuts[o+1] = true, true, true
		}
		at := 0
		rng := rand.New(rand.NewPCG(seed, 0))
		for name, sizes := range map[string]func() int{
			"one byte":   func() int { return 1 },
			"five bytes": func() int { return 5 },
			"random":     func() int { return 1 + rng.IntN(300) },
			"around every boundary": func() int {
				for n := 1; ; n++ {
					if at+n >= len(in) || cuts[at+n] {
						at += n
						return n
					}
				}
			},
		} {
			got, gerr := fuzzRelay(c, in, sizes)
			if !bytes.Equal(got, whole) || fmt.Sprint(gerr) != fmt.Sprint(err) {
				t.Fatalf("%s: client received %d bytes and %v; in one piece %d bytes and %v", name, len(got), gerr, len(whole), err)
			}
		}
		if c.DropNotices {
			return
		}
		if !bytes.HasPrefix(in, whole) {
			t.Fatal("the client received bytes the server did not send in that order")
		}
		// Walk what the client received.
		var subs []uint32
		for o := whole; len(o) >= 5; {
			n := int(binary.BigEndian.Uint32(o[1:5]))
			if n < 4 || 1+n > len(o) {
				break // a message cut short by the end of the bytes
			}
			switch o[0] {
			case 'R':
				subs = append(subs, binary.BigEndian.Uint32(o[5:9]))
			case 'E', 'N':
			default:
				want := []uint32{10, 11, 12, 0}
				if len(subs) != 4 || subs[0] != want[0] || subs[1] != want[1] || subs[2] != want[2] || subs[3] != want[3] {
					t.Fatalf("message %q passed after authentication requests %v", o[0], subs)
				}
			}
			o = o[1+n:]
		}
		if len(subs) > 4 {
			t.Fatalf("authentication requests %v passed", subs)
		}
	})
}

func FuzzParseTable(f *testing.F) {
	f.Add([]byte(metaJSON(metaSlices)))
	f.Add([]byte(metaJSON(slicesJSON(28, "meta", 5))))
	f.Add([]byte(`{"slices":{"03":{}}}`))
	f.Add([]byte(metaJSON(metaSlices) + "}"))
	f.Add([]byte(metaJSON(metaSlices) + `]{"max_conns":1}`))
	f.Add([]byte(strings.Replace(metaJSON(metaSlices), `"max_conns":64`, `"max_conns":64,"MAX_CONNS":65,"max_conns":66`, 1)))
	f.Add([]byte(strings.Replace(metaJSON(metaSlices), `"wall_ms":55000`, `"wall_ms":null`, 1)))
	f.Add([]byte(metaJSON(`{"3":{"meta":9223372036854775807},"7":{"meta":9223372036854775807}}`)))
	f.Fuzz(func(t *testing.T, b []byte) {
		tb, err := ParseTable(b)
		if err != nil {
			return
		}
		m1, err := tb.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		tb2, err := ParseTable(m1)
		if err != nil {
			t.Fatalf("canonical form refused: %v\n%s", err, m1)
		}
		if m2, _ := tb2.Marshal(); !bytes.Equal(m1, m2) {
			t.Fatalf("not stable:\n%s\n%s", m1, m2)
		}
		if a, c, r := tb.Terms(); a+c+r > tb.MaxConns {
			t.Fatal("terms above the ceiling accepted")
		}
	})
}
