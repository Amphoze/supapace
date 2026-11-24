package pgsock

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// rdConn serves a fixed byte stream to a guard and counts the bytes read.
type rdConn struct {
	r    *bytes.Reader
	read int
}

func (c *rdConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}
func (c *rdConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *rdConn) Close() error                     { return nil }
func (c *rdConn) LocalAddr() net.Addr              { return nil }
func (c *rdConn) RemoteAddr() net.Addr             { return nil }
func (c *rdConn) SetDeadline(time.Time) error      { return nil }
func (c *rdConn) SetReadDeadline(time.Time) error  { return nil }
func (c *rdConn) SetWriteDeadline(time.Time) error { return nil }

// readAll reads a server's stream through a guard (in reads of chunk bytes)
// until it stops: what reached the library, the error and the bytes taken from
// the connection. A panic fails the test.
func readAll(t testing.TB, stream []byte, trust bool, b Budget, chunk int) (got []byte, err error, taken int) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the guard panicked on %x: %v", stream, r)
		}
	}()
	c := &rdConn{r: bytes.NewReader(stream)}
	g := newGuard(c, b, testSalt(), trust, time.Now())
	buf := make([]byte, chunk)
	for range 1 << 16 {
		n, e := g.Read(buf)
		got = append(got, buf[:n]...)
		if e != nil {
			return got, e, c.read
		}
	}
	t.Fatalf("the guard never stopped on %x", stream)
	return
}

func wmsg(typ byte, body []byte) []byte {
	m := binary.BigEndian.AppendUint32([]byte{typ}, uint32(len(body))+4)
	return append(m, body...)
}

func wauth(sub uint32, data string) []byte {
	return wmsg('R', append(binary.BigEndian.AppendUint32(nil, sub), data...))
}

var wMech = "SCRAM-SHA-256\x00\x00"

func wGood() string { return "r=NONCEsrv,s=" + b64salt() + ",i=4096" }

func wSF(first string) []byte { return append(wauth(10, wMech), wauth(11, first)...) }

// A header whose stated length is below 4, or beyond the cap or a platform's
// int, is refused with its five bytes alone: nothing of the body is read.
func TestGuardWire_HeaderRefusedBeforeTheBody(t *testing.T) {
	for _, l := range []uint32{0, 1, 2, 3, 1<<20 + 5, 1<<31 - 1, 1 << 31, 1<<31 + 3, 1<<31 + 4, 1<<32 - 5, 1<<32 - 4, 1<<32 - 1} {
		for _, typ := range []byte{'R', 'E', 'Z', 0, 255} {
			s := append(binary.BigEndian.AppendUint32([]byte{typ}, l), bytes.Repeat([]byte{'x'}, 64)...)
			got, err, taken := readAll(t, s, false, DefaultBudget, 1<<16)
			if !errors.Is(err, ErrBudget) || len(got) != 0 || taken != 5 {
				t.Errorf("length %d type %d: %v after %d bytes, %d delivered", l, typ, err, taken, len(got))
			}
		}
	}
}

// An authentication request whose body is shorter than its subtype, and every
// subtype the exchange does not expect at that point, is refused before the
// library sees it.
func TestGuardWire_AuthSubtypes(t *testing.T) {
	for n := 0; n <= 3; n++ {
		got, err, _ := readAll(t, wmsg('R', bytes.Repeat([]byte{0}, n)), true, DefaultBudget, 64)
		if !errors.Is(err, ErrNotScram) || len(got) != 0 {
			t.Errorf("body of %d bytes: %v, %d delivered", n, err, len(got))
		}
	}
	for _, sub := range []uint32{3, 5} {
		_, err, _ := readAll(t, wauth(sub, "x"), false, DefaultBudget, 64)
		if !errors.Is(err, ErrCleartextRequested) {
			t.Errorf("subtype %d: %v", sub, err)
		}
	}
	for _, sub := range []uint32{1, 2, 4, 6, 7, 8, 9, 13, 255, 1 << 24, 1 << 31, 1<<32 - 1, 0x0A000000} {
		for _, trust := range []bool{false, true} {
			got, err, _ := readAll(t, wauth(sub, wMech), trust, DefaultBudget, 64)
			if !errors.Is(err, ErrNotScram) || len(got) != 0 {
				t.Errorf("subtype %d trust %v: %v", sub, trust, err)
			}
		}
	}
	// the exchange's order: each subtype is accepted only in its place
	for name, s := range map[string][]byte{
		"11 first": wauth(11, wGood()), "12 first": wauth(12, "v=x"),
		"10 twice":    append(wauth(10, wMech), wauth(10, wMech)...),
		"12 after 10": append(wauth(10, wMech), wauth(12, "v=x")...),
		"0 after 10":  append(wauth(10, wMech), wauth(0, "")...),
		"0 after 11":  append(wSF(wGood()), wauth(0, "")...),
		"0 first":     wauth(0, ""),
	} {
		_, err, _ := readAll(t, s, false, DefaultBudget, 1<<16)
		if err == nil || err == io.EOF {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Only the platform's own server-first message reaches the library: the
// salt's every length around the expected one, every form of the count, every
// shape.
func TestGuardWire_ServerFirstOnlyTheExactMessage(t *testing.T) {
	salt := testSalt()
	var firsts []string
	for n := 0; n <= 40; n++ {
		if n != len(salt) {
			firsts = append(firsts, "r=N,s="+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{salt[0]}, n))+",i=4096")
		}
	}
	for _, it := range []string{"", "0", "1", "4095", "4097", "04096", "004096", "+4096", "-4096", " 4096", "4096 ", "4096\n", "4096\x00",
		"2147483647", "2147483648", "4294967296", "4294971392", "9999999999", "10000004096", "18446744073709555712",
		"٤٠٩٦", "0x1000", "4096e0", "4,096", "4096x"} {
		firsts = append(firsts, "r=N,s="+b64salt()+",i="+it)
	}
	s := b64salt()
	firsts = append(firsts, "", ",", ",,", ",,,", "r", "r=N", "r=N,s="+s, "r=N,s="+s+",", "r=N,,i=4096", "r=N,s="+s+",i=4096,", "r=N,s="+s+",i=4096,x=1",
		"R=N,s="+s+",i=4096", "r=N,S="+s+",i=4096", "r=N,s="+s+",I=4096", "rN,s="+s+",i=4096", "r=N,s"+s+",i=4096", "r=N,s="+s+",i4096",
		"s="+s+",r=N,i=4096", "i=4096,r=N,s="+s, "r=N,i=4096,s="+s, "x=1,r=N,s="+s+",i=4096", " r=N,s="+s+",i=4096",
		"r=N,s="+s+",i=4096 ", "r=N,s="+s+"\xff,i=4096", "r=\xff\xfe,s="+s+",i=4096x", "r=N,s=\xff\xfe,i=4096",
		"r=N,s="+strings.TrimRight(s, "=")+",i=4096", "r=N,s="+base64.URLEncoding.EncodeToString(salt)+"x,i=4096",
		"r=N,s="+s+"=,i=4096", "r=N,s="+s[:len(s)-4]+",i=4096")
	for _, f := range firsts {
		got, err, _ := readAll(t, wSF(f), false, DefaultBudget, 1<<16)
		if !errors.Is(err, ErrScramParams) {
			t.Errorf("server-first %q: %v", f, err)
		}
		if bytes.Contains(got, []byte("i=")) {
			t.Errorf("server-first %q reached the library", f)
		}
	}
	got, err, _ := readAll(t, wSF(wGood()), false, DefaultBudget, 3)
	if err != io.EOF || !bytes.Equal(got, wSF(wGood())) {
		t.Errorf("the platform's own message: %v, %d of %d bytes", err, len(got), len(wSF(wGood())))
	}
}

// No truncation and no single-byte change of a complete login makes the guard
// panic, and what it delivers is always a whole-message prefix of the stream.
func TestGuardWire_NoPanicOnTruncationOrByteChange(t *testing.T) {
	login := append(wSF(wGood()), wauth(12, "v=abcdef")...)
	login = append(login, wauth(0, "")...)
	login = append(login, wmsg('S', []byte("a\x00b\x00"))...)
	login = append(login, wmsg('Z', []byte("I"))...)
	for _, trust := range []bool{false, true} {
		for i := 0; i <= len(login); i++ {
			got, _, _ := readAll(t, login[:i], trust, DefaultBudget, 7)
			if !bytes.HasPrefix(login, got) {
				t.Fatalf("cut at %d: delivered bytes are not a prefix", i)
			}
		}
		for i := range login {
			for _, v := range []byte{0, 1, 3, 4, 5, 10, 11, 12, ',', '=', 'r', 's', 'i', 0x80, 0xff} {
				s := append([]byte{}, login...)
				s[i] = v
				readAll(t, s, trust, DefaultBudget, 1<<16)
				readAll(t, s[:i+1], trust, DefaultBudget, 5)
			}
		}
	}
}

func FuzzGuardWire_Read(f *testing.F) {
	f.Add(wSF(wGood()), false, uint8(7))
	f.Add(append(wauth(0, ""), wmsg('Z', []byte("I"))...), true, uint8(1))
	f.Add(wauth(10, wMech), false, uint8(200))
	f.Fuzz(func(t *testing.T, s []byte, trust bool, chunk uint8) {
		got, _, _ := readAll(t, s, trust, Budget{Bytes: 4096, MessageBytes: 1024, ParamStatus: 4, Notices: 4}.withDefaults(), int(chunk)+1)
		if !bytes.HasPrefix(s, got) {
			t.Fatalf("delivered bytes are not a prefix of the stream")
		}
		if bytes.Contains(got, []byte(",i=")) && !bytes.Contains(got, []byte(wGood()[len("r=NONCEsrv"):])) {
			t.Fatalf("a server-first message of another salt or count reached the library: %q", got)
		}
	})
}

// The frontend framing counts one request owing a ReadyForQuery per Query
// and Sync however the bytes are cut, after any startup packet length.
func TestGuardWire_WriteFraming(t *testing.T) {
	for _, sl := range []uint32{0, 1, 3, 4, 5, 8, 9, 20} {
		stream := binary.BigEndian.AppendUint32(nil, sl)
		if sl > 4 {
			stream = append(stream, bytes.Repeat([]byte{1}, int(sl)-4)...)
		}
		want := 2
		stream = append(stream, wmsg('Q', []byte("x\x00"))...)
		stream = append(stream, wmsg('P', nil)...)
		stream = append(stream, 'S', 0, 0, 0, 0) // a length below 4 frames an empty body
		stream = append(stream, wmsg('X', nil)...)
		for step := 1; step <= len(stream); step++ {
			g := newGuard(&rdConn{r: bytes.NewReader(nil)}, DefaultBudget, nil, false, time.Now())
			for p := stream; len(p) > 0; p = p[min(step, len(p)):] {
				g.Write(p[:min(step, len(p))])
			}
			if g.outstanding != want {
				t.Fatalf("startup length %d, writes of %d: %d requests, want %d", sl, step, g.outstanding, want)
			}
		}
	}
}
