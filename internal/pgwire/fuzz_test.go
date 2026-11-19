package pgwire

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"
)

func FuzzHeader(f *testing.F) {
	f.Add([]byte{'D', 0, 0, 0, 4})
	f.Add([]byte{'R', 0, 0, 0, 3})
	f.Add([]byte{'E', 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 5 {
			return
		}
		typ, n, err := Header([5]byte(b[:5]))
		length := binary.BigEndian.Uint32(b[1:5])
		if typ != b[0] || (err != nil) != (length < 4) || err == nil && (n < 0 || n != int(length)-4) {
			t.Fatalf("%x: %q %d %v", b[:5], typ, n, err)
		}
		tls, gss := EncryptionRequest(b)
		if tls && gss || (tls || gss) && CancelRequest(b) {
			t.Fatalf("%x: two kinds at once", b)
		}
		if l, ok := StartupLength(b); ok && (l < 8 || l > 10000) {
			t.Fatalf("%x: startup length %d", b, l)
		}
	})
}

func FuzzScramIterations(f *testing.F) {
	f.Add([]byte("r=abc,s=c2FsdA==,i=4096"))
	f.Add([]byte("r=,s=,i=0"))
	f.Add([]byte("r=a,s=b,i=99999999999"))
	f.Fuzz(func(t *testing.T, b []byte) {
		n, err := ScramIterations(b)
		if err != nil {
			return
		}
		if n < 1 || n > 1<<31-1 || !bytes.HasSuffix(b, []byte(",i="+strconv.Itoa(n))) {
			t.Fatalf("%q: %d", b, n)
		}
	})
}
