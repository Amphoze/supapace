package pgwire

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func hdr(typ byte, length uint32) [5]byte {
	var h [5]byte
	h[0] = typ
	binary.BigEndian.PutUint32(h[1:], length)
	return h
}

func TestHeader_LengthRule(t *testing.T) {
	for _, c := range []struct {
		length uint32
		body   int
		err    bool
	}{
		{0, 0, true}, {3, 0, true}, {4, 0, false}, {5, 1, false},
		{1 << 30, 1<<30 - 4, false}, {0xffffffff, 0xffffffff - 4, false},
	} {
		typ, n, err := Header(hdr('D', c.length))
		if (err != nil) != c.err || err != nil && !errors.Is(err, ErrLength) {
			t.Errorf("length %d: err %v", c.length, err)
			continue
		}
		if err == nil && (typ != 'D' || n != c.body) {
			t.Errorf("length %d: %q %d, want D %d", c.length, typ, n, c.body)
		}
	}
}

func TestAuthSubtype(t *testing.T) {
	for _, code := range []uint32{AuthOK, AuthCleartext, AuthMD5, AuthSASL, AuthSASLContinue, AuthSASLFinal, 7} {
		got, err := AuthSubtype(binary.BigEndian.AppendUint32(nil, code))
		if err != nil || got != code {
			t.Errorf("%d: %d %v", code, got, err)
		}
	}
	if _, err := AuthSubtype([]byte{0, 0, 0}); err == nil {
		t.Error("three bytes: no error")
	}
	if AuthOK != 0 || AuthCleartext != 3 || AuthMD5 != 5 || AuthSASL != 10 || AuthSASLContinue != 11 || AuthSASLFinal != 12 {
		t.Error("constants")
	}
}

func TestScramIterations_Parse(t *testing.T) {
	ok := map[string]int{
		"r=abc,s=c2FsdA==,i=4096":       4096,
		"r=abc,s=c2FsdA==,i=1":          1,
		"r=abc,s=c2FsdA==,i=2147483647": 2147483647,
	}
	for in, want := range ok {
		if got, err := ScramIterations([]byte(in)); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{
		"", "r=abc,s=c2FsdA==", "r=abc,s=c2FsdA==,i=", "r=abc,s=c2FsdA==,i=x", "r=abc,s=c2FsdA==,i=-1",
		"r=abc,s=c2FsdA==,i=+5", "r=abc,s=c2FsdA==,i=0", "r=abc,s=c2FsdA==,i=04096", "r=abc,s=c2FsdA==,i=2147483648",
		"r=abc,s=c2FsdA==,i=99999999999999999999", "r=abc,i=4096,s=c2FsdA==", "s=c2FsdA==,r=abc,i=4096",
		"r=abc,s=c2FsdA==,i=4096,x=1", "r=abc,s=c2FsdA==,i=4096 ",
	} {
		if n, err := ScramIterations([]byte(in)); err == nil {
			t.Errorf("%q: accepted as %d", in, n)
		}
	}
}

func TestRowFields(t *testing.T) {
	for _, n := range []int{0, 1, 1664, 32767, 65535} {
		got, err := RowFields(binary.BigEndian.AppendUint16(nil, uint16(n)))
		if err != nil || got != n {
			t.Errorf("%d: %d %v", n, got, err)
		}
	}
	if _, err := RowFields([]byte{1}); err == nil {
		t.Error("one byte: no error")
	}
}

func req(length, code uint32) []byte {
	return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, length), code)
}

func TestEncryptionRequest_TLSAndGSS(t *testing.T) {
	for _, c := range []struct {
		b        []byte
		tls, gss bool
	}{
		{req(8, 80877103), true, false},
		{req(8, 80877104), false, true},
		{req(8, 80877102), false, false},
		{req(9, 80877103), false, false},
		{req(16, 80877104), false, false},
		{req(8, 196608), false, false},
		{req(8, 80877103)[:7], false, false},
	} {
		if tls, gss := EncryptionRequest(c.b); tls != c.tls || gss != c.gss {
			t.Errorf("%x: %v %v", c.b, tls, gss)
		}
	}
}

func TestCancelRequest(t *testing.T) {
	if !CancelRequest(req(16, 80877102)) {
		t.Error("cancel not recognised")
	}
	for _, b := range [][]byte{req(8, 80877102), req(17, 80877102), req(16, 80877103), req(16, 196608), req(16, 80877102)[:7]} {
		if CancelRequest(b) {
			t.Errorf("%x recognised", b)
		}
	}
}

func TestStartupLength_Bounds(t *testing.T) {
	for _, c := range []struct {
		n  uint32
		ok bool
	}{{0, false}, {7, false}, {8, true}, {10000, true}, {10001, false}, {0xffffffff, false}} {
		n, ok := StartupLength(req(c.n, 196608))
		if ok != c.ok || ok && n != int(c.n) {
			t.Errorf("%d: %d %v", c.n, n, ok)
		}
	}
	if _, ok := StartupLength([]byte{0, 0, 0, 8}); ok {
		t.Error("four bytes accepted")
	}
}

func TestTooManyConnections_IsAnErrorResponse(t *testing.T) {
	b := TooManyConnections()
	typ, n, err := Header([5]byte(b[:5]))
	if err != nil || typ != 'E' || n != len(b)-5 {
		t.Fatalf("header %q %d %v of %d bytes", typ, n, err, len(b))
	}
	var e pgproto3.ErrorResponse
	if err := e.Decode(b[5:]); err != nil {
		t.Fatal(err)
	}
	if e.Severity != "FATAL" || e.SeverityUnlocalized != "FATAL" || e.Code != "53300" || e.Message != "too many connections" {
		t.Fatalf("%+v", e)
	}
	b[5] = 'X'
	if TooManyConnections()[5] == 'X' {
		t.Fatal("the answer is shared, not a fresh copy")
	}
}
