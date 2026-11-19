package pgwire

import (
	"strings"
	"testing"
)

// Every rule of the server-first parse, one at a time against the form that
// passes: the three attributes r, s and i in that order and nothing else, and
// a count of ASCII digits only.
func TestScramIterations_EveryRule(t *testing.T) {
	const good = "r=abc,s=c2FsdA==,i=4096"
	if n, err := ScramIterations([]byte(good)); err != nil || n != 4096 {
		t.Fatalf("control: %d %v", n, err)
	}
	for _, c := range []struct{ from, to string }{
		{"r=", "x="}, {"r=", "R="}, {"r=", "r"}, {"r=", "m=x,r="}, // an extension before the nonce
		{"s=", "x="}, {"s=", "S="},
		{"i=", "x="}, {"i=", "I="}, {"i=", "i=4096,i="},
		{"4096", "4/96"}, {"4096", "4:96"}, {"4096", "40 96"}, {"4096", " 4096"}, {"4096", "4096\x00"}, {"4096", "4096\n"},
		{"4096", "4096.0"}, {"4096", "4e3"}, {"4096", "0x1000"}, {"4096", "４096"}, // a full-width digit
		{"4096", "12345678901"}, {"4096", "4294971392"}, // 2^32 + 4096
		{",s=", ",,s="}, {",i=", ",i=1,"},
	} {
		in := strings.Replace(good, c.from, c.to, 1)
		if n, err := ScramIterations([]byte(in)); err == nil {
			t.Errorf("%q: accepted as %d", in, n)
		}
	}
	if n, err := ScramIterations([]byte("r=,s=,i=1234567890")); err != nil || n != 1234567890 { // ten digits, empty values
		t.Errorf("ten digits: %d %v", n, err)
	}
}

// The requests of the first eight bytes are told apart by length and code
// together: a known code with another length is none of them.
func TestFirstEight_LengthAndCodeTogether(t *testing.T) {
	for _, n := range []uint32{0, 7, 9, 12, 15, 17, 24, 268, 10000} {
		if CancelRequest(req(n, 80877102)) {
			t.Errorf("cancel code with length %d recognised", n)
		}
		if tls, gss := EncryptionRequest(req(n, 80877103)); tls || gss {
			t.Errorf("TLS code with length %d recognised", n)
		}
		if tls, gss := EncryptionRequest(req(n, 80877104)); tls || gss {
			t.Errorf("GSS code with length %d recognised", n)
		}
	}
	if CancelRequest(nil) || CancelRequest(req(16, 80877102)[:7]) {
		t.Error("fewer than eight bytes recognised")
	}
	if !CancelRequest(append(req(16, 80877102), 1, 2, 3)) {
		t.Error("only the first eight bytes are read")
	}
}
