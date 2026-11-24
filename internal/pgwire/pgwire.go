// Package pgwire holds the checks of the Postgres wire protocol that the
// platform's guards share: they judge a message header, an authentication
// request's subtype, a SCRAM challenge's iteration count, a row description's
// field count and the first eight bytes a client sends. Each reads only the
// bytes it is given and allocates nothing from a length a peer states.
package pgwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
)

// Authentication request subtypes.
const (
	AuthOK, AuthCleartext, AuthMD5, AuthSASL, AuthSASLContinue, AuthSASLFinal uint32 = 0, 3, 5, 10, 11, 12
)

// Request codes of the first eight bytes.
const (
	codeCancel = 80877102
	codeTLS    = 80877103
	codeGSS    = 80877104
	// maxStartup is the longest startup packet accepted.
	maxStartup = 10000
)

var (
	// ErrLength is a message length below the four bytes of the length itself, or a body
	// longer than an int holds (on a platform with a 32-bit int).
	ErrLength = errors.New("pgwire: message length below 4")
	errShort  = errors.New("pgwire: message too short")
	errScram  = errors.New("pgwire: malformed server-first message")
)

// Header returns a backend message's type and the length of its body: the
// announced length less the four bytes of the length itself.
func Header(h [5]byte) (typ byte, bodyLen int, err error) {
	n := binary.BigEndian.Uint32(h[1:])
	if n < 4 || uint64(n-4) > math.MaxInt { // a body length that does not fit an int is refused, not wrapped
		return h[0], 0, ErrLength
	}
	return h[0], int(n - 4), nil
}

// AuthSubtype returns the subtype of an authentication request's body.
func AuthSubtype(body []byte) (uint32, error) {
	if len(body) < 4 {
		return 0, errShort
	}
	return binary.BigEndian.Uint32(body), nil
}

// ScramIterations returns the iteration count of a SCRAM server-first message
// "r=…,s=…,i=N" (the payload of a SASL-continue request after its subtype): N
// is a decimal from 1 to 2^31-1 without sign or leading zero, and nothing
// follows it.
func ScramIterations(serverFirst []byte) (int, error) {
	f := bytes.Split(serverFirst, []byte(","))
	if len(f) != 3 || !bytes.HasPrefix(f[0], []byte("r=")) || !bytes.HasPrefix(f[1], []byte("s=")) ||
		!bytes.HasPrefix(f[2], []byte("i=")) {
		return 0, errScram
	}
	d := f[2][2:]
	if len(d) == 0 || len(d) > 10 || d[0] == '0' {
		return 0, errScram
	}
	n := int64(0) // ten digits fit; an int may be 32 bits
	for _, c := range d {
		if c < '0' || c > '9' {
			return 0, errScram
		}
		n = n*10 + int64(c-'0')
	}
	if n > 1<<31-1 {
		return 0, errScram
	}
	return int(n), nil
}

// RowFields returns the field count of a row description: its first two bytes.
func RowFields(body []byte) (int, error) {
	if len(body) < 2 {
		return 0, errShort
	}
	return int(binary.BigEndian.Uint16(body)), nil
}

func first(b []byte) (length, code uint32, ok bool) {
	if len(b) < 8 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:]), true
}

// EncryptionRequest tells whether the first eight bytes are a TLS or a GSS
// encryption request.
func EncryptionRequest(first8 []byte) (tls, gss bool) {
	n, code, ok := first(first8)
	return ok && n == 8 && code == codeTLS, ok && n == 8 && code == codeGSS
}

// CancelRequest tells whether the first eight bytes begin a cancel request:
// length 16 and the cancel code.
func CancelRequest(first8 []byte) bool {
	n, code, ok := first(first8)
	return ok && n == 16 && code == codeCancel
}

// StartupLength returns a startup packet's announced length when it is 8 to
// 10,000 bytes.
func StartupLength(first8 []byte) (int, bool) {
	n, _, ok := first(first8)
	if !ok || n < 8 || n > maxStartup {
		return 0, false
	}
	return int(n), true
}

// TooManyConnections returns, ready to write, the ErrorResponse a full server
// gives: severity FATAL, SQLSTATE 53300, "too many connections".
func TooManyConnections() []byte {
	body := []byte("SFATAL\x00VFATAL\x00C53300\x00Mtoo many connections\x00\x00")
	return append(binary.BigEndian.AppendUint32([]byte{'E'}, uint32(4+len(body))), body...)
}
