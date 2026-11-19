// Package dashtok signs and verifies the dashboard's three token formats: the
// principal assertion the gateway mints per request, the session token of the
// session cookie, and the log-out ticket that carries a log-out chain.
//
// A token is v1.<P>.<S>: P is the unpadded base64url of a JSON object with
// exactly the members of its kind, in their order, without white space, and S
// the unpadded base64url of an Ed25519 signature over the kind's label
// followed by P. The labels differ per kind, so no token verifies as another
// kind. Verification checks the size first, then the envelope, then the
// signature, and only then parses the payload. Errors are the sentinel values
// below and carry no token material.
package dashtok

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	assertionLabel = "supapace-assertion-v1."
	sessionLabel   = "supapace-session-v1."
	logoutLabel    = "supapace-logout-v1."

	maxToken    = 4096 // bytes, checked before anything else
	sigChars    = 86   // unpadded base64url of a 64-byte signature
	keyChars    = 43   // unpadded base64url of a 32-byte seed or key
	maxShort    = 60   // seconds: the longest lifetime of an assertion or a ticket
	skew        = 5    // seconds an iat may lie ahead of now
	maxRefs     = 16   // refs a ticket carries at most
	maxPrinting = 255  // bytes of iss, sub and node
	maxName     = 128  // bytes of a display name
)

// Assertion is the principal assertion's payload.
type Assertion struct {
	Node    string `json:"node"`
	Iss     string `json:"iss"`
	Sub     string `json:"sub"`
	Name    string `json:"name"`
	Ref     string `json:"ref"`
	Role    string `json:"role"`
	Purpose string `json:"purpose"`
	Iat     int64  `json:"iat"`
	Exp     int64  `json:"exp"`
}

// Session is the session token's payload. Ref is "_" on the sign-in host.
type Session struct {
	Iss  string `json:"iss"`
	Sub  string `json:"sub"`
	Name string `json:"name"`
	Ref  string `json:"ref"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// Ticket is the log-out ticket's payload: the refs still to visit, in order,
// and whether the principal has more project origins than the first ticket
// of the chain listed.
type Ticket struct {
	Iss  string   `json:"iss"`
	Sub  string   `json:"sub"`
	Refs []string `json:"refs"`
	More bool     `json:"more"`
	Iat  int64    `json:"iat"`

	Exp int64 `json:"exp"`
}

var (
	ErrMalformed = errors.New("dashtok: malformed")
	ErrSignature = errors.New("dashtok: bad signature")
	ErrExpired   = errors.New("dashtok: expired")
	ErrNotYet    = errors.New("dashtok: issued in the future")
	ErrLifetime  = errors.New("dashtok: lifetime out of bounds")
	ErrNode      = errors.New("dashtok: another node")
	ErrField     = errors.New("dashtok: payload members or values not as specified")

	errKey = errors.New("dashtok: private key of the wrong size")
)

var b64 = base64.RawURLEncoding.Strict()

// GenerateKey returns the contents of a new key pair's two files: the 32-byte
// seed and the 32-byte public key, each as one line of unpadded base64url.
func GenerateKey() (private, public []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return []byte(b64.EncodeToString(priv.Seed()) + "\n"), []byte(b64.EncodeToString(pub) + "\n"), nil
}

// ParsePrivate reads a private key file: 43 base64url characters and at most
// one line end.
func ParsePrivate(file []byte) (ed25519.PrivateKey, error) {
	seed, err := keyFile(file)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ParsePublic reads a public key file in the same form.
func ParsePublic(file []byte) (ed25519.PublicKey, error) {
	k, err := keyFile(file)
	return ed25519.PublicKey(k), err
}

func keyFile(file []byte) ([]byte, error) {
	s := strings.TrimSuffix(string(file), "\n")
	if len(s) != keyChars || !alphabet(s) {
		return nil, ErrMalformed
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, ErrMalformed
	}
	return b, nil
}

func SignAssertion(k ed25519.PrivateKey, a Assertion) (string, error) {
	if !a.valid() {
		return "", ErrField
	}
	return sign(k, assertionLabel, a)
}

// VerifyAssertion accepts an assertion for node that is unexpired at now,
// issued at most 5 s ahead of it, with a lifetime of at most 60 s.
func VerifyAssertion(k ed25519.PublicKey, token, node string, now time.Time) (Assertion, error) {
	var a Assertion
	if err := open(k, assertionLabel, token, &a); err != nil {
		return Assertion{}, err
	}
	if !a.valid() {
		return Assertion{}, ErrField
	}
	if err := times(a.Iat, a.Exp, maxShort, now); err != nil {
		return Assertion{}, err
	}
	if a.Node != node {
		return Assertion{}, ErrNode
	}
	return a, nil
}

func SignSession(k ed25519.PrivateKey, s Session) (string, error) {
	if !s.valid() {
		return "", ErrField
	}
	return sign(k, sessionLabel, s)
}

// VerifySession accepts a session token unexpired at now, issued at most 5 s
// ahead of it, with a lifetime of at most maxSeconds.
func VerifySession(k ed25519.PublicKey, token string, maxSeconds int64, now time.Time) (Session, error) {
	var s Session
	if err := open(k, sessionLabel, token, &s); err != nil {
		return Session{}, err
	}
	if !s.valid() {
		return Session{}, ErrField
	}
	if err := times(s.Iat, s.Exp, maxSeconds, now); err != nil {
		return Session{}, err
	}
	return s, nil
}

func SignTicket(k ed25519.PrivateKey, t Ticket) (string, error) {
	if !t.valid() {
		return "", ErrField
	}
	return sign(k, logoutLabel, t)
}

// VerifyTicket accepts a log-out ticket unexpired at now, issued at most 5 s
// ahead of it, with a lifetime of at most 60 s.
func VerifyTicket(k ed25519.PublicKey, token string, now time.Time) (Ticket, error) {
	var t Ticket
	if err := open(k, logoutLabel, token, &t); err != nil {
		return Ticket{}, err
	}
	if !t.valid() {
		return Ticket{}, ErrField
	}
	if err := times(t.Iat, t.Exp, maxShort, now); err != nil {
		return Ticket{}, err
	}
	return t, nil
}

// times refuses exp <= now, iat > now+skew and a lifetime outside (0, max].
// exp - max can only wrap upwards, towards a refusal; a bound <= 0 accepts
// nothing.
func times(iat, exp, max int64, now time.Time) error {
	t := now.Unix()
	switch {
	case exp <= t:
		return ErrExpired
	case iat > t+skew:
		return ErrNotYet
	case max <= 0 || exp <= iat || iat < exp-max:
		return ErrLifetime
	}
	return nil
}

func sign(k ed25519.PrivateKey, label string, v any) (string, error) {
	if len(k) != ed25519.PrivateKeySize {
		return "", errKey
	}
	payload, err := canonical(v)
	if err != nil {
		return "", ErrField
	}
	p := b64.EncodeToString(payload)
	// The members' bounds keep every payload far below maxToken.
	return "v1." + p + "." + b64.EncodeToString(ed25519.Sign(k, []byte(label+p))), nil
}

// open checks the envelope and the signature of token under label and then
// decodes its payload into v, which must be exactly v's canonical encoding.
func open(k ed25519.PublicKey, label, token string, v any) error {
	if len(token) > maxToken || !strings.HasPrefix(token, "v1.") {
		return ErrMalformed
	}
	p, s, ok := strings.Cut(token[3:], ".")
	if !ok || p == "" || len(s) != sigChars || !alphabet(p) || !alphabet(s) {
		return ErrMalformed
	}
	sig, err1 := b64.DecodeString(s)
	payload, err2 := b64.DecodeString(p)
	if err1 != nil || err2 != nil {
		return ErrMalformed
	}
	if len(k) != ed25519.PublicKeySize || !ed25519.Verify(k, []byte(label+p), sig) {
		return ErrSignature
	}
	// Syntax and white space: the compacted form of the payload is the
	// payload itself.
	var c bytes.Buffer
	if json.Compact(&c, payload) != nil || !bytes.Equal(c.Bytes(), payload) {
		return ErrMalformed
	}
	// Members: decode, then require the canonical encoding of what was
	// decoded to be the payload byte for byte. This refuses a missing, a
	// duplicated, a reordered or a differently spelled member, a null, an
	// escape the encoder would not write and a number in another notation.
	if json.Unmarshal(payload, v) != nil {
		return ErrField
	}
	if re, err := canonical(v); err != nil || !bytes.Equal(re, payload) {
		return ErrField
	}
	return nil
}

// canonical is the one encoding of a payload: members in struct order, no
// white space, no HTML escaping.
func canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

func (a Assertion) valid() bool {
	return text(a.Node, 1, maxPrinting) && principal(a.Iss, a.Sub, a.Name) && isRef(a.Ref) &&
		(a.Role == "owner" || a.Role == "developer" || a.Role == "read_only") &&
		(a.Purpose == "" || a.Purpose == "reveal")
}

func (s Session) valid() bool {
	return principal(s.Iss, s.Sub, s.Name) && (s.Ref == "_" || isRef(s.Ref))
}

func (t Ticket) valid() bool {
	if !principal(t.Iss, t.Sub, "") || len(t.Refs) == 0 || len(t.Refs) > maxRefs {
		return false
	}
	for _, r := range t.Refs {
		if !isRef(r) {
			return false
		}
	}
	return true
}

func principal(iss, sub, name string) bool {
	return printable(iss) && printable(sub) && text(name, 0, maxName)
}

// printable: 1 to 255 bytes of printable ASCII, space included.
func printable(s string) bool {
	if len(s) == 0 || len(s) > maxPrinting {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// text: min to max bytes of UTF-8 without a control character and without
// U+2028 or U+2029, which JSON encoders do not all write the same way.
func text(s string, min, max int) bool {
	if len(s) < min || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

// isRef: the shape of a project ref, ^[a-z0-9]{20}$.
func isRef(s string) bool {
	if len(s) != 20 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

// alphabet reports whether s holds only base64url characters. encoding/base64
// skips CR and LF even in strict mode; this check keeps them out.
func alphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
