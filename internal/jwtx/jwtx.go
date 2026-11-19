// Package jwtx signs and verifies RS256 JSON Web Tokens, reads and writes JSON
// Web Key Sets, and binds a key's class to the roles its tokens may carry.
//
// Verification is strict: the algorithm is fixed to RS256 by the verifier,
// header and payload must be single JSON objects with no duplicate member name
// at any depth and at most 64 levels of nesting, the token holds only the
// base64url alphabet and dots, and the size limit is checked before anything
// else. Errors are the sentinel values below and never carry token or key
// material.
package jwtx

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// Class is the class of a verification key: "anon", "service_role" or
// "issuer" for a project, ClassDashboard for the dashboard's sign-in issuer.
type Class string

// ClassDashboard is the class of a key that verifies ID tokens for dashboard
// sign-in (VerifyID). CheckRole refuses it for every role, and KeyFromJWK and
// ParseJWKS never produce it: it enters only through DashboardKeyFromJWK and
// ParseDashboardJWKS.
const ClassDashboard Class = "dashboard"

// Key is a public verification key and the class that bounds its tokens' roles.
type Key struct {
	KID   string
	Class Class
	Pub   *rsa.PublicKey
}

// Claims are the verified payload. Raw holds every member; numbers in it are
// json.Number.
type Claims struct {
	Role, Sub string
	Exp       int64
	Raw       map[string]any
}

const (
	maxToken = 8 << 10  // bytes, checked before decoding
	maxJWKS  = 64 << 10 // bytes, checked before decoding
	maxDepth = 64       // nesting of objects and arrays, the outermost object included
	nbfSkew  = 30       // seconds a token's nbf may lie ahead of now
	alg      = "RS256"  // the only algorithm, fixed by the verifier
	keyBits  = 2048     // GenerateKey
	minBits  = 2048     // KeyFromJWK, ParseJWKS
	maxBits  = 4096     // KeyFromJWK, ParseJWKS
	pubE     = 65537    // the only accepted public exponent
)

var (
	ErrMalformed       = errors.New("jwtx: malformed")
	ErrDuplicateMember = errors.New("jwtx: duplicate member name")
	ErrAlg             = errors.New("jwtx: algorithm not RS256")
	ErrNoKID           = errors.New("jwtx: kid missing")
	ErrUnknownKID      = errors.New("jwtx: unknown kid")
	ErrSignature       = errors.New("jwtx: bad signature")
	ErrExpired         = errors.New("jwtx: expired or no exp")
	ErrNotYetValid     = errors.New("jwtx: not yet valid")
	ErrNoRole          = errors.New("jwtx: role missing")
	ErrRole            = errors.New("jwtx: role not allowed for this key")
	ErrKey             = errors.New("jwtx: unacceptable key")
)

var b64 = base64.RawURLEncoding.Strict()

// GenerateKey returns a new RSA-2048 key and its kid, the RFC 7638 thumbprint.
func GenerateKey() (priv *rsa.PrivateKey, kid string, err error) {
	priv, err = rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, "", err
	}
	return priv, KID(&priv.PublicKey), nil
}

// Sign returns an RS256 token over claims with the given kid in its header.
func Sign(priv *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	if kid == "" {
		return "", ErrNoKID
	}
	h, err := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", errors.New("jwtx: claims not encodable")
	}
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return in + "." + b64.EncodeToString(sig), nil
}

// Verify checks token against keys at time now and returns the key that
// signed it and its claims. It does not bind the role to the key's class;
// callers follow it with CheckRole.
func Verify(token string, keys []Key, now time.Time) (Key, Claims, error) {
	k, p, err := verifySigned(token, keys)
	if err != nil {
		return Key{}, Claims{}, err
	}
	t := now.Unix()
	exp, ok, err := numericDate(p, "exp")
	if err != nil {
		return Key{}, Claims{}, err
	}
	if !ok || exp <= t {
		return Key{}, Claims{}, ErrExpired
	}
	nbf, ok, err := numericDate(p, "nbf")
	if err != nil {
		return Key{}, Claims{}, err
	}
	if ok && nbf > t+nbfSkew {
		return Key{}, Claims{}, ErrNotYetValid
	}
	role, _ := p["role"].(string)
	if role == "" {
		return Key{}, Claims{}, ErrNoRole
	}
	sub, isStr := p["sub"].(string)
	if _, present := p["sub"]; present && !isStr {
		return Key{}, Claims{}, ErrMalformed
	}
	return k, Claims{Role: role, Sub: sub, Exp: exp, Raw: p}, nil
}

// verifySigned is the part of verification both entry points share: size and
// alphabet, three segments, strict JSON, the algorithm, no crit, exactly one
// supplied key with the token's kid, the signature, and then the payload as
// one strict JSON object. It reads no claim.
func verifySigned(token string, keys []Key) (Key, map[string]any, error) {
	if len(token) > maxToken || !inAlphabet(token, true) || strings.Count(token, ".") != 2 {
		return Key{}, nil, ErrMalformed
	}
	seg := strings.Split(token, ".")
	hb, err1 := b64.DecodeString(seg[0])
	pb, err2 := b64.DecodeString(seg[1])
	sig, err3 := b64.DecodeString(seg[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return Key{}, nil, ErrMalformed
	}
	h, err := decodeObject(hb)
	if err != nil {
		return Key{}, nil, err
	}
	if a, _ := h["alg"].(string); a != alg {
		return Key{}, nil, ErrAlg
	}
	if _, ok := h["crit"]; ok {
		return Key{}, nil, ErrMalformed // no extension is understood
	}
	kid, _ := h["kid"].(string)
	if kid == "" {
		return Key{}, nil, ErrNoKID
	}
	// A kid listed more than once is ambiguous: which class applies would
	// depend on the order of keys.
	var k Key
	matches := 0
	for _, c := range keys {
		if c.KID == kid {
			k = c
			matches++
		}
	}
	if matches != 1 || k.Pub == nil {
		return Key{}, nil, ErrUnknownKID
	}
	sum := sha256.Sum256([]byte(token[:len(seg[0])+1+len(seg[1])]))
	if rsa.VerifyPKCS1v15(k.Pub, crypto.SHA256, sum[:], sig) != nil {
		return Key{}, nil, ErrSignature
	}
	p, err := decodeObject(pb)
	if err != nil {
		return Key{}, nil, err
	}
	return k, p, nil
}

// inAlphabet reports whether s holds only base64url characters, and dots when
// dot is set. encoding/base64 skips CR and LF even in strict mode, so this
// check is what keeps two different strings from decoding alike.
func inAlphabet(s string, dot bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || dot && c == '.') {
			return false
		}
	}
	return true
}

// numericDate reads member name as an integer JSON number. A member that is
// present but not one is ErrMalformed.
func numericDate(m map[string]any, name string) (v int64, ok bool, err error) {
	raw, ok := m[name]
	if !ok {
		return 0, false, nil
	}
	n, isNum := raw.(json.Number)
	if !isNum {
		return 0, false, ErrMalformed
	}
	v, err = n.Int64()
	if err != nil {
		return 0, false, ErrMalformed
	}
	return v, true, nil
}

// decodeObject parses b as exactly one JSON object, rejecting invalid UTF-8,
// trailing data, nesting deeper than maxDepth and a duplicate member name in
// any object. encoding/json alone
// keeps the last of duplicates silently, which would let this package read one
// role while another parser reads another.
func decodeObject(b []byte) (map[string]any, error) {
	if !utf8.Valid(b) {
		return nil, ErrMalformed
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, ErrMalformed
	}
	m, err := object(d, 1)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrMalformed
	}
	return m, nil
}

// object reads the members of an object whose '{' was already consumed, at
// nesting level depth.
func object(d *json.Decoder, depth int) (map[string]any, error) {
	m := map[string]any{}
	for {
		t, err := d.Token()
		if err != nil {
			return nil, ErrMalformed
		}
		if t == json.Delim('}') {
			return m, nil
		}
		name, ok := t.(string)
		if !ok {
			return nil, ErrMalformed
		}
		if _, dup := m[name]; dup {
			return nil, ErrDuplicateMember
		}
		if m[name], err = value(d, depth); err != nil {
			return nil, err
		}
	}
}

// value reads one value inside a container at nesting level depth.
func value(d *json.Decoder, depth int) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, ErrMalformed
	}
	if (t == json.Delim('{') || t == json.Delim('[')) && depth >= maxDepth {
		return nil, ErrMalformed
	}
	switch t {
	case json.Delim('{'):
		return object(d, depth+1)
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, err := value(d, depth+1)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		if _, err := d.Token(); err != nil {
			return nil, ErrMalformed
		}
		return a, nil
	case json.Delim('}'), json.Delim(']'):
		return nil, ErrMalformed
	}
	return t, nil
}
