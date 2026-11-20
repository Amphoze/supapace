package jwtx

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
)

// KID returns the RFC 7638 thumbprint of pub, base64url encoded.
func KID(pub *rsa.PublicKey) string {
	// Members in lexicographic order, no whitespace, as RFC 7638 §3 requires.
	j := `{"e":"` + b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()) +
		`","kty":"RSA","n":"` + b64.EncodeToString(pub.N.Bytes()) + `"}`
	sum := sha256.Sum256([]byte(j))
	return b64.EncodeToString(sum[:])
}

// KeyFromJWK builds a key from the base64url modulus and exponent of an RSA
// JWK. The modulus must be 2048–4096 bits and the exponent 65537, both in
// their minimal encoding; anything else is ErrKey.
func KeyFromJWK(kid string, class Class, n, e string) (Key, error) {
	if kid == "" {
		return Key{}, ErrNoKID
	}
	if class != "anon" && class != "service_role" && class != "issuer" {
		return Key{}, ErrKey
	}
	if !inAlphabet(n, false) || !inAlphabet(e, false) {
		return Key{}, ErrKey
	}
	nb, err1 := b64.DecodeString(n)
	eb, err2 := b64.DecodeString(e)
	if err1 != nil || err2 != nil || len(nb) == 0 || nb[0] == 0 || string(eb) != "\x01\x00\x01" {
		return Key{}, ErrKey
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: pubE}
	if !acceptable(pub) {
		return Key{}, ErrKey
	}
	return Key{KID: kid, Class: class, Pub: pub}, nil
}

// acceptable reports whether pub has an odd 2048–4096-bit modulus and the
// exponent 65537.
func acceptable(pub *rsa.PublicKey) bool {
	return pub != nil && pub.N != nil && pub.E == pubE && pub.N.Bit(0) == 1 &&
		pub.N.BitLen() >= minBits && pub.N.BitLen() <= maxBits
}

type jwk struct {
	Kty string `json:"kty"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// MarshalJWKS encodes keys as a public JSON Web Key Set. Classes are not
// part of the output. A duplicate kid or a key KeyFromJWK would refuse is
// ErrKey.
func MarshalJWKS(keys []Key) ([]byte, error) {
	out := struct {
		Keys []jwk `json:"keys"`
	}{Keys: []jwk{}}
	seen := map[string]bool{}
	for _, k := range keys {
		if k.KID == "" {
			return nil, ErrNoKID
		}
		if !acceptable(k.Pub) || seen[k.KID] {
			return nil, ErrKey
		}
		seen[k.KID] = true
		out.Keys = append(out.Keys, jwk{Kty: "RSA", KID: k.KID, Use: "sig", Alg: alg,
			N: b64.EncodeToString(k.Pub.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(k.Pub.E)).Bytes())})
	}
	return json.Marshal(out)
}

// ParseJWKS reads a JSON Web Key Set of at most 64 KiB strictly (no duplicate
// member names, no trailing data, bounded nesting) and returns its RSA
// signature keys, each of the given class.
//
// An entry is skipped when its kty is not "RSA", or it has a "use" other than
// "sig", or an "alg" other than "RS256": issuers publish such keys beside
// their signing keys. The whole set is refused when a kty, kid, use, alg, n or
// e member of any entry is not a string (ErrMalformed); when no entry is
// usable, a usable entry carries a private member, is outside the bounds of
// KeyFromJWK, or shares its kid with another usable entry (ErrKey); or when a
// usable entry has no kid (ErrNoKID).
func ParseJWKS(b []byte, class Class) ([]Key, error) { return parseJWKS(b, class, false) }

// parseJWKS is ParseJWKS; with keyOps (the dashboard's sign-in keys) an entry
// whose key_ops is present and holds no "verify" is skipped too, and a key_ops
// that is not an array of strings refuses the set.
func parseJWKS(b []byte, class Class, keyOps bool) ([]Key, error) {
	if len(b) > maxJWKS {
		return nil, ErrMalformed
	}
	if class != "anon" && class != "service_role" && class != "issuer" {
		return nil, ErrKey
	}
	set, err := decodeObject(b)
	if err != nil {
		return nil, err
	}
	list, ok := set["keys"].([]any)
	if _, present := set["keys"]; present && !ok {
		return nil, ErrMalformed
	}
	var keys []Key
	seen := map[string]bool{}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, ErrMalformed
		}
		str := func(name string) (string, bool) {
			v, present := m[name]
			s, isStr := v.(string)
			return s, !present || isStr
		}
		kty, ok1 := str("kty")
		kid, ok2 := str("kid")
		use, ok3 := str("use")
		a, ok4 := str("alg")
		n, ok5 := str("n")
		e, ok6 := str("e")
		if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) {
			return nil, ErrMalformed
		}
		// Secret material in any entry, skipped ones included, refuses the set:
		// a document carrying it must not be stored or served.
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, ok := m[private]; ok {
				return nil, ErrKey
			}
		}
		verify, err := verifyOp(m, keyOps)
		if err != nil {
			return nil, err
		}
		if _, hasUse := m["use"]; kty != "RSA" || hasUse && use != "sig" || !verify {
			continue
		}
		if _, hasAlg := m["alg"]; hasAlg && a != alg {
			continue
		}
		if kid == "" {
			return nil, ErrNoKID
		}
		if seen[kid] {
			return nil, ErrKey
		}
		k, err := KeyFromJWK(kid, class, n, e)
		if err != nil {
			return nil, err
		}
		seen[kid] = true
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, ErrKey
	}
	return keys, nil
}

// verifyOp reports whether an entry may verify signatures by its key_ops:
// true when it is not read (check false) or absent; else whether it holds
// "verify". A key_ops that is not an array of strings is ErrMalformed.
func verifyOp(m map[string]any, check bool) (bool, error) {
	v, present := m["key_ops"]
	if !check || !present {
		return true, nil
	}
	ops, ok := v.([]any)
	if !ok {
		return false, ErrMalformed
	}
	verify := false
	for _, o := range ops {
		s, ok := o.(string)
		if !ok {
			return false, ErrMalformed
		}
		verify = verify || s == "verify"
	}
	return verify, nil
}
