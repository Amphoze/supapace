package jwtx

import (
	"crypto/subtle"
	"errors"
	"time"
)

const (
	idLeeway = 60  // seconds of clock leeway on exp, iat and nbf
	idMaxAge = 600 // seconds an ID token's iat may lie in the past
	idMaxSub = 255 // bytes of sub
)

var (
	// ErrNonce: the ID token's nonce is missing or is not the expected one.
	ErrNonce = errors.New("jwtx: nonce missing or not the expected one")
	// ErrClaim: iss, aud, azp or sub is missing or not the expected value.
	ErrClaim = errors.New("jwtx: claim missing or not the expected value")
)

// IDCheck is what an ID token for dashboard sign-in must carry.
type IDCheck struct{ Issuer, ClientID, Nonce string }

// IDClaims are the verified claims of an ID token. Name is untrusted display
// text, possibly empty.
type IDClaims struct {
	Sub, Name string
	Iat, Exp  int64
}

// VerifyID checks an OpenID Connect ID token for dashboard sign-in. It shares
// Verify's parse and signature code, then requires: a key of ClassDashboard;
// iss equal to want.Issuer; aud equal to want.ClientID, or an array holding
// it, with azp when the array has more than one member (a present azp always
// equal to the client id); exp and iat
// present, with 60 s of leeway, iat at most 600 s old; a present nbf no more
// than 60 s ahead; nonce equal to want.Nonce; sub 1 to 255 bytes of printable
// ASCII; name, when present, a string. It does not read role. A check with an
// empty member accepts nothing.
func VerifyID(token string, keys []Key, want IDCheck, now time.Time) (IDClaims, error) {
	if want.Issuer == "" || want.ClientID == "" || want.Nonce == "" {
		return IDClaims{}, ErrClaim
	}
	k, p, err := verifySigned(token, keys)
	if err != nil {
		return IDClaims{}, err
	}
	if k.Class != ClassDashboard {
		return IDClaims{}, ErrKey
	}
	str := func(name string) (string, bool, error) {
		v, present := p[name]
		s, isStr := v.(string)
		if present && !isStr {
			return "", false, ErrMalformed
		}
		return s, present, nil
	}

	iss, _, err := str("iss")
	if err != nil {
		return IDClaims{}, err
	}
	if iss != want.Issuer {
		return IDClaims{}, ErrClaim
	}
	azp, hasAzp, err := str("azp")
	if err != nil {
		return IDClaims{}, err
	}
	if hasAzp && azp != want.ClientID {
		return IDClaims{}, ErrClaim
	}
	switch aud := p["aud"].(type) {
	case string:
		if aud != want.ClientID {
			return IDClaims{}, ErrClaim
		}
	case []any:
		found := false
		for _, a := range aud {
			s, ok := a.(string)
			if !ok {
				return IDClaims{}, ErrMalformed
			}
			found = found || s == want.ClientID
		}
		if !found || len(aud) > 1 && !hasAzp {
			return IDClaims{}, ErrClaim
		}
	case nil:
		if _, present := p["aud"]; !present {
			return IDClaims{}, ErrClaim
		}
		return IDClaims{}, ErrMalformed
	default:
		return IDClaims{}, ErrMalformed
	}

	t := now.Unix()
	exp, ok, err := numericDate(p, "exp")
	if err != nil {
		return IDClaims{}, err
	}
	if !ok || exp <= t-idLeeway {
		return IDClaims{}, ErrExpired
	}
	iat, ok, err := numericDate(p, "iat")
	if err != nil {
		return IDClaims{}, err
	}
	if !ok || iat < t-idMaxAge {
		return IDClaims{}, ErrExpired
	}
	if iat > t+idLeeway {
		return IDClaims{}, ErrNotYetValid
	}
	nbf, ok, err := numericDate(p, "nbf")
	if err != nil {
		return IDClaims{}, err
	}
	if ok && nbf > t+idLeeway {
		return IDClaims{}, ErrNotYetValid
	}

	sub, _, err := str("sub")
	if err != nil {
		return IDClaims{}, err
	}
	if !printableASCII(sub, idMaxSub) {
		return IDClaims{}, ErrClaim
	}
	name, _, err := str("name")
	if err != nil {
		return IDClaims{}, err
	}
	// The nonce last: ErrNonce means a token that is valid in everything else.
	nonce, _, err := str("nonce")
	if err != nil {
		return IDClaims{}, err
	}
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(want.Nonce)) != 1 {
		return IDClaims{}, ErrNonce
	}
	return IDClaims{Sub: sub, Name: name, Iat: iat, Exp: exp}, nil
}

// printableASCII: 1 to max bytes of 0x20 to 0x7e.
func printableASCII(s string, max int) bool {
	if len(s) == 0 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// DashboardKeyFromJWK is KeyFromJWK, with every check of it, for a key of
// ClassDashboard.
func DashboardKeyFromJWK(kid, n, e string) (Key, error) {
	k, err := KeyFromJWK(kid, "issuer", n, e)
	if err != nil {
		return Key{}, err
	}
	k.Class = ClassDashboard
	return k, nil
}

// ParseDashboardJWKS is ParseJWKS, with every check of it, for a key set of
// ClassDashboard.
func ParseDashboardJWKS(b []byte) ([]Key, error) {
	keys, err := ParseJWKS(b, "issuer")
	if err != nil {
		return nil, err
	}
	for i := range keys {
		keys[i].Class = ClassDashboard
	}
	return keys, nil
}
