package jwtx

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"testing"
)

// keyOpsSet is a key set of the test key under kid "a" with the given extra
// members, and under kid "b" without any.
func keyOpsSet(t *testing.T, extra string) []byte {
	t.Helper()
	priv, _ := key(t)
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	return []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"a","n":%q,"e":"AQAB"%s},{"kty":"RSA","kid":"b","n":%q,"e":"AQAB"}]}`,
		n, extra, n))
}

func kids(ks []Key) []string {
	var s []string
	for _, k := range ks {
		s = append(s, k.KID)
	}
	return s
}

// The dashboard's sign-in keys: an entry whose key_ops is present and holds
// no "verify" is not a signing key and is skipped; a key_ops that is not an
// array of strings refuses the set.
func TestParseDashboardJWKS_KeyOps(t *testing.T) {
	for _, c := range []struct {
		extra string
		want  []string
		err   error
	}{
		{``, []string{"a", "b"}, nil},
		{`,"key_ops":["verify"]`, []string{"a", "b"}, nil},
		{`,"key_ops":["sign","verify"]`, []string{"a", "b"}, nil},
		{`,"key_ops":["encrypt","wrapKey"]`, []string{"b"}, nil},
		{`,"key_ops":[]`, []string{"b"}, nil},
		{`,"key_ops":"verify"`, nil, ErrMalformed},
		{`,"key_ops":["verify",1]`, nil, ErrMalformed},
		{`,"key_ops":null`, nil, ErrMalformed},
	} {
		ks, err := ParseDashboardJWKS(keyOpsSet(t, c.extra))
		if !errors.Is(err, c.err) || !slices.Equal(kids(ks), c.want) {
			t.Errorf("%s: %q %v, want %q %v", c.extra, kids(ks), err, c.want, c.err)
		}
	}
	// An encryption-only set has no usable key.
	priv, _ := key(t)
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	only := fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"a","n":%q,"e":"AQAB","key_ops":["encrypt"]}]}`, n)
	if _, err := ParseDashboardJWKS([]byte(only)); !errors.Is(err, ErrKey) {
		t.Errorf("encryption-only: %v", err)
	}
}

// The project issuer's key set is parsed as before: key_ops is not read.
func TestParseJWKS_KeyOpsNotRead(t *testing.T) {
	for _, extra := range []string{``, `,"key_ops":["encrypt","wrapKey"]`, `,"key_ops":[]`, `,"key_ops":"verify"`,
		`,"key_ops":["verify",1]`, `,"key_ops":null`} {
		ks, err := ParseJWKS(keyOpsSet(t, extra), "issuer")
		if err != nil || !slices.Equal(kids(ks), []string{"a", "b"}) {
			t.Errorf("%s: %q %v", extra, kids(ks), err)
		}
	}
}
