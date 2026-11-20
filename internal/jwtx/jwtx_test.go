package jwtx

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
	testKID string
)

// key returns one RSA key generated for this test run.
func key(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		testKey, testKID, err = GenerateKey()
		if err != nil {
			panic(err)
		}
	})
	return testKey, testKID
}

var now = time.Unix(1_800_000_000, 0)

func enc(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// jsonEsc spells every character of an ASCII string as a JSON escape.
func jsonEsc(s string) string {
	var b strings.Builder
	for _, c := range s {
		b.WriteString("\\" + fmt.Sprintf("u%04x", c))
	}
	return b.String()
}

// signRaw signs header and payload exactly as given, so tests can build
// tokens Sign would never produce.
func signRaw(t *testing.T, priv *rsa.PrivateKey, header, payload string) string {
	t.Helper()
	in := enc(header) + "." + enc(payload)
	h := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func keys(t *testing.T, class Class) []Key {
	priv, kid := key(t)
	return []Key{{KID: kid, Class: class, Pub: &priv.PublicKey}}
}

func hdr(t *testing.T) string {
	_, kid := key(t)
	return `{"alg":"RS256","kid":"` + kid + `","typ":"JWT"}`
}

func wantErr(t *testing.T, token string, ks []Key, want error) {
	t.Helper()
	_, _, err := Verify(token, ks, now)
	if !errors.Is(err, want) {
		t.Fatalf("Verify: got %v, want %v", err, want)
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	priv, kid := key(t)
	tok, err := Sign(priv, kid, map[string]any{"role": "anon", "sub": "u1", "exp": now.Unix() + 60, "x": "y"})
	if err != nil {
		t.Fatal(err)
	}
	k, c, err := Verify(tok, keys(t, "anon"), now)
	if err != nil {
		t.Fatal(err)
	}
	if k.KID != kid || k.Class != "anon" {
		t.Fatalf("key %+v", k)
	}
	if c.Role != "anon" || c.Sub != "u1" || c.Exp != now.Unix()+60 || c.Raw["x"] != "y" {
		t.Fatalf("claims %+v", c)
	}
}

func TestVerify_RejectsAlgNone(t *testing.T) {
	_, kid := key(t)
	tok := enc(`{"alg":"none","kid":"`+kid+`"}`) + "." + enc(`{"role":"service_role","exp":1900000000}`) + "."
	wantErr(t, tok, keys(t, "service_role"), ErrAlg)
}

func TestVerify_RejectsHS256WithPublicKeyAsSecret(t *testing.T) {
	priv, kid := key(t)
	secret, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	in := enc(`{"alg":"HS256","kid":"`+kid+`"}`) + "." + enc(`{"role":"service_role","exp":1900000000}`)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(in))
	wantErr(t, in+"."+base64.RawURLEncoding.EncodeToString(m.Sum(nil)), keys(t, "anon"), ErrAlg)
}

func TestVerify_RejectsMissingKID(t *testing.T) {
	priv, _ := key(t)
	wantErr(t, signRaw(t, priv, `{"alg":"RS256"}`, `{"role":"anon","exp":1900000000}`), keys(t, "anon"), ErrNoKID)
}

func TestVerify_RejectsUnknownKID(t *testing.T) {
	priv, _ := key(t)
	wantErr(t, signRaw(t, priv, `{"alg":"RS256","kid":"other"}`, `{"role":"anon","exp":1900000000}`), keys(t, "anon"), ErrUnknownKID)
}

func TestVerify_RejectsBadSignature(t *testing.T) {
	priv, kid := key(t)
	tok, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix() + 60})
	if err != nil {
		t.Fatal(err)
	}
	// A valid signature over a different payload.
	other, err := Sign(priv, kid, map[string]any{"role": "service_role", "exp": now.Unix() + 60})
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(tok, ".")
	q := strings.Split(other, ".")
	wantErr(t, p[0]+"."+q[1]+"."+p[2], keys(t, "anon"), ErrSignature)
	// Another key under the same kid.
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, signRaw(t, stranger, hdr(t), `{"role":"anon","exp":1900000000}`), keys(t, "anon"), ErrSignature)
}

func TestVerify_RejectsExpMissing(t *testing.T) {
	priv, _ := key(t)
	wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon"}`), keys(t, "anon"), ErrExpired)
}

func TestVerify_RejectsExpString(t *testing.T) {
	priv, _ := key(t)
	wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":"1900000000"}`), keys(t, "anon"), ErrMalformed)
}

func TestVerify_RejectsExpEqualNow(t *testing.T) {
	priv, kid := key(t)
	tok, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, tok, keys(t, "anon"), ErrExpired)
	// Sub-second remainder of now does not extend the token.
	if _, _, err := Verify(tok, keys(t, "anon"), now.Add(900*time.Millisecond)); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
	if _, _, err := Verify(tok, keys(t, "anon"), now.Add(-time.Second)); err != nil {
		t.Fatalf("one second before exp: %v", err)
	}
}

func TestVerify_RejectsNbfFuture(t *testing.T) {
	priv, kid := key(t)
	mk := func(nbf int64) string {
		tok, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix() + 600, "nbf": nbf})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	wantErr(t, mk(now.Unix()+31), keys(t, "anon"), ErrNotYetValid)
	if _, _, err := Verify(mk(now.Unix()+30), keys(t, "anon"), now); err != nil {
		t.Fatalf("nbf = now+30: %v", err)
	}
	wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"nbf":"1"}`), keys(t, "anon"), ErrMalformed)
}

func TestVerify_RejectsFourSegments(t *testing.T) {
	priv, kid := key(t)
	tok, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix() + 60})
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, tok+".", keys(t, "anon"), ErrMalformed)
	wantErr(t, tok+"."+enc("x"), keys(t, "anon"), ErrMalformed)
	p := strings.Split(tok, ".")
	wantErr(t, p[0]+"."+p[1], keys(t, "anon"), ErrMalformed)
	// Padded or standard-alphabet base64 is not base64url.
	wantErr(t, p[0]+"=."+p[1]+"."+p[2], keys(t, "anon"), ErrMalformed)
	wantErr(t, strings.NewReplacer("-", "+", "_", "/").Replace(tok)+"+", keys(t, "anon"), ErrMalformed)
}

func TestVerify_RejectsMissingRole(t *testing.T) {
	priv, _ := key(t)
	for _, p := range []string{`{"exp":1900000000}`, `{"exp":1900000000,"role":1}`, `{"exp":1900000000,"role":""}`, `{"exp":1900000000,"role":null}`} {
		wantErr(t, signRaw(t, priv, hdr(t), p), keys(t, "anon"), ErrNoRole)
	}
}

func TestVerify_RejectsOversize(t *testing.T) {
	priv, kid := key(t)
	ok, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix() + 60, "pad": strings.Repeat("a", 5600)})
	if err != nil {
		t.Fatal(err)
	}
	if len(ok) > maxToken {
		t.Fatalf("fixture too large: %d", len(ok))
	}
	if _, _, err := Verify(ok, keys(t, "anon"), now); err != nil {
		t.Fatal(err)
	}
	big, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix() + 60, "pad": strings.Repeat("a", 8192)})
	if err != nil {
		t.Fatal(err)
	}
	wantErr(t, big, keys(t, "anon"), ErrMalformed)
}

func TestVerify_RejectsDuplicateHeaderMember(t *testing.T) {
	priv, kid := key(t)
	wantErr(t, signRaw(t, priv, `{"alg":"none","alg":"RS256","kid":"`+kid+`"}`, `{"role":"anon","exp":1900000000}`), keys(t, "anon"), ErrDuplicateMember)
	wantErr(t, signRaw(t, priv, `{"alg":"RS256","alg":"RS256","kid":"`+kid+`"}`, `{"role":"anon","exp":1900000000}`), keys(t, "anon"), ErrDuplicateMember)
}

func TestVerify_RejectsDuplicatePayloadMember(t *testing.T) {
	priv, _ := key(t)
	wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"role":"service_role"}`), keys(t, "anon"), ErrDuplicateMember)
	// Escaped spelling of the same name is the same member.
	wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"`+jsonEsc("role")+`":"service_role"}`), keys(t, "anon"), ErrDuplicateMember)
	// Nested objects are checked too.
	wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"app":{"a":1,"a":2}}`), keys(t, "anon"), ErrDuplicateMember)
	// Case variants are distinct members, and only the exact "role" counts.
	if _, c, err := Verify(signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"Role":"service_role"}`), keys(t, "anon"), now); err != nil || c.Role != "anon" {
		t.Fatalf("case variant: %v %+v", err, c)
	}
}

func TestVerify_RejectsMalformedJSON(t *testing.T) {
	priv, _ := key(t)
	for _, p := range []string{`[]`, `null`, `{"role":"anon","exp":1900000000}x`, `{"role":"anon","exp":1900000000}{}`, "{\"role\":\"an\xffon\",\"exp\":1900000000}", `{"role":"anon","exp":1.9e9}`} {
		wantErr(t, signRaw(t, priv, hdr(t), p), keys(t, "anon"), ErrMalformed)
	}
	_, kid := key(t)
	wantErr(t, signRaw(t, priv, `{"alg":"RS256","kid":"`+kid+`","crit":["exp"]}`, `{"role":"anon","exp":1900000000}`), keys(t, "anon"), ErrMalformed)
}

func TestVerify_ErrorsCarryNoTokenMaterial(t *testing.T) {
	priv, kid := key(t)
	secret := "zzsecretzz"
	toks := []string{
		signRaw(t, priv, `{"alg":"`+secret+`","kid":"`+kid+`"}`, `{}`),
		signRaw(t, priv, `{"alg":"RS256","kid":"`+secret+`"}`, `{}`),
		signRaw(t, priv, hdr(t), `{"role":"anon","exp":"`+secret+`"}`),
		signRaw(t, priv, hdr(t), `{"role":"anon","`+secret+`":1,"`+secret+`":2}`),
		secret + "." + secret + "." + secret,
	}
	for _, tok := range toks {
		_, _, err := Verify(tok, keys(t, "anon"), now)
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), kid) {
			t.Fatalf("error %q", err)
		}
	}
}

func TestCheckRole_Table(t *testing.T) {
	user := []string{"authenticated", "app_user", "service_role", "anon", "supabase_admin", "pgbouncer", "supapace_backup", "pg_monitor"}
	rows := []struct {
		class Class
		role  string
		roles []string
		want  error
	}{
		{"anon", "anon", nil, nil},
		{"anon", "service_role", nil, ErrRole},
		{"service_role", "service_role", nil, nil},
		{"service_role", "authenticated", user, ErrRole},
		{"issuer", "authenticated", user, nil},
		{"issuer", "service_role", user, ErrRole},
		{"issuer", "anon", user, ErrRole},
		{"issuer", "supabase_admin", user, ErrRole},
		{"issuer", "pgbouncer", user, ErrRole},
		{"issuer", "supapace_backup", user, ErrRole},
		{"issuer", "pg_monitor", user, ErrRole},
		{"issuer", "app_user", user, nil},
		{"issuer", "other_user", user, ErrRole},
		{"issuer", "authenticated", nil, ErrRole},
		{"bogus", "anon", user, ErrRole},
		{"anon", "", nil, ErrNoRole},
	}
	for _, r := range rows {
		err := CheckRole(Key{KID: "k", Class: r.class}, Claims{Role: r.role}, r.roles)
		if !errors.Is(err, r.want) || (r.want == nil) != (err == nil) {
			t.Errorf("%s/%s: got %v, want %v", r.class, r.role, err, r.want)
		}
	}
}

func TestForbiddenUserRole_Verbatim(t *testing.T) {
	for _, r := range []string{
		"anon", "service_role", "authenticator", "dashboard_user", "pgbouncer", "postgres",
		"supabase_admin", "supabase_auth_admin", "supabase_etl_admin", "supabase_privileged_role",
		"supabase_read_only_user", "supabase_replication_admin", "supabase_storage_admin",
		"supabase_realtime_admin", "supapace_backup",
		"pg_", "pg_monitor", "pg_anything", "supabase_", "supabase_x", "supapace_", "supapace_x",
	} {
		if !ForbiddenUserRole(r) {
			t.Errorf("%q allowed", r)
		}
	}
	for _, r := range []string{"authenticated", "app_user", "pg", "supabase", "supapace", "xpg_monitor", "anon2"} {
		if ForbiddenUserRole(r) {
			t.Errorf("%q forbidden", r)
		}
	}
}

// modulus returns an odd number of exactly bits bits, base64url encoded.
func modulus(bits int) string {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.SetBit(n, 0, 1)
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func TestKeyFromJWK_Bounds(t *testing.T) {
	const e = "AQAB"
	for _, c := range []struct {
		n, e string
		ok   bool
	}{
		{modulus(1024), e, false},
		{modulus(2047), e, false},
		{modulus(2048), e, true},
		{modulus(4096), e, true},
		{modulus(4097), e, false},
		{modulus(8192), e, false},
		{modulus(2048), "Aw", false},     // e = 3
		{modulus(2048), "AAEAAQ", false}, // 65537 with a leading zero octet
		{modulus(2048), "AQAB=", false},
		{leadZero(modulus(2048)), e, false}, // leading zero octet in n
		{"", e, false},
		{modulus(2048), "", false},
	} {
		k, err := KeyFromJWK("k1", "issuer", c.n, c.e)
		if c.ok != (err == nil) || (err != nil && !errors.Is(err, ErrKey)) {
			t.Errorf("n %d chars, e %q: %v", len(c.n), c.e, err)
		}
		if err == nil && (k.KID != "k1" || k.Class != "issuer" || k.Pub.E != 65537) {
			t.Errorf("key %+v", k)
		}
	}
	if _, err := KeyFromJWK("", "issuer", modulus(2048), e); !errors.Is(err, ErrNoKID) {
		t.Errorf("empty kid: %v", err)
	}
	if _, err := KeyFromJWK("k1", "admin", modulus(2048), e); !errors.Is(err, ErrKey) {
		t.Errorf("bad class: %v", err)
	}
}

func TestJWKS_RoundTrip(t *testing.T) {
	priv, kid := key(t)
	k2, err := KeyFromJWK("second", "issuer", modulus(4096), "AQAB")
	if err != nil {
		t.Fatal(err)
	}
	in := []Key{{KID: kid, Class: "issuer", Pub: &priv.PublicKey}, k2}
	b, err := MarshalJWKS(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"d"`) || strings.Contains(string(b), "issuer") {
		t.Fatalf("jwks %s", b)
	}
	out, err := ParseJWKS(b, "issuer")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d keys", len(out))
	}
	for i := range in {
		if out[i].KID != in[i].KID || out[i].Class != "issuer" || out[i].Pub.N.Cmp(in[i].Pub.N) != 0 || out[i].Pub.E != in[i].Pub.E {
			t.Fatalf("key %d differs", i)
		}
	}
	// A token signed by the key verifies against the parsed set.
	tok, err := Sign(priv, kid, map[string]any{"role": "authenticated", "exp": now.Unix() + 60})
	if err != nil {
		t.Fatal(err)
	}
	if k, _, err := Verify(tok, out, now); err != nil || k.KID != kid {
		t.Fatalf("verify against parsed jwks: %v", err)
	}

	n := modulus(2048)
	one := func(member string) string {
		return `{"keys":[{"kty":"RSA","kid":"a","n":"` + n + `","e":"AQAB"` + member + `}]}`
	}
	for name, c := range map[string]struct {
		doc  string
		want error
	}{
		"empty set":      {`{"keys":[]}`, ErrKey},
		"no keys member": {`{}`, ErrKey},
		"not json":       {`{`, ErrMalformed},
		"trailing":       {one("") + "x", ErrMalformed},
		"keys object":    {`{"keys":{}}`, ErrMalformed},
		"no kid":         {`{"keys":[{"kty":"RSA","n":"` + n + `","e":"AQAB"}]}`, ErrNoKID},
		"kty EC":         {`{"keys":[{"kty":"EC","kid":"a","n":"` + n + `","e":"AQAB"}]}`, ErrKey},
		"small n":        {`{"keys":[{"kty":"RSA","kid":"a","n":"` + modulus(1024) + `","e":"AQAB"}]}`, ErrKey},
		"private":        {one(`,"d":"AQAB"`), ErrKey},
		"use enc":        {one(`,"use":"enc"`), ErrKey},
		"alg RS512":      {one(`,"alg":"RS512"`), ErrKey},
		"duplicate kid":  {`{"keys":[{"kty":"RSA","kid":"a","n":"` + n + `","e":"AQAB"},{"kty":"RSA","kid":"a","n":"` + n + `","e":"AQAB"}]}`, ErrKey},
		"duplicate n":    {one(`,"n":"` + n + `"`), ErrDuplicateMember},
	} {
		if _, err := ParseJWKS([]byte(c.doc), "issuer"); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if _, err := ParseJWKS([]byte(one(`,"use":"sig","alg":"RS256"`)), "issuer"); err != nil {
		t.Errorf("use/alg present: %v", err)
	}
}

func TestKID_IsThumbprint(t *testing.T) {
	// RFC 7638 §3.1 example key and thumbprint.
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	k, err := KeyFromJWK("x", "issuer", n, "AQAB")
	if err != nil {
		t.Fatal(err)
	}
	if got := KID(k.Pub); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("KID = %s", got)
	}
}

func TestKID_MatchesGenerateKey(t *testing.T) {
	priv, kid := key(t)
	if priv.N.BitLen() != 2048 {
		t.Fatalf("bits %d", priv.N.BitLen())
	}
	if KID(&priv.PublicKey) != kid {
		t.Fatal("KID differs from GenerateKey's kid")
	}
}

var (
	otherOnce sync.Once
	otherKey  *rsa.PrivateKey
)

// other returns a second RSA key, distinct from key(t).
func other(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	otherOnce.Do(func() {
		var err error
		if otherKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return otherKey
}

const okPayload = `{"role":"anon","exp":1900000000}`

func TestVerify_RejectsAlgVariants(t *testing.T) {
	priv, kid := key(t)
	for _, a := range []string{`"none"`, `"None"`, `"NONE"`, `"RS256 "`, `" RS256"`, `"rs256"`, `"HS256"`, `"PS256"`, `"RS512"`, `"ES256"`, `"RS256\u0000"`, `["RS256"]`, `256`, `null`, `true`, `{}`, `""`} {
		wantErr(t, signRaw(t, priv, `{"alg":`+a+`,"kid":"`+kid+`"}`, okPayload), keys(t, "anon"), ErrAlg)
	}
	// alg absent.
	wantErr(t, signRaw(t, priv, `{"kid":"`+kid+`"}`, okPayload), keys(t, "anon"), ErrAlg)
	// Escaped spelling of RS256 is the same string and is accepted.
	if _, _, err := Verify(signRaw(t, priv, `{"alg":"`+jsonEsc("RS256")+`","kid":"`+kid+`"}`, okPayload), keys(t, "anon"), now); err != nil {
		t.Fatalf("escaped RS256: %v", err)
	}
}

func TestVerify_IgnoresHeaderKeyMembers(t *testing.T) {
	_, kid := key(t)
	att := other(t)
	// An attacker-supplied key in jwk/jku/x5c/x5u never replaces the verifier's key.
	for _, m := range []string{
		`"jwk":{"kty":"RSA","n":"` + b64.EncodeToString(att.N.Bytes()) + `","e":"AQAB"}`,
		`"jku":"https://sp.test/jwks.json"`, `"x5u":"https://sp.test/c.pem"`, `"x5c":["AAAA"]`,
	} {
		wantErr(t, signRaw(t, att, `{"alg":"RS256","kid":"`+kid+`",`+m+`}`, `{"role":"service_role","exp":1900000000}`), keys(t, "service_role"), ErrSignature)
	}
	// b64:false is meaningless without crit, and crit is refused in any form.
	priv, _ := key(t)
	for _, c := range []string{`"crit":["b64"],"b64":false`, `"crit":[]`, `"crit":null`, `"crit":"x"`} {
		wantErr(t, signRaw(t, priv, `{"alg":"RS256","kid":"`+kid+`",`+c+`}`, okPayload), keys(t, "anon"), ErrMalformed)
	}
	// typ is not interpreted.
	if _, _, err := Verify(signRaw(t, priv, `{"alg":"RS256","kid":"`+kid+`","typ":"at+jwt"}`, okPayload), keys(t, "anon"), now); err != nil {
		t.Fatalf("typ: %v", err)
	}
}

func TestVerify_RejectsKIDShapes(t *testing.T) {
	priv, kid := key(t)
	for _, k := range []string{`1`, `["` + kid + `"]`, `{"kid":"` + kid + `"}`, `""`, `null`, `true`} {
		wantErr(t, signRaw(t, priv, `{"alg":"RS256","kid":`+k+`}`, okPayload), keys(t, "anon"), ErrNoKID)
	}
	for _, k := range []string{kid + " ", " " + kid, kid + `\u0000`, strings.ToLower(kid), strings.Repeat("k", 4000)} {
		wantErr(t, signRaw(t, priv, `{"alg":"RS256","kid":"`+k+`"}`, okPayload), keys(t, "anon"), ErrUnknownKID)
	}
	// A key with an empty kid in the slice never matches a token.
	wantErr(t, signRaw(t, priv, `{"alg":"RS256","kid":""}`, okPayload), []Key{{KID: "", Class: "anon", Pub: &priv.PublicKey}}, ErrNoKID)
	// A matching entry with no public key is unknown, not a panic.
	wantErr(t, signRaw(t, priv, hdr(t), okPayload), []Key{{KID: kid, Class: "anon"}}, ErrUnknownKID)
}

// An attacker holding a tenant issuer key that shares a kid with the
// project's anon or service_role key must never obtain the privileged class.
func TestVerify_RejectsAmbiguousKID(t *testing.T) {
	plat, kid := key(t)
	att := other(t)
	platAnon := Key{KID: kid, Class: "anon", Pub: &plat.PublicKey}
	platSvc := Key{KID: kid, Class: "service_role", Pub: &plat.PublicKey}
	issuer := Key{KID: kid, Class: "issuer", Pub: &att.PublicKey}
	forged := signRaw(t, att, hdr(t), `{"role":"service_role","exp":1900000000}`)
	genuine := signRaw(t, plat, hdr(t), okPayload)
	for _, set := range [][]Key{{platSvc, issuer}, {issuer, platSvc}, {platAnon, issuer}, {issuer, platAnon}, {platAnon, platSvc}, {platSvc, platAnon}} {
		for _, tok := range []string{forged, genuine} {
			if _, _, err := Verify(tok, set, now); !errors.Is(err, ErrUnknownKID) {
				t.Fatalf("kid shared by %q and %q: %v", set[0].Class, set[1].Class, err)
			}
		}
	}
}

func TestVerify_RejectsDuplicateMembersAnywhere(t *testing.T) {
	priv, kid := key(t)
	ks := keys(t, "anon")
	for _, p := range []string{
		`{"role":"anon","exp":1900000000,"role":"service_role"}`,
		`{"role":"service_role","role":"anon","exp":1900000000}`,
		`{"role":"anon","exp":1900000000,"exp":1900000001}`,
		`{"role":"anon","exp":1900000000,"a":[{"b":1,"b":2}]}`,
		`{"role":"anon","exp":1900000000,"a":{"b":{"c":1,"c":2}}}`,
	} {
		wantErr(t, signRaw(t, priv, hdr(t), p), ks, ErrDuplicateMember)
	}
	wantErr(t, signRaw(t, priv, `{"alg":"RS256","kid":"`+kid+`","kid":"x"}`, okPayload), ks, ErrDuplicateMember)
	// A duplicate header member is reported before the signature is checked;
	// a duplicate payload member only after it.
	wantErr(t, signRaw(t, other(t), hdr(t), `{"role":"anon","role":"anon","exp":1900000000}`), ks, ErrSignature)
}

func TestVerify_RejectsMalformedJSONShapes(t *testing.T) {
	priv, kid := key(t)
	ks := keys(t, "anon")
	for _, p := range []string{
		"\xef\xbb\xbf" + okPayload, // BOM
		okPayload + `{"role":"service_role"}`,
		okPayload + `]`,
		`{"role":"anon","exp":1900000000,}`,
		`{"role":"anon" "exp":1900000000}`,
		`{"role":"anon","exp":1900000000`,
		`{role:"anon","exp":1900000000}`,
		"{\"role\":\"anon\",\"exp\":1900000000,\"x\":\"\xc0\xaf\"}",
		`{"role":"anon","exp":1900000000,"a":[1,}`,
		`{"role":"anon","exp":1900000000,"a":[1}`,
		`{"role":"anon","exp":1900000000,"a":{]}`,
		`"x"`, `1`, ``,
	} {
		wantErr(t, signRaw(t, priv, hdr(t), p), ks, ErrMalformed)
	}
	// Insignificant whitespace around a signed object is harmless and accepted.
	if _, _, err := Verify(signRaw(t, priv, hdr(t), " \n"+okPayload+"\t "), ks, now); err != nil {
		t.Fatalf("whitespace: %v", err)
	}
	// Deep nesting inside the size cap terminates quickly with an error or a result, never a crash.
	deep := `{"alg":"RS256","kid":"` + kid + `","x":` + strings.Repeat("[", 5500) + strings.Repeat("]", 5500) + `}`
	start := time.Now()
	_, _, _ = Verify(enc(deep)+"."+enc(okPayload)+".AA", ks, now)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("deep header took %v", d)
	}
}

func TestVerify_NumericDates(t *testing.T) {
	priv, _ := key(t)
	ks := keys(t, "anon")
	for _, e := range []string{`1e400`, `9223372036854775808`, `1.9e9`, `1900000000.0`, `1900000000.5`, `"1900000000"`, `null`, `true`, `[1900000000]`, `{}`} {
		wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":`+e+`}`), ks, ErrMalformed)
		wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"nbf":`+e+`}`), ks, ErrMalformed)
	}
	for _, e := range []string{`-1`, `0`, `-9223372036854775808`, `-0`} {
		wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":`+e+`}`), ks, ErrExpired)
	}
	// nbf far in the past and negative are fine; max int64 nbf is not yet valid.
	for _, n := range []string{`0`, `-5`} {
		if _, _, err := Verify(signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"nbf":`+n+`}`), ks, now); err != nil {
			t.Fatalf("nbf %s: %v", n, err)
		}
	}
	wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"nbf":9223372036854775807}`), ks, ErrNotYetValid)
	// exp checked before nbf.
	wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":1,"nbf":9223372036854775807}`), ks, ErrExpired)
}

func TestVerify_RoleAndSubShapes(t *testing.T) {
	priv, _ := key(t)
	ks := keys(t, "anon")
	for _, r := range []string{`["anon"]`, `{"a":"anon"}`, `0`, `true`} {
		wantErr(t, signRaw(t, priv, hdr(t), `{"role":`+r+`,"exp":1900000000}`), ks, ErrNoRole)
	}
	// Verify returns odd role strings verbatim; CheckRole refuses them for
	// anon/service_role keys and unless listed exactly for issuer keys.
	for _, r := range []string{`"anon "`, `" anon"`, `"anon\u0000"`, `"ANON"`, `"an\"on"`, `"ａｎｏｎ"`} {
		k, c, err := Verify(signRaw(t, priv, hdr(t), `{"role":`+r+`,"exp":1900000000}`), ks, now)
		if err != nil {
			t.Fatalf("role %s: %v", r, err)
		}
		if CheckRole(k, c, nil) == nil || CheckRole(Key{Class: "service_role"}, c, nil) == nil {
			t.Fatalf("role %s passed CheckRole", r)
		}
	}
	for _, s := range []string{`1`, `null`, `["u"]`, `{}`, `true`} {
		wantErr(t, signRaw(t, priv, hdr(t), `{"role":"anon","exp":1900000000,"sub":`+s+`}`), ks, ErrMalformed)
	}
}

func TestVerify_RejectsSignatureShapes(t *testing.T) {
	priv, kid := key(t)
	ks := keys(t, "anon")
	tok, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix() + 60})
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(tok, ".")
	sig, err := base64.RawURLEncoding.DecodeString(p[2])
	if err != nil {
		t.Fatal(err)
	}
	in := p[0] + "." + p[1] + "."
	// Non-canonical trailing bits: 256 bytes leave 4 unused bits in the last character.
	last := strings.IndexByte(b64Alphabet, p[2][len(p[2])-1])
	nonCanon := p[2][:len(p[2])-1] + string(b64Alphabet[last^1])
	for name, s := range map[string]string{
		"padded":         p[2] + "=",
		"std alphabet":   base64.RawStdEncoding.EncodeToString(sig),
		"non-canonical":  nonCanon,
		"empty":          "",
		"all zero":       b64.EncodeToString(make([]byte, len(sig))),
		"leading zero":   b64.EncodeToString(append([]byte{0}, sig...)),
		"one byte short": b64.EncodeToString(sig[1:]),
		"one byte long":  b64.EncodeToString(append(append([]byte{}, sig...), 0)),
		"sig plus n":     b64.EncodeToString(addN(sig, priv)),
		"space inside":   p[2][:10] + " " + p[2][10:],
	} {
		_, _, err := Verify(in+s, ks, now)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !strings.ContainsAny(base64.RawStdEncoding.EncodeToString(sig), "+/") {
		t.Log("std-alphabet case did not exercise + or /")
	}
}

// TestVerify_RejectsLineBreaks: encoding/base64 skips CR and LF even in Strict
// mode, so a token with a line break inside its signature segment decodes to
// the same signature and verifies, although it is a different string.
func TestVerify_RejectsLineBreaks(t *testing.T) {
	priv, kid := key(t)
	tok, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix() + 60})
	if err != nil {
		t.Fatal(err)
	}
	i := strings.LastIndexByte(tok, '.') + 10
	for _, nl := range []string{"\n", "\r", "\r\n"} {
		if _, _, err := Verify(tok[:i]+nl+tok[i:], keys(t, "anon"), now); err == nil {
			t.Errorf("token with %q inside its signature segment verified", nl)
		}
		if _, _, err := Verify(tok+nl, keys(t, "anon"), now); err == nil {
			t.Errorf("token with trailing %q verified", nl)
		}
	}
}

func TestVerify_RejectsSegmentShapes(t *testing.T) {
	ks := keys(t, "anon")
	for _, tok := range []string{"", ".", "..", "...", "a", "a.b", ".b.c", "a..c", " " + "a.b.c", "a.b.c "} {
		if _, _, err := Verify(tok, ks, now); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", tok, err)
		}
	}
}

// exactToken builds a valid token of exactly n bytes.
func exactToken(t *testing.T, n int) string {
	t.Helper()
	priv, kid := key(t)
	for sp := 0; sp < 4; sp++ {
		h := `{"alg":"RS256",` + strings.Repeat(" ", sp) + `"kid":"` + kid + `"}`
		for pad := 0; pad < n; pad++ {
			p := `{"role":"anon","exp":1900000000,"pad":"` + strings.Repeat("a", pad) + `"}`
			l := len(enc(h)) + 1 + len(enc(p)) + 1 + 342
			if l == n {
				return signRaw(t, priv, h, p)
			}
			if l > n {
				break
			}
		}
	}
	t.Fatalf("no token of %d bytes", n)
	return ""
}

func TestVerify_SizeCapBoundary(t *testing.T) {
	ks := keys(t, "anon")
	at := exactToken(t, maxToken)
	if len(at) != 8192 {
		t.Fatalf("len %d", len(at))
	}
	if _, _, err := Verify(at, ks, now); err != nil {
		t.Fatalf("8192 bytes: %v", err)
	}
	over := exactToken(t, maxToken+1)
	wantErr(t, over, ks, ErrMalformed)
	// The cap is checked first: an oversize string of garbage is ErrMalformed
	// without being split or decoded.
	huge := strings.Repeat(".", 1<<20)
	allocs := testing.AllocsPerRun(10, func() { _, _, _ = Verify(huge, ks, now) })
	if allocs != 0 {
		t.Fatalf("oversize input allocated %v times", allocs)
	}
}

func TestVerify_NoGoroutineBoundedAllocs(t *testing.T) {
	ks := keys(t, "anon")
	tok := exactToken(t, maxToken)
	before := runtime.NumGoroutine()
	allocs := testing.AllocsPerRun(20, func() {
		if _, _, err := Verify(tok, ks, now); err != nil {
			t.Fatal(err)
		}
	})
	if runtime.NumGoroutine() > before { // one ending elsewhere meanwhile is no failure
		t.Fatalf("goroutines %d -> %d", before, runtime.NumGoroutine())
	}
	if allocs > 400 {
		t.Fatalf("allocs per Verify of a max-size token: %v", allocs)
	}
	t.Logf("allocs per max-size Verify: %v", allocs)
}

func TestCheckRole_Shapes(t *testing.T) {
	for _, r := range []struct {
		class Class
		role  string
		roles []string
		ok    bool
	}{
		{"anon", "anon", []string{"anon"}, true},
		{"anon", "authenticated", []string{"authenticated"}, false},
		{"service_role", "anon", nil, false},
		{"service_role", "service_role", []string{}, true},
		{"", "anon", []string{"anon"}, false},
		{"", "", nil, false},
		{"Anon", "anon", nil, false},
		{"ANON", "ANON", []string{"ANON"}, false},
		{"issuer", "", []string{""}, false},
		{"issuer", "authenticated", []string{}, false},
		{"issuer", "authenticated", []string{"Authenticated"}, false},
		{"issuer", "authenticated ", []string{"authenticated"}, false},
		{"issuer", "postgres", []string{"postgres"}, false},
		{"issuer", "authenticator", []string{"authenticator"}, false},
		{"issuer", "pg_read_server_files", []string{"pg_read_server_files"}, false},
		{"issuer", "supabase_x", []string{"supabase_x"}, false},
		{"issuer", "supapace_x", []string{"supapace_x"}, false},
		{"issuer", "dashboard_user", []string{"dashboard_user"}, false},
		// Exact-case, exact-bytes custom names pass only when listed; Postgres
		// matches role names exactly, so these are distinct roles there too.
		{"issuer", "ANON", []string{"ANON"}, true},
		{"issuer", "Service_Role", []string{"Service_Role"}, true},
	} {
		err := CheckRole(Key{KID: "k", Class: r.class}, Claims{Role: r.role}, r.roles)
		if (err == nil) != r.ok {
			t.Errorf("%q/%q in %q: %v", r.class, r.role, r.roles, err)
		}
	}
}

// The nine explicit supabase_* and supapace_backup names are also covered by
// the supabase_ and supapace_ prefix rules, so no path through
// ForbiddenUserRole tells the entries from the prefixes. They stay in the set
// on purpose and are checked here by membership.
func TestForbiddenUserRole_ExplicitSet(t *testing.T) {
	// Each named role of the set must be in the explicit list, not only
	// caught by a prefix, so that a prefix change cannot silently drop it.
	for _, r := range []string{
		"anon", "service_role", "authenticator", "dashboard_user", "pgbouncer", "postgres",
		"supabase_admin", "supabase_auth_admin", "supabase_etl_admin", "supabase_privileged_role",
		"supabase_read_only_user", "supabase_replication_admin", "supabase_storage_admin",
		"supabase_realtime_admin", "supapace_backup",
	} {
		if !forbidden[r] {
			t.Errorf("%q not in the explicit set", r)
		}
	}
	if len(forbidden) != 15 {
		t.Errorf("explicit set has %d names", len(forbidden))
	}
}

func TestParseJWKS_Members(t *testing.T) {
	n := modulus(2048)
	one := func(member string) string {
		return `{"keys":[{"kty":"RSA","kid":"a","n":"` + n + `","e":"AQAB"` + member + `}]}`
	}
	for _, m := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, err := ParseJWKS([]byte(one(`,"`+m+`":"AQAB"`)), "issuer"); !errors.Is(err, ErrKey) {
			t.Errorf("private %s: %v", m, err)
		}
	}
	for name, doc := range map[string]string{
		"kty number": `{"keys":[{"kty":1,"kid":"a","n":"` + n + `","e":"AQAB"}]}`,
		"kid number": `{"keys":[{"kty":"RSA","kid":1,"n":"` + n + `","e":"AQAB"}]}`,
		"n array":    `{"keys":[{"kty":"RSA","kid":"a","n":["` + n + `"],"e":"AQAB"}]}`,
		"use null":   one(`,"use":null`),
		"key string": `{"keys":["x"]}`,
	} {
		if _, err := ParseJWKS([]byte(doc), "issuer"); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"kty rsa":     `{"keys":[{"kty":"rsa","kid":"a","n":"` + n + `","e":"AQAB"}]}`,
		"n padded":    `{"keys":[{"kty":"RSA","kid":"a","n":"` + n + `=","e":"AQAB"}]}`,
		"n std alpha": `{"keys":[{"kty":"RSA","kid":"a","n":"` + strings.NewReplacer("-", "+", "_", "/").Replace(modulusWithURLChars()) + `","e":"AQAB"}]}`,
		"no n":        `{"keys":[{"kty":"RSA","kid":"a","e":"AQAB"}]}`,
		"no e":        `{"keys":[{"kty":"RSA","kid":"a","n":"` + n + `"}]}`,
	} {
		if _, err := ParseJWKS([]byte(doc), "issuer"); !errors.Is(err, ErrKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseJWKS([]byte(one("")), "admin"); !errors.Is(err, ErrKey) {
		t.Errorf("bad class: %v", err)
	}
	if _, err := ParseJWKS([]byte(one("")), ""); !errors.Is(err, ErrKey) {
		t.Errorf("empty class: %v", err)
	}
}

// modulusWithURLChars returns a 2048-bit odd modulus whose encoding contains
// '-' or '_'.
func modulusWithURLChars() string {
	for i := 0; ; i++ {
		b := make([]byte, 256)
		b[0], b[255] = 0x80|byte(i), 0xff
		for j := 1; j < 255; j++ {
			b[j] = byte(i + j)
		}
		if s := b64.EncodeToString(b); strings.ContainsAny(s, "-_") {
			return s
		}
	}
}

func TestMarshalJWKS_MinimalEncoding(t *testing.T) {
	priv, kid := key(t)
	b, err := MarshalJWKS([]Key{{KID: kid, Class: "anon", Pub: &priv.PublicKey}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"e":"AQAB"`) || strings.Contains(string(b), `"n":"AA`) {
		t.Fatalf("jwks %s", b)
	}
	if b2, err := MarshalJWKS(nil); err != nil || string(b2) != `{"keys":[]}` {
		t.Fatalf("empty: %s %v", b2, err)
	}
}

// addN returns sig + N as a big-endian byte string (a value congruent to sig
// modulo N, one byte longer or out of range).
func addN(sig []byte, priv *rsa.PrivateKey) []byte {
	var s = new(big.Int).SetBytes(sig)
	return s.Add(s, priv.N).Bytes()
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func TestForbiddenUserRole_ExactCase(t *testing.T) {
	// Postgres role names are case-sensitive; these are other roles.
	for _, r := range []string{"Anon", "SERVICE_ROLE", "Postgres", "PG_monitor", "Pg_monitor", "SUPABASE_ADMIN", "Supapace_backup", "PgBouncer"} {
		if ForbiddenUserRole(r) {
			t.Errorf("%q forbidden", r)
		}
	}
}

func TestVerify_RejectsOutsideAlphabet(t *testing.T) {
	priv, kid := key(t)
	tok, err := Sign(priv, kid, map[string]any{"role": "anon", "exp": now.Unix() + 60})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"\n", "\r", " ", "\t", "=", "+", "/", "\x00", "\xff", "%"} {
		for _, i := range []int{0, 5, strings.IndexByte(tok, '.') + 3, len(tok)} {
			wantErr(t, tok[:i]+c+tok[i:], keys(t, "anon"), ErrMalformed)
		}
	}
}

func TestVerify_NestingLimit(t *testing.T) {
	priv, _ := key(t)
	nest := func(d int) string {
		return `{"role":"anon","exp":1900000000,"x":` + strings.Repeat("[", d) + strings.Repeat("]", d) + `}`
	}
	// The payload object is level 1; 63 arrays inside it reach the limit.
	if _, _, err := Verify(signRaw(t, priv, hdr(t), nest(maxDepth-1)), keys(t, "anon"), now); err != nil {
		t.Fatalf("depth %d: %v", maxDepth, err)
	}
	wantErr(t, signRaw(t, priv, hdr(t), nest(maxDepth)), keys(t, "anon"), ErrMalformed)
}

func TestParseJWKS_Bounds(t *testing.T) {
	n := modulus(2048)
	good := `{"keys":[{"kty":"RSA","kid":"a","n":"` + n + `","e":"AQAB"}]}`
	pad := `,"x":"` + strings.Repeat("a", maxJWKS-len(good)-7) + `"`
	at := good[:len(good)-1] + pad + `}`
	if len(at) != maxJWKS {
		t.Fatalf("len %d", len(at))
	}
	if _, err := ParseJWKS([]byte(at), "issuer"); err != nil {
		t.Fatalf("at limit: %v", err)
	}
	if _, err := ParseJWKS([]byte(at[:len(at)-1]+" }"), "issuer"); !errors.Is(err, ErrMalformed) {
		t.Fatalf("one over: %v", err)
	}
	start := time.Now()
	for _, doc := range []string{
		strings.Repeat("[", 1<<20),
		`{"keys":` + strings.Repeat("[", 30000) + strings.Repeat("]", 30000) + `}`,
		`{"keys":[{"kty":"RSA","kid":"a","n":"` + n + `","e":"AQAB","x":` + strings.Repeat(`{"a":`, maxDepth) + `1` + strings.Repeat("}", maxDepth) + `}]}`,
	} {
		if _, err := ParseJWKS([]byte(doc), "issuer"); !errors.Is(err, ErrMalformed) {
			t.Errorf("%d bytes: %v", len(doc), err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestParseJWKS_SkipsForeignKeys(t *testing.T) {
	n, n2 := modulus(2048), modulus(3072)
	rsaKey := func(kid, extra string) string {
		return `{"kty":"RSA","kid":"` + kid + `","n":"` + n + `","e":"AQAB"` + extra + `}`
	}
	ec := `{"kty":"EC","kid":"e","crv":"P-256","x":"AA","y":"AA"}`
	set := func(ks ...string) []byte { return []byte(`{"keys":[` + strings.Join(ks, ",") + `]}`) }
	got := func(b []byte) []string {
		t.Helper()
		ks, err := ParseJWKS(b, "issuer")
		if err != nil {
			t.Fatalf("%s: %v", b, err)
		}
		var ids []string
		for _, k := range ks {
			ids = append(ids, k.KID)
		}
		return ids
	}
	if ids := got(set(ec, rsaKey("enc", `,"use":"enc"`), rsaKey("ok", `,"use":"sig","alg":"RS256"`))); len(ids) != 1 || ids[0] != "ok" {
		t.Fatalf("mixed set: %v", ids)
	}
	// Skipped entries are not checked for kid, bounds or duplicates.
	for name, b := range map[string][]byte{
		"alg RS512":           set(rsaKey("x", `,"alg":"RS512"`), rsaKey("ok", "")),
		"kty lower case":      set(`{"kty":"rsa","kid":"x","n":"`+n+`","e":"AQAB"}`, rsaKey("ok", "")),
		"skipped without kid": set(`{"kty":"EC","crv":"P-256"}`, rsaKey("ok", "")),
		"skipped shares kid":  set(`{"kty":"EC","kid":"ok"}`, rsaKey("ok", "")),
		"skipped small":       set(`{"kty":"RSA","kid":"x","use":"enc","n":"`+modulus(1024)+`","e":"Aw"}`, rsaKey("ok", "")),
		"no kty":              set(`{"kid":"x","n":"`+n+`","e":"AQAB"}`, rsaKey("ok", "")),
	} {
		if ids := got(b); len(ids) != 1 || ids[0] != "ok" {
			t.Errorf("%s: %v", name, ids)
		}
	}
	two := `{"kty":"RSA","kid":"b","n":"` + n2 + `","e":"AQAB"}`
	if ids := got(set(rsaKey("ok", ""), ec, two)); len(ids) != 2 || ids[0] != "ok" || ids[1] != "b" {
		t.Fatalf("order: %v", ids)
	}
	even := new(big.Int).Lsh(big.NewInt(1), 2047)
	for name, c := range map[string]struct {
		b    []byte
		want error
	}{
		"only skipped":       {set(ec, rsaKey("enc", `,"use":"enc"`)), ErrKey},
		"usable private":     {set(ec, rsaKey("ok", `,"qi":"AQAB"`)), ErrKey},
		"usable small":       {set(ec, `{"kty":"RSA","kid":"s","n":"`+modulus(1024)+`","e":"AQAB"}`), ErrKey},
		"usable even":        {set(ec, `{"kty":"RSA","kid":"s","n":"`+b64.EncodeToString(even.Bytes())+`","e":"AQAB"}`), ErrKey},
		"usable e=3":         {set(ec, `{"kty":"RSA","kid":"s","n":"`+n+`","e":"Aw"}`), ErrKey},
		"usable non-minimal": {set(ec, `{"kty":"RSA","kid":"s","n":"`+leadZero(n)+`","e":"AQAB"}`), ErrKey},
		"skipped private":    {set(rsaKey("enc", `,"use":"enc","d":"AQAB"`), rsaKey("ok", "")), ErrKey},
		"skipped secret":     {set(`{"kty":"oct","kid":"o","k":"AQAB"}`, rsaKey("ok", "")), ErrKey},
		"usable dup kid":     {set(rsaKey("ok", ""), ec, `{"kty":"RSA","kid":"ok","n":"`+n2+`","e":"AQAB"}`), ErrKey},
		"usable no kid":      {set(ec, `{"kty":"RSA","n":"`+n+`","e":"AQAB"}`), ErrNoKID},
		"usable empty kid":   {set(ec, rsaKey("", "")), ErrNoKID},
		"skipped kid type":   {set(`{"kty":"EC","kid":1}`, rsaKey("ok", "")), ErrMalformed},
		"skipped use type":   {set(`{"kty":"EC","use":["sig"]}`, rsaKey("ok", "")), ErrMalformed},
		"skipped kty type":   {set(`{"kty":null}`, rsaKey("ok", "")), ErrMalformed},
		"usable e type":      {set(`{"kty":"RSA","kid":"a","n":"` + n + `","e":65537}`), ErrMalformed},
		"usable alg type":    {set(rsaKey("ok", `,"alg":true`)), ErrMalformed},
		"usable n with line": {set(`{"kty":"RSA","kid":"a","n":"` + n[:40] + `\n` + n[40:] + `","e":"AQAB"}`), ErrKey},
	} {
		if _, err := ParseJWKS(c.b, "issuer"); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

func TestKeyFromJWK_RejectsEvenAndOutsideAlphabet(t *testing.T) {
	even := new(big.Int).Lsh(big.NewInt(1), 2047)
	even.SetBit(even, 1, 1)
	if _, err := KeyFromJWK("k", "issuer", b64.EncodeToString(even.Bytes()), "AQAB"); !errors.Is(err, ErrKey) {
		t.Errorf("even modulus: %v", err)
	}
	n := modulus(2048)
	for _, c := range []string{"\n", "\r", "\r\n", " ", "\t", "=", "+", "/", "."} {
		if _, err := KeyFromJWK("k", "issuer", n[:30]+c+n[30:], "AQAB"); !errors.Is(err, ErrKey) {
			t.Errorf("n with %q: %v", c, err)
		}
		if _, err := KeyFromJWK("k", "issuer", n, "AQ"+c+"AB"); !errors.Is(err, ErrKey) {
			t.Errorf("e with %q: %v", c, err)
		}
	}
}

func TestMarshalJWKS_RefusesBadKeys(t *testing.T) {
	priv, kid := key(t)
	good := Key{KID: kid, Class: "anon", Pub: &priv.PublicKey}
	small := Key{KID: "s", Class: "issuer", Pub: &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 1023, 1), E: pubE}}
	even := Key{KID: "v", Class: "issuer", Pub: &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2047), E: pubE}}
	e3 := Key{KID: "t", Class: "issuer", Pub: &rsa.PublicKey{N: priv.N, E: 3}}
	for name, ks := range map[string][]Key{
		"duplicate kid": {good, {KID: kid, Class: "service_role", Pub: &priv.PublicKey}},
		"nil pub":       {good, {KID: "n", Class: "issuer"}},
		"small":         {good, small},
		"even":          {even},
		"e=3":           {e3},
	} {
		if _, err := MarshalJWKS(ks); !errors.Is(err, ErrKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := MarshalJWKS([]Key{good, {KID: "", Pub: &priv.PublicKey}}); !errors.Is(err, ErrNoKID) {
		t.Errorf("empty kid: %v", err)
	}
}

// leadZero re-encodes a base64url integer with one leading zero octet.
func leadZero(v string) string {
	raw, err := b64.DecodeString(v)
	if err != nil {
		panic(err)
	}
	return b64.EncodeToString(append([]byte{0}, raw...))
}
