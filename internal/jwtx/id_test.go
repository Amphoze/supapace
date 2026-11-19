package jwtx

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var idWant = IDCheck{Issuer: "https://issuer.test", ClientID: "client-1", Nonce: "6oZqdX5MOLq_qBJ8vppAnT4fk6AP8UiP9zX8-Rev_9A"}

func idClaims() map[string]any {
	return map[string]any{
		"iss": idWant.Issuer, "aud": idWant.ClientID, "sub": "user-1", "name": "Ada",
		"nonce": idWant.Nonce, "iat": now.Unix(), "exp": now.Unix() + 300,
	}
}

func dashKeys(t *testing.T) []Key { return keys(t, ClassDashboard) }

func idToken(t *testing.T, mod func(map[string]any)) string {
	t.Helper()
	c := idClaims()
	if mod != nil {
		mod(c)
	}
	priv, kid := key(t)
	tok, err := Sign(priv, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerifyID_Accepts(t *testing.T) {
	for name, mod := range map[string]func(map[string]any){
		"audience string":             nil,
		"audience array with azp":     func(c map[string]any) { c["aud"] = []string{"other", idWant.ClientID}; c["azp"] = idWant.ClientID },
		"audience array of one":       func(c map[string]any) { c["aud"] = []string{idWant.ClientID} },
		"audience array of one, azp":  func(c map[string]any) { c["aud"] = []string{idWant.ClientID}; c["azp"] = idWant.ClientID },
		"audience string, same azp":   func(c map[string]any) { c["azp"] = idWant.ClientID },
		"no name":                     func(c map[string]any) { delete(c, "name") },
		"exp 59 s ago":                func(c map[string]any) { c["exp"] = now.Unix() - 59 },
		"iat 60 s ahead":              func(c map[string]any) { c["iat"] = now.Unix() + 60 },
		"iat 600 s ago":               func(c map[string]any) { c["iat"] = now.Unix() - 600 },
		"nbf 60 s ahead":              func(c map[string]any) { c["nbf"] = now.Unix() + 60 },
		"other members ignored":       func(c map[string]any) { c["email"] = "x"; c["groups"] = []string{"a"} },
		"sub of 255 printable":        func(c map[string]any) { c["sub"] = strings.Repeat("~", 255) },
		"role is not asked for, any":  func(c map[string]any) { c["role"] = "service_role" },
		"name with markup, untrusted": func(c map[string]any) { c["name"] = "<b>x</b>" },
	} {
		tok := idToken(t, mod)
		got, err := VerifyID(tok, dashKeys(t), idWant, now)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		c := idClaims()
		if mod != nil {
			mod(c)
		}
		wantName, _ := c["name"].(string)
		if got.Sub != c["sub"] || got.Name != wantName || got.Iat != c["iat"] || got.Exp != c["exp"] {
			t.Errorf("%s: claims %+v", name, got)
		}
	}
}

func TestVerifyID_Refusals(t *testing.T) {
	priv, kid := key(t)
	dk := dashKeys(t)
	cases := []struct {
		name string
		tok  string
		ks   []Key
		want error
	}{
		{"control", idToken(t, nil), dk, nil},
		{"wrong nonce", idToken(t, func(c map[string]any) { c["nonce"] = "x" + idWant.Nonce }), dk, ErrNonce},
		{"nonce prefix", idToken(t, func(c map[string]any) { c["nonce"] = idWant.Nonce[:42] }), dk, ErrNonce},
		{"nonce of the same length", idToken(t, func(c map[string]any) { c["nonce"] = idWant.Nonce[:42] + "B" }), dk, ErrNonce},
		{"no nonce", idToken(t, func(c map[string]any) { delete(c, "nonce") }), dk, ErrNonce},
		{"nonce not a string", idToken(t, func(c map[string]any) { c["nonce"] = 1 }), dk, ErrMalformed},
		{"wrong nonce and no sub", idToken(t, func(c map[string]any) { c["nonce"] = "x"; delete(c, "sub") }), dk, ErrClaim},
		{"wrong nonce and a sub of 256", idToken(t, func(c map[string]any) { c["nonce"] = "x"; c["sub"] = strings.Repeat("a", 256) }), dk, ErrClaim},
		{"no nonce and a name not a string", idToken(t, func(c map[string]any) { delete(c, "nonce"); c["name"] = 1 }), dk, ErrMalformed},
		{"wrong audience", idToken(t, func(c map[string]any) { c["aud"] = "client-2" }), dk, ErrClaim},
		{"no audience", idToken(t, func(c map[string]any) { delete(c, "aud") }), dk, ErrClaim},
		{"audience array of two without azp", idToken(t, func(c map[string]any) { c["aud"] = []string{idWant.ClientID, "other"} }), dk, ErrClaim},
		{"audience array of one, wrong azp", idToken(t, func(c map[string]any) { c["aud"] = []string{idWant.ClientID}; c["azp"] = "x" }), dk, ErrClaim},
		{"audience array of one, another client", idToken(t, func(c map[string]any) { c["aud"] = []string{"other"} }), dk, ErrClaim},
		{"audience array without the client", idToken(t, func(c map[string]any) { c["aud"] = []string{"a", "b"}; c["azp"] = idWant.ClientID }), dk, ErrClaim},
		{"audience array empty", idToken(t, func(c map[string]any) { c["aud"] = []string{}; c["azp"] = idWant.ClientID }), dk, ErrClaim},
		{"audience array of numbers", idToken(t, func(c map[string]any) { c["aud"] = []int{1}; c["azp"] = idWant.ClientID }), dk, ErrMalformed},
		{"audience a number", idToken(t, func(c map[string]any) { c["aud"] = 1 }), dk, ErrMalformed},
		{"wrong authorised party", idToken(t, func(c map[string]any) { c["aud"] = []string{idWant.ClientID, "x"}; c["azp"] = "x" }), dk, ErrClaim},
		{"wrong authorised party, string audience", idToken(t, func(c map[string]any) { c["azp"] = "x" }), dk, ErrClaim},
		{"authorised party not a string", idToken(t, func(c map[string]any) { c["azp"] = 1 }), dk, ErrMalformed},
		{"wrong issuer", idToken(t, func(c map[string]any) { c["iss"] = idWant.Issuer + "/" }), dk, ErrClaim},
		{"issuer differs in case", idToken(t, func(c map[string]any) { c["iss"] = strings.ToUpper(idWant.Issuer) }), dk, ErrClaim},
		{"no issuer", idToken(t, func(c map[string]any) { delete(c, "iss") }), dk, ErrClaim},
		{"expired past the leeway", idToken(t, func(c map[string]any) { c["exp"] = now.Unix() - 60 }), dk, ErrExpired},
		{"no exp", idToken(t, func(c map[string]any) { delete(c, "exp") }), dk, ErrExpired},
		{"issued more than ten minutes ago", idToken(t, func(c map[string]any) { c["iat"] = now.Unix() - 601 }), dk, ErrExpired},
		{"no iat", idToken(t, func(c map[string]any) { delete(c, "iat") }), dk, ErrExpired},
		{"iat ahead past the leeway", idToken(t, func(c map[string]any) { c["iat"] = now.Unix() + 61 }), dk, ErrNotYetValid},
		{"nbf ahead past the leeway", idToken(t, func(c map[string]any) { c["nbf"] = now.Unix() + 61 }), dk, ErrNotYetValid},
		{"iat a string", idToken(t, func(c map[string]any) { c["iat"] = "1" }), dk, ErrMalformed},
		{"no sub", idToken(t, func(c map[string]any) { delete(c, "sub") }), dk, ErrClaim},
		{"empty sub", idToken(t, func(c map[string]any) { c["sub"] = "" }), dk, ErrClaim},
		{"sub of 256", idToken(t, func(c map[string]any) { c["sub"] = strings.Repeat("a", 256) }), dk, ErrClaim},
		{"sub not ascii", idToken(t, func(c map[string]any) { c["sub"] = "usér" }), dk, ErrClaim},
		{"sub with a control", idToken(t, func(c map[string]any) { c["sub"] = "a\nb" }), dk, ErrClaim},
		{"sub a number", idToken(t, func(c map[string]any) { c["sub"] = 1 }), dk, ErrMalformed},
		{"name a number", idToken(t, func(c map[string]any) { c["name"] = 1 }), dk, ErrMalformed},
		{"unknown kid", idToken(t, nil), []Key{{KID: "other", Class: ClassDashboard, Pub: &priv.PublicKey}}, ErrUnknownKID},
		{"key of class issuer", idToken(t, nil), keys(t, "issuer"), ErrKey},
		{"key of class anon", idToken(t, nil), keys(t, "anon"), ErrKey},
		{"key of class service_role", idToken(t, nil), keys(t, "service_role"), ErrKey},
		{"another algorithm", signRaw(t, priv, `{"alg":"RS384","kid":"`+kid+`"}`, mustJSON(idClaims())), dk, ErrAlg},
		{"algorithm none", signRaw(t, priv, `{"alg":"none","kid":"`+kid+`"}`, mustJSON(idClaims())), dk, ErrAlg},
		{"crit", signRaw(t, priv, `{"alg":"RS256","kid":"`+kid+`","crit":["x"]}`, mustJSON(idClaims())), dk, ErrMalformed},
		{"duplicate member", signRaw(t, priv, hdr(t), `{"nonce":"x",`+mustJSON(idClaims())[1:]), dk, ErrDuplicateMember},
		{"duplicate header member", signRaw(t, priv, `{"alg":"RS256","alg":"RS256","kid":"`+kid+`"}`, mustJSON(idClaims())), dk, ErrDuplicateMember},
		{"duplicate member, one escaped", signRaw(t, priv, hdr(t), `{"\u006eonce":"x",`+mustJSON(idClaims())[1:]), dk, ErrDuplicateMember},
		{"nonce in other case only", idToken(t, func(c map[string]any) { c["Nonce"] = c["nonce"]; delete(c, "nonce") }), dk, ErrNonce},
		{"issuer in other case only", idToken(t, func(c map[string]any) { c["ISS"] = c["iss"]; delete(c, "iss") }), dk, ErrClaim},
		{"exp a fraction", idToken(t, func(c map[string]any) { c["exp"] = float64(now.Unix()) + 300.5 }), dk, ErrMalformed},
		{"bad signature", flipSig(idToken(t, nil)), dk, ErrSignature},
		{"oversize", strings.Repeat("a", 8<<10+1), dk, ErrMalformed},
	}
	for _, c := range cases {
		_, err := VerifyID(c.tok, c.ks, idWant, now)
		if !errors.Is(err, c.want) || (err == nil) != (c.want == nil) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
	// A check with an empty member accepts nothing, not even a token that
	// echoes the empty value.
	for _, w := range []IDCheck{{"", idWant.ClientID, idWant.Nonce}, {idWant.Issuer, "", idWant.Nonce}, {idWant.Issuer, idWant.ClientID, ""}} {
		tok := idToken(t, func(c map[string]any) { c["iss"], c["aud"], c["nonce"] = w.Issuer, w.ClientID, w.Nonce })
		if _, err := VerifyID(tok, dk, w, now); err == nil {
			t.Errorf("empty check %+v accepted", w)
		}
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestCheckRole_RefusesTheDashboardClass(t *testing.T) {
	k := Key{KID: "k", Class: ClassDashboard}
	all := []string{"authenticated", "editor", "anon", "service_role", "dashboard", "owner"}
	for _, role := range all {
		if err := CheckRole(k, Claims{Role: role}, all); !errors.Is(err, ErrRole) {
			t.Errorf("dashboard key, role %q: %v", role, err)
		}
	}
	// Control: the same roles under the as-built classes.
	if CheckRole(Key{Class: "issuer"}, Claims{Role: "editor"}, all) != nil ||
		CheckRole(Key{Class: "anon"}, Claims{Role: "anon"}, nil) != nil ||
		CheckRole(Key{Class: "service_role"}, Claims{Role: "service_role"}, nil) != nil {
		t.Fatal("control refused")
	}
}

// TestVerify_ProjectTokensUnchanged runs the project paths end to end — Verify
// then CheckRole — for each as-built class, and shows that a dashboard key
// gives a project nothing: its ID token is no project token and a project
// token is no ID token.
func TestVerify_ProjectTokensUnchanged(t *testing.T) {
	priv, kid := key(t)
	sign := func(c map[string]any) string {
		tok, err := Sign(priv, kid, c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	exp := now.Unix() + 60
	users := []string{"authenticated", "editor"}
	for _, c := range []struct {
		class Class
		role  string
		ok    bool
	}{
		{"anon", "anon", true}, {"anon", "service_role", false},
		{"service_role", "service_role", true}, {"service_role", "anon", false},
		{"issuer", "authenticated", true}, {"issuer", "editor", true}, {"issuer", "postgres", false},
		{ClassDashboard, "authenticated", false}, {ClassDashboard, "anon", false}, {ClassDashboard, "service_role", false},
	} {
		k, cl, err := Verify(sign(map[string]any{"role": c.role, "exp": exp}), keys(t, c.class), now)
		if err != nil {
			t.Fatalf("%s/%s: Verify %v", c.class, c.role, err)
		}
		if err := CheckRole(k, cl, users); (err == nil) != c.ok {
			t.Errorf("%s/%s: CheckRole %v", c.class, c.role, err)
		}
	}
	// A dashboard ID token has no role: the project path refuses it.
	if _, _, err := Verify(idToken(t, nil), dashKeys(t), now); !errors.Is(err, ErrNoRole) {
		t.Errorf("ID token on the project path: %v", err)
	}
	// A project token signed by a project key is refused by VerifyID.
	for _, class := range []Class{"anon", "service_role", "issuer"} {
		tok := idToken(t, func(c map[string]any) { c["role"] = string(class) })
		if _, err := VerifyID(tok, keys(t, class), idWant, now); !errors.Is(err, ErrKey) {
			t.Errorf("%s key on the ID path: %v", class, err)
		}
	}
}

func TestDashboardKeys_OnlyThroughTheirOwnConstructors(t *testing.T) {
	const e = "AQAB"
	n := modulus(2048)
	if _, err := KeyFromJWK("k", ClassDashboard, n, e); !errors.Is(err, ErrKey) {
		t.Errorf("KeyFromJWK dashboard: %v", err)
	}
	priv, kid := key(t)
	set, err := MarshalJWKS([]Key{{KID: kid, Class: "issuer", Pub: &priv.PublicKey}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJWKS(set, ClassDashboard); !errors.Is(err, ErrKey) {
		t.Errorf("ParseJWKS dashboard: %v", err)
	}
	// The dashboard constructors give dashboard keys...
	k, err := DashboardKeyFromJWK("k", n, e)
	if err != nil || k.Class != ClassDashboard || k.KID != "k" || k.Pub.N.BitLen() != 2048 {
		t.Fatalf("DashboardKeyFromJWK: %+v %v", k, err)
	}
	ks, err := ParseDashboardJWKS(set)
	if err != nil || len(ks) != 1 || ks[0].Class != ClassDashboard || ks[0].KID != kid {
		t.Fatalf("ParseDashboardJWKS: %+v %v", ks, err)
	}
	if _, err := VerifyID(idToken(t, nil), ks, idWant, now); err != nil {
		t.Fatalf("a parsed dashboard set verifies: %v", err)
	}
	// ...under every check of KeyFromJWK and ParseJWKS.
	for name, c := range map[string]struct {
		kid, n, e string
		want      error
	}{
		"short modulus":    {"k", modulus(2047), e, ErrKey},
		"long modulus":     {"k", modulus(4097), e, ErrKey},
		"exponent 3":       {"k", n, "Aw", ErrKey},
		"padded exponent":  {"k", n, "AAEAAQ", ErrKey},
		"leading zero":     {"k", leadZero(n), e, ErrKey},
		"even modulus":     {"k", n[:len(n)-1] + "A", e, ErrKey},
		"outside alphabet": {"k", n + "=", e, ErrKey},
		"empty kid":        {"", n, e, ErrNoKID},
	} {
		if _, err := DashboardKeyFromJWK(c.kid, c.n, c.e); !errors.Is(err, c.want) {
			t.Errorf("DashboardKeyFromJWK %s: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		set  string
		want error
	}{
		"empty set":        {`{"keys":[]}`, ErrKey},
		"private member":   {`{"keys":[{"kty":"RSA","kid":"k","n":"` + n + `","e":"AQAB","d":"x"}]}`, ErrKey},
		"duplicate kid":    {`{"keys":[{"kty":"RSA","kid":"k","n":"` + n + `","e":"AQAB"},{"kty":"RSA","kid":"k","n":"` + n + `","e":"AQAB"}]}`, ErrKey},
		"short modulus":    {`{"keys":[{"kty":"RSA","kid":"k","n":"` + modulus(1024) + `","e":"AQAB"}]}`, ErrKey},
		"duplicate member": {`{"keys":[],"keys":[]}`, ErrDuplicateMember},
		"oversize":         {`{"keys":[` + strings.Repeat(" ", 64<<10) + `]}`, ErrMalformed},
		"no kid":           {`{"keys":[{"kty":"RSA","n":"` + n + `","e":"AQAB"}]}`, ErrNoKID},
	} {
		if _, err := ParseDashboardJWKS([]byte(c.set)); !errors.Is(err, c.want) {
			t.Errorf("ParseDashboardJWKS %s: %v", name, err)
		}
	}
}

// FuzzVerifyID: no input panics, and nothing verifies without the key.
func FuzzVerifyID(f *testing.F) {
	priv, kid, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	good, _ := Sign(priv, kid, idClaims())
	f.Add(good)
	f.Add("")
	f.Add("a.b.c")
	ks := []Key{{KID: kid, Class: ClassDashboard, Pub: &priv.PublicKey}}
	f.Fuzz(func(t *testing.T, s string) {
		if _, err := VerifyID(s, ks, idWant, now); err == nil && s != good {
			t.Fatalf("verified a token that is not the seed")
		}
	})
}

// FuzzVerifyIDPayload signs arbitrary payloads so that the fuzzer reaches the
// claim checks behind the signature: none may panic.
func FuzzVerifyIDPayload(f *testing.F) {
	priv, kid, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(mustJSON(idClaims()))
	f.Add(`{"aud":["client-1"],"azp":"client-1"}`)
	ks := []Key{{KID: kid, Class: ClassDashboard, Pub: &priv.PublicKey}}
	hdr := `{"alg":"RS256","kid":"` + kid + `"}`
	f.Fuzz(func(t *testing.T, p string) {
		if len(p) > 4<<10 {
			return
		}
		tok := signRaw(t, priv, hdr, p)
		c, err := VerifyID(tok, ks, idWant, now)
		if err == nil && (c.Sub == "" || c.Exp <= now.Unix()-60) {
			t.Fatalf("accepted %q as %+v", p, c)
		}
	})
}

// flipSig changes one bit of a token's signature.
func flipSig(tok string) string {
	i := strings.LastIndexByte(tok, '.')
	sig, _ := base64.RawURLEncoding.DecodeString(tok[i+1:])
	sig[0] ^= 1
	return tok[:i+1] + base64.RawURLEncoding.EncodeToString(sig)
}

// TestVerifyID_DatesRequiredNearEpoch: a missing exp or iat is refused for
// being missing, not because zero happens to lie in the past.
func TestVerifyID_DatesRequiredNearEpoch(t *testing.T) {
	at := now.Add(-time.Duration(now.Unix()-30) * time.Second) // 30 s after the epoch
	mk := func(mod func(map[string]any)) string {
		return idToken(t, func(c map[string]any) { c["iat"], c["exp"] = int64(30), int64(330); mod(c) })
	}
	if _, err := VerifyID(mk(func(map[string]any) {}), dashKeys(t), idWant, at); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, m := range []string{"exp", "iat"} {
		if _, err := VerifyID(mk(func(c map[string]any) { delete(c, m) }), dashKeys(t), idWant, at); !errors.Is(err, ErrExpired) {
			t.Errorf("no %s: %v", m, err)
		}
	}
}
