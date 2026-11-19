package gateway

import (
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/routes"
)

// audToken is an issuer token of project A for authenticated with the given
// aud member; nil leaves the member out.
func audToken(t *testing.T, s signer, aud any) string {
	t.Helper()
	c := map[string]any{"role": "authenticated", "exp": time.Now().Unix() + 300}
	if aud != nil {
		c["aud"] = aud
	}
	tok, err := jwtx.Sign(s.priv, s.kid, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func withAud(aud []string) *routes.File {
	f := file(1, "active")
	p := f.Projects[refA]
	p.Aud = aud
	f.Projects[refA] = p
	return &f
}

func TestAud_IssuerTokenWithoutAListedAudienceRefused(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, withAud([]string{"app", "other"}))
	anon := a.anon.token(t, "anon")
	for _, c := range []struct {
		name   string
		aud    any
		status int
	}{
		{"no aud", nil, 401},
		{"unlisted string", "x", 401},
		{"unlisted list", []string{"x", "y"}, 401},
		{"empty list", []string{}, 401},
		{"case differs", "App", 401},
		{"non-string elements", []any{1, true, nil}, 401},
		{"number", 7, 401},
		{"object", map[string]any{"app": true}, 401},
		{"listed string", "app", 200},
		{"listed in a list", []string{"x", "other"}, 200},
		{"listed after a non-string", []any{1, "app"}, 200},
	} {
		r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
		tok := audToken(t, a.iss, c.aud)
		r.Header.Set("Authorization", "Bearer "+tok)
		code := ""
		if c.status == 401 {
			code = "invalid_token"
		}
		e.expect(t, c.name, r, c.status, code)
		if c.status == 200 && e.last(t).Header.Get("Authorization") != "Bearer "+tok {
			t.Errorf("%s: forwarded another token", c.name)
		}
	}
	// Control: without the member the same unlisted token is served.
	e = newEnv(t, active())
	r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Bearer "+audToken(t, a.iss, "x"))
	e.expect(t, "no audience list", r, 200, "")
	r = withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Bearer "+audToken(t, a.iss, nil))
	e.expect(t, "no audience list, no aud", r, 200, "")
}

func TestAud_PlatformKeysExempt(t *testing.T) {
	a, _, _ := keys()
	e := newEnv(t, withAud([]string{"app"}))
	anon, svc := a.anon.token(t, "anon"), a.svc.token(t, "service_role")
	e.expect(t, "anon apikey alone", withKey(req("GET", hostA, "/rest/v1/", nil), anon), 200, "")
	e.expect(t, "service apikey alone", withKey(req("GET", hostA, "/rest/v1/", nil), svc), 200, "")
	for name, bearer := range map[string]string{"anon bearer": anon, "service bearer": svc} {
		r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
		r.Header.Set("Authorization", "Bearer "+bearer)
		e.expect(t, name, r, 200, "")
	}
	// Control on the same entry: an issuer token without aud is refused.
	r := withKey(req("GET", hostA, "/rest/v1/", nil), anon)
	r.Header.Set("Authorization", "Bearer "+a.iss.token(t, "authenticated"))
	e.expect(t, "issuer bearer", r, 401, "invalid_token")
	// Project B has no list: its issuer tokens are not checked.
	_, b, _ := keys()
	r = withKey(req("GET", hostB, "/rest/v1/", nil), b.anon.token(t, "anon"))
	r.Header.Set("Authorization", "Bearer "+b.iss.token(t, "authenticated"))
	e.expect(t, "other project", r, 200, "")
}
