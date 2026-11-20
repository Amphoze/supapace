package main

import (
	"crypto/x509"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
)

const (
	tIss      = "https://issuer.test"
	tClient   = "dashboard"
	tRedirect = "https://sign-in.studio.test/-/auth/callback"
)

// tIssuerStub is an issuer stand-in with a fresh key, its key set as the
// gateway would parse it, and the subject "user-1".
func tIssuerStub(t *testing.T) (*issuerStub, []jwtx.Key) {
	t.Helper()
	priv, kid, err := jwtx.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "key.der"), string(der))
	write(t, filepath.Join(dir, "subject"), "user-1\n")
	s, err := newIssuerStub(filepath.Join(dir, "key.der"), tIss, tClient, filepath.Join(dir, "subject"))
	if err != nil {
		t.Fatal(err)
	}
	set, err := jwtx.MarshalJWKS([]jwtx.Key{{KID: kid, Class: jwtx.ClassDashboard, Pub: &priv.PublicKey}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwtx.ParseDashboardJWKS(set)
	if err != nil {
		t.Fatal(err)
	}
	return s, keys
}

func tAuthorize(redirect, state string, nonce ...string) string {
	n := "n-1"
	if len(nonce) > 0 {
		n = nonce[0]
	}
	return "https://issuer.test/authorize?" + url.Values{"response_type": {"id_token"}, "response_mode": {"form_post"},
		"client_id": {tClient}, "redirect_uri": {redirect}, "scope": {"openid"}, "nonce": {n}, "state": {state}}.Encode()
}

func TestIssuerStub_FormPost(t *testing.T) {
	s, keys := tIssuerStub(t)
	state := "v1._.AAECAwQFBgc.0.Lw"
	r := tReq(s, "GET", tAuthorize(tRedirect, state), nil)
	page := tBody(t, r)
	if r.StatusCode != 200 {
		t.Fatalf("authorize: %d %q", r.StatusCode, page)
	}
	action, fields := tForm(t, page)
	if action = html.UnescapeString(action); action != tRedirect {
		t.Errorf("the form posts to %q, want the redirect URI given, %q", action, tRedirect)
	}
	if !strings.Contains(page, `method="post"`) {
		t.Errorf("the form is not a post: %q", page)
	}
	if got := fields.Get("state"); got != state {
		t.Errorf("state %q, want it unchanged, %q", got, state)
	}
	// Exactly one further field beside the two the callback reads.
	extra := []string{}
	for k := range fields {
		if k != "id_token" && k != "state" {
			extra = append(extra, k)
		}
	}
	if len(extra) != 1 || fields.Get(extra[0]) == "" {
		t.Errorf("fields beside id_token and state: %q, want exactly one with a value", extra)
	}
	c, err := jwtx.VerifyID(fields.Get("id_token"), keys, jwtx.IDCheck{Issuer: tIss, ClientID: tClient, Nonce: "n-1"}, time.Now())
	if err != nil || c.Sub != "user-1" {
		t.Fatalf("the ID token: %+v %v, want it to verify for user-1", c, err)
	}
	if c.Exp-c.Iat != 300 {
		t.Errorf("the ID token lives %d s, want 300", c.Exp-c.Iat)
	}
	// Control: the token is bound to the nonce the authorisation request sent.
	if _, err := jwtx.VerifyID(fields.Get("id_token"), keys, jwtx.IDCheck{Issuer: tIss, ClientID: tClient, Nonce: "n-2"}, time.Now()); err != jwtx.ErrNonce {
		t.Errorf("another nonce: %v, want ErrNonce", err)
	}

	// Without the cookie hold=1 the page submits itself; with it the page has
	// no script and waits for its button.
	if !strings.Contains(page, "<script>document.forms[0].submit()</script>") {
		t.Errorf("without hold=1 the page does not submit itself: %q", page)
	}
	held := tBody(t, tReq(s, "GET", tAuthorize(tRedirect, state), nil, "Cookie", "a=b; hold=1"))
	if strings.Contains(held, "submit()") || !strings.Contains(held, "<button>") {
		t.Errorf("with hold=1 the page is %q, want a button and no submitting script", held)
	}
	if a, f := tForm(t, held); html.UnescapeString(a) != tRedirect || f.Get("state") != state || f.Get("id_token") == "" {
		t.Errorf("the held page's form: %q %v", a, f)
	}
	// Control: another value of the cookie does not hold.
	if p := tBody(t, tReq(s, "GET", tAuthorize(tRedirect, state), nil, "Cookie", "hold=2")); !strings.Contains(p, "submit()") {
		t.Errorf("hold=2 held the page")
	}

	// The subject is read at each request: the test sets it beforehand.
	write(t, s.subjectFile, "user-2")
	_, f2 := tForm(t, tBody(t, tReq(s, "GET", tAuthorize(tRedirect, state, "n-3"), nil)))
	if c, err := jwtx.VerifyID(f2.Get("id_token"), keys, jwtx.IDCheck{Issuer: tIss, ClientID: tClient, Nonce: "n-3"}, time.Now()); err != nil || c.Sub != "user-2" {
		t.Errorf("after the subject file changed: %+v %v", c, err)
	}
}

func TestIssuerStub_Refusals(t *testing.T) {
	s, _ := tIssuerStub(t)
	ok := url.Values{"response_type": {"id_token"}, "response_mode": {"form_post"}, "client_id": {tClient},
		"redirect_uri": {tRedirect}, "nonce": {"n"}, "state": {"s"}}
	for name, change := range map[string][2]string{
		"response_type":      {"response_type", "code"},
		"response_mode":      {"response_mode", "query"},
		"client_id":          {"client_id", "other"},
		"nonce":              {"nonce", ""},
		"redirect_uri http":  {"redirect_uri", "http://sign-in.studio.test/-/auth/callback"},
		"redirect_uri empty": {"redirect_uri", ""},
		"redirect_uri host":  {"redirect_uri", "https:///x"},
	} {
		q := url.Values{}
		for k, v := range ok {
			q[k] = v
		}
		q.Set(change[0], change[1])
		if r := tReq(s, "GET", "https://issuer.test/authorize?"+q.Encode(), nil); r.StatusCode != 400 {
			t.Errorf("%s: %d, want 400", name, r.StatusCode)
		}
	}
	if r := tReq(s, "GET", "https://issuer.test/authorize?"+ok.Encode(), nil); r.StatusCode != 200 {
		t.Fatalf("control: %d", r.StatusCode)
	}
	if r := tReq(s, "POST", "https://issuer.test/authorize?"+ok.Encode(), nil); r.StatusCode != 405 {
		t.Errorf("POST: %d, want 405", r.StatusCode)
	}
	if r := tReq(s, "GET", "https://issuer.test/other", nil); r.StatusCode != 404 {
		t.Errorf("another path: %d, want 404", r.StatusCode)
	}
	write(t, s.subjectFile, "\n")
	if r := tReq(s, "GET", "https://issuer.test/authorize?"+ok.Encode(), nil); r.StatusCode != 409 {
		t.Errorf("no subject set: %d, want 409", r.StatusCode)
	}
	os.Remove(s.subjectFile)
	if r := tReq(s, "GET", "https://issuer.test/authorize?"+ok.Encode(), nil); r.StatusCode != 409 {
		t.Errorf("no subject file: %d, want 409", r.StatusCode)
	}
}

func TestIssuerStub_Usage(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "k"), "not a key")
	for _, args := range [][]string{
		{"issuer"},
		{"issuer", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k", "--signing-key", "s", "--issuer", tIss, "--client-id", tClient},
		{"issuer", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k", "--signing-key", "s", "--issuer", tIss, "--subject-file", "f"},
		{"issuer", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k", "--signing-key", "s", "--client-id", tClient, "--subject-file", "f"},
		{"issuer", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k", "--signing-key", "s", "--issuer", tIss, "--client-id", tClient, "--subject-file", "f", "extra"},
	} {
		if code, out, _ := runOut(args...); code != 2 || out != "" {
			t.Errorf("%q: exit %d, stdout %q", args, code, out)
		}
	}
	// A signing key that is not a PKCS #8 RSA key is an error, not a usage error.
	if code, _, errs := runOut("issuer", "--listen", "127.0.0.1:0", "--cert", "c", "--key", "k", "--signing-key", filepath.Join(dir, "k"),
		"--issuer", tIss, "--client-id", tClient, "--subject-file", "f"); code != 1 || !strings.Contains(errs, "signing key") {
		t.Errorf("a bad signing key: exit %d, %q", code, errs)
	}
}
