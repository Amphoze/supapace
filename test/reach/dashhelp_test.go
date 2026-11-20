package reach

// Helpers of the dashboard's tests that need no node: the test issuer's key
// and ID tokens, assertions signed with a chosen key, the browser harness's
// scenario, the fetch metadata a browser sends, and the path forms the tests
// send. Untagged, like helpers_test.go; their self-tests are in
// dashhelp_self_test.go. The helpers that need a node are in dashnode_test.go.

import (
	"crypto/ed25519"
	"crypto/rsa"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/dashtok"
	"github.com/Amphoze/supapace/internal/jwtx"
)

// dashClientID is the client id the test issuer is registered with.
const dashClientID = "dashboard"

// dashNewIssuer is a fresh key of the test issuer, its kid and its public key
// set, as `supapace dashboard issuer set --jwks` reads it.
func dashNewIssuer() (*rsa.PrivateKey, string, []byte, error) {
	priv, kid, err := jwtx.GenerateKey()
	if err != nil {
		return nil, "", nil, err
	}
	set, err := jwtx.MarshalJWKS([]jwtx.Key{{KID: kid, Class: jwtx.ClassDashboard, Pub: &priv.PublicKey}})
	return priv, kid, set, err
}

// dashIDToken is an ID token of issuer iss for the dashboard's client, for sub
// and nonce, issued at now and valid for five minutes.
func dashIDToken(priv *rsa.PrivateKey, kid, iss, sub, nonce string, now time.Time) (string, error) {
	return jwtx.Sign(priv, kid, map[string]any{"iss": iss, "aud": dashClientID, "sub": sub, "nonce": nonce,
		"iat": now.Unix(), "exp": now.Unix() + 300})
}

// dashAssert signs a with key — the node's own or any other — issued at now
// and expiring 30 s later, as the gateway mints one.
func dashAssert(key ed25519.PrivateKey, a dashtok.Assertion, now time.Time) (string, error) {
	a.Iat, a.Exp = now.Unix(), now.Unix()+30
	return dashtok.SignAssertion(key, a)
}

// dashScenario is one scenario of the browser harness
// (test/harness/browsers/run.mjs): its engine, its host map, the CA it trusts
// (the path in the container), its timeout, page script on (nil) or off, and
// its steps.
type dashScenario struct {
	Engine  string            `json:"engine"`
	Hosts   map[string]string `json:"hosts"`
	CA      string            `json:"ca,omitempty"`
	Timeout int               `json:"timeout_ms"`
	Script  *bool             `json:"script,omitempty"`
	Steps   []map[string]any  `json:"steps"`
}

// dashFetch sends what a browser's request from a page of origin carries:
// Sec-Fetch-Site same-origin; for a GET that accepts text/html a navigation
// (Sec-Fetch-Mode navigate, Sec-Fetch-Dest document, Sec-Fetch-User ?1),
// otherwise a fetch (Sec-Fetch-Mode cors, Sec-Fetch-Dest empty) with Origin
// on a method other than GET and HEAD; and the cookies given. A header the
// request already has is left as it is, so a test can send any other value.
type dashFetch struct {
	base    http.RoundTripper
	origin  string
	cookies []*http.Cookie
}

func (f dashFetch) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	set := func(name, value string) {
		if _, ok := r.Header[name]; !ok {
			r.Header.Set(name, value)
		}
	}
	set("Sec-Fetch-Site", "same-origin")
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
		set("Sec-Fetch-Mode", "navigate")
		set("Sec-Fetch-Dest", "document")
		set("Sec-Fetch-User", "?1")
	} else {
		set("Sec-Fetch-Mode", "cors")
		set("Sec-Fetch-Dest", "empty")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			set("Origin", f.origin)
		}
	}
	for _, c := range f.cookies {
		r.AddCookie(c)
	}
	return f.base.RoundTrip(r)
}

// dashPathForms are the forms of path p (an absolute path of plain segments)
// that rule 0 and the ref check judge: by name, p itself and p reached
// through a dot segment, encoded or overlong; through a doubly encoded one;
// p with its first segment upper-cased; with its first slash after the first
// segment doubled, a backslash, encoded backslash or encoded slash; with a
// control character; with the Kelvin sign for its first k; with a fragment at
// the end, before a dot segment and after each segment but the last
// ("fragment_<i>"); and,
// for each segment equal to ref, foreign in its place ("foreign_<i>").
func dashPathForms(p, ref, foreign string) map[string]string {
	segs := strings.Split(p[1:], "/")
	rest := strings.TrimPrefix(p[1:], segs[0])
	m := map[string]string{
		"plain": p, "dotdot": "/x/.." + p, "dotdot_encoded": "/x/%2e%2e" + p, "dot_mixed": "/x/.%2E" + p,
		"double_encoding": "/x/%252e%252e" + p, "overlong_dot": "/x/%C0%AE" + p,
		"upper": "/" + strings.ToUpper(segs[0]) + rest, "control": p + "%01",
		"fragment_end": p + "#", "fragment_dotdot": p + "#/../x",
	}
	if rest != "" {
		for name, sep := range map[string]string{"double_slash": "//", "backslash": `\`, "backslash_encoded": "%5c", "encoded_slash": "%2f"} {
			m[name] = "/" + segs[0] + sep + rest[1:]
		}
	}
	if i := strings.IndexByte(p, 'k'); i >= 0 {
		m["kelvin"] = p[:i] + "%E2%84%AA" + p[i+1:]
	}
	for i, s := range segs {
		if i < len(segs)-1 {
			m["fragment_"+strconv.Itoa(i)] = "/" + strings.Join(segs[:i+1], "/") + "#/" + strings.Join(segs[i+1:], "/")
		}
		if s == ref {
			f := append([]string(nil), segs...)
			f[i] = foreign
			m["foreign_"+strconv.Itoa(i)] = "/" + strings.Join(f, "/")
		}
	}
	return m
}
