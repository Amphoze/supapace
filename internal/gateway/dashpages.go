package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
)

// The gateway's own pages are constant templates. A page has at most one
// script and one style, both constants, each admitted by its hash in the
// page's policy; nothing of a request is ever inside either. The untrusted
// strings a page shows — a display name, a project's name, a return path —
// go through the template's escaping, a path only as an attribute's value.

const (
	relayScript = `document.forms[0].submit()`
	nextScript  = `location.replace(document.getElementById("next").getAttribute("href"))`
	pageStyle   = `body{font:16px/1.5 system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem}`
)

// The pages' words. None holds anything of a request.
const (
	textDidNotComplete = "Sign-in did not complete."
	textFailed         = "Sign-in could not be completed."
	textNoCookie       = "This browser did not keep the sign-in cookie. Allow cookies for this site, then start again."
	textUnpresented    = "Sign-in completed, and this browser did not send back the session cookie it was given. Allow cookies for this site, then start again."
	textMethod         = "This address takes the sign-in form and nothing else."
	textBadTicket      = "Log out did not complete: this log-out address is not valid or is no longer valid."
	textSignedOut      = "Log out from a dashboard ends the session of that dashboard, of up to sixteen other projects of yours, and of this sign-in page."
	textEnded          = "No dashboard session was shown with this log-out, so none was ended. The session of this sign-in page is ended. A session still open on a dashboard is ended by Log out from a page of that dashboard."
	textMore           = "Sessions on further projects stay valid until they expire or your access is revoked."
)

var pages = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html><html lang="en"><meta name="viewport" content="width=device-width"><title>{{.}}</title><style>` + pageStyle + `</style>{{end}}
{{define "relay"}}{{template "head" "Signing in"}}<form method="post" action="{{.Action}}"><input type="hidden" name="id_token" value="{{.Token}}"><input type="hidden" name="state" value="{{.State}}"><button>Continue</button></form><script>` + relayScript + `</script>{{end}}
{{define "next"}}{{template "head" "Signing in"}}<noscript><meta http-equiv="refresh" content="0;url={{.}}"></noscript><p><a id="next" href="{{.}}">Continue</a></p><script>` + nextScript + `</script>{{end}}
{{define "refusal"}}{{template "head" "Dashboard"}}<p>{{.Text}}</p>{{if .Link}}<p><a href="{{.Link}}">Start again</a></p>{{end}}{{end}}
{{define "signedout"}}{{template "head" "Log out"}}<h1>Log out</h1>{{if .Ended}}
<p>` + textEnded + `</p>{{else}}<p>` + textSignedOut + `</p>{{end}}{{if .More}}<p>` + textMore + `</p>{{end}}{{if .EndSession}}<p><a href="{{.EndSession}}">Sign out at the identity provider</a></p>{{end}}{{end}}
{{define "picker"}}{{template "head" "Projects"}}<h1>Projects</h1>{{if .Name}}<p>Signed in as {{.Name}}.</p>{{end}}<ul>{{range .Projects}}<li><a href="{{.URL}}">{{.Name}}</a> <small>{{.Ref}}</small></li>{{else}}<li>No project.</li>{{end}}</ul><p><a href="/-/auth/logout">Log out</a></p>{{end}}
`))

// cspHash is the policy's source expression for an inline script or style.
func cspHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

var relayHash, nextHash, styleHash = cspHash(relayScript), cspHash(nextScript), cspHash(pageStyle)

// headers sets what every answer of the sign-in handler carries: the
// dashboard's headers, no-store, and the policy of the gateway's own pages
// in place of the dashboard's — nothing loads, script is the one hash given
// ('none' for an answer without a script), and a form posts only to
// formAction. Every answer of the sign-in host asks for an origin-keyed
// agent cluster: the relay page and a project origin's script may be
// same-site.
func (s *signIn) headers(script, formAction string) {
	h := s.w.Header()
	dashHeaders(h)
	h.Set("Content-Security-Policy", "default-src 'none'; script-src "+script+"; style-src "+styleHash+
		"; frame-ancestors 'none'; base-uri 'none'; form-action "+formAction)
	h.Set("Cache-Control", "no-store")
	if s.ref == "_" {
		h.Set("Origin-Agent-Cluster", "?1")
	}
}

// page writes one of the pages.
func (s *signIn) page(status int, name string, data any, script, formAction string) {
	var b bytes.Buffer
	if err := pages.ExecuteTemplate(&b, name, data); err != nil {
		s.refuse(http.StatusServiceUnavailable, "unavailable") // a template that cannot run; never half a page
		return
	}
	s.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	s.headers(script, formAction)
	s.w.WriteHeader(status)
	s.w.Write(b.Bytes())
}

// refusal writes a refusal page: fixed words and, when link is set, one link
// to start again. It leads nowhere of its own accord.
func (s *signIn) refusal(status int, text, link string) {
	s.page(status, "refusal", struct{ Text, Link string }{text, link}, "'none'", "'none'")
}

// refuse writes a refusal that is not a page: the gateway's error body.
func (s *signIn) refuse(status int, code string) {
	h := s.w.Header()
	h.Set("Content-Type", "application/json")
	if status == http.StatusServiceUnavailable {
		h.Set("Retry-After", "5")
	}
	s.headers("'none'", "'none'")
	s.w.WriteHeader(status)
	fmt.Fprintf(s.w, `{"code":%q}`, code)
}

func (s *signIn) redirect(location string) {
	s.w.Header().Set("Location", location)
	s.headers("'none'", "'none'")
	s.w.WriteHeader(http.StatusFound)
}
