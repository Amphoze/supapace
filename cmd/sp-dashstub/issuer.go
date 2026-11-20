package main

// sp-dashstub issuer: a stand-in for the dashboard's sign-in issuer in tests.
// GET /authorize, the ID-token flow by form_post (response_type id_token,
// response_mode form_post, the client id, a nonce, an https redirect_uri),
// answers a page whose form posts to the redirect URI given: an ID token for
// the subject in the subject file (read at each request: the test sets it
// beforehand), signed RS256 with the key file the test wrote; the state
// unchanged; and one further field, session_state, which a callback must
// ignore. The page submits itself unless the request carries the cookie
// hold=1: then it has no script and waits for its button.

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/jwtx"
)

func init() { subcommands["issuer"] = issuer }

const idTokenSecs = 300

func issuer(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("issuer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "", "TLS listen address")
	cert := fs.String("cert", "", "certificate PEM file for the issuer's host")
	key := fs.String("key", "", "key PEM file")
	signing := fs.String("signing-key", "", "the ID tokens' RSA key, PKCS #8 DER")
	iss := fs.String("issuer", "", "the tokens' iss")
	client := fs.String("client-id", "", "the client id: the tokens' aud")
	subject := fs.String("subject-file", "", "file holding the subject of the next token")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *listen == "" || *cert == "" || *key == "" ||
		*signing == "" || *iss == "" || *client == "" || *subject == "" {
		fmt.Fprintln(stderr, "usage: sp-dashstub issuer --listen ADDR --cert FILE --key FILE --signing-key FILE --issuer ISS --client-id ID --subject-file FILE")
		return 2
	}
	s, err := newIssuerStub(*signing, *iss, *client, *subject)
	if err != nil {
		fmt.Fprintln(stderr, "issuer:", err)
		return 1
	}
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Fprintln(stderr, "issuer:", err)
		return 1
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "issuer:", err)
		return 1
	}
	fmt.Fprintln(stdout, "listening", ln.Addr())
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}
	fmt.Fprintln(stderr, "issuer:", srv.ServeTLS(ln, "", ""))
	return 1
}

type issuerStub struct {
	iss, client, subjectFile string
	priv                     *rsa.PrivateKey
	kid                      string
	now                      func() time.Time
}

func newIssuerStub(keyFile, iss, client, subjectFile string) (*issuerStub, error) {
	der, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	priv, ok := k.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, errors.New("the signing key is not a PKCS #8 RSA key")
	}
	return &issuerStub{iss: iss, client: client, subjectFile: subjectFile, priv: priv, kid: jwtx.KID(&priv.PublicKey), now: time.Now}, nil
}

func (s *issuerStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/authorize" {
		http.Error(w, "not_found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	to, err := url.Parse(q.Get("redirect_uri"))
	if q.Get("response_type") != "id_token" || q.Get("response_mode") != "form_post" || q.Get("client_id") != s.client ||
		q.Get("nonce") == "" || err != nil || to.Scheme != "https" || to.Host == "" {
		http.Error(w, "bad_request", http.StatusBadRequest)
		return
	}
	b, _ := os.ReadFile(s.subjectFile)
	sub := strings.TrimSpace(string(b))
	if sub == "" {
		http.Error(w, "no subject set", http.StatusConflict)
		return
	}
	now := s.now().Unix()
	tok, err := jwtx.Sign(s.priv, s.kid, map[string]any{"iss": s.iss, "aud": s.client, "sub": sub,
		"nonce": q.Get("nonce"), "iat": now, "exp": now + idTokenSecs})
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	script := template.JS(relayScript)
	if c, err := r.Cookie("hold"); err == nil && c.Value == "1" {
		script = ""
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	flowPages.ExecuteTemplate(w, "form", map[string]any{"Title": "issuer", "Script": script, "Action": template.URL(to.String()),
		"Fields": map[string]string{"id_token": tok, "state": q.Get("state"), "session_state": "stub"}})
}
