package main

// sp-probe mgmt is a stand-in for the Management API, for checking the upstream
// CLI's side of the contract in docs/management-api.md:
//
//	sp-probe mgmt --listen ADDR --log FILE --token FILE
//
// It serves plain HTTP on ADDR and prints "listening ADDR" once ready; it runs
// until killed. --token FILE holds the one bearer token it accepts (the file's
// content less one trailing newline; not empty). Answers:
//
//	GET /v1/projects, Authorization "Bearer TOKEN"   200, a JSON array of one project
//	GET /v1/projects, any other Authorization or none 401 {"message":"Unauthorized"}
//	any other method or request target               404 {"message":"Not Found"}
//
// The request target must be exactly /v1/projects: a query string is another
// target. Every request appends one record to FILE, written before the answer
// is sent:
//
//	request METHOD TARGET PROTO
//	header NAME                 one line per header name, sorted; never a value
//	auth SCHEME                 the Authorization header's scheme: 1 to 32 ASCII
//	                            letters followed by a space; "?" for any other
//	                            value, "-" when there is no such header
//	answer STATUS
//
// Every field is one token: a byte outside printable ASCII, and the space, is
// written as "?". Header values are never logged. The request target and header
// names are logged as received: a client must not carry a secret in either.

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

const mgmtProject = `[{"id":"standin","ref":"standinstandinstandi","name":"stand-in","organization_id":"standin",` +
	`"organization_slug":"standin","region":"local","created_at":"2026-01-01T00:00:00Z","status":"ACTIVE_HEALTHY",` +
	`"database":{"host":"localhost","version":"17","postgres_engine":"17","release_channel":"ga"}}]`

func mgmtCommand(args []string, stdout io.Writer) verdict {
	fs := flag.NewFlagSet("sp-probe mgmt", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	listenAddr := fs.String("listen", "", "")
	logFile := fs.String("log", "", "")
	tokFile := fs.String("token", "", "")
	pos, err := parse(fs, args)
	if err != nil {
		return errorVerdict("usage: %v", err)
	}
	if len(pos) != 0 || *listenAddr == "" || *logFile == "" || *tokFile == "" {
		return errorVerdict("usage: mgmt --listen ADDR --log FILE --token FILE")
	}
	b, err := os.ReadFile(*tokFile)
	if err != nil {
		return errorVerdict("%s", plain(err.Error()))
	}
	tok := strings.TrimSuffix(string(b), "\n")
	if tok == "" {
		return errorVerdict("usage: the token file is empty")
	}
	log, err := os.OpenFile(*logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return errorVerdict("%s", plain(err.Error()))
	}
	defer log.Close()
	l, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return errorVerdict("%s", plain(err.Error()))
	}
	fmt.Fprintln(stdout, "listening", l.Addr())
	srv := &http.Server{Handler: &mgmtHandler{token: tok, log: log}, ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes: 64 << 10}
	return errorVerdict("%s", plain(srv.Serve(l).Error()))
}

type mgmtHandler struct {
	token string
	mu    sync.Mutex
	log   io.Writer
}

func (h *mgmtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth, hasAuth := r.Header["Authorization"]
	status, body := http.StatusNotFound, `{"message":"Not Found"}`
	switch {
	case r.Method != "GET" || r.RequestURI != "/v1/projects":
	case hasAuth && len(auth) == 1 && subtle.ConstantTimeCompare([]byte(auth[0]), []byte("Bearer "+h.token)) == 1:
		status, body = http.StatusOK, mgmtProject
	default:
		status, body = http.StatusUnauthorized, `{"message":"Unauthorized"}`
	}

	var rec strings.Builder
	fmt.Fprintf(&rec, "request %s %s %s\n", token(r.Method), token(r.RequestURI), token(r.Proto))
	for _, k := range slices.Sorted(maps.Keys(r.Header)) {
		fmt.Fprintf(&rec, "header %s\n", token(k))
	}
	scheme := "-"
	if hasAuth {
		scheme = authScheme(auth[0])
	}
	fmt.Fprintf(&rec, "auth %s\nanswer %d\n", scheme, status)
	h.mu.Lock()
	_, err := io.WriteString(h.log, rec.String())
	h.mu.Unlock()
	if err != nil {
		// An unrecorded request must not look answered.
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, body)
}

// authScheme returns the scheme of an Authorization value: 1 to 32 ASCII
// letters followed by a space; "?" for anything else.
func authScheme(v string) string {
	s, _, ok := strings.Cut(v, " ")
	if !ok || len(s) == 0 || len(s) > 32 {
		return "?"
	}
	for _, c := range []byte(s) {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return "?"
		}
	}
	return s
}
