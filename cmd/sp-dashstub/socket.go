package main

// sp-dashstub socket --listen PATH --public FILE --node ID --table FILE [--mode answer|silent|refuse:CODE]
//
// A stand-in for the control plane's dashboard socket: POST /v1/resolve and
// /v1/keys on a Unix socket, the assertion checked with the given public key
// and node id, membership and answers read from the table, no peer check and
// no rate limit. Every request appends one JSON line to PATH.log.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/dashcfg"
	"github.com/Amphoze/supapace/internal/dashsock"
	"github.com/Amphoze/supapace/internal/dashtok"
)

func init() { subcommands["socket"] = socket }

// refusals are the socket's refusal codes and their statuses.
var refusals = map[string]int{
	"peer": 403, "bad_assertion": 401, "rate_limited": 429,
	"not_here": 404, "not_a_member": 403, "unavailable": 503,
}

// stubProject is one ref's entry of the table.
type stubProject struct {
	Members []struct {
		Iss  string `json:"iss"`
		Sub  string `json:"sub"`
		Role string `json:"role"`
	} `json:"members"`
	Resolve dashsock.ResolveAnswer `json:"resolve"`
	Keys    dashsock.KeysAnswer    `json:"keys"`
}

type socketLogLine struct {
	Path    string `json:"path"`
	Ref     string `json:"ref"`
	Sub     string `json:"sub"`
	Role    string `json:"role"`
	Purpose string `json:"purpose"`
	Status  int    `json:"status"` // 0: received and never answered (silent)
}

type socketStub struct {
	pub   ed25519.PublicKey
	node  string
	table map[string]stubProject
	mode  string // "answer", "silent" or a refusal code
	log   *os.File
}

func socket(args []string, stdout, stderr io.Writer) int {
	s, path, err := newSocketStub(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "sp-dashstub socket:", err)
		fmt.Fprintln(stderr, "usage: sp-dashstub socket --listen PATH --public FILE --node ID --table FILE [--mode answer|silent|refuse:CODE]")
		return 2
	}
	l, err := listenUnix(path)
	if err != nil {
		fmt.Fprintln(stderr, "sp-dashstub socket:", err)
		return 1
	}
	srv := socketServer(s)
	fmt.Fprintln(stderr, "sp-dashstub socket: serving", path)
	err = srv.Serve(l)
	fmt.Fprintln(stderr, "sp-dashstub socket:", err)
	return 1
}

// socketServer bounds a request as the daemon's socket does: the header block,
// request line included, at 8 KiB (net/http reads 4 KiB beyond MaxHeaderBytes),
// and reads, writes and idle connections at 2 s each.
func socketServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, MaxHeaderBytes: 4 << 10, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second}
}

// newSocketStub parses the flags, the key and the table, and opens the log.
func newSocketStub(args []string, stderr io.Writer) (*socketStub, string, error) {
	fl := flag.NewFlagSet("socket", flag.ContinueOnError)
	fl.SetOutput(stderr)
	listen := fl.String("listen", "", "Unix socket path")
	public := fl.String("public", "", "assertion public key file")
	node := fl.String("node", "", "node id")
	table := fl.String("table", "", "table file")
	mode := fl.String("mode", "answer", "answer, silent or refuse:CODE")
	if err := fl.Parse(args); err != nil {
		return nil, "", err
	}
	if fl.NArg() > 0 || *listen == "" || *public == "" || *node == "" || *table == "" {
		return nil, "", errors.New("--listen, --public, --node and --table are required, and nothing else")
	}
	s := &socketStub{node: *node, mode: *mode}
	if code, ok := strings.CutPrefix(*mode, "refuse:"); ok {
		if _, known := refusals[code]; !known {
			return nil, "", fmt.Errorf("unknown refusal %q", code)
		}
		s.mode = code
	} else if *mode != "answer" && *mode != "silent" {
		return nil, "", fmt.Errorf("unknown mode %q", *mode)
	}
	b, err := os.ReadFile(*public)
	if err != nil {
		return nil, "", err
	}
	if s.pub, err = dashtok.ParsePublic(b); err != nil {
		return nil, "", fmt.Errorf("%s: %w", *public, err)
	}
	if b, err = os.ReadFile(*table); err != nil {
		return nil, "", err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s.table); err != nil {
		return nil, "", fmt.Errorf("%s: %w", *table, err)
	}
	if dec.More() {
		return nil, "", fmt.Errorf("%s: data after the table", *table)
	}
	if s.log, err = os.OpenFile(*listen+".log", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644); err != nil {
		return nil, "", err
	}
	return s, *listen, nil
}

// listenUnix listens on path, first removing a socket left there, and lets
// any local user connect: the directory decides who reaches it.
func listenUnix(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode().Type() == fs.ModeSocket {
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (s *socketStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	line := socketLogLine{Path: r.URL.Path}
	a, aerr := dashtok.Assertion{}, errors.New("not exactly one assertion header")
	if v := r.Header.Values(dashsock.HeaderAssertion); len(v) == 1 {
		a, aerr = dashtok.VerifyAssertion(s.pub, v[0], s.node, time.Now())
	}
	if aerr == nil {
		line.Ref, line.Sub, line.Role, line.Purpose = a.Ref, a.Sub, a.Role, a.Purpose
	}
	if s.mode == "silent" {
		s.write(line)
		<-r.Context().Done()
		return
	}
	status, answer := s.answer(r, a, aerr)
	line.Status = status
	s.write(line)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(answer)
	w.Write(b)
}

// answer applies the peer refusal mode, the transport rules, then checks 2, 4
// and 5; a refusal mode answers in the place of its check. The path is the
// request target exactly as received.
func (s *socketStub) answer(r *http.Request, a dashtok.Assertion, aerr error) (int, any) {
	refuse := func(status int, code string) (int, any) { return status, map[string]string{"code": code} }
	if s.mode == "peer" {
		return refuse(403, "peer")
	}
	switch {
	case r.RequestURI != "/v1/resolve" && r.RequestURI != "/v1/keys":
		return refuse(404, "not_found")
	case r.Method != http.MethodPost:
		return refuse(405, "method_not_allowed")
	case r.ContentLength != 0:
		return refuse(400, "bad_request")
	}
	// Every refusal mode but peer answers after the assertion is checked.
	if aerr != nil {
		return refuse(401, "bad_assertion")
	}
	if st, ok := refusals[s.mode]; ok {
		return refuse(st, s.mode)
	}
	p, ok := s.table[a.Ref]
	if !ok {
		return refuse(404, "not_here")
	}
	member := false
	for _, m := range p.Members {
		member = member || (m.Iss == a.Iss && m.Sub == a.Sub && m.Role == a.Role)
	}
	if !member {
		return refuse(403, "not_a_member")
	}
	if r.RequestURI == "/v1/resolve" {
		if dashsock.RoleClass(a.Role) != "rw" {
			p.Resolve.DSNRW = ""
		}
		return 200, p.Resolve
	}
	if a.Role != dashcfg.RoleOwner || a.Purpose != "reveal" {
		p.Keys.ServiceRoleKey = ""
	}
	return 200, p.Keys
}

func (s *socketStub) write(l socketLogLine) {
	b, _ := json.Marshal(l)
	// One write per line on an O_APPEND file: lines never interleave.
	s.log.Write(append(b, '\n'))
}
