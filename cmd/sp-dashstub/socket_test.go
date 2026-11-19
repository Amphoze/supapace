package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dashsock"
	"github.com/Amphoze/supapace/internal/dashtok"
)

const (
	refA  = "abcdefghij0123456789"
	refB  = "bcdefghij0123456789a"
	iss   = "https://issuer.test"
	node1 = "node-1"
)

// stubTable is the table every socket test uses: refA with one member of each
// role, refB with none. Its strings are as a test may write them, a foreign
// address and a malformed one included.
func stubTable() string {
	return `{
 "` + refA + `": {
  "members": [
   {"iss": "` + iss + `", "sub": "u-owner", "role": "owner"},
   {"iss": "` + iss + `", "sub": "u-dev", "role": "developer"},
   {"iss": "` + iss + `", "sub": "u-ro", "role": "read_only"}
  ],
  "resolve": {"ref": "` + refA + `", "name": "alpha", "state": "active", "db_version": "17.6.1",
   "pg_meta": 1, "dsn_rw": "postgresql://postgres:pw@10.213.0.9:5432/postgres",
   "dsn_ro": "not a connection string ", "api_url": "https://` + refA + `.example.test",
   "data_api": {"schemas": ["public", "graphql_public"], "extra_search_path": ["public", "extensions"], "max_rows": null},
   "generation": 4, "at": "2026-11-19T10:00:00Z"},
  "keys": {"anon_key": "anon-token", "service_role_key": "service-token",
   "signing_keys": [{"kid": "k1", "class": "project", "alg": "RS256", "kty": "RSA", "n": "AQAB", "e": "AQAB"}]}
 },
 "` + refB + `": {"members": [], "resolve": {"ref": "` + refB + `"}, "keys": {}}
}`
}

type socketHarness struct {
	t      *testing.T
	priv   ed25519.PrivateKey
	dir    string
	sock   string
	client *http.Client
}

// startSocket writes a key pair and the table, and serves the stub on a Unix
// socket with extra flags appended (a mode, for instance).
func startSocket(t *testing.T, table string, extra ...string) *socketHarness {
	t.Helper()
	privFile, pubFile, err := dashtok.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := dashtok.ParsePrivate(privFile)
	if err != nil {
		t.Fatal(err)
	}
	h := &socketHarness{t: t, priv: priv, dir: t.TempDir()}
	h.sock = filepath.Join(h.dir, "dash.sock")
	write(t, filepath.Join(h.dir, "assert.pub"), string(pubFile))
	write(t, filepath.Join(h.dir, "table.json"), table)
	args := append([]string{"--listen", h.sock, "--public", filepath.Join(h.dir, "assert.pub"),
		"--node", node1, "--table", filepath.Join(h.dir, "table.json")}, extra...)
	var errb bytes.Buffer
	s, path, err := newSocketStub(args, &errb)
	if err != nil {
		t.Fatalf("newSocketStub: %v (%s)", err, errb.String())
	}
	l, err := listenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(s)
	srv.Listener.Close()
	srv.Listener = l
	srv.Config = socketServer(s)
	srv.Start()
	t.Cleanup(func() { srv.Close(); s.log.Close() })
	h.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", h.sock)
		},
	}}
	t.Cleanup(h.client.CloseIdleConnections)
	return h
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *socketHarness) assertion(a dashtok.Assertion) string {
	h.t.Helper()
	if a.Node == "" {
		a.Node = node1
	}
	if a.Iss == "" {
		a.Iss = iss
	}
	if a.Iat == 0 {
		a.Iat = time.Now().Unix()
		a.Exp = a.Iat + 30
	}
	tok, err := dashtok.SignAssertion(h.priv, a)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

// do sends one request; token "" sends no assertion header.
func (h *socketHarness) do(method, path, token, body string) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, "http://dash"+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set(dashsock.HeaderAssertion, token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, b
}

func (h *socketHarness) post(path, sub, role, purpose string) (int, []byte) {
	h.t.Helper()
	return h.do("POST", path, h.assertion(dashtok.Assertion{Sub: sub, Ref: refA, Role: role, Purpose: purpose}), "")
}

func (h *socketHarness) logLines() []socketLogLine {
	h.t.Helper()
	b, err := os.ReadFile(h.sock + ".log")
	if err != nil {
		h.t.Fatal(err)
	}
	var out []socketLogLine
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		dec := json.NewDecoder(strings.NewReader(sc.Text()))
		dec.DisallowUnknownFields()
		var l socketLogLine
		if err := dec.Decode(&l); err != nil {
			h.t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		out = append(out, l)
	}
	return out
}

func wantCode(t *testing.T, what string, status int, body []byte, wantStatus int, code string) {
	t.Helper()
	if status != wantStatus || string(body) != `{"code":"`+code+`"}` {
		t.Errorf("%s: %d %s, want %d %s", what, status, body, wantStatus, code)
	}
}

func TestSocketStub_AnswersFromTable(t *testing.T) {
	h := startSocket(t, stubTable())
	var table map[string]stubProject
	if err := json.Unmarshal([]byte(stubTable()), &table); err != nil {
		t.Fatal(err)
	}
	written := table[refA]

	for _, role := range []string{"owner", "developer", "read_only"} {
		status, body := h.post("/v1/resolve", map[string]string{"owner": "u-owner", "developer": "u-dev", "read_only": "u-ro"}[role], role, "")
		if status != 200 {
			t.Fatalf("%s resolve: %d %s", role, status, body)
		}
		var got dashsock.ResolveAnswer
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		want := written.Resolve
		if role == "read_only" {
			want.DSNRW = ""
			if bytes.Contains(body, []byte("dsn_rw")) {
				t.Errorf("read_only: dsn_rw present: %s", body)
			}
		} else if got.DSNRW != "postgresql://postgres:pw@10.213.0.9:5432/postgres" {
			t.Errorf("%s: dsn_rw = %q", role, got.DSNRW)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s resolve:\n got %+v\nwant %+v", role, got, want)
		}
		// The malformed string is answered as written.
		if got.DSNRO != "not a connection string " {
			t.Errorf("%s: dsn_ro = %q", role, got.DSNRO)
		}
	}

	for _, c := range []struct {
		sub, role, purpose string
		service            bool
	}{
		{"u-owner", "owner", "reveal", true},
		{"u-owner", "owner", "", false},
		{"u-dev", "developer", "reveal", false},
		{"u-ro", "read_only", "reveal", false},
	} {
		status, body := h.post("/v1/keys", c.sub, c.role, c.purpose)
		if status != 200 {
			t.Fatalf("%+v keys: %d %s", c, status, body)
		}
		var got dashsock.KeysAnswer
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		want := written.Keys
		if !c.service {
			want.ServiceRoleKey = ""
			if bytes.Contains(body, []byte("service_role_key")) {
				t.Errorf("%+v: service_role_key present: %s", c, body)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%+v keys:\n got %+v\nwant %+v", c, got, want)
		}
	}
}

func TestSocketStub_Modes(t *testing.T) {
	t.Run("silent", func(t *testing.T) {
		h := startSocket(t, stubTable(), "--mode", "silent")
		tok := h.assertion(dashtok.Assertion{Sub: "u-owner", Ref: refA, Role: "owner"})
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://dash/v1/resolve", nil)
		req.Header.Set(dashsock.HeaderAssertion, tok)
		resp, err := h.client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("silent mode answered %d", resp.StatusCode)
		}
		if !strings.Contains(err.Error(), "deadline exceeded") {
			t.Fatalf("silent mode: %v, want a timeout after the request was accepted", err)
		}
		// The request reached the stub: it is in the log, unanswered.
		lines := h.logLines()
		if len(lines) != 1 || lines[0] != (socketLogLine{Path: "/v1/resolve", Ref: refA, Sub: "u-owner", Role: "owner", Status: 0}) {
			t.Fatalf("log = %+v", lines)
		}
	})
	t.Run("answer is the default", func(t *testing.T) {
		h := startSocket(t, stubTable())
		if status, body := h.post("/v1/resolve", "u-owner", "owner", ""); status != 200 {
			t.Fatalf("%d %s", status, body)
		}
		h2 := startSocket(t, stubTable(), "--mode", "answer")
		if status, body := h2.post("/v1/keys", "u-owner", "owner", ""); status != 200 {
			t.Fatalf("%d %s", status, body)
		}
	})
	for code, status := range map[string]int{"peer": 403, "bad_assertion": 401, "rate_limited": 429,
		"not_here": 404, "not_a_member": 403, "unavailable": 503} {
		t.Run("refuse:"+code, func(t *testing.T) {
			h := startSocket(t, stubTable(), "--mode", "refuse:"+code)
			for _, p := range []string{"/v1/resolve", "/v1/keys"} {
				// A request that answer mode serves is refused with the code.
				st, body := h.post(p, "u-owner", "owner", "reveal")
				wantCode(t, p, st, body, status, code)
			}
			if l := h.logLines(); len(l) != 2 || l[0].Status != status || l[1].Sub != "u-owner" {
				t.Errorf("log = %+v", l)
			}
		})
	}
}

func TestSocketStub_RefusesBadAssertionAndForeignRole(t *testing.T) {
	h := startSocket(t, stubTable())
	otherPriv := func() ed25519.PrivateKey {
		f, _, _ := dashtok.GenerateKey()
		k, _ := dashtok.ParsePrivate(f)
		return k
	}()
	now := time.Now().Unix()
	foreign, _ := dashtok.SignAssertion(otherPriv, dashtok.Assertion{Node: node1, Iss: iss, Sub: "u-owner", Ref: refA, Role: "owner", Iat: now, Exp: now + 30})
	good := dashtok.Assertion{Sub: "u-owner", Ref: refA, Role: "owner"}
	otherNode, expired, otherIss := good, good, good
	otherNode.Node = "node-2"
	expired.Iat, expired.Exp = now-40, now-10
	otherIss.Iss = "https://other-issuer.test"

	for _, p := range []string{"/v1/resolve", "/v1/keys"} {
		for name, tok := range map[string]string{
			"no header":    "",
			"garbage":      "v1.not.a-token",
			"another key":  foreign,
			"another node": h.assertion(otherNode),
			"expired":      h.assertion(expired),
			"session token": func() string {
				s, _ := dashtok.SignSession(h.priv, dashtok.Session{Iss: iss, Sub: "u-owner", Ref: refA, Iat: now, Exp: now + 60})
				return s
			}(),
		} {
			st, body := h.do("POST", p, tok, "")
			wantCode(t, p+" "+name, st, body, 401, "bad_assertion")
		}
		for name, a := range map[string]dashtok.Assertion{
			"owner claimed by a developer":     {Sub: "u-dev", Ref: refA, Role: "owner"},
			"developer claimed by a read_only": {Sub: "u-ro", Ref: refA, Role: "developer"},
			"read_only claimed by an owner":    {Sub: "u-owner", Ref: refA, Role: "read_only"},
			"unknown subject":                  {Sub: "u-none", Ref: refA, Role: "owner"},
			"another issuer":                   otherIss,
			"a project without members":        {Sub: "u-owner", Ref: refB, Role: "owner"},
		} {
			st, body := h.do("POST", p, h.assertion(a), "")
			wantCode(t, p+" "+name, st, body, 403, "not_a_member")
		}
		st, body := h.do("POST", p, h.assertion(dashtok.Assertion{Sub: "u-owner", Ref: "zzzzzzzzzz0123456789", Role: "owner"}), "")
		wantCode(t, p+" unknown ref", st, body, 404, "not_here")
		// Control: the same path with a good assertion is answered.
		if st, body := h.do("POST", p, h.assertion(good), ""); st != 200 {
			t.Errorf("%s control: %d %s", p, st, body)
		}
	}
}

func TestSocketStub_Transport(t *testing.T) {
	h := startSocket(t, stubTable())
	tok := h.assertion(dashtok.Assertion{Sub: "u-owner", Ref: refA, Role: "owner"})
	st, body := h.do("POST", "/v1/other", tok, "")
	wantCode(t, "other path", st, body, 404, "not_found")
	st, body = h.do("GET", "/v1/resolve", tok, "")
	wantCode(t, "GET", st, body, 405, "method_not_allowed")
	st, body = h.do("POST", "/v1/resolve", tok, "{}")
	wantCode(t, "body", st, body, 400, "bad_request")
	// A chunked body of unknown length is a body too.
	req, _ := http.NewRequest("POST", "http://dash/v1/keys", io.MultiReader(strings.NewReader("x")))
	req.Header.Set(dashsock.HeaderAssertion, tok)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("chunked body: %d", resp.StatusCode)
	}
	// A header block over 8 KiB is refused by the server.
	req, _ = http.NewRequest("POST", "http://dash/v1/keys", nil)
	req.Header.Set(dashsock.HeaderAssertion, tok)
	req.Header.Set("X-Pad", strings.Repeat("a", 16<<10))
	resp, err = h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 431 {
		t.Errorf("large header: %d", resp.StatusCode)
	}
	// Control: the same request without the padding is answered.
	if st, body := h.do("POST", "/v1/keys", tok, ""); st != 200 {
		t.Errorf("control: %d %s", st, body)
	}
}

func TestSocketStub_LogsEveryRequest(t *testing.T) {
	h := startSocket(t, stubTable())
	h.post("/v1/resolve", "u-ro", "read_only", "")
	h.post("/v1/keys", "u-owner", "owner", "reveal")
	h.do("POST", "/v1/keys", "", "")
	h.post("/v1/resolve", "u-dev", "owner", "")
	h.do("GET", "/v1/keys", "", "")
	want := []socketLogLine{
		{Path: "/v1/resolve", Ref: refA, Sub: "u-ro", Role: "read_only", Status: 200},
		{Path: "/v1/keys", Ref: refA, Sub: "u-owner", Role: "owner", Purpose: "reveal", Status: 200},
		{Path: "/v1/keys", Status: 401},
		{Path: "/v1/resolve", Ref: refA, Sub: "u-dev", Role: "owner", Status: 403},
		{Path: "/v1/keys", Status: 405},
	}
	if got := h.logLines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("log:\n got %+v\nwant %+v", got, want)
	}
	// Concurrent requests each leave one whole line.
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); h.post("/v1/keys", "u-dev", "developer", "") }()
	}
	wg.Wait()
	if got := h.logLines(); len(got) != len(want)+32 || got[len(got)-1].Sub != "u-dev" {
		t.Fatalf("after 32 concurrent requests: %d lines", len(got))
	}
}

func TestSocketStub_Usage(t *testing.T) {
	dir := t.TempDir()
	_, pub, _ := dashtok.GenerateKey()
	write(t, filepath.Join(dir, "pub"), string(pub))
	write(t, filepath.Join(dir, "table.json"), stubTable())
	write(t, filepath.Join(dir, "unknown.json"), `{"`+refA+`": {"members": [], "resolve": {"dsn": "x"}}}`)
	write(t, filepath.Join(dir, "trailing.json"), `{} {}`)
	base := func(table string, extra ...string) []string {
		return append([]string{"socket", "--listen", filepath.Join(dir, "s.sock"), "--public", filepath.Join(dir, "pub"),
			"--node", node1, "--table", filepath.Join(dir, table)}, extra...)
	}
	for name, args := range map[string][]string{
		"no flags":        {"socket"},
		"no node":         {"socket", "--listen", filepath.Join(dir, "s.sock"), "--public", filepath.Join(dir, "pub"), "--table", filepath.Join(dir, "table.json")},
		"extra argument":  append(base("table.json"), "x"),
		"bad mode":        base("table.json", "--mode", "loud"),
		"unknown refusal": base("table.json", "--mode", "refuse:nope"),
		"empty refusal":   base("table.json", "--mode", "refuse:"),
		"missing table":   base("absent.json"),
		"unknown member":  base("unknown.json"),
		"trailing data":   base("trailing.json"),
		"bad public key":  append(base("table.json"), "--public", filepath.Join(dir, "table.json")),
	} {
		if s, _, err := newSocketStub(args[1:], io.Discard); err == nil {
			s.log.Close()
			t.Errorf("%s: accepted", name)
		}
	}
	// Refused flags exit 2 with the usage; parsing never reaches the listener.
	if code, out, errs := runOut("socket", "--mode", "loud"); code != 2 || out != "" || !strings.Contains(errs, "usage") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	// Control: the same flags parse.
	var errb bytes.Buffer
	s, _, err := newSocketStub(base("table.json")[1:], &errb)
	if err != nil {
		t.Fatalf("control: %v %s", err, errb.String())
	}
	s.log.Close()
}

func TestSocketStub_ReplacesStaleSocketOnly(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "dash.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close() // a stale socket file stays behind
	l2, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o666 {
		t.Errorf("socket mode: %v %v", fi.Mode(), err)
	}
	l2.Close()
	// Control: a regular file at the path is not removed.
	file := filepath.Join(dir, "file")
	write(t, file, "keep")
	if _, err := listenUnix(file); err == nil {
		t.Fatal("listened over a regular file")
	}
	if b, _ := os.ReadFile(file); string(b) != "keep" {
		t.Fatal("regular file changed")
	}
}

// raw writes one request exactly as given and reads the answer.
func (h *socketHarness) raw(req string) (int, []byte) {
	h.t.Helper()
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		h.t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		h.t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, b
}

func rawRequest(method, target string, headers ...string) string {
	return method + " " + target + " HTTP/1.1\r\nHost: dash\r\nContent-Length: 0\r\n" + strings.Join(headers, "") + "\r\n"
}

func TestSocketStub_PathIsTheRawTarget(t *testing.T) {
	h := startSocket(t, stubTable())
	tok := dashsock.HeaderAssertion + ": " + h.assertion(dashtok.Assertion{Sub: "u-owner", Ref: refA, Role: "owner"}) + "\r\n"
	for _, target := range []string{
		"/v1/resolve?x=1", "/v1/resolve?", "/v1/%72esolve", "/v1%2Fresolve", "/v1/keys/",
		"http://dash/v1/resolve", "http://dash/v1/keys", "//v1/keys", "/v1/./keys",
	} {
		st, body := h.raw(rawRequest("POST", target, tok))
		wantCode(t, target, st, body, 404, "not_found")
	}
	// Control: the exact targets are answered.
	for _, target := range []string{"/v1/resolve", "/v1/keys"} {
		if st, body := h.raw(rawRequest("POST", target, tok)); st != 200 {
			t.Errorf("%s: %d %s", target, st, body)
		}
	}
}

func TestSocketStub_TwoAssertionHeaders(t *testing.T) {
	h := startSocket(t, stubTable())
	tok := h.assertion(dashtok.Assertion{Sub: "u-owner", Ref: refA, Role: "owner"})
	one := dashsock.HeaderAssertion + ": " + tok + "\r\n"
	for name, hdrs := range map[string][]string{
		"the same token twice":  {one, one},
		"a good and a bad one":  {one, dashsock.HeaderAssertion + ": v1.x.y\r\n"},
		"a bad and a good one":  {dashsock.HeaderAssertion + ": v1.x.y\r\n", one},
		"two spellings of name": {one, strings.ToLower(dashsock.HeaderAssertion) + ": " + tok + "\r\n"},
	} {
		st, body := h.raw(rawRequest("POST", "/v1/keys", hdrs...))
		wantCode(t, name, st, body, 401, "bad_assertion")
	}
	if l := h.logLines(); len(l) != 4 || l[0].Sub != "" {
		t.Errorf("log = %+v", l)
	}
	// Control: one header is answered.
	if st, body := h.raw(rawRequest("POST", "/v1/keys", one)); st != 200 {
		t.Errorf("one header: %d %s", st, body)
	}
}

// The header block, request line and final blank line included, may be 8,192
// bytes and no more.
func TestSocketStub_HeaderBoundIsExact(t *testing.T) {
	h := startSocket(t, stubTable())
	tok := dashsock.HeaderAssertion + ": " + h.assertion(dashtok.Assertion{Sub: "u-owner", Ref: refA, Role: "owner"}) + "\r\n"
	sized := func(n int) string {
		base := rawRequest("POST", "/v1/keys", tok, "X-Pad: \r\n")
		pad := n - len(base)
		return rawRequest("POST", "/v1/keys", tok, "X-Pad: "+strings.Repeat("a", pad)+"\r\n")
	}
	if r := sized(8192); len(r) != 8192 {
		t.Fatalf("built %d bytes", len(r))
	}
	if st, body := h.raw(sized(8192)); st != 200 {
		t.Errorf("8,192 bytes: %d %s", st, body)
	}
	if st, _ := h.raw(sized(8193)); st != 431 {
		t.Errorf("8,193 bytes: %d", st)
	}
}

func TestSocketStub_PeerRefusalBeforeTransport(t *testing.T) {
	h := startSocket(t, stubTable(), "--mode", "refuse:peer")
	for name, req := range map[string]string{
		"bad path":   rawRequest("POST", "/v1/other"),
		"bad method": rawRequest("GET", "/v1/keys"),
		"a body":     "POST /v1/keys HTTP/1.1\r\nHost: dash\r\nContent-Length: 2\r\n\r\n{}",
		"query":      rawRequest("POST", "/v1/keys?x"),
	} {
		st, body := h.raw(req)
		wantCode(t, name, st, body, 403, "peer")
	}
	// Control: in another refusal mode the transport checks come first.
	h2 := startSocket(t, stubTable(), "--mode", "refuse:unavailable")
	st, body := h2.raw(rawRequest("GET", "/v1/keys"))
	wantCode(t, "refuse:unavailable, bad method", st, body, 405, "method_not_allowed")
}

func TestSocketStub_AnswerBytesExact(t *testing.T) {
	h := startSocket(t, stubTable())
	var table map[string]stubProject
	if err := json.Unmarshal([]byte(stubTable()), &table); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(table[refA].Resolve)
	if _, body := h.post("/v1/resolve", "u-owner", "owner", ""); !bytes.Equal(body, want) {
		t.Errorf("resolve:\n got %q\nwant %q", body, want)
	}
	k := table[refA].Keys
	k.ServiceRoleKey = ""
	want, _ = json.Marshal(k)
	if _, body := h.post("/v1/keys", "u-owner", "owner", ""); !bytes.Equal(body, want) {
		t.Errorf("keys:\n got %q\nwant %q", body, want)
	}
}

// startSocketServer serves the stub on a server built by mk, so that a test
// can compare the stand-in's server with one that lacks its timeouts.
func startSocketServer(t *testing.T, table string, mk func(http.Handler) *http.Server) *socketHarness {
	h := startSocket(t, table)
	sock := filepath.Join(h.dir, "second.sock")
	l, err := listenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	s, _, err := newSocketStub([]string{"--listen", sock, "--public", filepath.Join(h.dir, "assert.pub"),
		"--node", node1, "--table", filepath.Join(h.dir, "table.json")}, &errb)
	if err != nil {
		t.Fatal(err)
	}
	srv := mk(s)
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close(); s.log.Close() })
	h.sock = sock
	return h
}

// closedWithin reports whether the server closes c within d (reading and
// discarding what it sends), and how long it took.
func closedWithin(c net.Conn, d time.Duration) (bool, time.Duration) {
	start := time.Now()
	c.SetReadDeadline(start.Add(d))
	_, err := io.Copy(io.Discard, c)
	ne, ok := err.(net.Error)
	return !(ok && ne.Timeout()), time.Since(start)
}

func noTimeouts(h http.Handler) *http.Server {
	s := socketServer(h)
	s.ReadTimeout, s.WriteTimeout, s.IdleTimeout = 0, 0, 0
	return s
}

func TestSocketStub_ReadWriteIdleTimeouts(t *testing.T) {
	tok := func(h *socketHarness) string {
		return dashsock.HeaderAssertion + ": " + h.assertion(dashtok.Assertion{Sub: "u-owner", Ref: refA, Role: "owner"}) + "\r\n"
	}
	dial := func(h *socketHarness) net.Conn {
		c, err := net.Dial("unix", h.sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}

	t.Run("declared body never sent", func(t *testing.T) {
		req := func(h *socketHarness) string {
			return "POST /v1/keys HTTP/1.1\r\nHost: dash\r\nContent-Length: 5\r\n" + tok(h) + "\r\n"
		}
		h := startSocketServer(t, stubTable(), socketServer)
		c := dial(h)
		io.WriteString(c, req(h))
		if closed, d := closedWithin(c, 6*time.Second); !closed {
			t.Errorf("connection held for %v", d)
		}
		// Control: without the timeouts the same connection is still open.
		h0 := startSocketServer(t, stubTable(), noTimeouts)
		c0 := dial(h0)
		io.WriteString(c0, req(h0))
		if closed, d := closedWithin(c0, 3*time.Second); closed {
			t.Errorf("control closed after %v", d)
		}
	})

	t.Run("client that never reads", func(t *testing.T) {
		// An answer far larger than the socket's buffers (a few hundred KiB),
		// yet small enough for the reading control to finish inside the 2 s write
		// bound on a loaded machine under the race detector.
		const size = 8 << 20
		big := strings.Replace(stubTable(), `"name": "alpha"`, `"name": "`+strings.Repeat("n", size)+`"`, 1)
		h := startSocketServer(t, big, socketServer)
		c := dial(h)
		io.WriteString(c, rawRequest("POST", "/v1/resolve", tok(h)))
		time.Sleep(3 * time.Second) // past the write bound, reading nothing
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _ := io.Copy(io.Discard, c)
		if n >= size {
			t.Errorf("a client that did not read got the whole answer (%d bytes)", n)
		}
		// Control: a client that reads at once gets all of it.
		c2 := dial(h)
		io.WriteString(c2, rawRequest("POST", "/v1/resolve", tok(h)))
		c2.SetReadDeadline(time.Now().Add(10 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c2), nil)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := io.Copy(io.Discard, resp.Body); err != nil || n < size {
			t.Errorf("reading client: %d bytes, %v", n, err)
		}
	})

	t.Run("idle connection", func(t *testing.T) {
		h := startSocketServer(t, stubTable(), socketServer)
		c := dial(h)
		io.WriteString(c, rawRequest("POST", "/v1/keys", tok(h)))
		r := bufio.NewReader(c)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(r, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%v %v", resp, err)
		}
		io.Copy(io.Discard, resp.Body)
		start := time.Now()
		c.SetReadDeadline(start.Add(6 * time.Second))
		_, err = r.ReadByte()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("idle connection held for %v", time.Since(start))
		}
		// Control: without the timeouts an idle connection stays open.
		h0 := startSocketServer(t, stubTable(), noTimeouts)
		c0 := dial(h0)
		io.WriteString(c0, rawRequest("POST", "/v1/keys", tok(h0)))
		r0 := bufio.NewReader(c0)
		c0.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err = http.ReadResponse(r0, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		c0.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err = r0.ReadByte(); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("control: %v", err)
		}
	})
}
