package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// standIn starts sp-probe mgmt on loopback with the bearer token tok and
// returns its address and log file.
func standIn(t *testing.T, tok string) (addr, logFile string) {
	t.Helper()
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logFile = filepath.Join(dir, "log")
	return start(t, "mgmt", "--listen", "127.0.0.1:0", "--log", logFile, "--token", tokFile), logFile
}

func madeUpToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sbp_" + hex.EncodeToString(b)
}

// mgmtRecord is one request as the stand-in logged it.
type mgmtRecord struct {
	request []string // method, target, protocol
	headers []string
	auth    string
	answer  int
}

func readMgmtLog(t *testing.T, logFile string) (recs []mgmtRecord, raw string) {
	t.Helper()
	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		kind, rest, _ := strings.Cut(line, " ")
		if kind == "request" {
			recs = append(recs, mgmtRecord{request: strings.Fields(rest)})
			continue
		}
		if len(recs) == 0 {
			t.Fatalf("log line %q before any request", line)
		}
		r := &recs[len(recs)-1]
		switch kind {
		case "header":
			r.headers = append(r.headers, rest)
		case "auth":
			r.auth = rest
		case "answer":
			if r.answer, err = strconv.Atoi(rest); err != nil {
				t.Fatalf("log line %q", line)
			}
		default:
			t.Fatalf("log line %q", line)
		}
	}
	return recs, string(b)
}

func get(t *testing.T, url string, hdr map[string]string) (int, string) {
	t.Helper()
	return send(t, "GET", url, hdr)
}

func send(t *testing.T, method, url string, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestMgmtStandIn_RecordsPathAndAuthorizationScheme(t *testing.T) {
	tok := madeUpToken(t)
	addr, logFile := standIn(t, tok)
	base := "http://" + addr

	cases := []struct {
		name, method, target string
		hdr                  map[string]string
		status               int
		body, auth           string
	}{
		// The accepted call: the control for every refusal below.
		{"accepted", "GET", "/v1/projects", map[string]string{"Authorization": "Bearer " + tok, "X-Probe-Name": "v"},
			200, `"ref":`, "Bearer"},
		{"wrong token", "GET", "/v1/projects", map[string]string{"Authorization": "Bearer " + madeUpToken(t)},
			401, `{"message":"Unauthorized"}`, "Bearer"},
		{"other scheme", "GET", "/v1/projects", map[string]string{"Authorization": "Token " + tok},
			401, `{"message":"Unauthorized"}`, "Token"},
		{"no header", "GET", "/v1/projects", nil, 401, `{"message":"Unauthorized"}`, "-"},
		{"other path", "GET", "/v1/projects/x?y=1", map[string]string{"Authorization": "Bearer " + tok},
			404, `{"message":"Not Found"}`, "Bearer"},
		{"other method", "POST", "/v1/projects", map[string]string{"Authorization": "Bearer " + tok},
			404, `{"message":"Not Found"}`, "Bearer"},
	}
	for _, c := range cases {
		status, body := send(t, c.method, base+c.target, c.hdr)
		if status != c.status || !strings.Contains(body, c.body) {
			t.Errorf("%s: %d %q; want %d with %q", c.name, status, body, c.status, c.body)
		}
	}
	recs, raw := readMgmtLog(t, logFile)
	if len(recs) != len(cases) {
		t.Fatalf("%d records, want %d:\n%s", len(recs), len(cases), raw)
	}
	for i, c := range cases {
		r := recs[i]
		want := []string{c.method, c.target, "HTTP/1.1"}
		if strings.Join(r.request, " ") != strings.Join(want, " ") || r.auth != c.auth || r.answer != c.status {
			t.Errorf("%s: record %+v; want request %v, auth %q, answer %d", c.name, r, want, c.auth, c.status)
		}
		if !slices.IsSorted(r.headers) {
			t.Errorf("%s: header names not sorted: %v", c.name, r.headers)
		}
		names := strings.Join(r.headers, ",")
		for k := range c.hdr {
			if !strings.Contains(","+names+",", ","+k+",") {
				t.Errorf("%s: header %s not recorded: %s", c.name, k, names)
			}
		}
		if (c.hdr == nil) == strings.Contains(names, "Authorization") {
			t.Errorf("%s: header names %s", c.name, names)
		}
	}
	// Header names are logged, never values: neither the token nor a header value.
	if strings.Contains(raw, tok[4:]) || strings.Contains(raw, "Go-http-client") {
		t.Errorf("log carries a header value:\n%s", raw)
	}
}

// The scheme is logged only as a short run of letters before a space; any
// other Authorization value is logged as "?", so a credential sent in another
// form never reaches the log.
func TestMgmtStandIn_SchemeOnlyWhenItIsOne(t *testing.T) {
	tok := madeUpToken(t)
	addr, logFile := standIn(t, tok)
	values := []struct{ value, auth string }{
		{"Bearer " + tok, "Bearer"}, // control: the same path logs a scheme
		{"Bearer\t" + tok, "?"},
		{tok, "?"},
		{tok + " x", "?"},
		{"Bearer", "?"},
		{"OnlyLettersNoSpace", "?"},
		{strings.Repeat("B", 33) + " x", "?"},
		{"Bearer: " + tok, "?"},
	}
	for _, v := range values {
		get(t, "http://"+addr+"/v1/projects", map[string]string{"Authorization": v.value})
	}
	recs, raw := readMgmtLog(t, logFile)
	if len(recs) != len(values) {
		t.Fatalf("%d records, want %d:\n%s", len(recs), len(values), raw)
	}
	for i, v := range values {
		if recs[i].auth != v.auth {
			t.Errorf("Authorization %q: logged %q, want %q", v.value, recs[i].auth, v.auth)
		}
	}
	if strings.Contains(raw, tok[4:]) {
		t.Errorf("log carries the token:\n%s", raw)
	}
}

func TestMgmtStandIn_TargetIsOneField(t *testing.T) {
	addr, logFile := standIn(t, madeUpToken(t))
	status, _ := get(t, "http://"+addr+"/v1/projects?a=%20b%0a", nil)
	recs, raw := readMgmtLog(t, logFile)
	if status != 404 || len(recs) != 1 || len(recs[0].request) != 3 || recs[0].request[1] != "/v1/projects?a=%20b%0a" {
		t.Errorf("status %d, log:\n%s", status, raw)
	}
}

// Each refused invocation is the accepted one less one thing; the accepted one
// is the control.
func TestMgmtStandIn_Usage(t *testing.T) {
	dir := t.TempDir()
	tokFile, empty, logFile := filepath.Join(dir, "token"), filepath.Join(dir, "empty"), filepath.Join(dir, "log")
	os.WriteFile(tokFile, []byte(madeUpToken(t)+"\n"), 0o600)
	os.WriteFile(empty, []byte("\n"), 0o600)
	start(t, "mgmt", "--listen", "127.0.0.1:0", "--log", logFile, "--token", tokFile)
	for _, args := range [][]string{
		{"mgmt"},
		{"mgmt", "--listen", "127.0.0.1:0", "--log", logFile},
		{"mgmt", "--listen", "127.0.0.1:0", "--token", tokFile},
		{"mgmt", "--log", logFile, "--token", tokFile},
		{"mgmt", "--listen", "127.0.0.1:0", "--log", logFile, "--token", empty},
		{"mgmt", "--listen", "127.0.0.1:0", "--log", logFile, "--token", filepath.Join(dir, "none")},
		{"mgmt", "--listen", "127.0.0.1:0", "--log", filepath.Join(dir, "none", "log"), "--token", tokFile},
		{"mgmt", "x", "--listen", "127.0.0.1:0", "--log", logFile, "--token", tokFile},
		{"mgmt", "--listen", "127.0.0.1:0", "--log", logFile, "--token", tokFile, "--timeout", "1s"},
	} {
		// An invocation that is wrongly accepted serves for ever: give up on it.
		done := make(chan string, 1)
		go func() {
			code, out := probe(t, args...)
			done <- fmt.Sprintf("%d %s", code, out)
		}()
		select {
		case got := <-done:
			if !strings.HasPrefix(got, "3 error ") {
				t.Errorf("%q: %q; want exit 3 and an error line", args, got)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("%q: accepted, still serving", args)
		}
	}
}

// contractRow is one row of the table of docs/management-api.md.
type contractRow struct {
	answer               int
	method, path, scheme string
	exit                 int
}

func contractTable(t *testing.T) []contractRow {
	t.Helper()
	b, err := os.ReadFile("../../docs/management-api.md")
	if err != nil {
		t.Fatal(err)
	}
	var rows []contractRow
	inTable := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "| Call |") {
			inTable = true
			continue
		}
		if inTable && !strings.HasPrefix(line, "|") {
			inTable = false
		}
		if inTable && !strings.HasPrefix(line, "|---") && !strings.HasPrefix(line, "| `supabase projects list` |") {
			t.Fatalf("table row %q is not a row of `supabase projects list`", line)
		}
		if !strings.HasPrefix(line, "| `supabase projects list` |") {
			continue
		}
		c := strings.Split(strings.Trim(line, "|"), "|")
		for i := range c {
			c[i] = strings.Trim(strings.TrimSpace(c[i]), "`")
		}
		if len(c) != 6 {
			t.Fatalf("table row %q: %d cells, want 6", line, len(c))
		}
		answer, err1 := strconv.Atoi(strings.TrimSuffix(strings.Fields(c[1] + " x")[0], ","))
		exit, err2 := strconv.Atoi(c[5])
		if err1 != nil || err2 != nil {
			t.Fatalf("table row %q", line)
		}
		rows = append(rows, contractRow{answer, c[2], c[3], c[4], exit})
	}
	if len(rows) == 0 {
		t.Fatal("docs/management-api.md has no row for `supabase projects list`")
	}
	return rows
}

// runCLI runs the upstream CLI's projects list against the stand-in at addr
// with token tok, in an empty home and work directory, and returns its exit
// status and output.
func runCLI(t *testing.T, cli, addr, tok string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	home, work := filepath.Join(dir, "home"), filepath.Join(dir, "work")
	profile := filepath.Join(dir, "standin.yaml")
	os.Mkdir(home, 0o700)
	os.Mkdir(work, 0o700)
	if err := os.WriteFile(profile, []byte("name: standin\napi_url: http://"+addr+"\ndashboard_url: http://"+addr+
		"\nproject_host: localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, cli, "projects", "list", "--profile", profile, "--output-format", "json")
	cmd.Dir = work
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin", "SUPABASE_ACCESS_TOKEN=" + tok,
		"SUPABASE_NO_KEYRING=1", "SUPABASE_TELEMETRY_DISABLED=1", "DO_NOT_TRACK=1", "SUPABASE_NO_UPDATE_NOTIFIER=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the CLI did not finish within 2 minutes:\n%s", out)
	}
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		t.Fatalf("running %s: %v", cli, err)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

func TestMgmtContract_ProjectsList(t *testing.T) {
	cli := os.Getenv("SUPAPACE_CLI")
	if cli == "" {
		t.Skip("SUPAPACE_CLI is not set: the pinned upstream CLI is not run against the stand-in")
	}
	rows := contractTable(t)
	tok := madeUpToken(t)
	for _, row := range rows {
		addr, logFile := standIn(t, tok)
		use := tok
		if row.answer != 200 {
			use = madeUpToken(t) // well formed, refused by the stand-in
		}
		code, out := runCLI(t, cli, addr, use)
		recs, raw := readMgmtLog(t, logFile)
		if len(recs) == 0 {
			t.Errorf("answer %d: the CLI sent the stand-in no request (exit %d):\n%s", row.answer, code, out)
			continue
		}
		for _, r := range recs {
			if len(r.request) != 3 || r.request[0] != row.method || r.request[1] != row.path ||
				r.auth != row.scheme || r.answer != row.answer {
				t.Errorf("answer %d: request %v auth %q answered %d; the table says %s %s %s:\n%s",
					row.answer, r.request, r.auth, r.answer, row.method, row.path, row.scheme, raw)
			}
		}
		if code != row.exit {
			t.Errorf("answer %d: exit status %d, the table says %d:\n%s", row.answer, code, row.exit, out)
		}
		if strings.Contains(out, use[4:]) {
			t.Errorf("answer %d: the CLI printed the token", row.answer)
		}
	}
}

// orderLog fails the test when a record is written after the answer started.
type orderLog struct {
	t       *testing.T
	rec     *httptest.ResponseRecorder
	fail    bool
	records int
}

func (l *orderLog) Write(b []byte) (int, error) {
	if l.rec.Body.Len() != 0 || l.rec.Flushed {
		l.t.Errorf("record written after the answer: %q", b)
	}
	l.records++
	if l.fail {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

// The record is written before the answer, and a request that cannot be
// recorded is not answered as served.
func TestMgmtStandIn_RecordsBeforeAnswering(t *testing.T) {
	for _, fail := range []bool{false, true} {
		rec := httptest.NewRecorder()
		l := &orderLog{t: t, rec: rec, fail: fail}
		h := &mgmtHandler{token: "tok", log: l}
		req := httptest.NewRequest("GET", "/v1/projects", nil)
		req.Header.Set("Authorization", "Bearer tok")
		h.ServeHTTP(rec, req)
		want := 200
		if fail {
			want = 500
		}
		if l.records != 1 || rec.Code != want || fail && strings.Contains(rec.Body.String(), "ref") {
			t.Errorf("log failing %v: %d records, answer %d %q; want 1 record and %d", fail, l.records, rec.Code,
				rec.Body.String(), want)
		}
	}
}
