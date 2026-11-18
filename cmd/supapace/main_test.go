package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type request struct{ method, uri, body string }

// reply is a scripted answer; status 0 answers nothing until the client goes
// away.
type reply struct {
	status int
	body   string
}

// fakeAPI serves scripted replies on a Unix socket and records requests. The
// last reply repeats once the script is exhausted.
type fakeAPI struct {
	mu      sync.Mutex
	reqs    []request
	replies []reply
	sock    string
	srv     *httptest.Server
}

func newFake(t *testing.T, replies ...reply) *fakeAPI {
	t.Helper()
	f := &fakeAPI{replies: replies, sock: filepath.Join(t.TempDir(), "admin.sock")}
	l, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, request{r.Method, r.URL.RequestURI(), string(b)})
		rep := f.replies[0]
		if len(f.replies) > 1 {
			f.replies = f.replies[1:]
		}
		f.mu.Unlock()
		if rep.status == 0 {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rep.status)
		io.WriteString(w, rep.body)
	}))
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	f.srv = srv
	t.Cleanup(srv.Close)
	return f
}

func (f *fakeAPI) requests() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.reqs...)
}

func (f *fakeAPI) run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, client{sock: f.sock, poll: time.Millisecond, outage: 200 * time.Millisecond}, &o, &e)
	return o.String(), e.String(), code
}

const (
	accepted = `{"ref":"abcdefghij0123456789","operation_id":12}` + "\n"
	pending  = `{"id":12,"ref":"abcdefghij0123456789","kind":"create","state":"pending","step":"1"}` + "\n"
	running  = `{"id":12,"ref":"abcdefghij0123456789","kind":"create","state":"running","step":"4a"}` + "\n"
)

func final(state string) string {
	return `{"id":12,"ref":"abcdefghij0123456789","kind":"create","state":"` + state + `","step":"12","last_error":""}` + "\n"
}

func jwksFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(p, []byte("{\n  \"keys\": []\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCLI_Requests(t *testing.T) {
	jf := jwksFile(t)
	const ref = "abcdefghij0123456789"
	for _, c := range []struct {
		args []string
		want request
	}{
		{[]string{"project", "create", "--name", "demo", "--issuer-jwks", jf, "--no-wait"},
			request{"POST", "/v1/projects", `{"name":"demo","issuer_jwks":{"keys":[]}}`}},
		{[]string{"project", "create", "--name", "demo", "--issuer-jwks", jf, "--ref", ref, "--user-role", "editor",
			"--user-role", "viewer", "--disk-quota", "8g", "--no-wait"},
			request{"POST", "/v1/projects", `{"name":"demo","ref":"abcdefghij0123456789","issuer_jwks":{"keys":[]},"user_roles":["editor","viewer"],"disk_quota_mb":8192}`}},
		{[]string{"project", "create", "--name", "demo", "--issuer-jwks", jf, "--disk-quota", "512m", "--no-wait"},
			request{"POST", "/v1/projects", `{"name":"demo","issuer_jwks":{"keys":[]},"disk_quota_mb":512}`}},
		{[]string{"project", "create", "--name", "demo", "--issuer-jwks", jf, "--disk-quota", "1T", "--no-wait"},
			request{"POST", "/v1/projects", `{"name":"demo","issuer_jwks":{"keys":[]},"disk_quota_mb":1048576}`}},
		{[]string{"project", "create", "--name", "demo", "--issuer-jwks", jf, "--disk-quota", "300", "--no-wait"},
			request{"POST", "/v1/projects", `{"name":"demo","issuer_jwks":{"keys":[]},"disk_quota_mb":300}`}},
		{[]string{"project", "list"}, request{"GET", "/v1/projects", ""}},
		{[]string{"project", "show", ref}, request{"GET", "/v1/projects/" + ref, ""}},
		{[]string{"project", "keys", ref}, request{"GET", "/v1/projects/" + ref + "/keys", ""}},
		{[]string{"project", "check", ref}, request{"POST", "/v1/projects/" + ref + "/check", ""}},
		{[]string{"project", "restart", ref, "--no-wait"}, request{"POST", "/v1/projects/" + ref + "/restart", `{}`}},
		{[]string{"project", "restart", ref, "--set", "max_connections=200", "--set", "work_mem=8MB=x",
			"--set", "disk_quota_mb=16384", "--no-wait"},
			request{"POST", "/v1/projects/" + ref + "/restart", `{"set":{"max_connections":"200","work_mem":"8MB=x"},"disk_quota_mb":16384}`}},
		{[]string{"project", "restart", "--no-wait", "--set", "work_mem=", ref},
			request{"POST", "/v1/projects/" + ref + "/restart", `{"set":{"work_mem":""}}`}},
		{[]string{"project", "delete", ref, "--no-wait"}, request{"DELETE", "/v1/projects/" + ref, ""}},
		{[]string{"project", "purge", ref, "--no-wait"}, request{"POST", "/v1/projects/" + ref + "/purge", ""}},
		{[]string{"project", "abort", ref, "--no-wait"}, request{"POST", "/v1/projects/" + ref + "/abort", ""}},
		{[]string{"op", "list"}, request{"GET", "/v1/operations", ""}},
		{[]string{"op", "list", ref}, request{"GET", "/v1/operations?ref=" + ref, ""}},
		{[]string{"op", "list", "a&b=c"}, request{"GET", "/v1/operations?ref=a%26b%3Dc", ""}},
		{[]string{"op", "show", "12"}, request{"GET", "/v1/operations/12", ""}},
		{[]string{"op", "retry", "12", "--no-wait"}, request{"POST", "/v1/operations/12/retry", ""}},
		{[]string{"node", "check"}, request{"GET", "/v1/node/check", ""}},
		{[]string{"project", "show", "../../v1/node/check"}, request{"GET", "/v1/projects/..%2F..%2Fv1%2Fnode%2Fcheck", ""}},
	} {
		f := newFake(t, reply{202, accepted})
		f.run(t, c.args...)
		if got := f.requests(); len(got) != 1 || got[0] != c.want {
			t.Errorf("%v:\n got %+v\nwant %+v", c.args, got, c.want)
		}
	}
}

func TestCLI_PrintsLastResponseVerbatim(t *testing.T) {
	// Odd but valid bytes: spacing, key order and escapes are not normalised.
	body := "{ \"projects\" : [ ],\n \"z\":\"\\u00e9\"}\n\n"
	f := newFake(t, reply{200, body})
	out, _, code := f.run(t, "project", "list")
	if out != body || code != 0 {
		t.Fatalf("stdout %q exit %d", out, code)
	}
	// A waited mutation prints the final operation only, byte for byte.
	f = newFake(t, reply{202, accepted}, reply{200, pending}, reply{200, running}, reply{200, final("done")})
	out, errOut, code := f.run(t, "project", "delete", "abcdefghij0123456789")
	if out != final("done") || code != 0 {
		t.Fatalf("stdout %q exit %d", out, code)
	}
	if !strings.Contains(errOut, "running") {
		t.Errorf("no progress on stderr: %q", errOut)
	}
	// An error body is printed as received.
	eb := `{"code":"not_found","message":"not found"}`
	f = newFake(t, reply{404, eb})
	if out, _, code = f.run(t, "project", "show", "abcdefghij0123456789"); out != eb || code != 1 {
		t.Fatalf("stdout %q exit %d", out, code)
	}
}

func TestCLI_CreatePollsToFinalOperation(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, pending}, reply{200, running}, reply{200, running}, reply{200, final("done")})
	out, _, code := f.run(t, "project", "create", "--name", "demo", "--issuer-jwks", jwksFile(t))
	if out != final("done") || code != 0 {
		t.Fatalf("stdout %q exit %d", out, code)
	}
	reqs := f.requests()
	if len(reqs) != 5 || reqs[0].uri != "/v1/projects" {
		t.Fatalf("requests %+v", reqs)
	}
	for _, r := range reqs[1:] {
		if r != (request{"GET", "/v1/operations/12", ""}) {
			t.Fatalf("poll %+v", r)
		}
	}
	// The poll interval is the client's.
	if c := defaultClient(); c.poll != 500*time.Millisecond {
		t.Fatalf("poll interval %v", c.poll)
	}
}

func TestCLI_PollSurvivesDaemonRestart(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, running})
	var o, e bytes.Buffer
	done := make(chan int)
	go func() {
		done <- run([]string{"project", "delete", "abcdefghij0123456789"},
			client{sock: f.sock, poll: 5 * time.Millisecond, outage: 5 * time.Second}, &o, &e)
	}()
	for len(f.requests()) < 3 {
		time.Sleep(time.Millisecond)
	}
	// The daemon goes away and comes back on the same socket.
	f.srv.CloseClientConnections()
	f.srv.Close()
	os.Remove(f.sock)
	time.Sleep(50 * time.Millisecond)
	g := newFake(t, reply{200, final("done")})
	if err := os.Rename(g.sock, f.sock); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != 0 || o.String() != final("done") {
		t.Fatalf("exit %d stdout %q stderr %q", code, o.String(), e.String())
	}

	// An outage longer than the bound ends with the last body received.
	f = newFake(t, reply{202, accepted}, reply{200, running})
	o.Reset()
	go func() {
		done <- run([]string{"project", "delete", "abcdefghij0123456789"},
			client{sock: f.sock, poll: 5 * time.Millisecond, outage: 50 * time.Millisecond}, &o, &e)
	}()
	for len(f.requests()) < 3 { // the second response was read before the third request
		time.Sleep(time.Millisecond)
	}
	f.srv.CloseClientConnections()
	f.srv.Close()
	os.Remove(f.sock)
	if code := <-done; code != 1 || o.String() != running {
		t.Fatalf("exit %d stdout %q", code, o.String())
	}
}

func TestCLI_NoWait(t *testing.T) {
	for _, args := range [][]string{
		{"project", "create", "--name", "demo", "--issuer-jwks", jwksFile(t), "--no-wait"},
		{"project", "restart", "abcdefghij0123456789", "--no-wait"},
		{"project", "delete", "abcdefghij0123456789", "--no-wait"},
		{"project", "purge", "abcdefghij0123456789", "--no-wait"},
		{"project", "abort", "abcdefghij0123456789", "--no-wait"},
		{"op", "retry", "12", "--no-wait"},
	} {
		f := newFake(t, reply{202, accepted}, reply{200, final("failed")})
		out, _, code := f.run(t, args...)
		if out != accepted || code != 0 || len(f.requests()) != 1 {
			t.Errorf("%v: stdout %q exit %d, %d requests", args, out, code, len(f.requests()))
		}
	}
}

func TestCLI_ExitCodes(t *testing.T) {
	jf := jwksFile(t)
	for _, c := range []struct {
		args    []string
		replies []reply
		want    int
	}{
		{[]string{"project", "list"}, []reply{{200, `{"projects":[]}`}}, 0},
		{[]string{"project", "show", "abcdefghij0123456789"}, []reply{{404, `{"code":"not_found","message":"x"}`}}, 1},
		{[]string{"project", "create", "--name", "d", "--issuer-jwks", jf}, []reply{{400, `{"code":"bad_request","message":"x"}`}}, 1},
		{[]string{"project", "create", "--name", "d", "--issuer-jwks", jf}, []reply{{202, accepted}, {200, final("done")}}, 0},
		{[]string{"project", "create", "--name", "d", "--issuer-jwks", jf}, []reply{{202, accepted}, {200, final("failed")}}, 1},
		{[]string{"project", "create", "--name", "d", "--issuer-jwks", jf}, []reply{{202, accepted}, {200, final("aborted")}}, 1},
		{[]string{"project", "delete", "abcdefghij0123456789"}, []reply{{202, accepted}, {404, `{"code":"not_found","message":"x"}`}}, 1},
		{[]string{"project", "delete", "abcdefghij0123456789"}, []reply{{503, `{"code":"containment_failed","message":"x"}`}}, 1},
		{[]string{"op", "retry", "12"}, []reply{{202, accepted}, {200, final("done")}}, 0},
		{[]string{"project", "check", "abcdefghij0123456789"}, []reply{{200, `{"ok":true,"drift":[]}`}}, 0},
		{[]string{"project", "check", "abcdefghij0123456789"}, []reply{{200, `{"ok":false,"code":"peer","message":"x","drift":[]}`}}, 1},
		{[]string{"project", "check", "abcdefghij0123456789"}, []reply{{200, `{"drift":[]}`}}, 1},
		{[]string{"node", "check"}, []reply{{200, `{"ok":true,"containment_failed":false,"checks":[]}`}}, 0},
		{[]string{"node", "check"}, []reply{{200, `{"ok":false,"containment_failed":true,"checks":[]}`}}, 1},
		{[]string{"project", "list"}, []reply{{500, `{"code":"internal","message":"x"}`}}, 1},
	} {
		f := newFake(t, c.replies...)
		if _, _, code := f.run(t, c.args...); code != c.want {
			t.Errorf("%v: exit %d, want %d", c.args, code, c.want)
		}
	}
	// No daemon: exit 1 and nothing on stdout.
	var o, e bytes.Buffer
	if code := run([]string{"project", "list"}, client{sock: filepath.Join(t.TempDir(), "none")}, &o, &e); code != 1 || o.Len() != 0 {
		t.Fatalf("no daemon: exit %d stdout %q", code, o.String())
	}

	// Usage errors: exit 2, no request, nothing on stdout, usage on stderr.
	for _, args := range [][]string{
		nil,
		{"project"},
		{"project", "frobnicate"},
		{"nope", "list"},
		{"project", "list", "extra"},
		{"project", "show"},
		{"project", "show", "a", "b"},
		{"project", "show", ""},
		{"project", "show", "abcdefghij0123456789", "--no-wait"},
		{"project", "create", "--issuer-jwks", jf},
		{"project", "create", "--name", "d"},
		{"project", "create", "--name", "d", "--issuer-jwks", jf, "--ref", ""},
		{"project", "create", "--name", "d", "--issuer-jwks", jf, "--ref="},
		{"project", "create", "--name", "d", "--issuer-jwks", jf, "--disk-quota", "8x"},
		{"project", "create", "--name", "d", "--issuer-jwks", jf, "--disk-quota", ""},
		{"project", "create", "--name", "d", "--issuer-jwks", jf, "--disk-quota", "-1g"},
		{"project", "create", "--name", "d", "--issuer-jwks", jf, "--disk-quota", "99999999999999999999g"},
		{"project", "create", "--name", "d", "--issuer-jwks", jf, "--unknown"},
		{"project", "create", "--name", "d", "--issuer-jwks", jf, "positional"},
		{"project", "restart", "abcdefghij0123456789", "--set", "novalue"},
		{"project", "restart", "abcdefghij0123456789", "--set", "=v"},
		{"project", "restart", "abcdefghij0123456789", "--set", "a=1", "--set", "a=2"},
		{"project", "restart", "abcdefghij0123456789", "--set", "disk_quota_mb=lots"},
		{"op", "list", "a", "b"},
		{"op", "show"},
		{"node", "check", "x"},
	} {
		f := newFake(t, reply{200, `{}`})
		out, errOut, code := f.run(t, args...)
		if code != 2 || out != "" || len(f.requests()) != 0 || !strings.Contains(errOut, "usage") {
			t.Errorf("%q: exit %d stdout %q, %d requests", args, code, out, len(f.requests()))
		}
	}
}

func TestCLI_AbortExitsZeroOnAborted(t *testing.T) {
	for state, want := range map[string]int{"aborted": 0, "failed": 1, "done": 1} {
		f := newFake(t, reply{202, accepted}, reply{200, running}, reply{200, final(state)})
		out, _, code := f.run(t, "project", "abort", "abcdefghij0123456789")
		if code != want || out != final(state) {
			t.Errorf("abort ending %s: exit %d, want %d; stdout %q", state, code, want, out)
		}
	}
	f := newFake(t, reply{409, `{"code":"conflict","message":"x"}`})
	if _, _, code := f.run(t, "project", "abort", "abcdefghij0123456789"); code != 1 {
		t.Fatalf("abort refused: exit %d", code)
	}
}

// A runtime error is exit 2 with the error alone, no usage text.
func TestCLI_RuntimeErrorWithoutUsage(t *testing.T) {
	big := filepath.Join(t.TempDir(), "big.json")
	os.WriteFile(big, bytes.Repeat([]byte(" "), maxFile+1), 0o600)
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{"), 0o600)
	for _, file := range []string{filepath.Join(t.TempDir(), "missing"), big, bad} {
		f := newFake(t, reply{200, `{}`})
		out, errOut, code := f.run(t, "project", "create", "--name", "d", "--issuer-jwks", file)
		if code != 2 || out != "" || len(f.requests()) != 0 || strings.Contains(errOut, "usage") ||
			strings.Count(errOut, "\n") != 1 || !strings.Contains(errOut, file) {
			t.Errorf("%s: exit %d stdout %q stderr %q", file, code, out, errOut)
		}
	}
}

func TestCLI_Help(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		f := newFake(t, reply{200, `{}`})
		out, errOut, code := f.run(t, args...)
		if code != 0 || errOut != "" || len(f.requests()) != 0 || out != usageText() {
			t.Errorf("%q: exit %d stderr %q, %d requests", args, code, errOut, len(f.requests()))
		}
	}
	// A command's help is its own usage.
	for _, args := range [][]string{{"project", "create", "--help"}, {"project", "list", "-h"}, {"op", "retry", "12", "-help"}} {
		f := newFake(t, reply{200, `{}`})
		out, errOut, code := f.run(t, args...)
		if code != 0 || errOut != "" || len(f.requests()) != 0 || out != "usage:\n"+commandUsage(args[0]+" "+args[1]) {
			t.Errorf("%q: exit %d stdout %q stderr %q, %d requests", args, code, out, errOut, len(f.requests()))
		}
	}
	u := usageText()
	for _, s := range []string{"project create", "--name", "--issuer-jwks", "--ref", "--user-role", "--disk-quota",
		"--no-wait", "project list", "project show", "project keys", "project check", "project restart", "--set",
		"project delete", "project purge", "project abort", "op list", "op show", "op retry", "node check",
		"max_connections", "disk_quota_mb", "Exit status", "130"} {
		if !strings.Contains(u, s) {
			t.Errorf("usage lacks %q", s)
		}
	}
	// Missing or unknown commands: the error and a pointer to --help on stderr,
	// not the whole usage; exit 2.
	for _, args := range [][]string{nil, {"project"}, {"frob"}, {"project", "frob"}} {
		f := newFake(t, reply{200, `{}`})
		out, errOut, code := f.run(t, args...)
		if code != 2 || out != "" || strings.Count(errOut, "\n") != 2 || !strings.Contains(errOut, "supapace --help") {
			t.Errorf("%q: exit %d stdout %q", args, code, out)
		}
	}
}

func TestCLI_FlagsAroundPositionals(t *testing.T) {
	const ref = "abcdefghij0123456789"
	want := request{"POST", "/v1/projects/" + ref + "/restart", `{"set":{"a":"1","b":"2"}}`}
	for _, args := range [][]string{
		{"project", "restart", "--set", "a=1", ref, "--set", "b=2", "--no-wait"},
		{"project", "restart", "--no-wait", "--set", "a=1", "--set", "b=2", ref},
		{"project", "restart", ref, "--set", "a=1", "--no-wait", "--set", "b=2"},
	} {
		f := newFake(t, reply{202, accepted})
		if _, errOut, code := f.run(t, args...); code != 0 || len(f.requests()) != 1 || f.requests()[0] != want {
			t.Errorf("%q: exit %d %q %+v", args, code, errOut, f.requests())
		}
	}
}

func opJSON(state, step, lastError string) string {
	return `{"id":12,"ref":"abcdefghij0123456789","kind":"create","state":"` + state + `","step":"` + step +
		`","last_error":"` + lastError + `"}` + "\n"
}

func TestCLI_FailedOperationSummary(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, opJSON("running", "3", "")},
		reply{200, opJSON("failed", "4", "timeout: cluster did not answer")})
	out, errOut, code := f.run(t, "project", "create", "--name", "d", "--issuer-jwks", jwksFile(t))
	if code != 1 || out != opJSON("failed", "4", "timeout: cluster did not answer") {
		t.Fatalf("exit %d stdout %q", code, out)
	}
	for _, s := range []string{
		"operation 12 failed after step 4: timeout: cluster did not answer",
		"supapace op retry 12", "supapace project abort abcdefghij0123456789",
	} {
		if !strings.Contains(errOut, s) {
			t.Errorf("stderr lacks %q:\n%s", s, errOut)
		}
	}
	// A failed restart: retry only (abort is for creates).
	rf := strings.Replace(opJSON("failed", "R1", "internal: x"), `"create"`, `"restart"`, 1)
	f = newFake(t, reply{202, accepted}, reply{200, rf})
	_, errOut, code = f.run(t, "project", "restart", "abcdefghij0123456789")
	if code != 1 || !strings.Contains(errOut, "operation 12 failed after step R1: internal: x") ||
		!strings.Contains(errOut, "supapace op retry 12") || strings.Contains(errOut, "project abort") {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
	// Aborted while the command waited for done: a summary, no way on.
	f = newFake(t, reply{202, accepted}, reply{200, opJSON("aborted", "3", "")})
	_, errOut, code = f.run(t, "project", "create", "--name", "d", "--issuer-jwks", jwksFile(t))
	if code != 1 || !strings.Contains(errOut, "operation 12 aborted after step 3") || strings.Contains(errOut, "op retry") {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
	// Success prints no summary.
	f = newFake(t, reply{202, accepted}, reply{200, opJSON("done", "12", "")})
	if _, errOut, code = f.run(t, "project", "create", "--name", "d", "--issuer-jwks", jwksFile(t)); code != 0 ||
		strings.Contains(errOut, "failed") {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
}

func TestCLI_ProgressWording(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, opJSON("pending", "", "")}, reply{200, opJSON("running", "3", "")},
		reply{200, opJSON("pending", "3", "timeout: step 4: cluster not ready")},
		reply{200, opJSON("pending", "3", "timeout: step 4: cluster not ready")},
		reply{200, opJSON("running", "3", "timeout: step 4: cluster not ready")}, reply{200, opJSON("done", "12", "")})
	_, errOut, code := f.run(t, "project", "create", "--name", "d", "--issuer-jwks", jwksFile(t))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, s := range []string{"operation 12: pending, before its first step", "operation 12: running, after step 3",
		"operation 12: last error: timeout: step 4: cluster not ready"} {
		if !strings.Contains(errOut, s) {
			t.Errorf("stderr lacks %q:\n%s", s, errOut)
		}
	}
	if n := strings.Count(errOut, "last error"); n != 1 {
		t.Errorf("last error printed %d times:\n%s", n, errOut)
	}
	if strings.Contains(errOut, "at step") {
		t.Errorf("old wording:\n%s", errOut)
	}
}

func TestCLI_OutageGiveUpSaysOperationContinues(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, running})
	var o, e bytes.Buffer
	done := make(chan int)
	go func() {
		done <- run([]string{"project", "delete", "abcdefghij0123456789"},
			client{sock: f.sock, poll: 5 * time.Millisecond, outage: 50 * time.Millisecond}, &o, &e)
	}()
	for len(f.requests()) < 3 {
		time.Sleep(time.Millisecond)
	}
	f.srv.CloseClientConnections()
	f.srv.Close()
	os.Remove(f.sock)
	if code := <-done; code != 1 || o.String() != running ||
		!strings.Contains(e.String(), "operation 12 continues on the node; follow it with 'supapace op show 12'") ||
		!strings.Contains(e.String(), "still waiting") {
		t.Fatalf("exit %d stdout %q stderr %q", code, o.String(), e.String())
	}
}

func TestCLI_InterruptWhilePolling(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, running})
	var o, e bytes.Buffer
	done := make(chan int)
	go func() {
		done <- run([]string{"project", "delete", "abcdefghij0123456789"},
			client{sock: f.sock, poll: 5 * time.Millisecond, outage: time.Minute}, &o, &e)
	}()
	for len(f.requests()) < 3 {
		time.Sleep(time.Millisecond)
	}
	syscall.Kill(os.Getpid(), syscall.SIGINT)
	select {
	case code := <-done:
		if code != 130 || o.String() != running ||
			!strings.Contains(e.String(), "operation 12 continues on the node; follow it with 'supapace op show 12'") {
			t.Fatalf("exit %d stdout %q stderr %q", code, o.String(), e.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no exit after SIGINT")
	}
}

func TestCLI_SocketErrors(t *testing.T) {
	dir := t.TempDir()
	// Missing socket.
	missing := filepath.Join(dir, "none.sock")
	var o, e bytes.Buffer
	if code := run([]string{"project", "list"}, client{sock: missing}, &o, &e); code != 1 ||
		!strings.Contains(e.String(), "cannot reach "+missing) || !strings.Contains(e.String(), "is supapaced running?") {
		t.Fatalf("missing: exit %d %q", code, e.String())
	}
	// A socket nobody listens on.
	dead := filepath.Join(dir, "dead.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: dead, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	e.Reset()
	if code := run([]string{"project", "list"}, client{sock: dead}, &o, &e); code != 1 ||
		!strings.Contains(e.String(), "cannot reach "+dead+": connection refused (is supapaced running?)") {
		t.Fatalf("refused: exit %d %q", code, e.String())
	}
	// Permission denied (meaningless as root).
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket permissions")
	}
	f := newFake(t, reply{200, `{}`})
	os.Chmod(f.sock, 0)
	e.Reset()
	if code := run([]string{"project", "list"}, client{sock: f.sock}, &o, &e); code != 1 || o.Len() != 0 ||
		!strings.Contains(e.String(), "cannot reach "+f.sock+": permission denied (run as root)") {
		t.Fatalf("denied: exit %d %q", code, e.String())
	}
}

// interruptAfterFirstPoll returns a client whose first poll is followed by a
// SIGINT that is delivered before the CLI looks at the poll's answer.
func interruptAfterFirstPoll(sock string) client {
	var once sync.Once
	return client{sock: sock, poll: 5 * time.Millisecond, outage: time.Minute, polled: func() {
		once.Do(func() {
			syscall.Kill(os.Getpid(), syscall.SIGINT)
			time.Sleep(200 * time.Millisecond)
		})
	}}
}

// An interrupt right after a poll keeps that poll's body: a final one ends
// by its own rules, another one is printed with exit 130.
func TestCLI_InterruptAfterPollKeepsNewestBody(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, final("done")})
	var o, e bytes.Buffer
	if code := run([]string{"project", "delete", "abcdefghij0123456789"}, interruptAfterFirstPoll(f.sock), &o, &e); code != 0 ||
		o.String() != final("done") {
		t.Fatalf("final: exit %d stdout %q stderr %q", code, o.String(), e.String())
	}
	f = newFake(t, reply{202, accepted}, reply{200, running}, reply{200, final("done")})
	o.Reset()
	e.Reset()
	if code := run([]string{"project", "delete", "abcdefghij0123456789"}, interruptAfterFirstPoll(f.sock), &o, &e); code != 130 ||
		o.String() != running {
		t.Fatalf("running: exit %d stdout %q stderr %q", code, o.String(), e.String())
	}
}

// A signal before the mutation's answer: nothing on stdout, exit 130, and a
// hint that the request may have been accepted.
func TestCLI_InterruptDuringMutationRequest(t *testing.T) {
	for _, c := range []struct {
		args []string
		hint string
	}{
		{[]string{"project", "delete", "abcdefghij0123456789"}, "supapace op list abcdefghij0123456789"},
		{[]string{"project", "abort", "abcdefghij0123456789", "--no-wait"}, "supapace op list abcdefghij0123456789"},
		{[]string{"project", "create", "--name", "d", "--issuer-jwks", jwksFile(t), "--ref", "abcdefghij0123456789"},
			"supapace op list abcdefghij0123456789"},
		{[]string{"project", "create", "--name", "d", "--issuer-jwks", jwksFile(t), "--no-wait"}, "supapace op list'"},
		{[]string{"op", "retry", "12"}, "supapace op list'"},
	} {
		f := newFake(t, reply{})
		var o, e bytes.Buffer
		done := make(chan int)
		go func() { done <- run(c.args, client{sock: f.sock, poll: time.Millisecond, outage: time.Minute}, &o, &e) }()
		for len(f.requests()) < 1 {
			time.Sleep(time.Millisecond)
		}
		syscall.Kill(os.Getpid(), syscall.SIGINT)
		select {
		case code := <-done:
			if code != 130 || o.Len() != 0 || !strings.Contains(e.String(), "may already have been accepted") ||
				!strings.Contains(e.String(), c.hint) {
				t.Errorf("%q: exit %d stdout %q stderr %q", c.args, code, o.String(), e.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%q: no exit after SIGINT", c.args)
		}
	}
}

func TestCLI_DoubleDashEndsFlags(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"op", "list", "--", "-b"}, "/v1/operations?ref=-b"},
		{[]string{"project", "show", "--", "-x"}, "/v1/projects/-x"},
		{[]string{"project", "restart", "--set", "a=1", "--", "--no-wait"}, "/v1/projects/--no-wait/restart"},
	} {
		f := newFake(t, reply{200, `{}`})
		f.run(t, c.args...)
		if r := f.requests(); len(r) != 1 || r[0].uri != c.want {
			t.Errorf("%q: %+v", c.args, r)
		}
	}
	// Two positionals after "--" are still too many.
	f := newFake(t, reply{200, `{}`})
	if _, _, code := f.run(t, "op", "list", "--", "a", "-b"); code != 2 {
		t.Fatalf("exit %d", code)
	}
	// After "--" a valid flag is a positional too.
	if _, errOut, code := f.run(t, "project", "restart", "--", "abcdefghij0123456789", "--no-wait"); code != 2 ||
		len(f.requests()) != 0 || !strings.Contains(errOut, "wrong number of arguments") {
		t.Fatalf("exit %d %q, %d requests", code, errOut, len(f.requests()))
	}
}

func TestCLI_GroupHelp(t *testing.T) {
	for _, args := range [][]string{{"project", "help"}, {"project", "-h"}, {"op", "--help"}, {"node", "-help"}} {
		f := newFake(t, reply{200, `{}`})
		out, errOut, code := f.run(t, args...)
		if code != 0 || errOut != "" || out != usageText() || len(f.requests()) != 0 {
			t.Errorf("%q: exit %d stderr %q", args, code, errOut)
		}
	}
	for _, g := range []string{"project", "op", "node"} {
		f := newFake(t, reply{200, `{}`})
		out, errOut, code := f.run(t, g)
		if code != 2 || out != "" || !strings.Contains(errOut, "missing command") || strings.Contains(errOut, "Exit status") {
			t.Errorf("%s: exit %d stderr %q", g, code, errOut)
		}
	}
}

// TestCLI_UsageErrorShowsTheCommandOnly: a malformed command prints the
// error, that command's usage and a pointer to --help, not the whole text.
func TestCLI_UsageErrorShowsTheCommandOnly(t *testing.T) {
	f := newFake(t, reply{200, `{}`})
	out, errOut, code := f.run(t, "project", "restart", "abcdefghij0123456789", "--frob")
	want := "supapace: project restart: flag provided but not defined: -frob\nusage:\n" +
		commandUsage("project restart") + "see 'supapace --help' for the usage of every command\n"
	if code != 2 || out != "" || errOut != want {
		t.Fatalf("exit %d stdout %q stderr:\n%s\nwant:\n%s", code, out, errOut, want)
	}
	if u := commandUsage("project restart"); !strings.HasPrefix(u, "  project restart REF") || !strings.Contains(u, "max_connections") ||
		strings.Contains(u, "project delete") {
		t.Fatalf("command usage %q", u)
	}
	if commandUsage("node check") != "  node check\n" || commandUsage("project frob") != "" {
		t.Fatalf("node check %q", commandUsage("node check"))
	}
}

// TestCLI_HelpSaysWhatKeysAndTokensAre: the help of create, keys and show
// explains how tokens are signed, what each key is for and that show's state
// is not health.
func TestCLI_HelpSaysWhatKeysAndTokensAre(t *testing.T) {
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for verb, wants := range map[string][]string{
		"project create": {"no shared secret", "RS256", `"kid"`, `"role"`, `"exp"`, "Authorization: Bearer",
			"create role editor nologin", "grant editor to authenticator"},
		"project keys": {"url", "ca_cert", "anon_key", "client applications", "service_role_key", "trusted servers",
			"postgres_password", "docker exec -it pg-REF psql -h 127.0.0.1 -U postgres", "psql asks for it"},
		"project show": {"not health", "project check"},
		"project list": {"--state STATE", "aborted"},
	} {
		u := flat(commandUsage(verb))
		for _, w := range wants {
			if !strings.Contains(u, w) {
				t.Errorf("%s: usage lacks %q", verb, w)
			}
		}
	}
}

func TestCLI_ListStateFilter(t *testing.T) {
	f := newFake(t, reply{200, `{"projects":[]}`})
	if _, _, code := f.run(t, "project", "list", "--state", "active", "--state", "deleted"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if r := f.requests(); len(r) != 1 || r[0].uri != "/v1/projects?state=active&state=deleted" {
		t.Fatalf("requests %+v", r)
	}
}

// TestCLI_CreateSaysWhereToLook: a create that succeeded points at project
// keys and, for user roles other than authenticated, says they must exist.
func TestCLI_CreateSaysWhereToLook(t *testing.T) {
	jf := jwksFile(t)
	f := newFake(t, reply{202, accepted}, reply{200, final("done")})
	_, errOut, code := f.run(t, "project", "create", "--name", "d", "--issuer-jwks", jf, "--user-role", "authenticated",
		"--user-role", "editor")
	if code != 0 || !strings.Contains(errOut, "'supapace project keys abcdefghij0123456789'") ||
		!strings.Contains(errOut, "role(s) editor once each exists") {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
	f = newFake(t, reply{202, accepted})
	_, errOut, code = f.run(t, "project", "create", "--name", "d", "--issuer-jwks", jf, "--no-wait")
	if code != 0 || !strings.Contains(errOut, "abcdefghij0123456789 is being created; follow it with 'supapace op show 12'; once it is done") ||
		strings.Contains(errOut, "role") {
		t.Fatalf("no-wait: exit %d stderr %q", code, errOut)
	}
	// Nothing on a failure, nor for other commands.
	f = newFake(t, reply{202, accepted}, reply{200, final("failed")})
	if _, errOut, _ = f.run(t, "project", "create", "--name", "d", "--issuer-jwks", jf); strings.Contains(errOut, "project keys") {
		t.Fatalf("failed create: %q", errOut)
	}
	f = newFake(t, reply{202, accepted}, reply{200, final("done")})
	if _, errOut, _ = f.run(t, "project", "delete", "abcdefghij0123456789"); strings.Contains(errOut, "project keys") {
		t.Fatalf("delete: %q", errOut)
	}
}

// TestCLI_EmptyStepWording: an operation that has completed no step is
// "before its first step", never "after step ".
func TestCLI_EmptyStepWording(t *testing.T) {
	df := strings.Replace(opJSON("failed", "", "internal: x"), `"create"`, `"delete"`, 1)
	f := newFake(t, reply{202, accepted}, reply{200, df})
	_, errOut, code := f.run(t, "project", "delete", "abcdefghij0123456789")
	if code != 1 || !strings.Contains(errOut, "operation 12 failed before its first step: internal: x") ||
		strings.Contains(errOut, "after step") {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
}
