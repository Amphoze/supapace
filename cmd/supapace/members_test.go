package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mref = "abcdefghij0123456789"

func memberDoc(role, prev, serviceKey, extra string) string {
	r := "null"
	if role != "" {
		r = `"` + role + `"`
	}
	p := "null"
	if prev != "" {
		p = `"` + prev + `"`
	}
	return `{"ref":"` + mref + `","issuer":"https://id.example.test","subject":"alice","role":` + r + `,"previous_role":` + p +
		`,"service_key":"` + serviceKey + `"` + extra + `,"dashboard_generation":17}` + "\n"
}

func TestCLI_MemberAndDashboardCommands(t *testing.T) {
	jf := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jf, []byte(`{"keys":[{"kty":"RSA","kid":"a"},{"kty":"EC","kid":"b"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := "/v1/projects/" + mref
	for _, c := range []struct {
		args []string
		want request
	}{
		{[]string{"member", "add", mref, "--subject", "alice", "--role", "owner"},
			request{"POST", p + "/members", `{"subject":"alice","role":"owner"}`}},
		{[]string{"member", "add", "--issuer", "https://id.example.test", mref, "--subject", "a/b?c", "--role", "read_only"},
			request{"POST", p + "/members", `{"issuer":"https://id.example.test","subject":"a/b?c","role":"read_only"}`}},
		{[]string{"member", "set-role", mref, "--subject", "alice", "--role", "developer"},
			request{"POST", p + "/members/role", `{"subject":"alice","role":"developer"}`}},
		{[]string{"member", "set-role", mref, "--subject", "alice", "--role", "developer", "--keep-service-key"},
			request{"POST", p + "/members/role", `{"subject":"alice","role":"developer","service_key":"keep"}`}},
		{[]string{"member", "remove", mref, "--subject", "alice"},
			request{"POST", p + "/members/remove", `{"subject":"alice"}`}},
		{[]string{"member", "remove", mref, "--subject", "alice", "--issuer", "i", "--rotate-service-key"},
			request{"POST", p + "/members/remove", `{"issuer":"i","subject":"alice","service_key":"rotate"}`}},
		{[]string{"member", "list", mref}, request{"GET", p + "/members", ""}},
		{[]string{"member", "clean-jobs", mref}, request{"POST", p + "/members/clean-jobs", ""}},
		{[]string{"dashboard", "issuer", "set", "--issuer", "https://id.example.test", "--client-id", "studio",
			"--authorize-url", "https://id.example.test/authorize", "--jwks", jf},
			request{"PUT", "/v1/dashboard/issuer", `{"issuer":"https://id.example.test","client_id":"studio","authorize_url":"https://id.example.test/authorize","jwks":{"keys":[{"kty":"RSA","kid":"a"},{"kty":"EC","kid":"b"}]}}`}},
		{[]string{"dashboard", "issuer", "set", "--issuer", "i", "--client-id", "c", "--authorize-url", "https://a",
			"--jwks", jf, "--end-session-url", "https://e", "--session-hours", "2"},
			request{"PUT", "/v1/dashboard/issuer", `{"issuer":"i","client_id":"c","authorize_url":"https://a","end_session_url":"https://e","session_seconds":7200,"jwks":{"keys":[{"kty":"RSA","kid":"a"},{"kty":"EC","kid":"b"}]}}`}},
		{[]string{"dashboard", "issuer", "show"}, request{"GET", "/v1/dashboard/issuer", ""}},
		{[]string{"dashboard", "revoke", "https://id.example.test", "alice"},
			request{"POST", "/v1/dashboard/revocations", `{"issuer":"https://id.example.test","subject":"alice"}`}},
		{[]string{"dashboard", "show"}, request{"GET", "/v1/dashboard", ""}},
		{[]string{"project", "rotate-key", mref, "--service"}, request{"POST", p + "/service-key/rotate", ""}},
		{[]string{"project", "audit", mref}, request{"GET", p + "/audit", ""}},
		{[]string{"project", "audit", mref, "--tail", "5"}, request{"GET", p + "/audit?tail=5", ""}},
	} {
		body := `{"ok":"whatever the API says","in_force":true}` + "\n"
		f := newFake(t, reply{200, body})
		out, _, code := f.run(t, c.args...)
		if code != 0 || out != body {
			t.Fatalf("%q: exit %d, stdout %q", c.args, code, out)
		}
		if r := f.requests(); len(r) != 1 || r[0] != c.want {
			t.Fatalf("%q: requests %+v, want %+v", c.args, r, c.want)
		}
	}
	// An API error: the body on stdout, exit 1.
	errBody := `{"code":"conflict","message":"this node has no studio domain"}` + "\n"
	for _, args := range [][]string{{"member", "list", mref}, {"member", "add", mref, "--subject", "a", "--role", "owner"},
		{"dashboard", "issuer", "show"}, {"project", "audit", mref}} {
		f := newFake(t, reply{409, errBody})
		if out, _, code := f.run(t, args...); code != 1 || out != errBody {
			t.Fatalf("%q: %d %q", args, code, out)
		}
	}
	// Usage errors: nothing is sent.
	for _, args := range [][]string{
		{"member", "add", mref, "--role", "owner"},
		{"member", "add", mref, "--subject", "a"},
		{"member", "add", mref, "--subject", "a", "--role", "owner", "--issuer", ""},
		{"member", "add", "--subject", "a", "--role", "owner"},
		{"member", "set-role", mref, "--subject", "a"},
		{"member", "remove", mref, "--subject", "a", "--keep-service-key", "--rotate-service-key"},
		{"member", "remove", mref},
		{"member", "list"},
		{"member", "frob", mref},
		{"dashboard", "revoke", "only-one"},
		{"dashboard", "issuer", "set", "--issuer", "i", "--client-id", "c", "--authorize-url", "u"},
		{"dashboard", "issuer", "set", "--issuer", "i", "--client-id", "c", "--authorize-url", "u", "--jwks", jf, "--session-hours", "9"},
		{"dashboard", "issuer", "set", "--issuer", "i", "--client-id", "c", "--authorize-url", "u", "--jwks", jf, "--session-hours", "0"},
		{"dashboard", "issuer"},
		{"dashboard", "issuer", "frob"},
		{"project", "audit", mref, "--tail", "x"},
	} {
		f := newFake(t, reply{200, "{}\n"})
		out, stderr, code := f.run(t, args...)
		if code != 2 || out != "" || len(f.requests()) != 0 || !strings.HasPrefix(stderr, "supapace: ") {
			t.Fatalf("%q: exit %d, stdout %q, stderr %q", args, code, out, stderr)
		}
	}
}

func TestCLI_Usage(t *testing.T) {
	u := usageText()
	for _, verb := range []string{"member add", "member set-role", "member remove", "member list", "member clean-jobs",
		"dashboard issuer set", "dashboard issuer show", "dashboard revoke", "dashboard show", "project rotate-key",
		"project audit"} {
		if !strings.Contains(u, "\n  "+verb+" ") && !strings.Contains(u, "\n  "+verb+"\n") {
			t.Errorf("usage lacks %q", verb)
		}
		args := append(strings.Fields(verb), "--help")
		f := newFake(t, reply{200, "{}\n"})
		out, _, code := f.run(t, args...)
		if code != 0 || !strings.HasPrefix(out, "usage:\n  "+verb) {
			t.Errorf("%s --help: %d %q", verb, code, out)
		}
	}
	for _, s := range []string{
		"supapace dashboard revoke", // how a session ends for good
		"--keep-service-key",        // what keeps a removal reversible
		"server-side clients",       // who must take a new key
		"scheduled jobs",            // what a read_only removal deletes
		"not_in_force",              // what a non-zero exit after a commit means
		"exits 0 only when",         // dashboard show's exit
	} {
		if !strings.Contains(u, s) {
			t.Errorf("usage lacks %q", s)
		}
	}
	for _, l := range strings.Split(u, "\n") {
		if len(l) > 80 {
			t.Errorf("usage line over 80 columns: %q", l)
		}
	}
	// The group words take --help too.
	for _, g := range []string{"member", "dashboard"} {
		f := newFake(t, reply{200, "{}\n"})
		if out, _, code := f.run(t, g, "--help"); code != 0 || out != u {
			t.Errorf("%s --help: %d", g, code)
		}
	}
}

const wantRevokeHint = "supapace: if this principal was removed in the last eight hours, a session cookie it kept is valid again; " +
	"'supapace dashboard revoke ISSUER SUBJECT' ends it\n"

func TestCLI_MemberAdd_PrintsTheRevokeHint(t *testing.T) {
	doc := memberDoc("owner", "", "unchanged", `,"rotation":null,"still_valid":null,"jobs":null`)
	f := newFake(t, reply{200, doc})
	out, stderr, code := f.run(t, "member", "add", mref, "--subject", "alice", "--role", "owner")
	if code != 0 || out != doc || stderr != wantRevokeHint {
		t.Fatalf("%d %q %q", code, out, stderr)
	}
	// Committed and not in force: still the hint, and the not-in-force lines.
	nif := `{"code":"not_in_force","message":"committed; not yet in force: dashboard file: disk full",` + doc[1:]
	f = newFake(t, reply{503, nif})
	out, stderr, code = f.run(t, "member", "add", mref, "--subject", "alice", "--role", "owner")
	if code != 1 || out != nif || !strings.Contains(stderr, wantRevokeHint) || !strings.Contains(stderr, "committed; not yet in force") {
		t.Fatalf("%d %q %q", code, out, stderr)
	}
	// A refused add: its error, not the hint.
	refused := `{"code":"conflict","message":"the principal is already a member"}` + "\n"
	f = newFake(t, reply{409, refused})
	out, stderr, code = f.run(t, "member", "add", mref, "--subject", "alice", "--role", "owner")
	if code != 1 || out != refused || strings.Contains(stderr, "revoke") {
		t.Fatalf("%d %q %q", code, out, stderr)
	}
}

func TestCLI_RotationWarningOnStderr(t *testing.T) {
	rotated := memberDoc("", "owner", "rotated", `,"rotation":{"gateway":"done","rest":"done"},"still_valid":null,"jobs":null`)
	f := newFake(t, reply{200, rotated})
	out, stderr, code := f.run(t, "member", "remove", mref, "--subject", "alice")
	if code != 0 || out != rotated {
		t.Fatalf("%d %q", code, out)
	}
	if !strings.Contains(stderr, "server-side clients must take the new key") || !strings.Contains(stderr, "supapace project keys "+mref) {
		t.Fatalf("%q", stderr)
	}
	// Before the request: what the removal does by default.
	if !strings.HasPrefix(stderr, "supapace: removing a member") {
		t.Fatalf("%q", stderr)
	}
	// Kept: the still_valid text.
	sv := "the service_role key of project " + mref + " that this owner could read stays valid"
	kept := memberDoc("", "owner", "kept", `,"rotation":null,"still_valid":"`+sv+`","jobs":null`)
	f = newFake(t, reply{200, kept})
	_, stderr, code = f.run(t, "member", "remove", mref, "--subject", "alice", "--keep-service-key")
	if code != 0 || !strings.Contains(stderr, sv) || strings.Contains(stderr, "must take the new key") {
		t.Fatalf("%d %q", code, stderr)
	}
	// Unchanged: no word on keys.
	plain := memberDoc("", "developer", "unchanged", `,"rotation":null,"still_valid":null,"jobs":null`)
	f = newFake(t, reply{200, plain})
	_, stderr, _ = f.run(t, "member", "remove", mref, "--subject", "alice")
	if strings.Contains(stderr, "must take the new key") {
		t.Fatalf("%q", stderr)
	}
	// An owed signal is a success that says what follows.
	owed := memberDoc("developer", "owner", "rotated", `,"rotation":{"gateway":"done","rest":"owed: signal follows"},"still_valid":null,"jobs":null`)
	f = newFake(t, reply{200, owed})
	_, stderr, code = f.run(t, "member", "set-role", mref, "--subject", "alice", "--role", "developer")
	if code != 0 || !strings.Contains(stderr, "must take the new key") {
		t.Fatalf("%d %q", code, stderr)
	}
	// project rotate-key says it too.
	rk := `{"ref":"` + mref + `","service_key":"rotated","rotation":{"gateway":"done","rest":"done"}}` + "\n"
	f = newFake(t, reply{200, rk})
	out, stderr, code = f.run(t, "project", "rotate-key", mref, "--service")
	if code != 0 || out != rk || !strings.Contains(stderr, "must take the new key") {
		t.Fatalf("%d %q %q", code, out, stderr)
	}
	// Control characters in what the daemon sent are not printed.
	evil := memberDoc("", "owner", "kept", `,"rotation":null,"still_valid":"ok\u001b[2Jcleared‮","jobs":null`)
	f = newFake(t, reply{200, evil})
	_, stderr, _ = f.run(t, "member", "remove", mref, "--subject", "alice", "--keep-service-key")
	if strings.ContainsAny(stderr, "\x1b‮") || !strings.Contains(stderr, "ok[2Jcleared") {
		t.Fatalf("%q", stderr)
	}
}

func TestCLI_RotateKeyNeedsService(t *testing.T) {
	f := newFake(t, reply{200, "{}\n"})
	out, stderr, code := f.run(t, "project", "rotate-key", mref)
	if code != 2 || out != "" || len(f.requests()) != 0 || !strings.Contains(stderr, "--service") {
		t.Fatalf("%d %q %q", code, out, stderr)
	}
}

func TestCLI_NotInForce_NonZeroExitAndTheLine(t *testing.T) {
	for _, c := range []struct {
		name, body string
		args       []string
		jobs       bool
	}{
		{"push failed", `{"code":"not_in_force","message":"committed; not yet in force: dashboard file: disk full",` +
			memberDoc("", "developer", "unchanged", `,"rotation":null,"still_valid":null,"jobs":null`)[1:], []string{"member", "remove", mref, "--subject", "alice"}, false},
		{"jobs not run", `{"code":"not_in_force","message":"committed; not yet in force: dashboard file: disk full",` +
			memberDoc("", "read_only", "unchanged", `,"rotation":null,"still_valid":null,"jobs":"not run: dashboard not in force"`)[1:], []string{"member", "remove", mref, "--subject", "alice"}, true},
		{"jobs failed", `{"code":"not_in_force","message":"committed; not yet in force: read-only clean-up: timeout",` +
			memberDoc("developer", "read_only", "unchanged", `,"rotation":null,"still_valid":null,"jobs":"failed: timeout"`)[1:], []string{"member", "set-role", mref, "--subject", "alice", "--role", "developer"}, true},
		{"revocation", `{"code":"not_in_force","message":"committed; not yet in force: dashboard file: disk full","issuer":"i","subject":"s","not_before":"2026-11-19T10:00:00Z","dashboard_generation":null}` + "\n",
			[]string{"dashboard", "revoke", "i", "s"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t, reply{503, c.body})
			out, stderr, code := f.run(t, c.args...)
			if code != 1 || out != c.body {
				t.Fatalf("%d %q", code, out)
			}
			line := strings.Index(stderr, "supapace: committed; not yet in force: ")
			jobs := strings.Index(stderr, "supapace: the read-only role's sessions and scheduled jobs are not yet cleaned; the daemon retries\n")
			// The second line: what is still admitted (a file not written), or
			// the retry of a clean-up that failed.
			second := "supapace: the gateway still applies the previous member, issuer and revocation table: until the daemon writes " +
				"the file, a removed or revoked principal is still admitted and an added one is not; the daemon retries in each " +
				"round, and 'supapace dashboard show' exits 0 once it is in force\n"
			if strings.Contains(c.body, "read-only clean-up: ") {
				second = "supapace: the daemon retries; 'supapace dashboard show' tells when it is\n"
			}
			retries := strings.Index(stderr, second)
			if line < 0 || retries < line || (jobs >= 0) != c.jobs || c.jobs && jobs < line {
				t.Fatalf("%q", stderr)
			}
		})
	}
	// clean-jobs: no commit to speak of; the line says what did not run.
	body := `{"code":"not_in_force","message":"the read-only clean-up did not run: dashboard not in force","ref":"` + mref + `","jobs":"not run: dashboard not in force"}` + "\n"
	f := newFake(t, reply{503, body})
	out, stderr, code := f.run(t, "member", "clean-jobs", mref)
	if code != 1 || out != body || !strings.Contains(stderr, "supapace: the read-only clean-up did not run: dashboard not in force\n") ||
		strings.Contains(stderr, "committed") {
		t.Fatalf("%d %q", code, stderr)
	}
}

func TestCLI_DashboardShow_ExitFollowsInForce(t *testing.T) {
	in := `{"studio_domain":"studio.example.test","in_force":true,"dashboard_generation":5,"members":2,"revocations":0}` + "\n"
	out := `{"studio_domain":"studio.example.test","in_force":false,"dashboard_generation":null,"members":2,"revocations":0}` + "\n"
	f := newFake(t, reply{200, in})
	if o, stderr, code := f.run(t, "dashboard", "show"); code != 0 || o != in || stderr != "" {
		t.Fatalf("%d %q %q", code, o, stderr)
	}
	f = newFake(t, reply{200, out})
	o, stderr, code := f.run(t, "dashboard", "show")
	if code != 1 || o != out || !strings.Contains(stderr, "not in force") {
		t.Fatalf("%d %q %q", code, o, stderr)
	}
	f = newFake(t, reply{200, "not json\n"})
	if _, _, code := f.run(t, "dashboard", "show"); code != 1 {
		t.Fatalf("%d", code)
	}
}

func TestCLI_MemberList_Readable(t *testing.T) {
	body := `{"ref":"` + mref + `","members":[{"issuer":"https://id.example.test","subject":"alice","role":"owner","added_at":"2026-11-19T10:00:00Z"},` +
		`{"issuer":"https://id.example.test","subject":"b\u001b[31m","role":"read_only","added_at":"2026-11-19T11:00:00Z"}]}` + "\n"
	f := newFake(t, reply{200, body})
	out, stderr, code := f.run(t, "member", "list", mref)
	if code != 0 || out != body {
		t.Fatalf("%d %q", code, out)
	}
	if !strings.Contains(stderr, "owner      alice  (https://id.example.test) since 2026-11-19T10:00:00Z") ||
		!strings.Contains(stderr, "read_only  b[31m") || strings.Contains(stderr, "\x1b") {
		t.Fatalf("%q", stderr)
	}
	empty := `{"ref":"` + mref + `","members":[]}` + "\n"
	f = newFake(t, reply{200, empty})
	_, stderr, _ = f.run(t, "member", "list", mref)
	if !strings.Contains(stderr, "no members") || !strings.Contains(stderr, "supapace member add "+mref) {
		t.Fatalf("%q", stderr)
	}
}

// A rotation step that failed is not something 'dashboard show' reports.
func TestCLI_NotInForce_RotationLine(t *testing.T) {
	body := `{"code":"not_in_force","message":"committed; not yet in force: service-key rotation: rest: permission denied","ref":"` + mref +
		`","service_key":"rotated","rotation":{"gateway":"done","rest":"failed: permission denied"}}` + "\n"
	f := newFake(t, reply{503, body})
	out, stderr, code := f.run(t, "project", "rotate-key", mref, "--service")
	if code != 1 || out != body || !strings.Contains(stderr, "the rotation is not complete: until the daemon's next rounds finish it, the gateway or the REST service may still accept the old key") ||
		strings.Contains(stderr, "dashboard show") || !strings.Contains(stderr, "must take the new key") {
		t.Fatalf("%d %q", code, stderr)
	}
}

// Nothing claims the old key is refused before an answer without an error.
func TestCLI_RotateKey_NoPromiseBeforeTheAnswer(t *testing.T) {
	f := newFake(t, reply{200, `{"ref":"` + mref + `","service_key":"rotated","rotation":{"gateway":"done","rest":"done"}}` + "\n"})
	_, stderr, _ := f.run(t, "project", "rotate-key", mref, "--service")
	if !strings.HasPrefix(stderr, "supapace: rotating the project's service_role key; this cannot be undone\n") {
		t.Fatalf("%q", stderr)
	}
	u := usageText()
	if strings.Contains(u, "from the answer on") || strings.Contains(stderr, "from the answer on") {
		t.Fatal("an unconditional promise remains")
	}
	for _, s := range []string{
		"Once the command answers without an error the gateway refuses the old key",
		"An answer not_in_force (exit 1) means the change is stored but the gateway still admits the member",
		"A developer's removal rotates nothing by default",
		"what an owner or developer did in the database as postgres stays",
		"member add and a role change that raises a role are refused",
	} {
		if !strings.Contains(strings.Join(strings.Fields(u), " "), s) {
			t.Errorf("usage lacks %q", s)
		}
	}
}

// A developer whose membership ends or is lowered without a rotation is told
// that a key it may hold stays valid; a raised one is not.
func TestCLI_DeveloperEnded_KeyLine(t *testing.T) {
	line := "the service_role key of project " + mref + " was not rotated; a developer may have captured it from the project's traffic: 'supapace project rotate-key " + mref + " --service' rotates it"
	for _, c := range []struct {
		role string
		want bool
	}{{"", true}, {"read_only", true}, {"owner", false}} {
		doc := memberDoc(c.role, "developer", "unchanged", `,"rotation":null,"still_valid":null,"jobs":null`)
		f := newFake(t, reply{200, doc})
		args := []string{"member", "remove", mref, "--subject", "alice"}
		if c.role != "" {
			args = []string{"member", "set-role", mref, "--subject", "alice", "--role", c.role}
		}
		_, stderr, code := f.run(t, args...)
		if code != 0 || strings.Contains(stderr, line) != c.want {
			t.Fatalf("%q: %q", c.role, stderr)
		}
	}
	// Rotated: no such line.
	f := newFake(t, reply{200, memberDoc("", "developer", "rotated", `,"rotation":{"gateway":"done","rest":"done"},"still_valid":null,"jobs":null`)})
	if _, stderr, _ := f.run(t, "member", "remove", mref, "--subject", "alice", "--rotate-service-key"); strings.Contains(stderr, "was not rotated") {
		t.Fatalf("%q", stderr)
	}
}

// Interrupted or cut off after the request was sent, a member command says
// where to look, the file's state included.
func TestCLI_MemberTransportError_SaysWhereToLook(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "admin.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Read(make([]byte, 4096)) // the request, then nothing
			c.Close()
		}
	}()
	var o, e bytes.Buffer
	code := run([]string{"member", "remove", mref, "--subject", "a"}, client{sock: sock, poll: time.Millisecond, outage: time.Second}, &o, &e)
	if code != 1 || o.Len() != 0 || !strings.Contains(e.String(), "may already have been accepted; look with 'supapace member list "+mref+"' and 'supapace dashboard show'") {
		t.Fatalf("%d %q", code, e.String())
	}
}

// A clean-up left to the round because containment is not verified points at
// node check, not at dashboard show; the help says when the clean-up runs.
func TestCLI_ContainmentCleanupLine(t *testing.T) {
	body := `{"code":"not_in_force","message":"committed; not yet in force: read-only clean-up: not run: the node's containment is not verified; ` +
		`the daemon runs it from the owed record once it is",` +
		memberDoc("", "read_only", "unchanged", `,"rotation":null,"still_valid":null,"jobs":"not run: containment not verified"`)[1:]
	f := newFake(t, reply{503, body})
	_, stderr, code := f.run(t, "member", "remove", mref, "--subject", "alice")
	if code != 1 || !strings.Contains(stderr, "supapace: the daemon runs the clean-up once 'supapace node check' reports the node's containment verified\n") ||
		strings.Contains(stderr, "'supapace dashboard show' tells when it is") {
		t.Fatalf("%d %q", code, stderr)
	}
	if u := strings.Join(strings.Fields(usageText()), " "); !strings.Contains(u,
		"The daemon runs this clean-up before the command answers (while the node's containment is not verified, only once it is)") {
		t.Fatal("usage lacks when the clean-up runs")
	}
}
