package main

import (
	"strings"
	"testing"
)

const bkRef = "abcdefghij0123456789"

func restoreOp(state, step, lastError string) string {
	return `{"id":12,"ref":"` + bkRef + `","kind":"restore","state":"` + state + `","step":"` + step +
		`","last_error":"` + lastError + `","result":null}` + "\n"
}

func TestCLI_RestoreFlags(t *testing.T) {
	path := "/v1/projects/" + bkRef + "/restore"
	for _, c := range []struct {
		args []string
		body string
	}{
		{[]string{"project", "restore", bkRef, "--to", "latest", "--no-wait"}, `{"to":"latest"}`},
		{[]string{"project", "restore", "--to", "0/16B3748", "--no-wait", bkRef}, `{"to":"0/16B3748"}`},
		{[]string{"project", "restore", bkRef, "--to", "2026-11-18T10:43:32Z", "--timeline", "2", "--from", "offsite", "--no-wait"},
			`{"to":"2026-11-18T10:43:32Z","timeline":2,"from":"offsite"}`},
		{[]string{"project", "restore", bkRef, "--from", "local", "--to", "latest", "--no-wait"}, `{"to":"latest","from":"local"}`},
		// The API refuses these with bad_request; the CLI passes what it can read.
		{[]string{"project", "restore", bkRef, "--to", "now", "--timeline", "0", "--from", "remote", "--no-wait"},
			`{"to":"now","timeline":0,"from":"remote"}`},
	} {
		f := newFake(t, reply{202, accepted})
		_, errOut, code := f.run(t, c.args...)
		want := request{"POST", path, c.body}
		if got := f.requests(); code != 0 || len(got) != 1 || got[0] != want {
			t.Errorf("%v: exit %d %q\n got %+v\nwant %+v", c.args, code, errOut, got, want)
		}
	}
	// Usage errors: nothing is sent, exit 2.
	for _, args := range [][]string{
		{"project", "restore", bkRef},
		{"project", "restore", bkRef, "--to", ""},
		{"project", "restore", bkRef, "--to", "latest", "--timeline", "two"},
		{"project", "restore", bkRef, "--to", "latest", "--timeline", ""},
		{"project", "restore", "--to", "latest"},
		{"project", "restore", bkRef, bkRef, "--to", "latest"},
		{"project", "restore", bkRef, "--to", "latest", "--as-of", "x"},
	} {
		f := newFake(t, reply{202, accepted})
		out, errOut, code := f.run(t, args...)
		if code != 2 || out != "" || len(f.requests()) != 0 || !strings.Contains(errOut, "project restore REF --to") {
			t.Errorf("%v: exit %d stdout %q stderr %q", args, code, out, errOut)
		}
	}
	// Without --no-wait the restore is followed to its end.
	f := newFake(t, reply{202, accepted}, reply{200, restoreOp("waiting_job", "T4p", "")}, reply{200, restoreOp("done", "T11", "")})
	out, errOut, code := f.run(t, "project", "restore", bkRef, "--to", "latest")
	if code != 0 || out != restoreOp("done", "T11", "") || !strings.Contains(errOut, "operation 12: waiting_job, after step T4p") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errOut)
	}
}

func TestCLI_CreateLayoutFlag(t *testing.T) {
	jf := jwksFile(t)
	for _, c := range []struct {
		args []string
		body string
	}{
		{[]string{"--layout", "1"}, `{"name":"demo","issuer_jwks":{"keys":[]},"layout":1}`},
		{[]string{"--layout", "2"}, `{"name":"demo","issuer_jwks":{"keys":[]},"layout":2}`},
		{[]string{"--upload-per-day", "100", "--upload-objects-per-day", "9000"},
			`{"name":"demo","issuer_jwks":{"keys":[]},"upload_mb_per_day":100,"upload_objects_per_day":9000}`},
		{[]string{"--upload-per-day", "16g"}, `{"name":"demo","issuer_jwks":{"keys":[]},"upload_mb_per_day":16384}`},
		{[]string{"--upload-per-day", "0"}, `{"name":"demo","issuer_jwks":{"keys":[]},"upload_mb_per_day":0}`},
		{nil, `{"name":"demo","issuer_jwks":{"keys":[]}}`},
	} {
		f := newFake(t, reply{202, accepted})
		args := append([]string{"project", "create", "--name", "demo", "--issuer-jwks", jf, "--no-wait"}, c.args...)
		_, errOut, code := f.run(t, args...)
		want := request{"POST", "/v1/projects", c.body}
		if got := f.requests(); code != 0 || len(got) != 1 || got[0] != want {
			t.Errorf("%v: exit %d %q\n got %+v\nwant %+v", c.args, code, errOut, got, want)
		}
	}
	for _, extra := range [][]string{{"--layout", "one"}, {"--layout", ""}, {"--upload-per-day", "1.5g"}, {"--upload-per-day", "512k"}, {"--upload-per-day", "-1"},
		{"--upload-objects-per-day", "x"}} {
		f := newFake(t, reply{202, accepted})
		args := append([]string{"project", "create", "--name", "demo", "--issuer-jwks", jf, "--no-wait"}, extra...)
		_, errOut, code := f.run(t, args...)
		if code != 2 || len(f.requests()) != 0 {
			t.Errorf("%v: exit %d", extra, code)
		}
		if extra[0] == "--upload-per-day" && !strings.Contains(errOut, "want whole MiB") {
			t.Errorf("%v: %q", extra, errOut)
		}
	}
	// A restart takes the two upload settings through --set.
	f := newFake(t, reply{202, accepted})
	f.run(t, "project", "restart", bkRef, "--set", "upload_per_day=2g", "--set", "upload_objects_per_day=0", "--no-wait")
	if got := f.requests(); len(got) != 1 || got[0].body != `{"upload_mb_per_day":2048,"upload_objects_per_day":0}` {
		t.Fatalf("%+v", got)
	}
	for _, s := range []string{"upload_per_day=x", "upload_per_day=1.5g", "upload_per_day=1", "upload_objects_per_day="} {
		f := newFake(t, reply{202, accepted})
		args := []string{"project", "restart", bkRef, "--set", s, "--no-wait"}
		if s == "upload_per_day=1" {
			args = append(args, "--set", s) // given twice
		}
		_, errOut, code := f.run(t, args...)
		if code != 2 || len(f.requests()) != 0 {
			t.Errorf("--set %s: exit %d", s, code)
		}
		if strings.HasPrefix(s, "upload_per_day=") && s != "upload_per_day=1" && !strings.Contains(errOut, "want whole MiB") {
			t.Errorf("--set %s: %q", s, errOut)
		}
	}
}

func TestCLI_SupersededIsFinalAndExits1(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, restoreOp("running", "T5", "")},
		reply{200, restoreOp("superseded", "T6", "history_mismatch: x")}, reply{200, restoreOp("done", "T11", "")})
	out, errOut, code := f.run(t, "project", "restore", bkRef, "--to", "latest")
	if code != 1 || out != restoreOp("superseded", "T6", "history_mismatch: x") || len(f.requests()) != 3 {
		t.Fatalf("exit %d stdout %q, %d requests", code, out, len(f.requests()))
	}
	if !strings.Contains(errOut, "operation 12 superseded after step T6") ||
		!strings.Contains(errOut, "supapace op list "+bkRef) || strings.Contains(errOut, "op retry") {
		t.Fatalf("stderr %q", errOut)
	}
	// The control: failed is final too, with its ways on.
	f = newFake(t, reply{202, accepted}, reply{200, restoreOp("failed", "T6", "deadline: x")})
	_, errOut, code = f.run(t, "project", "restore", bkRef, "--to", "latest")
	for _, s := range []string{"supapace op retry 12", "supapace project restore " + bkRef + " --to",
		"supapace project delete " + bkRef} {
		if code != 1 || !strings.Contains(errOut, s) {
			t.Errorf("exit %d: stderr lacks %q: %q", code, s, errOut)
		}
	}
}

func TestCLI_BackupsOneDocument(t *testing.T) {
	body := `{"ref":"` + bkRef + `","layout":1,"sets":[]}` + "\n"
	f := newFake(t, reply{200, body})
	out, errOut, code := f.run(t, "project", "backups", bkRef)
	if code != 0 || out != body || errOut != "" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errOut)
	}
	if got := f.requests(); len(got) != 1 || got[0] != (request{"GET", "/v1/projects/" + bkRef + "/backups", ""}) {
		t.Fatalf("%+v", got)
	}
	eb := `{"code":"not_found","message":"no such project"}`
	f = newFake(t, reply{404, eb})
	if out, _, code = f.run(t, "project", "backups", bkRef); code != 1 || out != eb {
		t.Fatalf("exit %d stdout %q", code, out)
	}
	for _, args := range [][]string{{"project", "backups"}, {"project", "backups", bkRef, "--no-wait"}} {
		f = newFake(t, reply{200, body})
		if out, _, code = f.run(t, args...); code != 2 || out != "" {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestCLI_BackupUsageTexts(t *testing.T) {
	u := strings.Join(strings.Fields(usageText()), " ")
	for _, s := range []string{"project backups REF", "project restore REF --to TARGET", "--timeline N",
		"--from local|offsite", "--upload-per-day SIZE", "--upload-objects-per-day N", "--layout N",
		"upload_per_day=SIZE", "upload_objects_per_day", "restoring", "previous_timeline", "fails earlier leaves the project as it was", "superseded", "development node"} {
		if !strings.Contains(u, s) {
			t.Errorf("usage lacks %q", s)
		}
	}
	for _, verb := range []string{"project restore", "project backups"} {
		f := newFake(t, reply{200, `{}`})
		out, _, code := f.run(t, strings.Fields(verb+" --help")...)
		if code != 0 || out != "usage:\n"+commandUsage(verb) || !strings.Contains(out, verb) {
			t.Errorf("%s --help: exit %d %q", verb, code, out)
		}
	}
	if r := commandUsage("project restore"); !strings.Contains(r, "--to TARGET") || !strings.Contains(r, "--from") ||
		strings.Contains(r, "project delete") {
		t.Errorf("restore usage:\n%s", r)
	}
}
