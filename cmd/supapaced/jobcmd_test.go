package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/bkjob"
	"github.com/Amphoze/supapace/internal/jobio"
)

// The fake tool: this test binary run as "pgbackrest" through a link. It
// writes to both of its streams, records its environment and exits with the
// number in the file "exit" beside it (0 without one).
func init() {
	if filepath.Base(os.Args[0]) != "pgbackrest" {
		return
	}
	dir := filepath.Dir(os.Args[0])
	os.WriteFile(filepath.Join(dir, "env"), []byte(strings.Join(os.Environ(), "\n")), 0o600)
	os.Stdout.WriteString("tool console line\nERROR: [050]: from the tool\n")
	os.Stderr.WriteString("tool error line\n")
	b, _ := os.ReadFile(filepath.Join(dir, "exit"))
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	os.Exit(n)
}

type jobLab struct{ dir, tool string }

// newJobLab gives the job command a spool with one segment, an input and the
// fake tool.
func newJobLab(t *testing.T, kind string) *jobLab {
	t.Helper()
	l := &jobLab{dir: t.TempDir(), tool: t.TempDir()}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	os.Symlink(exe, filepath.Join(l.tool, "pgbackrest"))
	os.Mkdir(filepath.Join(l.dir, "spool"), 0o700)
	os.WriteFile(filepath.Join(l.dir, "spool", "000000010000000000000001"), make([]byte, 1<<20), 0o600) // the smallest segment size
	in, err := jobio.MarshalInput(jobio.Input{Job: 3, Kind: kind, Subject: "ref", Stanza: "ref-1", UID: os.Getuid(),
		Timelines: []uint32{1}, MaxEntries: 56})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(l.dir, "input.json"), in, 0o600)
	oldTool, oldIn, oldSpool := bkjob.Tool, jobInput, jobSpool
	bkjob.Tool, jobInput, jobSpool = filepath.Join(l.tool, "pgbackrest"), filepath.Join(l.dir, "input.json"), filepath.Join(l.dir, "spool")
	t.Cleanup(func() { bkjob.Tool, jobInput, jobSpool = oldTool, oldIn, oldSpool })
	t.Setenv("TMPDIR", t.TempDir())
	return l
}

func runJob(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	oldOut, oldErr := stdout, stderr
	stdout, stderr = &out, &errb
	defer func() { stdout, stderr = oldOut, oldErr }()
	code := run(append([]string{"job"}, args...))
	return code, out.String(), errb.String()
}

// Whatever the tool writes, the job's standard output is its one result line;
// the tool runs with the pinned environment and the passphrase only.
func TestJobCmd_ResultIsTheOnlyStdoutLine(t *testing.T) {
	l := newJobLab(t, "push")
	t.Setenv(bkjob.PassName, "the-pass")
	t.Setenv("PGHOST", "elsewhere")                            // a stale libpq variable
	t.Setenv("PGBACKREST_LOG_LEVEL_CONSOLE", "detail")         // a stale option
	t.Setenv("PGBACKREST_REPO1_S3_BUCKET", "not-a-job-option") // one Env does not name
	code, out, _ := runJob(t, "push")
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("exit %d, stdout %q: want one line", code, out)
	}
	v, fail, err := jobio.ParseResult("push", []byte(out))
	if err != nil || fail != nil || v.(jobio.PushResult).Pushed != 1 {
		t.Fatalf("result %v %v %v", v, fail, err)
	}
	b, err := os.ReadFile(filepath.Join(l.tool, "env"))
	if err != nil {
		t.Fatal("control: the tool did not run")
	}
	env := strings.Split(string(b), "\n")
	for _, want := range []string{"PGBACKREST_CONFIG=/dev/null", "PGBACKREST_STANZA=ref-1", "PGBACKREST_LOG_LEVEL_CONSOLE=warn", bkjob.PassName + "=the-pass"} {
		if !slices.Contains(env, want) {
			t.Errorf("the tool's environment lacks %s", want)
		}
	}
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if _, pinned := bkjob.Environ("ref-1", "push", false, "the-pass")[k]; strings.HasPrefix(k, "PG") && !pinned {
			t.Errorf("the tool's environment holds %s", e)
		}
	}
}

func TestJobCmd_ExitCodes(t *testing.T) {
	l := newJobLab(t, "push")
	for _, args := range [][]string{{}, {"backup"}, {"replicate"}, {"push", "extra"}} {
		if code, out, _ := runJob(t, args...); code != 2 || out != "" {
			t.Errorf("job %q: exit %d, stdout %q; want 2 and nothing", args, code, out)
		}
	}
	// The input must be the platform's and name the same kind.
	in := filepath.Join(l.dir, "input.json")
	good, _ := os.ReadFile(in)
	for _, bad := range []string{`{"job":1}`, strings.Replace(string(good), `"push"`, `"check"`, 1), "not json"} {
		os.WriteFile(in, []byte(bad), 0o600)
		if code, out, _ := runJob(t, "push"); code != 2 || out != "" {
			t.Errorf("input %s: exit %d, stdout %q; want 2", bad, code, out)
		}
	}
	os.Remove(in)
	if code, _, _ := runJob(t, "push"); code != 2 {
		t.Errorf("no input: exit %d", code)
	}
	os.WriteFile(in, good, 0o600)

	// The tool fails: exit 1 with the failure document.
	os.WriteFile(filepath.Join(l.tool, "exit"), []byte("50"), 0o600)
	code, out, _ := runJob(t, "push")
	_, fail, err := jobio.ParseResult("push", []byte(out))
	if code != 1 || err != nil || fail == nil || fail.Code != bkjob.CodeRepository || !strings.Contains(fail.Message, "[050]") {
		t.Errorf("a failed tool: exit %d, %q (%v)", code, out, err)
	}
	os.WriteFile(filepath.Join(l.tool, "exit"), []byte("0"), 0o600)
	if code, out, _ := runJob(t, "push"); code != 0 || !strings.HasPrefix(out, `{"ok":true`) {
		t.Errorf("a done push: exit %d, %q", code, out)
	}
}
