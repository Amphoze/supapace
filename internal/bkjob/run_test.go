package bkjob

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/jobio"
)

// The fake tool: this test binary, run under the name "pgbackrest" through a
// link in a test's directory. It records its arguments, environment, parent
// and the bytes of the file its last argument names into calls, prints and
// exits as script says for that file's base name ("*": any other).
func init() {
	if filepath.Base(os.Args[0]) != "pgbackrest" {
		return
	}
	dir := filepath.Dir(os.Args[0])
	c := call{Args: os.Args[1:], Env: os.Environ(), PPID: os.Getppid()}
	key := "*"
	if n := len(c.Args); n > 0 {
		c.Data, _ = os.ReadFile(c.Args[n-1])
		c.Size = len(c.Data)
		c.Data = c.Data[:min(len(c.Data), 64)] // the first bytes are enough
		key = filepath.Base(c.Args[n-1])
	}
	b, _ := json.Marshal(c)
	f, err := os.OpenFile(filepath.Join(dir, "calls"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		os.Exit(99)
	}
	f.Write(append(b, '\n'))
	f.Close()
	var sc map[string]step
	if b, err := os.ReadFile(filepath.Join(dir, "script.json")); err == nil {
		json.Unmarshal(b, &sc)
	}
	s, ok := sc[key]
	if !ok {
		s = sc["*"]
	}
	os.Stdout.WriteString(s.Out)
	os.Stderr.WriteString(s.Err)
	os.Exit(s.Exit)
}

type call struct {
	Args []string
	Env  []string
	PPID int
	Data []byte // the first 64 bytes of the file handed over
	Size int
}

type step struct {
	Exit     int
	Out, Err string
}

// fakeTool puts the fake in place of the tool for the test and returns its
// directory.
func fakeTool(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(exe, filepath.Join(dir, "pgbackrest")); err != nil {
		t.Fatal(err)
	}
	old := Tool
	Tool = filepath.Join(dir, "pgbackrest")
	t.Cleanup(func() { Tool = old })
	return dir
}

func script(t *testing.T, dir string, s map[string]step) {
	t.Helper()
	b, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(dir, "script.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func calls(t *testing.T, dir string) []call {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "calls"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []call
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 64<<20)
	for sc.Scan() {
		var c call
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// The tool is executed itself, with its arguments as given — no shell reads
// them — and the passphrase reaches it only through its environment.
func TestRun_NoShell_NoPassphraseInArgv(t *testing.T) {
	dir := fakeTool(t)
	t.Setenv(PassName, "pass-in-env")
	odd := `/tmp/x; echo $(id) "q" 'r' *`
	exit, _, err := Run(context.Background(), "archive-push", odd)
	if err != nil || exit != 0 {
		t.Fatalf("Run = %d, %v", exit, err)
	}
	cs := calls(t, dir)
	if len(cs) != 1 {
		t.Fatalf("%d calls", len(cs))
	}
	c := cs[0]
	if !slices.Equal(c.Args, []string{"archive-push", odd}) {
		t.Errorf("argv %q: the arguments were read by something", c.Args)
	}
	if c.PPID != os.Getpid() {
		t.Errorf("the tool's parent is %d, not this process (%d): something ran in between", c.PPID, os.Getpid())
	}
	for _, a := range c.Args {
		if strings.Contains(a, "pass-in-env") {
			t.Errorf("the passphrase is on the command line: %q", a)
		}
	}
	if !slices.Contains(c.Env, PassName+"=pass-in-env") {
		t.Error("control: the passphrase is not in the tool's environment")
	}
}

// Standard output and standard error of the tool are captured, the last
// 64 KiB of them; nothing of it reaches the job's own standard output.
func TestRun_CapturesToolOutput_NothingReachesStdout(t *testing.T) {
	dir := fakeTool(t)
	big := strings.Repeat("x", 100<<10)
	script(t, dir, map[string]step{"small": {Out: "to-stdout\n", Err: "to-stderr\n"}, "big": {Out: big + "END\n"}})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var leaked []byte
	done := make(chan struct{})
	go func() { leaked, _ = io.ReadAll(r); close(done) }()
	orig := os.Stdout
	os.Stdout = w
	_, small, err1 := Run(context.Background(), "x", "small")
	_, long, err2 := Run(context.Background(), "x", "big")
	os.Stdout = orig
	w.Close()
	<-done
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if len(leaked) != 0 {
		t.Errorf("the job's standard output received %q", leaked)
	}
	if !strings.Contains(small, "to-stdout") || !strings.Contains(small, "to-stderr") {
		t.Errorf("output %q: both streams must be captured", small)
	}
	if len(long) != 64<<10 || !strings.HasSuffix(long, "END\n") {
		t.Errorf("long output: %d bytes ending %q; want the last 64 KiB", len(long), long[max(0, len(long)-8):])
	}
}

// A tool that exits 50 is a failed command — an exit code, no error — and the
// push job fails with a code of its own, not as a crash.
func TestRun_Exit50IsAFailedCommandNotACrash(t *testing.T) {
	dir := fakeTool(t)
	script(t, dir, map[string]step{"*": {Exit: 50, Out: "ERROR: [050]: unable to acquire lock\n"}})
	exit, out, err := Run(context.Background(), "archive-push", "/x")
	if err != nil || exit != 50 || !strings.Contains(out, "[050]") {
		t.Fatalf("Run = %d, %q, %v; want exit 50 and no error", exit, out, err)
	}
	l := newLab(t)
	script(t, l.tool, map[string]step{"*": {Exit: 50, Out: "ERROR: [050]: unable to acquire lock\n"}})
	l.put("000000010000000000000001", "seg")
	_, err = Push(context.Background(), l.input(1), l.spool)
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeRepository {
		t.Fatalf("Push = %v; want the failure %q", err, CodeRepository)
	}
	// Control: a tool that cannot be run is an error, not an exit code.
	Tool = filepath.Join(t.TempDir(), "absent")
	if _, _, err := Run(context.Background(), "x"); err == nil {
		t.Error("a missing tool ran")
	}
}

// A failure's message is cut to 256 bytes of valid UTF-8: encoded and read
// back it stays within the result's bound, also when the cut falls inside a
// character.
func TestFail_MessageReadsBackWithinItsBound(t *testing.T) {
	var e *Error
	if !errors.As(fail(CodeRepository, "%s", strings.Repeat("a", 255)+"é and more"), &e) {
		t.Fatal("not a job failure")
	}
	line, err := jobio.MarshalResult(jobio.Failure{Code: e.Code, Message: e.Message})
	if err != nil {
		t.Fatal(err)
	}
	_, f, err := jobio.ParseResult("push", line)
	if err != nil || f == nil || f.Message != strings.Repeat("a", 255) {
		t.Fatalf("read back: %v, %+v", err, f)
	}
}
