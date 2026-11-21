package bkjob

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

// Tool is the one program a job runs. Tests substitute a fake.
var Tool = "/usr/bin/pgbackrest"

// outputMax bounds what Run keeps of the tool's output: the last 64 KiB,
// where its errors are.
const outputMax = 64 << 10

// Run executes the tool with args and the job's own environment — never
// through a shell, so no argument is read as anything but itself. The tool's
// standard output (its console log) and standard error are captured together
// into output and never reach the job's standard output, which carries the
// result line alone. A tool that exits is an exit code and no error; err is a
// tool that could not be started or was stopped by a signal.
func Run(ctx context.Context, args ...string) (exit int, output string, err error) {
	return run(ctx, outputMax, args...)
}

// run is Run keeping the last max bytes of the output.
func run(ctx context.Context, max int, args ...string) (exit int, output string, err error) {
	out := tail{max: max}
	cmd := exec.CommandContext(ctx, Tool, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out.b), nil
	case errors.As(err, &ee) && ee.Exited():
		return ee.ExitCode(), string(out.b), nil
	}
	return -1, string(out.b), fmt.Errorf("bkjob: running %s: %w", Tool, err)
}

// tail keeps the last max bytes written to it.
type tail struct {
	b   []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if n := len(t.b) - t.max; n > 0 {
		t.b = append(t.b[:0], t.b[n:]...)
	}
	return len(p), nil
}

// Error is a job program's failure: a code of its kind and a message of at
// most 256 bytes. The job prints it as its result and exits 1.
type Error struct{ Code, Message string }

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// fail builds a failure. The message is cut to 256 bytes and stays valid
// UTF-8, so that it is no longer once encoded and read back.
func fail(code, format string, a ...any) error {
	m := fmt.Sprintf(format, a...)
	m = strings.ToValidUTF8(m[:min(len(m), 256)], "")
	return &Error{Code: code, Message: m}
}

// codes are the failure codes each kind's program can end with — the one list
// the program and the runner's recorder share. A kind is listed here once its
// program exists.
var codes = map[string][]string{
	"push":          {CodeRepositoryQuota, CodeRepository, CodeSpool, CodeStopped},
	"stanza-create": {CodeLogin, CodeArchiveTimeout, CodePgbackrest, CodeTablespace, CodeSymlink},
	"backup":        {CodeLogin, CodeArchiveTimeout, CodePgbackrest, CodeTablespace, CodeSymlink},
	"check":         {CodeLogin, CodeArchiveTimeout, CodePgbackrest, CodeTablespace, CodeSymlink},
}

// Codes returns the failure codes kind's program can end with, and whether
// kind's program is known here.
func Codes(kind string) ([]string, bool) {
	c, ok := codes[kind]
	return slices.Clone(c), ok
}
