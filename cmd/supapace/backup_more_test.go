package main

import (
	"strings"
	"testing"
)

// TestCLI_FailedRestoreOffersDeleteOnlyForARestoringProject: a restore that
// failed before it stopped the project leaves it as it was; the ways on must
// not tell the operator to delete it unconditionally. Red until the summary
// conditions the delete on the project being left restoring.
func TestCLI_FailedRestoreOffersDeleteOnlyForARestoringProject(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, restoreOp("failed", "T1", "conflict: x")})
	_, errOut, code := f.run(t, "project", "restore", bkRef, "--to", "latest")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, line := range strings.Split(errOut, "\n") {
		if strings.Contains(line, "project delete") && !strings.Contains(line, "restoring") {
			t.Errorf("delete offered unconditionally: %q", line)
		}
	}
}

// TestCLI_RestoreFlagsOddValuesReachTheAPI: the CLI passes what it can read;
// the API judges it (an empty --from is the default).
func TestCLI_RestoreFlagsOddValuesReachTheAPI(t *testing.T) {
	for _, c := range []struct {
		args []string
		body string
	}{
		{[]string{"--timeline", "-1"}, `{"to":"latest","timeline":-1}`},
		{[]string{"--timeline", "99999999999"}, `{"to":"latest","timeline":99999999999}`},
		{[]string{"--from", ""}, `{"to":"latest"}`},
	} {
		f := newFake(t, reply{202, accepted})
		args := append([]string{"project", "restore", bkRef, "--to", "latest", "--no-wait"}, c.args...)
		if _, _, code := f.run(t, args...); code != 0 || len(f.requests()) != 1 || f.requests()[0].body != c.body {
			t.Errorf("%v: exit %d %+v", c.args, code, f.requests())
		}
	}
}
