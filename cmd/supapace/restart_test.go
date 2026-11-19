package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/store"
)

func restartOp(state, step, lastError string) string {
	return strings.Replace(opJSON(state, step, lastError), `"create"`, `"restart"`, 1)
}

// A failed restart names every way on: retry, a new restart with other
// settings, delete; a refused quota names the restart to run instead.
func TestCLI_FailedRestartSummary(t *testing.T) {
	f := newFake(t, reply{202, accepted}, reply{200, restartOp("failed", "R2", "internal: x; the project stays restarting at generation 2 with its route draining")})
	_, errOut, code := f.run(t, "project", "restart", "abcdefghij0123456789")
	for _, s := range []string{"supapace op retry 12", "supapace project restart abcdefghij0123456789 --set KEY=VALUE",
		"supapace project delete abcdefghij0123456789"} {
		if code != 1 || !strings.Contains(errOut, s) {
			t.Errorf("exit %d, stderr lacks %q:\n%s", code, s, errOut)
		}
	}
	// A restart that failed before its bump left the project active: retry
	// only, nothing to replace or remove.
	f = newFake(t, reply{202, accepted}, reply{200, restartOp("failed", "R1", "internal: x")})
	_, errOut, code = f.run(t, "project", "restart", "abcdefghij0123456789")
	if code != 1 || !strings.Contains(errOut, "supapace op retry 12") || strings.Contains(errOut, "project delete") ||
		strings.Contains(errOut, "--set KEY=VALUE") {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
	f = newFake(t, reply{202, accepted}, reply{200, restartOp("failed", "R0",
		"quota_below_usage: disk_quota_mb 1024 is below the project's usage of 2300 MiB plus the 256 MiB a clean cluster start needs; "+
			"the smallest accepted value is 2556")})
	_, errOut, code = f.run(t, "project", "restart", "abcdefghij0123456789", "--set", "disk_quota_mb=1024")
	if code != 1 || strings.Contains(errOut, "op retry") ||
		!strings.Contains(errOut, "nothing was changed") || !strings.Contains(errOut, "--set disk_quota_mb=MIB") {
		t.Fatalf("exit %d stderr %q", code, errOut)
	}
}

// The help says what --user-role does to the default role, quotes the start
// headroom the store enforces, and names the ways out of a failed restart.
func TestCLI_UsageRolesQuotaAndRestart(t *testing.T) {
	u := strings.Join(strings.Fields(usageText()), " ")
	for _, s := range []string{
		"The roles given replace the default, authenticated: add --user-role authenticated to keep it.",
		"(authenticated, or one of the --user-role roles when any were given)",
		"the database role postgres, for schema changes;",
		"plus " + strconv.Itoa(store.QuotaHeadroomMB) + " MiB (what a clean cluster start needs) is refused (quota_below_usage;",
		"A cluster that stopped at its quota needs its usage plus 1280 MiB",
		"accepts a new restart with other settings, or a delete",
	} {
		if !strings.Contains(u, s) {
			t.Errorf("usage lacks %q", s)
		}
	}
	if strings.Contains(u, "superuser") {
		t.Error("usage still words postgres by what it is not")
	}
	if !strings.Contains(commandUsage("project restart"), "rolled back") {
		t.Error("restart's own usage lacks its notes")
	}
}
