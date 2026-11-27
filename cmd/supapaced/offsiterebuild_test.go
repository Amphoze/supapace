package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

// storeNode points the commands at the test database's node root.
func storeNode(t *testing.T) (*node, *store.Store) {
	t.Helper()
	cleanPGEnv(t)
	p, _, st := realStore(t, false)
	n := &node{t: t, root: p.Root, p: p}
	oldPaths, oldRoot := paths, rootOnly
	paths, rootOnly = p, false
	t.Cleanup(func() { paths, rootOnly = oldPaths, oldRoot })
	return n, st
}

func dbExec(t *testing.T, p nodecfg.Paths, q string, args ...any) {
	t.Helper()
	c, err := dbConn(p.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	if _, err := c.Exec(context.Background(), q, args...); err != nil {
		t.Fatal(err)
	}
}

// stateRow is every column of subject's backup_state row, as text.
func stateRow(t *testing.T, p nodecfg.Paths, subject string) string {
	t.Helper()
	c, err := dbConn(p.Root)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	var row string
	if err := c.QueryRow(context.Background(), "select b::text from backup_state b where subject = $1", subject).Scan(&row); err != nil {
		t.Fatal(err)
	}
	return row
}

const rebuildRef = "abcdefghij0123456789"

// stuckRebuild gives subject a state row whose rebuild holds pages pages.
func stuckRebuild(t *testing.T, p nodecfg.Paths, subject string, pages int) {
	t.Helper()
	dbExec(t, p, `insert into backup_state (subject, rebuild_key_marker, rebuild_version_marker, rebuild_pages, bytes_today)
		values ($1, 'archive/k"1', 'v-7', $2, 99)`, subject, pages)
}

func TestOffsiteRebuildContinue_ResetsOnlyAStuckRebuild(t *testing.T) {
	n, st := storeNode(t)
	ctx := context.Background()
	stuckRebuild(t, n.p, rebuildRef, bklimit.RebuildMaxPages)
	stuckRebuild(t, n.p, "cp", bklimit.RebuildMaxPages)
	for _, s := range []string{rebuildRef, "cp"} {
		if err := st.RaiseAlert(ctx, s, "rebuild-page-cap", "page", map[string]int64{"pages": bklimit.RebuildMaxPages}); err != nil {
			t.Fatal(err)
		}
	}
	other := stateRow(t, n.p, "cp")
	before, err := st.GetBackupState(ctx, rebuildRef)
	if err != nil {
		t.Fatal(err)
	}

	code, out, errs := n.run("", "offsite", "rebuild-continue", "--subject", rebuildRef)
	if code != 0 || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	// The pages merged so far and the two markers kept, quoted.
	for _, want := range []string{rebuildRef, "2048 pages", `"archive/k\"1"`, `"v-7"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %s: %q", want, out)
		}
	}
	if strings.Count(out, "\n") != 1 {
		t.Errorf("output is not one line: %q", out)
	}
	after, err := st.GetBackupState(ctx, rebuildRef)
	if err != nil {
		t.Fatal(err)
	}
	if after.RebuildPages != 0 {
		t.Fatalf("pages %d after the command", after.RebuildPages)
	}
	after.RebuildPages = before.RebuildPages
	if fmt.Sprintf("%+v", after) != fmt.Sprintf("%+v", before) {
		t.Fatalf("another column changed:\n%+v\n%+v", before, after)
	}
	// Its alert is cleared; the other subject's row and alert are as they were.
	if as, err := st.OpenAlerts(ctx, ""); err != nil || len(as) != 1 || as[0].Subject != "cp" {
		t.Fatalf("open alerts %+v, %v", as, err)
	}
	if got := stateRow(t, n.p, "cp"); got != other {
		t.Fatalf("another subject's row changed:\n%s\n%s", other, got)
	}
	// The control plane's own subject is continued by its name.
	if code, _, errs := n.run("", "offsite", "rebuild-continue", "--subject", "cp"); code != 0 {
		t.Fatalf("cp: exit %d, %q", code, errs)
	}
}

func TestOffsiteRebuildContinue_RefusesASubjectNotAtTheCap(t *testing.T) {
	n, st := storeNode(t)
	ctx := context.Background()
	stuckRebuild(t, n.p, rebuildRef, bklimit.RebuildMaxPages-1)
	if err := st.RaiseAlert(ctx, rebuildRef, "rebuild-page-cap", "page", nil); err != nil {
		t.Fatal(err)
	}
	refused := func(what, subject, want string) {
		t.Helper()
		before := ""
		if subject == rebuildRef {
			before = stateRow(t, n.p, subject)
		}
		code, out, errs := n.run("", "offsite", "rebuild-continue", "--subject", subject)
		if code != 1 || out != "" || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, want) {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", what, code, out, errs)
		}
		if subject == rebuildRef && stateRow(t, n.p, subject) != before {
			t.Fatalf("%s: the row changed", what)
		}
		if as, err := st.OpenAlerts(ctx, rebuildRef); err != nil || len(as) != 1 {
			t.Fatalf("%s: the alert was cleared: %+v, %v", what, as, err)
		}
	}
	refused("below the cap", rebuildRef, "is not stopped at its page cap")
	dbExec(t, n.p, "update backup_state set rebuild_pages = $2, rebuild_epoch = (select epoch from cp_meta) where subject = $1",
		rebuildRef, bklimit.RebuildMaxPages)
	refused("a record already rebuilt", rebuildRef, "is not stopped at its page cap")
	refused("an unknown subject", "zzzzzzzzzzzzzzzzzzzz", "no backup state")
	// Control: the same row, its record behind the epoch again, is continued.
	dbExec(t, n.p, "update backup_state set rebuild_epoch = 0 where subject = $1", rebuildRef)
	if code, _, errs := n.run("", "offsite", "rebuild-continue", "--subject", rebuildRef); code != 0 {
		t.Fatalf("control: exit %d, %q", code, errs)
	}
}

func TestOffsiteRebuildContinue_UsageAndRoot(t *testing.T) {
	n := newNode(t)
	for _, args := range [][]string{{}, {"--subject", "Not-A-Ref"}, {"--subject", "cp", "extra"}, {"--subject", ""}, {"--subject", "../cp"}} {
		if code, out, _ := n.run("", append([]string{"offsite", "rebuild-continue"}, args...)...); code != 2 || out != "" {
			t.Errorf("%v: exit %d, stdout %q", args, code, out)
		}
	}
	rootOnly = true
	if code, _, errs := n.run("", "offsite", "rebuild-continue", "--subject", "cp"); code != 1 || !strings.Contains(errs, "must run as root") {
		t.Fatalf("not root: exit %d, %q", code, errs)
	}
}

// cleanPGEnv removes every PG* variable for the test. The job command sets
// the archive tool's options in its own environment, and its tests run it in
// this process: what they leave would make a command that opens the store
// refuse its environment.
func cleanPGEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, v, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "PG") {
			os.Unsetenv(k)
			t.Cleanup(func() { os.Setenv(k, v) })
		}
	}
}

// While a restore of the control plane is marked, what answers on the
// daemon's socket is a recovery start nothing has checked: the commands that
// open the store refuse.
func TestOffsiteRebuildContinue_RefusedWhileARestoreIsMarked(t *testing.T) {
	n, _ := storeNode(t)
	stuckRebuild(t, n.p, "cp", bklimit.RebuildMaxPages)
	if err := os.WriteFile(n.p.CPRestoring(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(n.p.CPRestoring()) }) // the database's root is shared
	before := stateRow(t, n.p, "cp")
	code, out, errs := n.run("", "offsite", "rebuild-continue", "--subject", "cp")
	if code != 1 || out != "" || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "a control-plane restore is marked") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if stateRow(t, n.p, "cp") != before {
		t.Fatal("the row changed")
	}
	// Control: without the marker the rebuild is continued.
	os.Remove(n.p.CPRestoring())
	if code, _, errs := n.run("", "offsite", "rebuild-continue", "--subject", "cp"); code != 0 {
		t.Fatalf("control: exit %d, %q", code, errs)
	}
}

// A node whose control-plane database does not answer is told so, not the
// client library's words about a socket.
func TestOffsiteRebuildContinue_NoDatabaseIsSaidPlainly(t *testing.T) {
	n := newNode(t)
	cleanPGEnv(t)
	code, out, errs := n.run("", "offsite", "rebuild-continue", "--subject", "cp")
	if code != 1 || out != "" || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "the control-plane database does not answer") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
}
