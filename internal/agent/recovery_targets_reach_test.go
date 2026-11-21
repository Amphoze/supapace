//go:build reach

package agent

// Recovery starts that must end without a promotion, on a bare node (as the
// other recovery tests): an empty data directory, a target the archive does
// not reach and a target before the backup. Each ends as a failed start or
// an exited container, which the poll reports from Docker; none is read as
// "still replaying" for ever, and none as promoted.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/jackc/pgx/v5"
)

// rrStarted restores the project's files and runs the recovery start to tgt
// with the restore spool served; it returns how the start ended: promoted,
// or exited without a promotion. Any error of the poll, or neither within
// 180 s, fails the test. The serve job is stopped before it returns.
func rrStarted(t *testing.T, a *Agent, s Spec, tgt pgconf.RecoveryTarget) (promoted bool) {
	t.Helper()
	ctx := context.Background()
	if err := a.StopCluster(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	if err := a.WipeData(ctx, s); err != nil {
		t.Fatal(err)
	}
	out, err := rrJob(t, a, s, "restore", "", "", "sh", "-c", "pgbackrest --type=none restore && touch /var/lib/postgresql/data/recovery.signal")
	rrMust(t, "restore", out, err)
	rspool := filepath.Join(a.p.ProjectDir(s.Ref), "rspool")
	os.Remove(filepath.Join(rspool, "stop"))
	out, err = rrJob(t, a, s, "serve", "", "", "sh", "/x/serve.sh")
	rrMust(t, "serve", out, err)
	defer func() {
		os.WriteFile(filepath.Join(rspool, "stop"), nil, 0o644)
		wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		ids, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=supapace.test=1", "--filter", "name=-serve-"+s.Ref).Output()
		for _, id := range strings.Fields(string(ids)) {
			exec.CommandContext(wctx, "docker", "wait", id).Run()
			nodeDockerQuiet("rm", "-f", id)
		}
		os.Remove(filepath.Join(rspool, "stop"))
	}()
	if err := a.EnsureRecovery(ctx, s, tgt); err != nil {
		t.Fatalf("recovery start: %v", err)
	}
	for deadline := time.Now().Add(180 * time.Second); ; time.Sleep(time.Second) {
		promoted, exited, err := a.RecoveryState(ctx, s)
		switch {
		case err != nil:
			// A login cut by the server's own exit is an error of that poll (a
			// connection reset is neither a refused connect nor a budget error);
			// the next poll then reads the exit from Docker. Any other error fails.
			if _, gone, err2 := a.RecoveryState(ctx, s); err2 != nil || !gone {
				t.Fatalf("recovery state: %v", err)
			}
			t.Logf("a poll failed while the server exited: %v", err)
			return false
		case promoted:
			return true
		case exited:
			return false
		case time.Now().After(deadline):
			t.Fatalf("neither promoted nor exited within 180 s:\n%s", strings.Join(rrLog(t, s, 0), "\n"))
		}
	}
}

func rrLogHas(t *testing.T, s Spec, sub string) bool {
	t.Helper()
	for _, l := range rrLog(t, s, 0) {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func TestRecoveryStart_EmptyDirectoryAndUnreachableTargetsEndUnpromoted(t *testing.T) {
	var before, inside string
	a, s := rrBackedUp(t, 9, 700769, func(conn *pgx.Conn) {
		before = rrStr(t, conn, "select pg_catalog.pg_current_wal_lsn()::text")
	})
	ctx := context.Background()
	// After the backup: a position the archive reaches, then a second marker.
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatal(err)
	}
	conn := clSession(t, a, s)
	inside = rrStr(t, conn, "select pg_catalog.pg_current_wal_lsn()::text")
	clExec(t, conn, "insert into public.marker values (2)")
	clExec(t, conn, "select pg_catalog.pg_switch_wal()")
	closeSession(conn)
	rrStopAndPush(t, a, s)

	// An empty data directory (a restore that left nothing): the recovery start
	// carries no password variable, so the image initialises nothing and the
	// container exits. It is never a fresh cluster that reads as promoted.
	if err := a.StopCluster(ctx, s.Ref); err != nil {
		t.Fatal(err)
	}
	if err := a.WipeData(ctx, s); err != nil {
		t.Fatal(err)
	}
	// The container may exit before the start has read its process back (the
	// start then fails) or just after (the poll then reports it exited).
	startErr := a.EnsureRecovery(ctx, s, pgconf.RecoveryTarget{Timeline: "latest"})
	for deadline := time.Now().Add(120 * time.Second); startErr == nil; time.Sleep(time.Second) {
		promoted, exited, err := a.RecoveryState(ctx, s)
		if err != nil {
			t.Fatalf("empty directory: recovery state: %v", err)
		}
		if promoted {
			t.Fatal("a recovery start on an empty data directory reads as promoted")
		}
		if exited {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("empty directory: neither exited nor promoted within 120 s:\n%s", strings.Join(rrLog(t, s, 0), "\n"))
		}
	}
	if startErr != nil {
		t.Logf("an empty data directory: the start failed: %v", startErr)
		if out := nodeDocker(t, "inspect", "-f", "{{.State.Running}}", clusterName(s.Ref)); out != "false" {
			t.Fatalf("the failed start left a running container: %s", out)
		}
		if p, _, _ := a.RecoveryState(ctx, s); p {
			t.Fatal("a failed start reads as promoted")
		}
	}
	if ents, err := os.ReadDir(filepath.Join(a.p.ProjectDir(s.Ref), "data")); err != nil || len(ents) != 0 {
		t.Fatalf("the empty data directory was written to: %d entries, %v", len(ents), err)
	}
	t.Log("an empty data directory: exited, nothing initialised")

	for _, c := range []struct {
		name string
		t    pgconf.RecoveryTarget
		log  string
	}{
		{"a time after the end of the archive", pgconf.RecoveryTarget{Time: time.Now().Add(time.Hour), Timeline: "current"},
			"recovery ended before configured recovery target was reached"},
		{"a position after the end of the archive", pgconf.RecoveryTarget{LSN: "7FFFFFFF/0", Timeline: "current"},
			"recovery ended before configured recovery target was reached"},
		{"a position before the backup", pgconf.RecoveryTarget{LSN: before, Timeline: "current"},
			"before consistent recovery point"},
	} {
		if rrStarted(t, a, s, c.t) {
			t.Fatalf("%s: promoted", c.name)
		}
		if !rrLogHas(t, s, c.log) {
			t.Errorf("%s: the server log does not say %q:\n%s", c.name, c.log, strings.Join(rrLog(t, s, 0), "\n"))
		}
		// The exited start is no recovery to re-key: the session is refused
		// before any statement, and nothing was recorded as promoted.
		if _, err := a.Rekey(ctx, s); err == nil {
			t.Fatalf("%s: re-keyed an exited recovery start", c.name)
		}
		if st := mustState(t, a, s); st.Phase != PhaseR {
			t.Fatalf("%s: state %+v", c.name, st)
		}
		t.Logf("%s: exited without a promotion", c.name)
	}

	// Control: nothing of the failed starts stays behind. A position the archive
	// reaches promotes on the next timeline with the marker of before it.
	if !rrStarted(t, a, s, pgconf.RecoveryTarget{LSN: inside, Timeline: "current"}) {
		t.Fatalf("control: a position inside the archive did not promote:\n%s", strings.Join(rrLog(t, s, 0), "\n"))
	}
	tl, err := a.Rekey(ctx, s)
	if err != nil || tl != 2 {
		t.Fatalf("control: timeline %d, %v", tl, err)
	}
	if err := a.EnsureCluster(ctx, s); err != nil {
		t.Fatal(err)
	}
	conn = clSession(t, a, s)
	if got := rrMarkers(t, conn); got != "1" {
		t.Errorf("control: markers %q, want 1", got)
	}
	closeSession(conn)
}
