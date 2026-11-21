//go:build reach

package reach

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/store"
)

const (
	cpContainer = "sp-cp-db"
	daemonLog   = "/var/log/supapaced.log"
	// repairWait covers two repair rounds of the daemon (one a minute).
	repairWait = 130 * time.Second
)

// cpPsql runs one statement in the control-plane database as its owner.
func cpPsql(sql string) (string, error) {
	r, err := run(cmdTimeout, nil, "docker", "exec", "-u", "70:70", cpContainer, "psql", "-qAt", "-v", "ON_ERROR_STOP=1",
		"-U", "supapaced", "-d", "supapaced", "-c", sql)
	if err == nil && r.code != 0 {
		err = fmt.Errorf("psql exit %d: %s", r.code, brief(r.stderr))
	}
	return strings.TrimSpace(r.stdout), err
}

// cpState is sp-cp-db's "running restarts" as Docker records it, or "absent".
func cpState(t testing.TB) string {
	t.Helper()
	r, err := run(cmdTimeout, nil, "docker", "container", "inspect", "--format", "{{.State.Running}} {{.RestartCount}}", "--", cpContainer)
	if err != nil {
		t.Fatal(err)
	}
	if r.code != 0 {
		return "absent"
	}
	return strings.TrimSpace(r.stdout)
}

// cpBack waits until the control-plane database answers again, the store
// lists both fixture projects and both serve through the gateway.
func cpBack(t testing.TB, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		err := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			st, err := store.Open(ctx, filepath.Join(paths.CPDir(), "sock"))
			if err != nil {
				return err
			}
			defer st.Close()
			ps, err := st.ListProjects(ctx)
			if err != nil {
				return err
			}
			refs := make([]string, 0, len(ps))
			for _, p := range ps {
				refs = append(refs, p.Ref)
			}
			if !slices.Contains(refs, fixA.Ref) || !slices.Contains(refs, fixB.Ref) {
				return fmt.Errorf("store lists %v", refs)
			}
			// After a restart of the daemon a project answers 503 until it is
			// adopted again: the tests that follow need both fixtures serving.
			for _, p := range []Project{*fixA, *fixB} {
				resp, err := gatewayRoundTrip(t, p, "GET", whoamiPath, hdr("apikey", p.AnonKey), nil, netip.Addr{})
				if err != nil {
					return err
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					return fmt.Errorf("%s answers %d through the gateway", p.Ref, resp.StatusCode)
				}
			}
			return nil
		}()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("control-plane store not back within %v: %v (container %s)", within, err, cpState(t))
		}
		time.Sleep(2 * time.Second)
	}
}

// treeState lists every entry below dir with its size and modification time.
func treeState(t testing.TB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = fmt.Sprintf("%v %d %d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func logSize(t testing.TB) int64 {
	fi, err := os.Stat(daemonLog)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func logSince(t testing.TB, off int64) string {
	b, err := os.ReadFile(daemonLog)
	if err != nil {
		t.Fatal(err)
	}
	return string(b[min(off, int64(len(b))):])
}

// The restore marker present and the container removed: neither the agent's
// ensure nor the daemon's repair rounds start the control-plane database, and
// the directory a restore would be writing is not touched. Without the
// marker the next round brings it back with every project.
func TestControlPlane_NotStartedWhileARestoreIsMarked(t *testing.T) {
	ctx := context.Background()
	ag := agent.New(nodeConf(t), paths)
	marker := paths.CPRestoring()
	t.Cleanup(func() {
		os.Remove(marker)
		cpBack(t, 3*repairWait)
	})
	if _, err := cpPsql("select 1"); err != nil {
		t.Fatalf("control: the control-plane database does not answer before the test: %v", err)
	}
	off := logSize(t)
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	docker(t, "stop", "-t", "30", cpContainer)
	docker(t, "rm", cpContainer)
	data := filepath.Join(paths.CPProjectDir(), "data")
	before := treeState(t, data)

	err := ag.EnsureControlPlaneDB(ctx)
	if err == nil || !strings.Contains(err.Error(), "restore") {
		t.Fatalf("EnsureControlPlaneDB with the marker: %v", err)
	}
	if s := cpState(t); s != "absent" {
		t.Fatalf("after EnsureControlPlaneDB: %s", s)
	}
	// Two of the daemon's repair rounds refuse it (each logs the refusal);
	// it stays absent all along.
	for deadline := time.Now().Add(5 * time.Minute); strings.Count(logSince(t, off), "restore is marked") < 2; time.Sleep(2 * time.Second) {
		if s := cpState(t); s != "absent" {
			t.Fatalf("a repair round started it: %s", s)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no two refusals in the daemon's log within 5 minutes")
		}
	}
	if s := cpState(t); s != "absent" {
		t.Fatalf("a repair round started it: %s", s)
	}
	if after := treeState(t, data); len(after) != len(before) {
		t.Fatalf("the data directory changed: %d entries, then %d", len(before), len(after))
	} else {
		for p, v := range before {
			if after[p] != v {
				t.Fatalf("%s changed: %s, now %s", p, v, after[p])
			}
		}
	}
	// Control: the marker gone, the daemon brings it back.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	cpBack(t, 3*repairWait)
}

// setCPDiskQuota sets cp_disk_quota_mb in node.json (0: the field removed)
// and restarts the daemon, whose ensure then sets uid 70's quota from it —
// the way an operator changes it; a quota set by hand would be put back by
// the next repair round. It waits until the quota reads mb MiB.
func setCPDiskQuota(t testing.TB, mb int) {
	t.Helper()
	b, err := os.ReadFile(paths.NodeJSON())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if mb > 0 {
		doc["cp_disk_quota_mb"] = mb
	} else {
		delete(doc, "cp_disk_quota_mb")
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	release := holdDaemon(t)
	if err := os.WriteFile(paths.NodeJSON(), append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	release()
	want, _ := nodecfg.CPQuotas(nodeConf(t), paths)
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(time.Second) {
		_, hard, err := nodefs.QuotaUsage(context.Background(), paths.ProjectsDir(), nodecfg.ControlPlaneUID)
		if err == nil && hard == int64(want)<<10 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("uid 70's quota is not %d MiB within 3 minutes of the restart: %d KiB %v", want, hard, err)
		}
	}
}

// uid 70's quota on the projects filesystem lowered through the node's
// configuration to just above its use. A write that needs a new data block
// fails and the server stays up; a write that needs WAL space stops it
// (a PANIC). It recovers by itself — or, while recovery cannot write its WAL
// file, exits, and Docker restarts it in a loop at its back-off. Committed
// rows are kept. Nothing reports the state in the node check yet. After the
// raise the store answers with every row.
func TestControlPlane_StopsAtItsDiskQuotaAndComesBackAfterARaise(t *testing.T) {
	ctx := context.Background()
	// A run killed before its clean-up left a lowered quota in the node
	// file: put it back first (test nodes set no cp_disk_quota_mb).
	if b, err := os.ReadFile(paths.NodeJSON()); err == nil && bytes.Contains(b, []byte(`"cp_disk_quota_mb"`)) {
		t.Logf("a lowered quota left by an earlier run: removed")
		setCPDiskQuota(t, 0)
	}
	orig, err := os.ReadFile(paths.NodeJSON())
	if err != nil {
		t.Fatal(err)
	}
	uid := nodecfg.ControlPlaneUID
	// The first clean-up registered, so it runs last; the node file is
	// written back before anything that can end the clean-up early.
	t.Cleanup(func() {
		if err := os.WriteFile(paths.NodeJSON(), orig, 0o600); err != nil {
			t.Errorf("node.json back: %v", err)
		}
		release := holdDaemon(t)
		release()
		cpBack(t, 3*repairWait)
		cpPsql("drop table if exists reach_cp_fill, reach_cp_rows, reach_cp_tick")
		cpPsql("checkpoint")
	})
	const rows = 1000
	if _, err := cpPsql(fmt.Sprintf("drop table if exists reach_cp_fill, reach_cp_rows, reach_cp_tick; "+
		"create table reach_cp_rows as select g from generate_series(1, %d) g; create table reach_cp_tick (v int); "+
		"create table reach_cp_fill (b text); alter table reach_cp_fill alter column b set storage external; checkpoint", rows)); err != nil {
		t.Fatal(err)
	}
	used, _, err := nodefs.QuotaUsage(ctx, paths.ProjectsDir(), uid)
	if err != nil {
		t.Fatal(err)
	}
	limit := int(used>>10) + 48
	setCPDiskQuota(t, limit)
	cpBack(t, 3*repairWait) // the daemon's restart left the database as it was
	t.Logf("uid %d uses %d KiB; quota lowered to %d MiB through the configuration", uid, used, limit)
	start := cpState(t)

	// Data blocks, then WAL segments, until a write is refused.
	var failed error
	for i := 0; failed == nil && i < 64; i++ {
		_, failed = cpPsql("insert into reach_cp_fill select repeat(md5(g::text), 128) from generate_series(1, 2000) g")
	}
	if failed == nil {
		t.Fatalf("64 uncompressed inserts of 8 MiB fit a quota of %d MiB", limit)
	}
	t.Logf("data write at the quota: %v", failed)
	// A refused data block leaves the server up (an ERROR); then new WAL
	// segments stop it. Which limit a write meets first depends on the WAL
	// space left, so the first loop may already have stopped it (a PANIC).
	_, up := cpPsql("select 1")
	if up == nil {
		failed = nil
	}
	for i := 0; up == nil && failed == nil && i < 64; i++ {
		_, failed = cpPsql("insert into reach_cp_tick values (1); select pg_switch_wal()")
	}
	if up == nil && failed == nil {
		t.Fatalf("64 WAL segments fit a quota of %d MiB", limit)
	}
	t.Logf("WAL write at the quota: %v", failed)

	// For a minute: the quota stays lowered (nothing puts it back), Docker
	// restarts the server no faster than its back-off, and the node check
	// reports nothing yet.
	restarts := func(s string) int {
		f := strings.Fields(s)
		if len(f) != 2 {
			return 0
		}
		n, _ := strconv.Atoi(f[1])
		return n
	}
	id := cpID(t)
	var states []string
	for end := time.Now().Add(time.Minute); time.Now().Before(end); time.Sleep(5 * time.Second) {
		states = append(states, cpState(t))
		// The counter starts again in a new container: a re-creation would
		// hide restarts.
		if now := cpID(t); now != id {
			t.Fatalf("sp-cp-db re-created at its quota (%.12s, then %.12s)", id, now)
		}
		if _, hard, err := nodefs.QuotaUsage(ctx, paths.ProjectsDir(), uid); err != nil || hard != int64(limit)<<10 {
			t.Fatalf("the quota changed under the test: %d KiB %v", hard, err)
		}
	}
	d := restarts(states[len(states)-1]) - restarts(start)
	t.Logf("sp-cp-db (running restarts): %s, then %v: %d restarts in a minute", start, states, d)
	// Docker's back-off doubles from 100 ms: at most 10 restarts in 60 s.
	if d > 10 {
		t.Errorf("restarted %d times within a minute: faster than Docker's back-off", d)
	}
	nc, _ := cliWithin(t, time.Minute, "node", "check")
	var doc struct {
		OK     bool `json:"ok"`
		Checks []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
	}
	decode(t, "node check", nc, &doc)
	for _, c := range doc.Checks {
		if c.Name == "control-plane-quota" {
			t.Errorf("a control-plane-quota row exists now: assert what it reports here")
		}
		if c.Name == "control-plane-db" {
			t.Logf("node check while at the quota: ok=%v, control-plane-db ok=%v", doc.OK, c.OK)
		}
	}

	// The raise, through the configuration: every committed row is there.
	setCPDiskQuota(t, 0)
	cpBack(t, 3*repairWait)
	if out, err := cpPsql("select count(*) from reach_cp_rows"); err != nil || out != strconv.Itoa(rows) {
		t.Fatalf("rows after the raise: %q %v", out, err)
	}
}

// The data directory is on the projects filesystem and the socket where it
// was built; the store opens there (cpBack) and a database the daemon created
// at this layout has page checksums.
func TestControlPlane_DataMovedSocketStays(t *testing.T) {
	if _, err := os.Lstat(filepath.Join(paths.CPProjectDir(), "data", "PG_VERSION")); err != nil {
		t.Fatalf("no database on the projects filesystem: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(paths.CPDir(), "data")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the older data path is still there: %v", err)
	}
	mounts := docker(t, "container", "inspect", "--format", "{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}", "--", cpContainer)
	for _, want := range []string{filepath.Join(paths.CPProjectDir(), "data") + ":/var/lib/postgresql/data",
		filepath.Join(paths.CPDir(), "sock") + ":/var/run/postgresql", paths.ToolsDir() + ":/opt/supapace/tools"} {
		if !strings.Contains(mounts, want) {
			t.Errorf("no mount %s in %s", want, mounts)
		}
	}
	cpBack(t, time.Minute)
	sum, err := cpPsql("show data_checksums")
	t.Logf("data_checksums: %s %v (on for a database created at this layout, off for one moved from an older build's path)", sum, err)
	arch, err := cpPsql("show archive_command")
	if err != nil || !strings.HasSuffix(arch, "# pgbackrest") {
		t.Fatalf("archive_command %q %v", arch, err)
	}
}

// cpID is sp-cp-db's container id, or "" when it is absent.
func cpID(t testing.TB) string {
	t.Helper()
	r, err := run(cmdTimeout, nil, "docker", "container", "inspect", "--format", "{{.Id}}", "--", cpContainer)
	if err != nil {
		t.Fatal(err)
	}
	if r.code != 0 {
		return ""
	}
	return strings.TrimSpace(r.stdout)
}
