package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/nodefs"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/jackc/pgx/v5"
)

// ───────── fixtures for archive settings, repositories and quotas ─────────

// l2Host replaces the repository and quota seams of dir.go and task.go and
// records each call in the fake host's log. usage maps a mount to the
// (used, hard) KiB its quota report gives.
type l2Host struct {
	usage    map[string][2]int64
	usageErr map[string]error
	space    syscall.Statfs_t
}

func l2Seams(t *testing.T, f *fakeHost) *l2Host {
	h := &l2Host{usage: map[string][2]int64{}, usageErr: map[string]error{}}
	saved := []func(){
		swap(&createProjectDirL2, func(p nodecfg.Paths, ref string, uid, gid, mb int) error {
			f.record(fmt.Sprintf("createProjectDirL2 %s %d:%d %d", ref, uid, gid, mb))
			return nil
		}),
		swap(&ensureRepoDir, func(p nodecfg.Paths, subject string, uid, gid, mb int) error {
			f.record(fmt.Sprintf("ensureRepoDir %s %d:%d %d", subject, uid, gid, mb))
			return nil
		}),
		swap(&repoSetQuota, func(mount string, id, mb int) error {
			f.record(fmt.Sprintf("repoSetQuota %s %d %d", mount, id, mb))
			return nil
		}),
		swap(&quotaUsage, func(ctx context.Context, mount string, id int) (int64, int64, error) {
			f.record(fmt.Sprintf("quotaUsage %s %d", mount, id))
			u := h.usage[mount]
			return u[0], u[1], h.usageErr[mount]
		}),
		swap(&repoStatfs, func(path string, st *syscall.Statfs_t) error {
			f.record("statfs " + path)
			*st = h.space
			return nil
		}),
		swap(&removeEmptyRepoDirs, func(p nodecfg.Paths, subject string) error {
			f.record("removeEmptyRepoDirs " + subject)
			return nil
		}),
		swap(&removeEmptyFetchDir, func(p nodecfg.Paths, subject string) error {
			f.record("removeEmptyFetchDir " + subject)
			return nil
		}),
	}
	t.Cleanup(func() {
		for _, r := range saved {
			r()
		}
	})
	return h
}

// l2Setup is clSetup for a layout-2 project: the archive binary beside the
// daemon's executable, the project's spool directories and the repository
// seams faked.
func l2Setup(t *testing.T) (*Agent, *fakeHost, Spec, *clPG, *l2Host) {
	t.Helper()
	a, f, s, pg := clSetup(t)
	h := l2Seams(t, f)
	s.Layout, s.RepoQuotaMB, s.Stanza = 2, 4096, testRef+"-1"
	exe := filepath.Join(t.TempDir(), "supapaced")
	l2Binary(t, exe, "archive binary v1")
	daemonExe = func() (string, error) { return exe, nil } // restored by clFakePG's cleanup
	pd := a.p.ProjectDir(s.Ref)
	mkdirs(t, filepath.Join(pd, "spool"), filepath.Join(pd, "rspool", "req"), filepath.Join(pd, "rspool", "out"))
	return a, f, s, pg, h
}

// l2Binary writes the archive binary beside the daemon's executable exe.
func l2Binary(t *testing.T, exe, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(exe), "supapace-arch"), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func l2Tools(a *Agent, s Spec) string {
	return filepath.Join(a.p.RenderDir(s.Ref), "tools", "supapace-arch")
}

// l2Own is the log without Docker calls: what root did itself.
func l2Own(f *fakeHost) []string {
	var own []string
	for _, c := range f.calls() {
		if !strings.HasPrefix(c, "docker ") && !strings.HasPrefix(c, "inspect ") && !strings.HasPrefix(c, "list ") {
			own = append(own, c)
		}
	}
	return own
}

func l2Runs(f *fakeHost) []string {
	var runs []string
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "docker run ") || strings.HasPrefix(c, "docker create ") {
			runs = append(runs, c)
		}
	}
	return runs
}

// ───────── the layout-2 cluster ─────────

// TestClusterArgs_Layout2: both start kinds mount the two spool directories
// right after the tools mount, take the pinned settings after the image's,
// and render an override file without the archive and connection lines.
func TestClusterArgs_Layout2(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	s.FirstBoot = false
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatalf("first networked start: %v", err)
	}
	runs := clRuns(f, "pg-"+s.Ref)
	if len(runs) != 2 {
		t.Fatalf("%d creates", len(runs))
	}
	r, pd := a.p.RenderDir(s.Ref), a.p.ProjectDir(s.Ref)
	cl, err := pgconf.CommandLine(clFixture(t, "postgresql.conf"))
	if err != nil {
		t.Fatal(err)
	}
	pins, err := pgconf.Pins(s.GUC)
	if err != nil {
		t.Fatal(err)
	}
	wantCmd := slices.Concat([]string{a.cfg.Images.Postgres, "postgres", "-D", "/etc/postgresql"}, cl, pins)
	for i, run := range runs {
		phase := []string{"A", "B"}[i]
		tools := slices.Index(run, r+"/tools:/opt/supapace/tools:ro")
		if tools < 0 || !slices.Equal(run[tools+1:tools+5], []string{"-v", pd + "/spool:/opt/supapace/spool", "-v", pd + "/rspool:/opt/supapace/rspool"}) {
			t.Errorf("phase %s: spool mounts not right after the tools mount: %q", phase, run)
		}
		if got := positional(run); !slices.Equal(got, wantCmd) {
			t.Errorf("phase %s: command %q, want %q", phase, got, wantCmd)
		}
		clCommon2(t, a, s, run, phase)
	}
	if got := clLabel(runs[1], "supapace.config"); got != "supapace.config="+clHash(t, a, s, runs[1]) {
		t.Errorf("label %q does not cover the layout-2 argv", got)
	}
	conf := clRead(t, filepath.Join(r, "conf.d", pgconf.OverrideFile))
	want, err := pgconf.OverridesPinned(s.GUC, s.MemMB)
	if err != nil || !bytes.Equal(conf, want) {
		t.Fatalf("override file %q, want OverridesPinned %q (%v)", conf, want, err)
	}
	for _, l := range strings.Split(string(conf), "\n") {
		name, _, _ := strings.Cut(l, " = ")
		if slices.Contains([]string{"archive_mode", "archive_command", "restore_command", "max_connections",
			"superuser_reserved_connections", "reserved_connections"}, name) {
			t.Errorf("override file sets %s", name)
		}
	}
	// Control: the same project at layout 1 has the lines and no spool mount.
	a1, f1, s1, _ := clSetup(t)
	if err := a1.EnsureCluster(context.Background(), s1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(clRead(t, filepath.Join(a1.p.RenderDir(s1.Ref), "conf.d", pgconf.OverrideFile))), "max_connections = ") {
		t.Error("control: layout 1 lacks max_connections in its override file")
	}
	if strings.Contains(strings.Join(clRuns(f1, "pg-"+s1.Ref)[0], " "), "/opt/supapace/spool") {
		t.Error("control: layout 1 mounts a spool")
	}
}

// clCommon2 is clCommon for a layout-2 run: its flags and mounts against the
// common list, its command (checked by the caller) replaced by layout 1's.
func clCommon2(t *testing.T, a *Agent, s Spec, run []string, phase string) {
	t.Helper()
	cl, err := pgconf.CommandLine(clFixture(t, "postgresql.conf"))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(run, "--")
	clCommon(t, a, s, slices.Concat(run[:i+1], []string{a.cfg.Images.Postgres, "postgres", "-D", "/etc/postgresql"}, cl), phase)
}

// TestClusterLabel_DoesNotCoverTheArchiveBinary: a new archive binary leaves
// the configuration label as it is; a changed rendered file (control) does not.
func TestClusterLabel_DoesNotCoverTheArchiveBinary(t *testing.T) {
	a, _, s, _, _ := l2Setup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	label := func() string {
		args, err := a.clusterRunArgs(s, true)
		if err != nil {
			t.Fatal(err)
		}
		return labelValue(args, labelConfig)
	}
	before := label()
	exe, _ := daemonExe()
	l2Binary(t, exe, "archive binary v2, rebuilt")
	if err := a.ensureArchBinary(s.Ref); err != nil {
		t.Fatal(err)
	}
	if got := string(clRead(t, l2Tools(a, s))); got != "archive binary v2, rebuilt" {
		t.Fatalf("binary not copied: %q", got)
	}
	if after := label(); after != before {
		t.Fatalf("label changed with the archive binary: %s → %s", before, after)
	}
	// Control: a file the label covers.
	conf := filepath.Join(a.p.RenderDir(s.Ref), "conf.d", pgconf.OverrideFile)
	os.Chmod(conf, 0o644)
	os.WriteFile(conf, append(clRead(t, conf), "# changed\n"...), 0o444)
	if label() == before {
		t.Fatal("control: the label does not cover the override file")
	}
}

// TestEnsureCluster_NewArchiveBinaryRenamedIn_RunningClusterAdopted: a
// changed binary is renamed into the tools directory while the running
// cluster is adopted: no stop, no create; an unchanged one is not written.
func TestEnsureCluster_NewArchiveBinaryRenamedIn_RunningClusterAdopted(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	c := clCtr(t, f, "pg-"+s.Ref)
	var old syscall.Stat_t
	if err := syscall.Lstat(l2Tools(a, s), &old); err != nil {
		t.Fatalf("no archive binary after the first start: %v", err)
	}
	exe, _ := daemonExe()
	l2Binary(t, exe, "archive binary v2")
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("a new archive binary stopped or re-created the cluster: %q", m)
	}
	if got := clCtr(t, f, "pg-"+s.Ref); got.ID != c.ID {
		t.Fatal("container replaced")
	}
	var now syscall.Stat_t
	if err := syscall.Lstat(l2Tools(a, s), &now); err != nil || now.Ino == old.Ino {
		t.Fatalf("binary not replaced by a rename (inode %d → %d): %v", old.Ino, now.Ino, err)
	}
	fi, _ := os.Lstat(l2Tools(a, s))
	if string(clRead(t, l2Tools(a, s))) != "archive binary v2" || fi.Mode().Perm() != 0o555 {
		t.Fatalf("binary %q mode %v", clRead(t, l2Tools(a, s)), fi.Mode())
	}
	if !slices.Contains(f.calls(), fmt.Sprintf("write %s 555 %d:%d", l2Tools(a, s), os.Geteuid(), os.Getegid())) {
		t.Fatalf("not written root 0555 through the atomic writer: %q", f.calls())
	}
	ents, _ := os.ReadDir(filepath.Dir(l2Tools(a, s)))
	if len(ents) != 1 {
		t.Fatalf("tools directory holds %d entries", len(ents))
	}
	// The same binary again: nothing written.
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "write ") {
			t.Fatalf("an unchanged binary was written again: %s", c)
		}
	}
	// No binary beside the daemon: the ensure fails, the cluster is left as is.
	os.Remove(filepath.Join(filepath.Dir(exe), "supapace-arch"))
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("missing binary: %v %q", err, f.mutations())
	}
}

// TestEnsureCluster_Layout1AdoptedUnchanged: a running layout-1 cluster, and
// one created before layouts (layout 0), carrying the label as built, is
// adopted: no stop, no create, no file written.
func TestEnsureCluster_Layout1AdoptedUnchanged(t *testing.T) {
	for _, layouts := range [][2]int{{1, 1}, {0, 1}, {0, 0}} {
		t.Run(fmt.Sprint(layouts), func(t *testing.T) {
			a, f, s, _ := clSetup(t)
			s.Layout = layouts[0]
			c := clToPhaseB(t, a, f, s)
			if got := c.Labels[labelConfig]; got != clHash(t, a, s, c.Argv) {
				t.Fatalf("label %s is not the as-built hash", got)
			}
			s.Layout = layouts[1]
			f.resetLog()
			if err := a.EnsureCluster(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			if m := f.mutations(); len(m) != 0 {
				t.Fatalf("mutations %q", m)
			}
			for _, call := range f.calls() {
				if strings.HasPrefix(call, "write ") {
					t.Fatalf("adoption wrote %s", call)
				}
			}
			if _, err := os.Lstat(l2Tools(a, s)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a layout-1 project got an archive binary: %v", err)
			}
		})
	}
}

// TestEnsureCluster_PhaseRNeverAdopted_Removed: a recovery start (label
// phase R) is never adopted, whatever the state file says; it is removed
// first, and a normal start records phase B.
func TestEnsureCluster_PhaseRNeverAdopted_Removed(t *testing.T) {
	for _, statePhase := range []string{PhaseR, PhaseB} {
		t.Run(statePhase, func(t *testing.T) {
			a, f, s, _, _ := l2Setup(t)
			clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
			if err := a.EnsureCluster(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			c := clCtr(t, f, "pg-"+s.Ref)
			c.Labels[labelPhase] = "R" // everything else as an adoptable container
			delete(c.Nets, "proj-"+s.Ref)
			st := clReadState(t, a, s)
			st.Phase = statePhase
			clState(t, a, s, st)
			old := *c
			f.resetLog()
			if err := a.EnsureCluster(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			clRemovedAndRerun(t, a, f, s, &old, false)
		})
	}
}

// A state file left at phase R by a recovery start is never adopted, even
// beside a container whose labels would be: it is stopped and started again.
func TestEnsureCluster_PhaseRStateNeverAdopted(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	old := *clCtr(t, f, "pg-"+s.Ref)
	st := clReadState(t, a, s)
	st.Phase = PhaseR
	clState(t, a, s, st)
	f.resetLog()
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	clRemovedAndRerun(t, a, f, s, &old, true)
}

// TestStopCluster_RemovesARecoveryStart: the as-built stop finds a recovery
// start by its name and stops and removes it.
func TestStopCluster_RemovesARecoveryStart(t *testing.T) {
	a, f, s, _ := clSetup(t)
	f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, CapDrop: []string{"ALL"}, NetMode: "none",
		Labels: map[string]string{labelRole: "cluster", labelRef: s.Ref, labelPhase: "R"}, Nets: map[string]string{}})
	if err := a.StopCluster(context.Background(), s.Ref); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); !slices.Equal(m, []string{"docker stop -t 45 -- pg-" + s.Ref, "docker rm -v -- pg-" + s.Ref}) {
		t.Fatalf("mutations %q", m)
	}
	if c, _ := dockerInspectContainer(context.Background(), "pg-"+s.Ref); c != nil {
		t.Fatal("recovery start left")
	}
}

// TestState_PhaseRAccepted: the state file records a recovery start (phase
// R) and reads it back; an unknown phase is still refused both ways.
func TestState_PhaseRAccepted(t *testing.T) {
	a, _, s, _ := clSetup(t)
	want := State{Epoch: 1, Generation: 2, Phase: PhaseR, PMPid: 77, PMStart: 770}
	clState(t, a, s, want)
	if got, ok, err := a.readState(s.Ref); err != nil || !ok || got != want {
		t.Fatalf("read %+v %v %v", got, ok, err)
	}
	if err := a.writeState(s.Ref, State{Phase: "C"}); err == nil {
		t.Fatal("unknown phase written")
	}
	os.WriteFile(filepath.Join(a.p.RenderDir(s.Ref), stateFile), []byte(`{"epoch":1,"generation":2,"phase":"r","pm_pid":0,"pm_start":0,"listener_pid":0,"listener_start":0}`), 0o600)
	if _, _, err := a.readState(s.Ref); err == nil {
		t.Fatal("unknown phase read")
	}
}

// ───────── checks of a running cluster ─────────

// TestCheckCluster_NoArchiverQuery: the verdict is the login and nothing
// else: the session sends no statement but the assertion's, and a spool the
// server cannot write does not fail it.
func TestCheckCluster_NoArchiverQuery(t *testing.T) {
	a, f, s, pg, _ := l2Setup(t)
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	spool := filepath.Join(a.p.ProjectDir(s.Ref), "spool")
	os.Chmod(spool, 0)
	defer os.Chmod(spool, 0o755)
	f.resetLog()
	if _, err := a.CheckCluster(context.Background(), s); err != nil {
		t.Fatalf("verdict: %v", err)
	}
	if got := f.calls(); !slices.Equal(got, []string{fmt.Sprintf("dial supabase_admin pid=%d start=%d trust=false",
		clReadState(t, a, s).PMPid, clReadState(t, a, s).PMStart), "assert hba", "assert", "assert read-only login"}) {
		t.Fatalf("session %q", got)
	}
	// Control: the login is the verdict.
	pg.dialErrs = []error{errors.New("login refused")}
	if _, err := a.CheckCluster(context.Background(), s); err == nil {
		t.Fatal("a failed login passed")
	}
}

// TestCheckCluster_UsesPinnedNames: the drift rows come from the assertion
// told which names the cluster's layout sets on the command line.
func TestCheckCluster_UsesPinnedNames(t *testing.T) {
	for _, layout := range []int{0, 1, 2} {
		a, f, s, pg, _ := l2Setup(t)
		s.Layout = layout
		clToPhaseB(t, a, f, s)
		pg.assertNames = nil
		if err := a.VerifyCluster(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		if want := pgconf.PinnedNames(max(layout, 1)); !slices.Equal(pg.assertNames, want) {
			t.Errorf("layout %d: names %q, want %q", layout, pg.assertNames, want)
		}
	}
}

// ───────── project directory, spool directories, quotas ─────────

func TestEnsureDir_Layout2CreatesTheSpoolDirectories(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	f.resetLog()
	if err := a.EnsureDir(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if got := l2Own(f); !slices.Equal(got, []string{"createProjectDirL2 " + s.Ref + " 700005:700005 8192"}) {
		t.Fatalf("calls %q", got)
	}
}

// TestEnsureSpoolDirs_TaskAtProjectUid: the spool directories of a project
// made before them are created by a task at the project's uid; root creates
// nothing inside the project directory.
func TestEnsureSpoolDirs_TaskAtProjectUid(t *testing.T) {
	a, f, s, pg, _ := l2Setup(t)
	pd := a.p.ProjectDir(s.Ref)
	os.RemoveAll(filepath.Join(pd, "spool"))
	os.RemoveAll(filepath.Join(pd, "rspool"))
	before := entriesOf(t, pd)
	f.resetLog()
	if err := a.EnsureSpoolDirs(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	args := clOneRun(t, f, "task-"+s.Ref+"-spool")
	clHardenedTask(t, a, s, args, "spool")
	clWantPairs(t, "spool", args, "-v", pd+":/p", "--entrypoint", "mkdir")
	if n := len(flagValues(args, "-v")); n != 1 {
		t.Errorf("spool task mounts %d paths", n)
	}
	if got := positional(args); !slices.Equal(got, []string{a.cfg.Images.Postgres, "-p", "-m", "0700", "/p/spool", "/p/rspool", "/p/rspool/req", "/p/rspool/out"}) {
		t.Errorf("command %q", got)
	}
	if own := l2Own(f); len(own) != 0 {
		t.Errorf("root acted itself: %q", own)
	}
	if after := entriesOf(t, pd); !slices.Equal(after, before) {
		t.Errorf("root created %q inside the project directory", after)
	}
	// A failed task is an error; no project directory launches nothing.
	pg.taskExit["spool"] = "1"
	if err := a.EnsureSpoolDirs(context.Background(), s); err == nil {
		t.Fatal("failed task accepted")
	}
	os.RemoveAll(pd)
	f.resetLog()
	if err := a.EnsureSpoolDirs(context.Background(), s); err == nil || len(l2Runs(f)) != 0 {
		t.Fatalf("absent project directory: %v %q", err, l2Runs(f))
	}
	if err := a.EnsureSpoolDirs(context.Background(), Spec{Ref: "../x", UID: 700005, GID: 700005}); err == nil {
		t.Fatal("bad ref accepted")
	}
}

func entriesOf(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestSetQuota_Layout2SetsBothFilesystems: layout 2 sets the repository quota
// on the repository filesystem beside the disk quota; layout 1 only the disk
// quota; a layout-2 spec without a repository quota is refused before
// anything is set (0 would clear it).
func TestSetQuota_Layout2SetsBothFilesystems(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	f.resetLog()
	if err := a.SetQuota(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	want := []string{"setQuota 700005 8192", "repoSetQuota " + a.p.RepoRoot() + " 700005 4096"}
	if got := l2Own(f); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	s.Layout = 1
	f.resetLog()
	if err := a.SetQuota(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if got := l2Own(f); !slices.Equal(got, want[:1]) {
		t.Fatalf("layout 1: calls %q", got)
	}
	s.Layout, s.RepoQuotaMB = 2, 0
	f.resetLog()
	if err := a.SetQuota(context.Background(), s); err == nil || len(l2Own(f)) != 0 {
		t.Fatalf("no repository quota: %v %q", err, l2Own(f))
	}
}

func TestEnsureRepoDir_SubjectIdsAndQuota(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	f.resetLog()
	if err := a.EnsureRepoDir(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if got := l2Own(f); !slices.Equal(got, []string{"ensureRepoDir " + s.Ref + " 700005:700005 4096"}) {
		t.Fatalf("calls %q", got)
	}
	bad := s
	bad.Ref = "cp"
	if err := a.EnsureRepoDir(context.Background(), bad); err == nil {
		t.Fatal("a project spec named the control plane")
	}
}

// ───────── repository purges ─────────

// l2RepoDirs creates <repo>/<ref> root 0755 and the named directories in it.
func l2RepoDirs(t *testing.T, a *Agent, s Spec, dirs ...string) string {
	t.Helper()
	rd := a.p.RepoDir(s.Ref)
	mkdirs(t, a.p.RepoRoot(), rd)
	for _, d := range dirs {
		mkdirs(t, filepath.Join(rd, d))
	}
	return rd
}

// TestPurgeRepo_TwoTasksAtOwnerUids_ThenEmptyDirsRemoved_BothQuotasCleared:
// repo/ is emptied at the project's uid and fetch/ at the replicator's, each
// task mounting the subject directory; both quotas are cleared before them;
// only then does root remove the empty directories.
func TestPurgeRepo_TwoTasksAtOwnerUids_ThenEmptyDirsRemoved_BothQuotasCleared(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	rd := l2RepoDirs(t, a, s, "repo", "fetch")
	f.resetLog()
	if err := a.PurgeRepo(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ kind, user, dir string }{{"purge-repo", "700005:700005", "/r/repo"}, {"purge-fetch", "65530:700005", "/r/fetch"}} {
		args := clOneRun(t, f, "task-"+s.Ref+"-"+c.kind)
		// The common task flags, the user aside (checked below).
		common := slices.Clone(args)
		common[slices.Index(common, "--user")+1] = "700005:700005"
		clHardenedTask(t, a, s, common, c.kind)
		clWantPairs(t, c.kind, args, "--user", c.user, "-v", l2Exe(t)+":/supapaced:ro", "-v", rd+":/r",
			"--entrypoint", "/supapaced")
		if got := positional(args); !slices.Equal(got, []string{a.cfg.Images.Postgres, "rmtree", "--keep-root", c.dir}) {
			t.Errorf("%s command %q", c.kind, got)
		}
	}
	calls := f.calls()
	repoTask := clIndex(calls, clPrefix("docker run -d --name task-"+s.Ref+"-purge-repo"))
	fetchTask := clIndex(calls, clPrefix("docker run -d --name task-"+s.Ref+"-purge-fetch"))
	for _, q := range []string{"setQuota 700005 0", "repoSetQuota " + a.p.RepoRoot() + " 700005 0"} {
		if i := slices.Index(calls, q); i < 0 || i > repoTask {
			t.Errorf("%q not before the tasks: %q", q, calls)
		}
	}
	rm := slices.Index(calls, "removeEmptyRepoDirs "+s.Ref)
	if rm < clLastIndex(calls, "docker rm -f -v -- task-"+s.Ref+"-purge-fetch") || fetchTask < 0 || repoTask < 0 {
		t.Fatalf("directories removed before both tasks were done: %q", calls)
	}
	if slices.Contains(calls, "removeEmptyFetchDir "+s.Ref) {
		t.Fatal("the fetch-only removal is RemoveFetch's")
	}
	// A failed task stops the purge before any removal.
	a, f, s, pg, _ := l2Setup(t)
	l2RepoDirs(t, a, s, "repo", "fetch")
	pg.taskExit["purge-repo"] = "1"
	if err := a.PurgeRepo(context.Background(), s); err == nil {
		t.Fatal("failed task accepted")
	}
	if slices.ContainsFunc(f.calls(), clPrefix("removeEmptyRepoDirs")) || slices.ContainsFunc(f.calls(), clPrefix("docker run -d --name task-"+s.Ref+"-purge-fetch")) {
		t.Fatalf("went on after a failed task: %q", f.calls())
	}
}

// TestPurgeRepo_AbsentDirectoriesAreDone: an absent repo/ or fetch/ launches
// no task; an absent subject directory (a node that holds nothing of the
// project) is done with nothing launched and nothing removed.
func TestPurgeRepo_AbsentDirectoriesAreDone(t *testing.T) {
	for _, c := range []struct {
		name  string
		dirs  []string // nil: no subject directory at all
		tasks []string
	}{
		{"no subject directory", nil, nil},
		{"empty subject directory", []string{}, nil},
		{"repo only", []string{"repo"}, []string{"purge-repo"}},
		{"fetch only", []string{"fetch"}, []string{"purge-fetch"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			a, f, s, _, _ := l2Setup(t)
			if c.dirs != nil {
				l2RepoDirs(t, a, s, c.dirs...)
			}
			f.resetLog()
			if err := a.PurgeRepo(context.Background(), s); err != nil {
				t.Fatal(err)
			}
			var tasks []string
			for _, r := range l2Runs(f) {
				tasks = append(tasks, strings.TrimPrefix(strings.Fields(r)[4], "task-"+s.Ref+"-"))
			}
			if !slices.Equal(tasks, c.tasks) {
				t.Fatalf("tasks %q, want %q", tasks, c.tasks)
			}
			removed := slices.Contains(f.calls(), "removeEmptyRepoDirs "+s.Ref)
			if removed != (c.dirs != nil) {
				t.Fatalf("subject directory removal %v: %q", removed, f.calls())
			}
		})
	}
	// The repository root itself absent (a layout-1 node without one): done,
	// nothing called.
	a, f, s, _, _ := l2Setup(t)
	s.Layout = 1
	os.RemoveAll(a.p.RepoRoot())
	f.resetLog()
	if err := a.PurgeRepo(context.Background(), s); err != nil || len(l2Runs(f)) != 0 || len(l2Own(f)) != 0 {
		t.Fatalf("no repository root: %v %q", err, f.calls())
	}
	// At layout 2 the same node is an error: the repository quota cannot be
	// cleared on an absent root.
	s.Layout = 2
	defer swap(&repoSetQuota, nodefs.SetQuotaAt)()
	if err := a.PurgeRepo(context.Background(), s); err == nil || len(l2Runs(f)) != 0 {
		t.Fatalf("layout 2, no repository root: %v %q", err, l2Runs(f))
	}
}

// TestRemoveFetch_AbsentIsDone: without fetch/ (or without the subject
// directory) nothing is launched or removed; with it, one task at the
// replicator's uid empties it and the fetch-only removal follows.
func TestRemoveFetch_AbsentIsDone(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	if err := a.RemoveFetch(context.Background(), s); err != nil || len(l2Runs(f)) != 0 || len(l2Own(f)) != 0 {
		t.Fatalf("no subject directory: %v %q", err, f.calls())
	}
	rd := l2RepoDirs(t, a, s, "repo")
	if err := a.RemoveFetch(context.Background(), s); err != nil || len(l2Runs(f)) != 0 || len(l2Own(f)) != 0 {
		t.Fatalf("no fetch/: %v %q", err, f.calls())
	}
	mkdirs(t, filepath.Join(rd, "fetch"))
	f.resetLog()
	if err := a.RemoveFetch(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	args := clOneRun(t, f, "task-"+s.Ref+"-purge-fetch")
	clWantPairs(t, "purge-fetch", args, "--user", "65530:700005", "-v", rd+":/r")
	if got := positional(args); !slices.Equal(got, []string{a.cfg.Images.Postgres, "rmtree", "--keep-root", "/r/fetch"}) {
		t.Errorf("command %q", got)
	}
	if got := l2Own(f); !slices.Equal(got, []string{"removeEmptyFetchDir " + s.Ref}) {
		t.Fatalf("root's calls %q: fetch/ is removed alone, nothing else", got)
	}
	if len(l2Runs(f)) != 1 {
		t.Fatalf("runs %q", l2Runs(f))
	}
}

// TestPurgeRepo_RefusedWhileJobExists: any job container of the subject, in
// any state, refuses the purge before anything is changed; a job of another
// subject or a probe does not.
func TestPurgeRepo_RefusedWhileJobExists(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	l2RepoDirs(t, a, s, "repo", "fetch")
	job := f.ctr(fakeCtr{Name: "job-" + s.Ref + "-push", Labels: map[string]string{labelRole: "job", labelRef: s.Ref, "supapace.kind": "push"}})
	f.resetLog()
	if err := a.PurgeRepo(context.Background(), s); err == nil {
		t.Fatal("purged beside a job container")
	}
	if len(l2Runs(f)) != 0 || len(l2Own(f)) != 0 {
		t.Fatalf("acted while refusing: %q", f.calls())
	}
	f.mu.Lock()
	delete(f.ctrs, job.Name)
	f.mu.Unlock()
	f.ctr(fakeCtr{Name: "job-bbbbbbbbbb0123456789-push", Labels: map[string]string{labelRole: "job", labelRef: "bbbbbbbbbb0123456789"}})
	f.ctr(fakeCtr{Name: "job-probe-projects", Labels: map[string]string{labelRole: "job", labelRef: "probe-projects"}})
	if err := a.PurgeRepo(context.Background(), s); err != nil {
		t.Fatalf("other subjects' jobs: %v", err)
	}
	// A cluster or PostgREST container of the project refuses it too: the
	// disk quota is lifted.
	for _, name := range []string{"pg-" + s.Ref, "postgrest-" + s.Ref} {
		f.ctr(fakeCtr{Name: name, Labels: map[string]string{labelRole: "x"}})
		f.resetLog()
		if err := a.PurgeRepo(context.Background(), s); err == nil || len(l2Own(f)) != 0 || len(l2Runs(f)) != 0 {
			t.Fatalf("%s exists: %v %q", name, err, f.calls())
		}
		f.mu.Lock()
		delete(f.ctrs, name)
		f.mu.Unlock()
	}
	// A repository directory that is not a directory is an error.
	rd := a.p.RepoDir(s.Ref)
	os.RemoveAll(filepath.Join(rd, "fetch"))
	os.WriteFile(filepath.Join(rd, "fetch"), nil, 0o600)
	if err := a.PurgeRepo(context.Background(), s); err == nil {
		t.Fatal("a file at fetch/ accepted")
	}
	os.Remove(filepath.Join(rd, "fetch"))
	// A failed listing is an error, never "no job".
	defer swap(&dockerListContainers, func(ctx context.Context, label string) ([]dockerx.Container, error) {
		return nil, errors.New("docker: daemon busy")
	})()
	if err := a.PurgeRepo(context.Background(), s); err == nil {
		t.Fatal("a failed listing accepted")
	}
}

// ───────── host state, quota use, disk usage, space ─────────

// TestHostState_FourFacts: each fact is read from the host on its own.
func TestHostState_FourFacts(t *testing.T) {
	a, f, s, _, h := l2Setup(t)
	got, err := a.HostState(context.Background(), s)
	if err != nil || got != (HostState{ProjectDir: true}) {
		t.Fatalf("directory only: %+v %v", got, err)
	}
	clState(t, a, s, State{Epoch: 1, Generation: 1, Phase: PhaseB})
	f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, Labels: map[string]string{labelRole: "cluster"}})
	h.usage[a.p.ProjectsDir()] = [2]int64{8192 << 10, 8192 << 10}
	got, err = a.HostState(context.Background(), s)
	if err != nil || got != (HostState{true, true, true, true}) {
		t.Fatalf("all four: %+v %v", got, err)
	}
	os.RemoveAll(a.p.ProjectDir(s.Ref))
	os.Remove(filepath.Join(a.p.RenderDir(s.Ref), stateFile))
	clCtr(t, f, "pg-"+s.Ref).Running = false
	h.usage[a.p.ProjectsDir()] = [2]int64{}
	got, err = a.HostState(context.Background(), s)
	if err != nil || got != (HostState{}) {
		t.Fatalf("none: %+v %v", got, err)
	}
	// A link where the project directory belongs is not one.
	os.Symlink(t.TempDir(), a.p.ProjectDir(s.Ref))
	if got, err := a.HostState(context.Background(), s); err != nil || got.ProjectDir {
		t.Fatalf("link: %+v %v", got, err)
	}
	// Facts that cannot be read are errors.
	h.usageErr[a.p.RepoRoot()] = errors.New("quota tool failed")
	if _, err := a.HostState(context.Background(), s); err == nil {
		t.Fatal("unreadable quota accepted")
	}
	h.usageErr = map[string]error{}
	f.failInspect["pg-"+s.Ref] = errors.New("docker: daemon busy")
	if _, err := a.HostState(context.Background(), s); err == nil {
		t.Fatal("unreadable container accepted")
	}
	if _, err := a.HostState(context.Background(), Spec{Ref: "../x", UID: 700005}); err == nil {
		t.Fatal("bad ref accepted")
	}
}

// TestHostState_QuotaFullFromUsageNotFromTheContainer: the disk quota is full
// when its usage is within one 4 KiB block of its hard limit, whether or not
// the cluster runs.
func TestHostState_QuotaFullFromUsageNotFromTheContainer(t *testing.T) {
	a, f, s, _, h := l2Setup(t)
	const hard = 8192 << 10
	for _, c := range []struct {
		used, hard int64
		running    bool
		want       bool
	}{
		{hard - 4, hard, false, true},
		{hard, hard, false, true},
		{hard - 4, hard, true, true},
		{hard - 5, hard, true, false},
		{hard - 5, hard, false, false},
		{1 << 30, 0, false, false}, // no limit
	} {
		f.mu.Lock()
		delete(f.ctrs, "pg-"+s.Ref)
		f.mu.Unlock()
		if c.running {
			f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: true, Labels: map[string]string{labelRole: "cluster"}})
		}
		h.usage[a.p.ProjectsDir()] = [2]int64{c.used, c.hard}
		h.usage[a.p.RepoRoot()] = [2]int64{0, 4096 << 10}
		got, err := a.HostState(context.Background(), s)
		if err != nil || got.QuotaFull != c.want || got.ClusterRunning != c.running {
			t.Errorf("used %d of %d, running %v: %+v %v", c.used, c.hard, c.running, got, err)
		}
	}
}

type ctxKey struct{}

// TestQuotaUse_BothMounts: the uid's report on the projects filesystem and on
// the repository filesystem, read with the caller's context.
func TestQuotaUse_BothMounts(t *testing.T) {
	a, f, _, _, _ := l2Setup(t)
	var ctxs []context.Context
	defer swap(&quotaUsage, func(ctx context.Context, mount string, id int) (int64, int64, error) {
		f.record(fmt.Sprintf("quotaUsage %s %d", mount, id))
		ctxs = append(ctxs, ctx)
		if mount == a.p.RepoRoot() {
			return 30, 40, nil
		}
		return 10, 20, nil
	})()
	ctx := context.WithValue(context.Background(), ctxKey{}, "caller")
	f.resetLog()
	got, err := a.QuotaUse(ctx, 700005)
	if err != nil || got != (QuotaUse{10, 20, 30, 40}) {
		t.Fatalf("%+v %v", got, err)
	}
	if want := []string{"quotaUsage " + a.p.ProjectsDir() + " 700005", "quotaUsage " + a.p.RepoRoot() + " 700005"}; !slices.Equal(f.calls(), want) {
		t.Fatalf("calls %q", f.calls())
	}
	for _, c := range ctxs {
		if c.Value(ctxKey{}) != "caller" {
			t.Fatal("not the caller's context")
		}
	}
}

// TestQuotaUse_EndsWithItsContext: a quota tool that hangs (a fake first on
// PATH) ends when the caller's context does, with an error that matches it;
// control: the same fake answering gives the figures.
func TestQuotaUse_EndsWithItsContext(t *testing.T) {
	a, _, _ := newTestAgent(t)
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	tool := filepath.Join(dir, "xfs_quota")
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	write := func(body string) {
		if err := os.WriteFile(tool, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Control first.
	write(`echo "/dev/loop9 1200 0 2048 00 [--------] 5 0 65536 00 [--------] /x"`)
	got, err := a.QuotaUse(context.Background(), 700005)
	if err != nil || got != (QuotaUse{1200, 2048, 1200, 2048}) {
		t.Fatalf("control: %+v %v", got, err)
	}
	write(`: > ` + started + `; exec sleep 600`)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.QuotaUse(ctx, 700005); done <- err }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fake quota tool never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want an error matching the context's", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("QuotaUse did not end with its context")
	}
}

// TestDiskUsage_Layout2IsTheLargerOfBothFilesystems: a repository fuller
// than the data directory gives the repository's figure; a data directory
// fuller, the data's; layout 1 reads the projects filesystem only.
func TestDiskUsage_Layout2IsTheLargerOfBothFilesystems(t *testing.T) {
	a, f, s, _, h := l2Setup(t)
	defer swap(&diskUsage, func(ctx context.Context, p nodecfg.Paths, uid int) (int64, error) {
		f.record(fmt.Sprintf("diskUsage %d", uid))
		return 100 << 10, nil
	})()
	h.usage[a.p.ProjectsDir()] = [2]int64{100, 8192 << 10}
	h.usage[a.p.RepoRoot()] = [2]int64{300, 4096 << 10}
	if got, err := a.DiskUsage(context.Background(), s); err != nil || got != 300<<10 {
		t.Fatalf("repository fuller: %d %v", got, err)
	}
	h.usage[a.p.RepoRoot()] = [2]int64{50, 4096 << 10}
	if got, err := a.DiskUsage(context.Background(), s); err != nil || got != 100<<10 {
		t.Fatalf("data fuller: %d %v", got, err)
	}
	h.usageErr[a.p.RepoRoot()] = errors.New("quota tool failed")
	if _, err := a.DiskUsage(context.Background(), s); err == nil {
		t.Fatal("an unread repository usage accepted")
	}
	for _, layout := range []int{0, 1} {
		s.Layout = layout
		f.resetLog()
		if got, err := a.DiskUsage(context.Background(), s); err != nil || got != 100<<10 {
			t.Fatalf("layout %d: %d %v", layout, got, err)
		}
		if got := l2Own(f); !slices.Equal(got, []string{"diskUsage 700005"}) {
			t.Fatalf("layout %d: calls %q", layout, got)
		}
	}
}

func TestRepoSpace_StatfsOfTheRepositoryRoot(t *testing.T) {
	a, f, _, _, h := l2Setup(t)
	h.space = syscall.Statfs_t{Frsize: 4096, Bsize: 1 << 20, Blocks: 1 << 20, Bavail: 1 << 18, Bfree: 1 << 19}
	f.resetLog()
	size, free, err := a.RepoSpace(context.Background())
	if err != nil || size != 4096 || free != 1024 {
		t.Fatalf("%d %d %v", size, free, err)
	}
	if got := l2Own(f); !slices.Equal(got, []string{"statfs " + a.p.RepoRoot()}) {
		t.Fatalf("calls %q", got)
	}
}

// ───────── the backup role ─────────

func l2Grant(t *testing.T, f *fakeHost, grantErr error, reset bool, resetErr error) {
	t.Helper()
	saved := []func(){
		swap(&bootstrapGrantBackup, func(ctx context.Context, c *pgx.Conn) error { f.record("grant backup"); return grantErr }),
		swap(&bootstrapResetStatementStats, func(ctx context.Context, c *pgx.Conn) (bool, error) {
			f.record("reset statement stats")
			return reset, resetErr
		}),
	}
	t.Cleanup(func() {
		for _, r := range saved {
			r()
		}
	})
}

// TestGrantBackupRole_ScramSession_PlainSQL: one SCRAM session as the
// platform's superuser to the recorded postmaster, the grant and then the
// reset in it, nothing else.
func TestGrantBackupRole_ScramSession_PlainSQL(t *testing.T) {
	a, f, s, pg, _ := l2Setup(t)
	clToPhaseB(t, a, f, s)
	l2Grant(t, f, nil, true, nil)
	pg.targets = nil
	if err := a.GrantBackupRole(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	st := clReadState(t, a, s)
	if len(pg.targets) != 1 {
		t.Fatalf("%d sessions", len(pg.targets))
	}
	tg := pg.targets[0]
	if tg.AllowTrust || !tg.Superuser || tg.User != "supabase_admin" || tg.Password != s.Secrets.SupabaseAdminPassword ||
		!bytes.Equal(tg.ScramSalt, s.Secrets.ScramSalts["supabase_admin"]) || tg.PostmasterPid != st.PMPid || tg.PostmasterStart != st.PMStart {
		t.Fatalf("target %+v", tg)
	}
	want := []string{fmt.Sprintf("dial supabase_admin pid=%d start=%d trust=false", st.PMPid, st.PMStart), "grant backup", "reset statement stats"}
	if got := f.calls(); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	// Refusals: a grant that fails is the step's error; no cluster started in
	// phase B dials nothing.
	l2Grant(t, f, errors.New("permission denied"), true, nil)
	f.resetLog()
	if err := a.GrantBackupRole(context.Background(), s); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("grant failure: %v", err)
	}
	if slices.Contains(f.calls(), "reset statement stats") {
		t.Fatal("reset after a failed grant")
	}
	clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
	pg.targets = nil
	if err := a.GrantBackupRole(context.Background(), s); err == nil || len(pg.targets) != 0 {
		t.Fatalf("A-done: %v, %d dials", err, len(pg.targets))
	}
	pg.dialErrs = []error{errors.New("login refused")}
	clState(t, a, s, st)
	if err := a.GrantBackupRole(context.Background(), s); err == nil {
		t.Fatal("a failed login accepted")
	}
}

// TestGrantBackupRole_ThenResetsTheStatementStatistics_AResetFailureDoesNotFailIt.
func TestGrantBackupRole_ThenResetsTheStatementStatistics_AResetFailureDoesNotFailIt(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	clToPhaseB(t, a, f, s)
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	for _, c := range []struct {
		reset bool
		err   error
		log   string
	}{
		{false, errors.New("statement timeout\nforged line"), "level=WARN"},
		{false, nil, "not reset"},
	} {
		l2Grant(t, f, nil, c.reset, c.err)
		buf.Reset()
		f.resetLog()
		if err := a.GrantBackupRole(context.Background(), s); err != nil {
			t.Fatalf("reset %v %v failed the step: %v", c.reset, c.err, err)
		}
		if i, j := slices.Index(f.calls(), "grant backup"), slices.Index(f.calls(), "reset statement stats"); i < 0 || j < i {
			t.Fatalf("order %q", f.calls())
		}
		if !strings.Contains(buf.String(), c.log) || !strings.Contains(buf.String(), s.Ref) || strings.Count(buf.String(), "\n") != 1 {
			t.Fatalf("log %q", buf.String())
		}
	}
}

// ───────── exported wrappers ─────────

// TestWipeData_Exported: the as-built wipe, behind the spec's checks.
func TestWipeData_Exported(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	f.resetLog()
	if err := a.WipeData(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	args := clOneRun(t, f, "task-"+s.Ref+"-wipe")
	clHardenedTask(t, a, s, args, "wipe")
	if got := positional(args); !slices.Equal(got, []string{a.cfg.Images.Postgres, "rmtree", "--keep-root", "/p/data"}) {
		t.Fatalf("command %q", got)
	}
	for _, bad := range []Spec{{Ref: "../x", UID: 700005, GID: 700005}, {Ref: s.Ref}, {Ref: s.Ref, UID: 700005}} {
		f.resetLog()
		if err := a.WipeData(context.Background(), bad); err == nil || len(l2Runs(f)) != 0 {
			t.Fatalf("spec %v: %v %q", bad, err, l2Runs(f))
		}
	}
}

func TestRenderCluster_Exported(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	if err := a.RenderCluster(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if len(f.mutations()) != 0 {
		t.Fatalf("rendering touched Docker: %q", f.mutations())
	}
	for _, n := range []string{"passwd", "group", "pg_hba.conf", "conf.d/" + pgconf.OverrideFile, "tools/supapace-arch"} {
		if _, err := os.Lstat(filepath.Join(a.p.RenderDir(s.Ref), n)); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	if err := a.RenderCluster(context.Background(), Spec{Ref: "../x"}); err == nil {
		t.Fatal("bad spec accepted")
	}
}

// ───────── the spec's secrets ─────────

// TestSpec_SecretsNeverPrintedOrMarshalled: no fmt verb and no JSON encoding
// of a Spec carries a secret byte; the configuration label does not depend
// on the secrets.
func TestSpec_SecretsNeverPrintedOrMarshalled(t *testing.T) {
	a, f, s, _, _ := l2Setup(t)
	s.StanzaPass = "stanza-passphrase-0123456789"
	secrets := []string{s.Secrets.SupabaseAdminPassword, s.Secrets.PostgresPassword, s.Secrets.AuthenticatorPassword,
		s.Secrets.PgsodiumRootKey, s.StanzaPass, "salt-admin-01234", "salt-postgres-01"}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%q", "%x", "%X", "%o", "%e", "%t", "%U", "%c", "%b", "%8.3v", "%-30s"} {
		outs = append(outs, fmt.Sprintf(verb, s), fmt.Sprintf(verb, &s), fmt.Sprintf(verb, []Spec{s}), fmt.Sprintf(verb, map[string]Spec{"k": s}))
	}
	outs = append(outs, fmt.Sprint(s), fmt.Sprintln(s), fmt.Sprintf("%v", struct{ S Spec }{s}))
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(j))
	jp, _ := json.Marshal(&s)
	outs = append(outs, string(jp))
	for _, out := range outs {
		for _, sec := range secrets {
			if strings.Contains(out, sec) || strings.Contains(out, fmt.Sprintf("%x", sec)) || strings.Contains(out, fmt.Sprintf("%X", sec)) {
				t.Fatalf("secret %q in %q", sec, out)
			}
		}
	}
	if !strings.Contains(fmt.Sprintf("%d", s), s.Ref) {
		t.Fatal("the spec no longer prints its ref")
	}
	// The label of a layout-1 and of a layout-2 project does not change with
	// the secrets, and the layout-1 label is the as-built one.
	for _, layout := range []int{1, 2} {
		s.Layout = layout
		clState(t, a, s, State{Epoch: s.Epoch, Generation: s.Generation, Phase: PhaseADone})
		f.mu.Lock()
		delete(f.ctrs, "pg-"+s.Ref)
		f.mu.Unlock()
		if err := a.EnsureCluster(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		run := clLastRun(t, f, "pg-"+s.Ref)
		if got := labelValue(run, labelConfig); got != clHash(t, a, s, run) {
			t.Fatalf("layout %d: label %s is not the hash of its argv and files", layout, got)
		}
		other := s
		other.Secrets.SupabaseAdminPassword, other.StanzaPass = "another-password-0123", "another-passphrase"
		x, err := a.clusterRunArgs(s, true)
		if err != nil {
			t.Fatal(err)
		}
		y, err := a.clusterRunArgs(other, true)
		if err != nil || labelValue(x, labelConfig) != labelValue(y, labelConfig) {
			t.Fatalf("layout %d: the label depends on the secrets (%v)", layout, err)
		}
	}
}

// ───────── the fake's hook ─────────

func init() {
	fakeVerbs["frobnicate"] = func(f *fakeHost, args []string, _ []byte) (string, error) {
		return "frobnicated " + strings.Join(args[1:], " ") + fmt.Sprintf(" (%d containers)", len(f.ctrs)), nil
	}
	fakeVerbs["{{.HostConfig.Frob}}"] = func(f *fakeHost, args []string, _ []byte) (string, error) {
		return "frob of " + clLast(args), nil
	}
}

// TestFakeDocker_UnknownVerbGoesToFakeVerbs: a verb or format the fake does
// not model is looked up in fakeVerbs before it is a test error.
func TestFakeDocker_UnknownVerbGoesToFakeVerbs(t *testing.T) {
	f := fakeDocker(t)
	f.ctr(fakeCtr{Name: "c1"})
	out, err := dockerRun(context.Background(), "frobnicate", "a", "b")
	if err != nil || out != "frobnicated a b (1 containers)" {
		t.Fatalf("verb: %q %v", out, err)
	}
	out, err = dockerRun(context.Background(), "container", "inspect", "--format", "{{.HostConfig.Frob}}", "--", "c1")
	if err != nil || out != "frob of c1" {
		t.Fatalf("format: %q %v", out, err)
	}
	if !slices.Contains(f.calls(), "docker frobnicate a b") {
		t.Fatal("hooked call not recorded")
	}
	// Control: an unknown verb without a hook is still a test error.
	rec := &recordingTB{TB: t}
	g := fakeDocker(rec)
	if _, err := g.run([]string{"unhooked"}, nil); err == nil || !rec.failed {
		t.Fatalf("an unhooked verb passed: %v", err)
	}
}

type recordingTB struct {
	testing.TB
	failed bool
}

func (r *recordingTB) Errorf(string, ...any) { r.failed = true }

func l2Exe(t *testing.T) string {
	t.Helper()
	exe, err := daemonExe()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}
