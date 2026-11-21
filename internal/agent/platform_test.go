package agent

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
)

// ───────── the control-plane database: arguments, directories, quotas ─────────

func cpRun(t *testing.T, f *fakeHost, name string) []string {
	t.Helper()
	var found []string
	for _, r := range f.argv("run") {
		if flagValue(r, "--name") == name {
			found = r
		}
	}
	if found == nil {
		t.Fatalf("no docker run of %s in %q", name, f.calls())
	}
	return found
}

// cpArchiving is the archiving tail of the control plane's command, in order.
var cpArchiving = []string{"-c", "archive_mode=on", "-c", "archive_command=" + pgconf.ArchiveCommand,
	"-c", "restore_command=" + pgconf.RestoreCommand, "-c", "archive_timeout=300"}

func TestEnsureCP_ArgsWithArchiving(t *testing.T) {
	a, f, _ := cpSetup(t)
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	argv := cpRun(t, f, cpName)
	cp, pd := a.p.CPDir(), a.p.CPProjectDir()
	vols := flagValues(argv, "-v")
	want := []string{pd + "/data:/var/lib/postgresql/data", cp + "/sock:/var/run/postgresql", cp + "/etc:/etc/sp:ro",
		pd + "/spool:/opt/supapace/spool", pd + "/rspool:/opt/supapace/rspool", a.p.ToolsDir() + ":/opt/supapace/tools:ro"}
	if !slices.Equal(vols, want) {
		t.Fatalf("mounts %q\nwant %q", vols, want)
	}
	cmd := positional(argv)
	head := []string{a.cfg.Images.ControlPlane, "postgres", "-c", "listen_addresses=", "-c", "hba_file=/etc/sp/pg_hba.conf",
		"-c", "ident_file=/etc/sp/pg_ident.conf"}
	if !slices.Equal(cmd, slices.Concat(head, cpArchiving)) {
		t.Fatalf("command %q", cmd)
	}
	if flagValue(argv, "--restart") != "unless-stopped" || flagValue(argv, "--user") != "70:70" || flagValue(argv, "--network") != "none" {
		t.Fatalf("restart, user or network changed: %q", argv)
	}
	// Directories: the moved ones under the projects filesystem, 70:70 0700;
	// the outer one root 0700.
	log := strings.Join(f.calls(), "\n")
	for _, d := range []string{"data", "spool", "rspool", "rspool/req", "rspool/out"} {
		p := filepath.Join(pd, d)
		if fi, err := os.Lstat(p); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
		if !strings.Contains(log, "chown "+p+" 70:70") {
			t.Errorf("%s not given to 70:70", p)
		}
	}
	if fi, err := os.Lstat(pd); err != nil || fi.Mode().Perm() != 0o700 || strings.Contains(log, "chown "+pd+" ") {
		t.Errorf("%s: %v %v, want root 0700", pd, fi, err)
	}
	if _, err := os.Lstat(filepath.Join(cp, "data")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the older data path was created: %v", err)
	}
}

func TestEnsureCP_ArchiveCommandIsTheProjectsConstant(t *testing.T) {
	a, f, _ := cpSetup(t)
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range positional(cpRun(t, f, cpName)) {
		if v, ok := strings.CutPrefix(c, "archive_command="); ok {
			got = append(got, v)
		}
	}
	if len(got) != 1 || got[0] != pgconf.ArchiveCommand || !strings.HasSuffix(got[0], " # pgbackrest") {
		t.Fatalf("archive_command %q, want exactly the projects' %q with its marker word", got, pgconf.ArchiveCommand)
	}
}

func TestEnsureCP_NewDatabaseInitialisedWithChecksums(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(flagValues(cpRun(t, f, cpName), "-e"), "POSTGRES_INITDB_ARGS=--data-checksums") {
		t.Fatal("no POSTGRES_INITDB_ARGS=--data-checksums in the environment")
	}
	// An existing database is left as it is: re-created container, same files.
	data := filepath.Join(a.p.CPProjectDir(), "data")
	before := cpTree(t, data)
	f.ctrs[cpName].Labels[labelConfig] = "older"
	f.resetLog()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.argv("run")) != 1 {
		t.Fatalf("control: not re-created: %q", f.mutations())
	}
	if after := tree(t, data); !maps.Equal(before, after) {
		t.Fatalf("existing data directory changed:\n%v\n%v", before, after)
	}
}

func TestEnsureCP_SocketAndAccessFilesStayWhereTheyAreBuilt(t *testing.T) {
	a, f, _ := cpSetup(t)
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	argv := cpRun(t, f, cpName)
	cp := a.p.CPDir()
	vols := flagValues(argv, "-v")
	if !slices.Contains(vols, cp+"/sock:/var/run/postgresql") || !slices.Contains(vols, cp+"/etc:/etc/sp:ro") {
		t.Fatalf("socket or access files moved: %q", vols)
	}
	for _, p := range []string{filepath.Join(cp, "etc", "pg_hba.conf"), filepath.Join(cp, "etc", "pg_ident.conf")} {
		if fi, err := os.Lstat(p); err != nil || fi.Mode().Perm() != 0o444 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
	}
	if fi, err := os.Lstat(filepath.Join(cp, "sock")); err != nil || !fi.IsDir() {
		t.Errorf("socket directory: %v %v", fi, err)
	}
	for _, d := range []string{"sock", "etc"} {
		if _, err := os.Lstat(filepath.Join(a.p.CPProjectDir(), d)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s made below the projects filesystem: %v", d, err)
		}
	}
}

func TestEnsureCP_LabelChange_RecreatesOnce(t *testing.T) {
	a, f, _ := cpSetup(t)
	cpStamped(t, a)
	ctx := context.Background()
	// An older build's container: running, its label computed without archiving.
	f.ctr(fakeCtr{Name: cpName, Running: true, Restart: "unless-stopped", Labels: map[string]string{labelRole: "cp-db", labelConfig: strings.Repeat("0", 64)}})
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 3 || m[0] != "docker stop -t 30 -- sp-cp-db" || m[1] != "docker rm -- sp-cp-db" || !strings.HasPrefix(m[2], "docker run ") {
		t.Fatalf("mutations %q", m)
	}
	f.resetLog()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("re-created again: %q", m)
	}
}

func TestEnsureCP_LabelCoversItsArchiveBinary(t *testing.T) {
	a, f, cf := cpSetup(t)
	ctx := context.Background()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(a.p.ToolsDir(), archBinary)
	if b, err := os.ReadFile(tools); err != nil || string(b) != "cp archive binary v1" {
		t.Fatalf("tools copy: %q %v", b, err)
	}
	if fi, _ := os.Lstat(tools); fi.Mode().Perm() != 0o555 {
		t.Fatalf("tools copy mode %v", fi.Mode())
	}
	label := f.ctrs[cpName].Labels[labelConfig]
	// Same binary: adopted.
	f.resetLog()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("control: same binary re-created: %q", m)
	}
	cpBinary(t, cf, "cp archive binary v2")
	f.resetLog()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(tools); string(b) != "cp archive binary v2" {
		t.Fatalf("tools copy not replaced: %q", b)
	}
	if m := f.mutations(); len(m) != 3 || f.ctrs[cpName].Labels[labelConfig] == label {
		t.Fatalf("a new archive binary did not re-create: %q", m)
	}
	// A missing source: an error, the running container untouched.
	os.Remove(filepath.Join(filepath.Dir(cf.exe), archBinary))
	f.resetLog()
	if err := a.EnsureControlPlaneDB(ctx); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("missing archive binary: %v %q", err, f.mutations())
	}
}

// ───────── the one-time move ─────────

func TestEnsureCP_Move_ResumesFromEachState(t *testing.T) {
	type state struct{ old, moved, part, data bool }
	boom := errors.New("interrupted")
	for _, tc := range []struct {
		name       string
		failRename int   // the rename that fails in the first ensure (0: none)
		after      state // left by the first ensure
		resume     func(t *testing.T, a *Agent, part string)
		wantSecond []string // calls of the second ensure that touch the trees
	}{
		{name: "uninterrupted", after: state{moved: true, data: true}},
		{name: "stopped after the copy", failRename: 1, after: state{old: true, part: true},
			// A stale entry in the leftover copy: removed and copied again.
			resume: func(t *testing.T, a *Agent, part string) {
				os.WriteFile(filepath.Join(part, "stale"), []byte("x"), 0o600)
			},
			wantSecond: []string{"rename old moved", "rename part data"}},
		{name: "after the rename of the old tree", failRename: 2, after: state{moved: true, part: true},
			// The copy is not made again: the one action is the second rename.
			resume: func(t *testing.T, a *Agent, part string) {
				os.WriteFile(filepath.Join(part, "kept"), []byte("y"), 0o600)
			},
			wantSecond: []string{"rename part data"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f, cf := cpSetup(t)
			ctx := context.Background()
			old := filepath.Join(a.p.CPDir(), "data")
			mkdirs(t, a.p.CPDir())
			os.Chmod(a.p.CPDir(), 0o700)
			want := cpTree(t, old)
			f.ctr(fakeCtr{Name: cpName, Running: true, Restart: "unless-stopped", Labels: map[string]string{labelRole: "cp-db"}})
			moved, part, data := old+".moved", filepath.Join(a.p.CPProjectDir(), "data.part"), filepath.Join(a.p.CPProjectDir(), "data")
			names := map[string]string{old: "old", moved: "moved", part: "part", data: "data"}
			short := func(calls []string) []string {
				var out []string
				for _, c := range calls {
					if rest, ok := strings.CutPrefix(c, "rename "); ok {
						from, to, _ := strings.Cut(rest, " ")
						out = append(out, "rename "+names[from]+" "+names[to])
					}
				}
				return out
			}
			if tc.failRename != 0 {
				cf.renameErrs[tc.failRename] = boom
			}
			err := a.EnsureControlPlaneDB(ctx)
			if tc.failRename != 0 && !errors.Is(err, boom) || tc.failRename == 0 && err != nil {
				t.Fatalf("first ensure: %v", err)
			}
			// The container was stopped and removed before the copy.
			if m := f.mutations(); len(m) < 2 || m[0] != "docker stop -t 30 -- sp-cp-db" || m[1] != "docker rm -- sp-cp-db" {
				t.Fatalf("mutations %q", m)
			}
			exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }
			if got := (state{exists(old), exists(moved), exists(part), exists(data)}); got != tc.after {
				t.Fatalf("state after the first ensure %+v, want %+v", got, tc.after)
			}
			if tc.failRename != 0 {
				if len(f.argv("run")) != 0 {
					t.Fatal("started a container after a failed move")
				}
				tc.resume(t, a, part)
				f.resetLog()
				if err := a.EnsureControlPlaneDB(ctx); err != nil {
					t.Fatalf("resume: %v", err)
				}
				if got := short(f.calls()); !slices.Equal(got, tc.wantSecond) {
					t.Fatalf("resume did %q, want %q", got, tc.wantSecond)
				}
				if tc.name == "after the rename of the old tree" {
					want["kept"] = "-rw------- y"
				}
			}
			if got := tree(t, data); !maps.Equal(got, want) {
				t.Fatalf("moved database differs:\n got %v\nwant %v", got, want)
			}
			if got := tree(t, moved); tc.failRename != 2 && !maps.Equal(got, want) {
				t.Fatalf("data.moved differs: %v", got)
			}
			// Every copied entry was given its source's owner.
			if tc.failRename != 2 {
				log := strings.Join(f.calls(), "\n")
				for rel := range want {
					if !strings.Contains(log, "chown "+filepath.Join(part, rel)+" ") {
						t.Errorf("%s not chowned in the copy", rel)
					}
				}
			}
			// After both renames: nothing to do, the database as it is.
			f.resetLog()
			if err := a.EnsureControlPlaneDB(ctx); err != nil {
				t.Fatal(err)
			}
			if got := short(f.calls()); len(got) != 0 || len(f.mutations()) != 0 {
				t.Fatalf("done state moved again: %q %q", got, f.mutations())
			}
			if got := tree(t, data); !maps.Equal(got, want) {
				t.Fatalf("database changed after the move: %v", got)
			}
		})
	}
}

func TestEnsureCP_BothPopulatedWithoutMovedTreeRefused(t *testing.T) {
	a, f, _ := cpSetup(t)
	mkdirs(t, a.p.CPDir(), a.p.CPProjectDir())
	os.Chmod(a.p.CPDir(), 0o700)
	os.Chmod(a.p.CPProjectDir(), 0o700)
	old, data := filepath.Join(a.p.CPDir(), "data"), filepath.Join(a.p.CPProjectDir(), "data")
	wo, wd := cpTree(t, old), cpTree(t, data)
	os.WriteFile(filepath.Join(data, "other"), []byte("other database"), 0o600)
	wd["other"] = "-rw------- other database"
	f.ctr(fakeCtr{Name: cpName, Running: true, Restart: "unless-stopped", Labels: map[string]string{labelRole: "cp-db"}})
	err := a.EnsureControlPlaneDB(context.Background())
	if err == nil || !strings.Contains(err.Error(), "data") {
		t.Fatalf("got %v, want a refusal", err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutated: %q", m)
	}
	if !maps.Equal(tree(t, old), wo) || !maps.Equal(tree(t, data), wd) {
		t.Fatal("a tree changed")
	}
	// Control: with data.moved beside it, the same state is the finished move.
	if err := os.Rename(old, old+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// A data.moved with neither the copy nor the new tree is not a state the
// move leaves: refused, nothing started.
func TestEnsureCP_MovedTreeAloneRefused(t *testing.T) {
	a, f, _ := cpSetup(t)
	mkdirs(t, a.p.CPDir())
	os.Chmod(a.p.CPDir(), 0o700)
	cpTree(t, filepath.Join(a.p.CPDir(), "data.moved"))
	if err := a.EnsureControlPlaneDB(context.Background()); err == nil || len(f.argv("run")) != 0 {
		t.Fatalf("got %v %q", err, f.mutations())
	}
}

// What the copy cannot carry over faithfully is refused before the database
// is stopped and before any rename:
// the old tree stays where the database can start from it again.
func TestEnsureCP_MoveRefusesALink(t *testing.T) {
	a, f, _ := cpSetup(t)
	mkdirs(t, a.p.CPDir())
	os.Chmod(a.p.CPDir(), 0o700)
	old := filepath.Join(a.p.CPDir(), "data")
	cpTree(t, old)
	if err := os.Symlink("/etc", filepath.Join(old, "pg_tblspc_link")); err != nil {
		t.Fatal(err)
	}
	f.ctr(fakeCtr{Name: cpName, Running: true, Restart: "unless-stopped", Labels: map[string]string{labelRole: "cp-db"}})
	if err := a.EnsureControlPlaneDB(context.Background()); err == nil {
		t.Fatal("copied a link")
	}
	// Checked before the database is stopped: it keeps running on the old tree.
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("mutated before refusing: %q", m)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "rename ") {
			t.Fatalf("renamed after a failed copy: %s", c)
		}
	}
	if _, err := os.Lstat(old); err != nil || len(f.argv("run")) != 0 {
		t.Fatalf("old tree %v; runs %q", err, f.argv("run"))
	}
}

// ───────── the restore marker ─────────

func TestEnsureCP_RefusesWhileRestoring(t *testing.T) {
	// The repair round calls EnsureControlPlaneDB itself: the refusal is this
	// function's, whoever calls it.
	for _, existing := range []string{"absent", "stopped", "running"} {
		t.Run(existing, func(t *testing.T) {
			a, f, _ := cpSetup(t)
			ctx := context.Background()
			cpMark(t, a)
			if existing != "absent" {
				f.ctr(fakeCtr{Name: cpName, Running: existing == "running", Restart: "unless-stopped", Labels: map[string]string{labelRole: "cp-db"}})
			}
			// A half-restored directory.
			pd := a.p.CPProjectDir()
			mkdirs(t, pd)
			os.Chmod(pd, 0o700)
			half := cpTree(t, filepath.Join(pd, "data"))
			f.resetLog()
			err := a.EnsureControlPlaneDB(ctx)
			if err == nil || !strings.Contains(err.Error(), "restore") {
				t.Fatalf("got %v, want the restore refusal", err)
			}
			if m := f.mutations(); len(m) != 0 {
				t.Fatalf("mutated while restoring: %q", m)
			}
			if c := f.calls(); len(c) != 0 {
				t.Fatalf("did anything at all: %q", c)
			}
			if !maps.Equal(tree(t, filepath.Join(pd, "data")), half) {
				t.Fatal("the half-restored directory changed")
			}
			// Control: the marker gone, the same call starts it.
			os.Remove(a.p.CPRestoring())
			if err := a.EnsureControlPlaneDB(ctx); err != nil {
				t.Fatalf("control: %v", err)
			}
			if c := f.ctrs[cpName]; c == nil || !c.Running {
				t.Fatal("control: not running without the marker")
			}
		})
	}
}

// ───────── quotas ─────────

func TestEnsureCP_QuotasOnBothFilesystems_AtEveryEnsure(t *testing.T) {
	for _, tc := range []struct {
		name             string
		dev              bool
		disk, repo       int
		wantDisk, wantRp int
	}{
		{name: "default", wantDisk: 32768, wantRp: 32768},
		{name: "development node", dev: true, wantDisk: 2048, wantRp: 2048},
		{name: "node.json", dev: true, disk: 5000, repo: 7000, wantDisk: 5000, wantRp: 7000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f, _ := cpSetup(t)
			a.cfg.CPDiskQuotaMB, a.cfg.CPRepoQuotaMB = tc.disk, tc.repo
			if tc.dev {
				if err := os.WriteFile(filepath.Join(filepath.Dir(a.p.NodeJSON()), "dev-mode"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if d, r := nodecfg.CPQuotas(a.cfg, a.p); d != tc.wantDisk || r != tc.wantRp {
				t.Fatalf("fixture: CPQuotas %d %d", d, r)
			}
			want := []string{"repoSetQuota " + a.p.ProjectsDir() + " 70 " + strconv.Itoa(tc.wantDisk), "ensureRepoDir cp 70:70 " + strconv.Itoa(tc.wantRp)}
			for i := range 2 {
				f.resetLog()
				if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
					t.Fatal(err)
				}
				var got []string
				for _, c := range f.calls() {
					if strings.HasPrefix(c, "repoSetQuota ") || strings.HasPrefix(c, "ensureRepoDir ") {
						got = append(got, c)
					}
				}
				if !slices.Equal(got, want) {
					t.Fatalf("ensure %d: %q, want %q", i+1, got, want)
				}
			}
		})
	}
	// A quota that cannot be set starts nothing.
	for _, seam := range []string{"disk", "repository"} {
		t.Run("failure "+seam, func(t *testing.T) {
			a, f, _ := cpSetup(t)
			boom := errors.New("not enforced")
			if seam == "disk" {
				defer swap(&repoSetQuota, func(string, int, int) error { return boom })()
			} else {
				defer swap(&ensureRepoDir, func(nodecfg.Paths, string, int, int, int) error { return boom })()
			}
			if err := a.EnsureControlPlaneDB(context.Background()); !errors.Is(err, boom) || len(f.mutations()) != 0 {
				t.Fatalf("got %v %q", err, f.mutations())
			}
		})
	}
}

// ───────── the recovery start ─────────

var cpTarget = pgconf.RecoveryTarget{Timeline: "latest"}

func TestEnsureCPRecovery_NoRestartPolicy_RecoveryPins(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	// Without the marker: nothing.
	if err := a.EnsureControlPlaneRecovery(ctx, cpTarget); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("no marker: %v %q", err, f.mutations())
	}
	cpMark(t, a)
	if err := a.PrepareControlPlaneRestore(ctx); err != nil {
		t.Fatal(err)
	}
	// A target RecoveryPins refuses: refused before anything.
	f.resetLog()
	if err := a.EnsureControlPlaneRecovery(ctx, pgconf.RecoveryTarget{Timeline: "current"}); !errors.Is(err, pgconf.ErrGUCValue) || len(f.mutations()) != 0 {
		t.Fatalf("bad target: %v %q", err, f.mutations())
	}
	f.resetLog()
	if err := a.EnsureControlPlaneRecovery(ctx, cpTarget); err != nil {
		t.Fatal(err)
	}
	argv := cpRun(t, f, cpRecoveryName)
	if r := flagValue(argv, "--restart"); r != "" {
		t.Fatalf("restart policy %q", r)
	}
	if c := f.ctrs[cpRecoveryName]; c == nil || c.Restart != "no" || !c.Running {
		t.Fatalf("recovery container %+v", c)
	}
	pins, _ := pgconf.RecoveryPins(cpTarget)
	cmd := positional(argv)
	if !slices.Equal(cmd[len(cmd)-len(pins):], pins) {
		t.Fatalf("command does not end with the recovery pins: %q", cmd)
	}
	if !slices.Equal(cmd[len(cmd)-len(pins)-len(cpArchiving):len(cmd)-len(pins)], cpArchiving) {
		t.Fatalf("archiving settings missing before the pins: %q", cmd)
	}
	// The same mounts and user as sp-cp-db; no initdb password (an empty data
	// directory makes the image's entrypoint stop instead of creating one).
	if err := os.Remove(a.p.CPRestoring()); err != nil {
		t.Fatal(err)
	}
	delete(f.ctrs, cpRecoveryName)
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	db := cpRun(t, f, cpName)
	if !slices.Equal(flagValues(argv, "-v"), flagValues(db, "-v")) || flagValue(argv, "--user") != "70:70" || flagValue(argv, "--network") != "none" {
		t.Fatalf("recovery %q\ndb %q", argv, db)
	}
	for _, e := range flagValues(argv, "-e") {
		if strings.HasPrefix(e, "POSTGRES_PASSWORD=") {
			t.Fatal("recovery start carries an initdb password")
		}
	}
	// While sp-cp-db exists, no recovery start.
	cpMark(t, a)
	f.resetLog()
	if err := a.EnsureControlPlaneRecovery(ctx, cpTarget); err == nil || len(f.mutations()) != 0 {
		t.Fatalf("beside sp-cp-db: %v %q", err, f.mutations())
	}
}

func TestEnsureCPRecovery_HasNoExtensionPins(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	cpMark(t, a)
	if err := a.PrepareControlPlaneRestore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureControlPlaneRecovery(ctx, cpTarget); err != nil {
		t.Fatal(err)
	}
	cmd := strings.Join(positional(cpRun(t, f, cpRecoveryName)), " ")
	for _, p := range pgconf.RecoveryExtensionPins() {
		if p != "-c" && strings.Contains(cmd, p) {
			t.Fatalf("the projects' extension pin %q in %q", p, cmd)
		}
	}
	for _, name := range []string{"pgtle", "cron", "shared_preload_libraries"} {
		if strings.Contains(cmd, name) {
			t.Fatalf("%s in %q", name, cmd)
		}
	}
}

func TestStopCPRecovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		present bool
		running bool
		want    []string
	}{
		{name: "absent"},
		{name: "exited", present: true, want: []string{"docker rm -f -- sp-cp-recovery"}},
		{name: "running", present: true, running: true, want: []string{"docker stop -t 30 -- sp-cp-recovery", "docker rm -- sp-cp-recovery"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f, _ := cpSetup(t)
			if tc.present {
				f.ctr(fakeCtr{Name: cpRecoveryName, Running: tc.running, Labels: map[string]string{labelRole: "cp-recovery"}})
			}
			if err := a.StopControlPlaneRecovery(context.Background()); err != nil {
				t.Fatal(err)
			}
			if m := f.mutations(); !slices.Equal(m, tc.want) {
				t.Fatalf("mutations %q, want %q", m, tc.want)
			}
			if f.ctrs[cpRecoveryName] != nil {
				t.Fatal("still there")
			}
		})
	}
	// A stop that fails while it still runs: the error, nothing removed.
	a, f, _ := cpSetup(t)
	f.ctr(fakeCtr{Name: cpRecoveryName, Running: true})
	boom := errors.New("daemon busy")
	f.failVerb["stop"] = boom
	if err := a.StopControlPlaneRecovery(context.Background()); !errors.Is(err, boom) || f.ctrs[cpRecoveryName] == nil {
		t.Fatalf("got %v", err)
	}
}

// ───────── what `supapaced recover` calls ─────────

func TestPrepareControlPlaneRestore_MarkerDirectoriesQuotas_NoContainer(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	// Refused while sp-cp-db exists: nothing written.
	f.ctr(fakeCtr{Name: cpName, Running: false, Labels: map[string]string{labelRole: "cp-db"}})
	if err := a.PrepareControlPlaneRestore(ctx); err == nil {
		t.Fatal("prepared beside sp-cp-db")
	}
	if _, err := os.Lstat(a.p.CPRestoring()); !errors.Is(err, os.ErrNotExist) || len(f.mutations()) != 0 {
		t.Fatalf("marker %v, mutations %q", err, f.mutations())
	}
	delete(f.ctrs, cpName)
	// A database at the data path and no marker: refused, not emptied.
	pd := a.p.CPProjectDir()
	mkdirs(t, pd)
	os.Chmod(pd, 0o700)
	db := cpTree(t, filepath.Join(pd, "data"))
	if err := a.PrepareControlPlaneRestore(ctx); err == nil {
		t.Fatal("prepared over a database without the marker")
	}
	if !maps.Equal(tree(t, filepath.Join(pd, "data")), db) {
		t.Fatal("the database was touched")
	}
	os.RemoveAll(filepath.Join(pd, "data"))

	f.resetLog()
	if err := a.PrepareControlPlaneRestore(ctx); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(a.p.CPRestoring()); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || fi.Size() != 0 {
		t.Fatalf("marker %v %v", fi, err)
	}
	log := strings.Join(f.calls(), "\n")
	for _, want := range []string{"repoSetQuota " + a.p.ProjectsDir() + " 70 32768", "ensureRepoDir cp 70:70 32768",
		"chown " + filepath.Join(a.p.CPDir(), "sock") + " 70:70"} {
		if !strings.Contains(log, want) {
			t.Errorf("no %q in %s", want, log)
		}
	}
	for _, d := range []string{"data", "spool", "rspool", "rspool/req", "rspool/out"} {
		if fi, err := os.Lstat(filepath.Join(pd, d)); err != nil || !fi.IsDir() || !strings.Contains(log, "chown "+filepath.Join(pd, d)+" 70:70") {
			t.Errorf("%s: %v %v", d, fi, err)
		}
	}
	for _, name := range []string{"pg_hba.conf", "pg_ident.conf"} {
		if _, err := os.Lstat(filepath.Join(a.p.CPDir(), "etc", name)); err != nil {
			t.Error(err)
		}
	}
	if m := f.mutations(); len(m) != 0 {
		t.Fatalf("started something: %q", m)
	}
	// A re-run (after a stop at the checks): every tree emptied, the
	// directories themselves kept.
	repo := filepath.Join(a.p.RepoDir("cp"), "repo")
	mkdirs(t, repo)
	for _, d := range []string{filepath.Join(pd, "data"), filepath.Join(pd, "spool"), filepath.Join(pd, "rspool", "req"),
		filepath.Join(pd, "rspool", "out"), repo} {
		if err := os.MkdirAll(filepath.Join(d, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(d, "sub", "f"), []byte("first run"), 0o600)
		os.WriteFile(filepath.Join(d, "00000002.history"), []byte("first run"), 0o600)
	}
	f.ctr(fakeCtr{Name: cpRecoveryName, Running: true})
	if err := a.PrepareControlPlaneRestore(ctx); err != nil {
		t.Fatal(err)
	}
	if f.ctrs[cpRecoveryName] != nil {
		t.Fatal("re-run left the earlier recovery start running")
	}
	for _, d := range []string{filepath.Join(pd, "data"), filepath.Join(pd, "spool"), filepath.Join(pd, "rspool", "req"),
		filepath.Join(pd, "rspool", "out"), repo} {
		if ents, err := os.ReadDir(d); err != nil || len(ents) != 0 {
			t.Errorf("%s not emptied: %v %v", d, ents, err)
		}
	}
}

func TestControlPlaneRecoveryState_PromotionAndTheSystemIdentifier(t *testing.T) {
	a, f, cf := cpSetup(t)
	ctx := context.Background()
	sock := filepath.Join(a.p.CPDir(), "sock")
	// No recovery container, or an exited one: exited, no session.
	for _, c := range []*fakeCtr{nil, {Name: cpRecoveryName}} {
		delete(f.ctrs, cpRecoveryName)
		if c != nil {
			f.ctr(*c)
		}
		f.resetLog()
		p, e, id, err := a.ControlPlaneRecoveryState(ctx)
		if err != nil || p || !e || id != "" || slices.ContainsFunc(f.calls(), func(s string) bool { return strings.HasPrefix(s, "session") }) {
			t.Fatalf("container %v: %v %v %q %v %q", c, p, e, id, err, f.calls())
		}
	}
	f.ctr(fakeCtr{Name: cpRecoveryName, Running: true})
	boom := errors.New("relation does not exist")
	for _, tc := range []struct {
		name      string
		replaying bool
		id        int64
		err       error
		promoted  bool
		wantID    string
		wantErr   error
	}{
		{name: "not answering", err: errCPNotUp},
		{name: "in recovery", replaying: true, id: 7},
		{name: "promoted", id: 7362541983470516261, promoted: true, wantID: "7362541983470516261"},
		{name: "promoted, above 2^63", id: -1, promoted: true, wantID: "18446744073709551615"},
		{name: "promoted, high bit", id: -7362541983470516261, promoted: true, wantID: "11084202090239035355"},
		{name: "query fails", err: boom, wantErr: boom},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cf.session = func(_ context.Context, s string) (bool, int64, error) {
				if s != sock {
					t.Errorf("session over %s, want %s", s, sock)
				}
				return tc.replaying, tc.id, tc.err
			}
			p, e, id, err := a.ControlPlaneRecoveryState(ctx)
			if !errors.Is(err, tc.wantErr) || tc.wantErr == nil && err != nil || p != tc.promoted || e || id != tc.wantID {
				t.Fatalf("got %v %v %q %v", p, e, id, err)
			}
		})
	}
}

func TestFinishControlPlaneRestore_StopsThenRemovesFetchAndTheMarker(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	cpMark(t, a)
	fetch := filepath.Join(a.p.RepoDir("cp"), "fetch")
	mkdirs(t, filepath.Join(fetch, "archive", "cp-1"))
	os.WriteFile(filepath.Join(fetch, "archive", "cp-1", "archive.info"), []byte("x"), 0o640)
	f.ctr(fakeCtr{Name: cpRecoveryName, Running: true})
	// The stop fails: fetch/ and the marker stay.
	boom := errors.New("daemon busy")
	f.failVerb["stop"] = boom
	if err := a.FinishControlPlaneRestore(ctx); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Lstat(a.p.CPRestoring()); err != nil {
		t.Fatal("marker removed after a failed stop")
	}
	if _, err := os.Lstat(fetch); err != nil {
		t.Fatal("fetch/ removed after a failed stop")
	}
	delete(f.failVerb, "stop")
	f.resetLog()
	if err := a.FinishControlPlaneRestore(ctx); err != nil {
		t.Fatal(err)
	}
	calls := f.calls()
	stop := slices.Index(calls, "docker stop -t 30 -- sp-cp-recovery")
	rmFetch := slices.Index(calls, "removeEmptyFetchDir cp")
	if stop < 0 || rmFetch < stop {
		t.Fatalf("order %q", calls)
	}
	for _, p := range []string{fetch, a.p.CPRestoring()} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s left: %v", p, err)
		}
	}
	if f.ctrs[cpRecoveryName] != nil {
		t.Fatal("recovery container left")
	}
	// Again: everything absent is done.
	if err := a.FinishControlPlaneRestore(ctx); err != nil {
		t.Fatalf("repeat: %v", err)
	}
}

// ───────── the stamp: a node that had a database never initialises a new one ─────────

func cpStamp(a *Agent) string { return filepath.Join(a.p.CPDir(), "initialised") }

func cpPassword(argv []string) bool {
	return slices.ContainsFunc(flagValues(argv, "-e"), func(e string) bool { return strings.HasPrefix(e, "POSTGRES_PASSWORD=") })
}

// cpRuns is the docker run calls of sp-cp-db so far.
func cpRuns(f *fakeHost) [][]string {
	var out [][]string
	for _, r := range f.argv("run") {
		if flagValue(r, "--name") == cpName {
			out = append(out, r)
		}
	}
	return out
}

// A fresh node: one ensure starts the database with the initdb password,
// waits until it answers, stamps the node, makes the container again without
// the password and returns once that one answers. Created twice, then never
// again: a later ensure keeps the same container.
func TestEnsureCP_FreshNodeInitialisesAndStamps(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	runs := cpRuns(f)
	if len(runs) != 2 || !cpPassword(runs[0]) || cpPassword(runs[1]) {
		t.Fatalf("runs %d, passwords %v: want two, the first only with the password", len(runs), func() (p []bool) {
			for _, r := range runs {
				p = append(p, cpPassword(r))
			}
			return
		}())
	}
	if fi, err := os.Lstat(cpStamp(a)); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("no stamp: %v %v", fi, err)
	}
	// The order: the first start answered before the stamp; the second
	// start answered before the ensure returned.
	calls := f.calls()
	run1, run2 := slices.IndexFunc(calls, clIsClusterRunOf(cpName)), slices.IndexFunc(calls[slices.IndexFunc(calls, clIsClusterRunOf(cpName))+1:], clIsClusterRunOf(cpName))
	if run1 < 0 || run2 < 0 {
		t.Fatalf("calls %q", calls)
	}
	run2 += run1 + 1
	if s := slices.IndexFunc(calls[run1:run2], clPrefix("session ")); s < 0 {
		t.Fatalf("re-created before the first start answered: %q", calls[run1:run2])
	}
	if s := slices.IndexFunc(calls[run2:], clPrefix("session ")); s < 0 {
		t.Fatalf("returned before the stamped container answered: %q", calls[run2:])
	}
	id := f.ctrs[cpName].ID
	for range 2 {
		f.resetLog()
		if err := a.EnsureControlPlaneDB(ctx); err != nil || len(f.mutations()) != 0 || f.ctrs[cpName].ID != id {
			t.Fatalf("a later ensure: %v %q", err, f.mutations())
		}
	}
}

func clIsClusterRunOf(name string) func(string) bool {
	return func(c string) bool {
		return strings.HasPrefix(c, "docker run ") && strings.Contains(c, "--name "+name+" ")
	}
}

// Interrupted at each step of a fresh node's first ensure, the next ensure
// converges: one stamped container without the password, and no start after
// the stamp ever carries it.
func TestEnsureCP_FreshNodeInterruptedConverges(t *testing.T) {
	boom := errors.New("interrupted")
	for _, tc := range []struct {
		name      string
		interrupt func(f *fakeHost, cf *cpFake)
	}{
		// The first start runs, the daemon dies before it answered.
		{"after the first start", func(f *fakeHost, cf *cpFake) {
			cf.session = func(context.Context, string) (bool, int64, error) { return false, 0, boom }
		}},
		// The stamp is written, the removal of the first container fails.
		{"after the stamp", func(f *fakeHost, cf *cpFake) { f.failVerb["stop"] = boom }},
		// The first container is removed, the second start fails.
		{"during the re-creation", func(f *fakeHost, cf *cpFake) {
			n := 0
			f.onRun = func(args []string, _ []byte) (string, error, bool) {
				if args[0] == "run" && flagValue(args, "--name") == cpName {
					if n++; n == 2 {
						return "", boom, true
					}
				}
				return "", nil, false
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f, cf := cpSetup(t)
			ctx := context.Background()
			tc.interrupt(f, cf)
			if err := a.EnsureControlPlaneDB(ctx); !errors.Is(err, boom) {
				t.Fatalf("first ensure: %v", err)
			}
			cf.session = nil
			delete(f.failVerb, "stop")
			f.onRun = nil
			if err := a.EnsureControlPlaneDB(ctx); err != nil {
				t.Fatalf("next ensure: %v", err)
			}
			stamped, _ := present(cpStamp(a))
			c := f.ctrs[cpName]
			if !stamped || c == nil || !c.Running || cpPassword(c.Argv) {
				t.Fatalf("stamp %v, container %+v", stamped, c)
			}
			// Every start once the stamp existed came without the password.
			for _, r := range cpRuns(f)[1:] {
				if cpPassword(r) {
					t.Fatal("a start after the first carries the password")
				}
			}
			f.resetLog()
			if err := a.EnsureControlPlaneDB(ctx); err != nil || len(f.mutations()) != 0 {
				t.Fatalf("not converged: %v %q", err, f.mutations())
			}
		})
	}
}

func TestEnsureCP_StampedAndEmptyDataRefused(t *testing.T) {
	for _, existing := range []string{"absent", "stopped"} {
		t.Run(existing, func(t *testing.T) {
			a, f, _ := cpSetup(t)
			ctx := context.Background()
			mkdirs(t, a.p.CPDir())
			os.Chmod(a.p.CPDir(), 0o700)
			if err := os.WriteFile(cpStamp(a), nil, 0o444); err != nil {
				t.Fatal(err)
			}
			if existing == "stopped" {
				f.ctr(fakeCtr{Name: cpName, Restart: "unless-stopped", Labels: map[string]string{labelRole: "cp-db"}})
			}
			data := filepath.Join(a.p.CPProjectDir(), "data")
			err := a.EnsureControlPlaneDB(ctx)
			if err == nil || !strings.Contains(err.Error(), data) || !strings.Contains(err.Error(), "projects filesystem") {
				t.Fatalf("got %v, want a refusal naming %s and what to check", err, data)
			}
			if m := f.mutations(); len(m) != 0 {
				t.Fatalf("started something over an empty data directory: %q", m)
			}
			// Control: the database there, it starts, without the password.
			if err := os.WriteFile(filepath.Join(data, "PG_VERSION"), []byte("17\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := a.EnsureControlPlaneDB(ctx); err != nil {
				t.Fatalf("control: %v", err)
			}
			if c := f.ctrs[cpName]; c == nil || !c.Running {
				t.Fatal("control: not running")
			}
			if runs := f.argv("run"); len(runs) == 1 && cpPassword(runs[0]) {
				t.Fatal("a stamped node's start carries an initdb password")
			}
		})
	}
}

func TestEnsureCP_MoveStampsTheNode(t *testing.T) {
	a, f, _ := cpSetup(t)
	mkdirs(t, a.p.CPDir())
	os.Chmod(a.p.CPDir(), 0o700)
	cpTree(t, filepath.Join(a.p.CPDir(), "data"))
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(cpStamp(a)); err != nil {
		t.Fatalf("no stamp after the move: %v", err)
	}
	if cpPassword(cpRun(t, f, cpName)) {
		t.Fatal("the moved database's start carries an initdb password")
	}
}

func TestEnsureCP_StampRootOwnedNotWritableByTheDatabase(t *testing.T) {
	a, f, _ := cpSetup(t)
	data := filepath.Join(a.p.CPProjectDir(), "data")
	mkdirs(t, data)
	os.WriteFile(filepath.Join(data, "PG_VERSION"), []byte("17\n"), 0o600)
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(cpStamp(a))
	if err != nil || fi.Mode().Perm() != 0o444 {
		t.Fatalf("stamp %v %v, want 0444", fi, err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Uid) != os.Geteuid() {
		t.Fatalf("stamp owned by %d", st.Uid)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "chown "+cpStamp(a)) || strings.HasPrefix(c, "chown "+a.p.CPDir()+" ") {
			t.Fatalf("given away: %s", c)
		}
	}
	if fi, _ := os.Lstat(a.p.CPDir()); fi.Mode().Perm() != 0o700 {
		t.Fatalf("%s mode %v: the database's uid could reach the stamp", a.p.CPDir(), fi.Mode())
	}
}

// ───────── the preparation's emptying rules ─────────

// A re-run (the marker already there): every tree emptied, the repository
// and fetch/ by the tree-removal tasks at their owners' ids on the
// control-plane image — never by root — and fetch/ removed.
func TestPrepareControlPlaneRestore_ReRunEmptiesAtTheOwnersIDs(t *testing.T) {
	a, f, _ := cpSetup(t)
	ctx := context.Background()
	cpMark(t, a)
	repo, fetch := filepath.Join(a.p.RepoDir("cp"), "repo"), filepath.Join(a.p.RepoDir("cp"), "fetch")
	for _, d := range []string{repo, fetch} {
		mkdirs(t, filepath.Join(d, "archive", "cp-1"))
		os.WriteFile(filepath.Join(d, "archive", "cp-1", "archive.info"), []byte("first run"), 0o640)
	}
	if err := a.PrepareControlPlaneRestore(ctx); err != nil {
		t.Fatal(err)
	}
	if ents, err := os.ReadDir(repo); err != nil || len(ents) != 0 {
		t.Fatalf("repo/ after a re-run: %v %v", ents, err)
	}
	if _, err := os.Lstat(fetch); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fetch/ after a re-run: %v", err)
	}
	for _, want := range [][2]string{{"task-cp-purge-repo", "70:70"}, {"task-cp-purge-fetch", "65530:70"}} {
		r := cpRun(t, f, want[0])
		if flagValue(r, "--user") != want[1] || positional(r)[0] != a.cfg.Images.ControlPlane ||
			!slices.Equal(positional(r)[1:], []string{"rmtree", "--keep-root", "/r/" + strings.TrimPrefix(want[0], "task-cp-purge-")}) {
			t.Errorf("%s: %q", want[0], r)
		}
	}
	if !slices.Contains(f.calls(), "removeEmptyFetchDir cp") {
		t.Error("fetch/ not removed by descriptor")
	}
}

// A first preparation (no marker) on a node whose spool holds segments of
// the lost database: spool and rspool are the platform's own and are
// emptied; data and the repository are refused when they hold anything.
func TestPrepareControlPlaneRestore_FirstRunEmptiesTheSpools(t *testing.T) {
	a, f, _ := cpSetup(t)
	pd := a.p.CPProjectDir()
	for _, d := range []string{"spool", "rspool/req", "rspool/out"} {
		mkdirs(t, filepath.Join(pd, d))
		os.WriteFile(filepath.Join(pd, d, "000000010000000000000003"), []byte("old"), 0o600)
	}
	if err := a.PrepareControlPlaneRestore(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"spool", "rspool/req", "rspool/out"} {
		if ents, _ := os.ReadDir(filepath.Join(pd, d)); len(ents) != 0 {
			t.Errorf("%s not emptied: %v", d, ents)
		}
	}
	for _, r := range f.argv("run") {
		if strings.HasPrefix(flagValue(r, "--name"), "task-cp-") {
			t.Errorf("a first run launched %s", flagValue(r, "--name"))
		}
	}
}

// A write error the filesystem reports when the copy is synced stops the
// move before the old tree is renamed aside: the old tree stays the
// database, and the next ensure copies again.
func TestEnsureCP_Move_SyncErrorStopsBeforeTheCommitPoint(t *testing.T) {
	a, f, _ := cpSetup(t)
	mkdirs(t, a.p.CPDir())
	os.Chmod(a.p.CPDir(), 0o700)
	old := filepath.Join(a.p.CPDir(), "data")
	want := cpTree(t, old)
	eio := syscall.EIO
	restore := swap(&cpSyncfs, func(int) error { return eio })
	err := a.EnsureControlPlaneDB(context.Background())
	if !errors.Is(err, eio) {
		t.Fatalf("got %v, want the sync's error", err)
	}
	for _, c := range f.calls() {
		if strings.HasPrefix(c, "rename ") {
			t.Fatalf("renamed after a failed sync: %s", c)
		}
	}
	if got := tree(t, old); !maps.Equal(got, want) || len(cpRuns(f)) != 0 {
		t.Fatalf("old tree %v; runs %d", got, len(cpRuns(f)))
	}
	restore()
	if err := a.EnsureControlPlaneDB(context.Background()); err != nil {
		t.Fatalf("control: %v", err)
	}
	if got := tree(t, filepath.Join(a.p.CPProjectDir(), "data")); len(got) < len(want) {
		t.Fatalf("not moved after the sync works: %v", got)
	}
}
