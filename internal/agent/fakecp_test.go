package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// cpFake replaces the control plane's host seams for one test: the two
// quotas, the repository directory, the archive binary beside the daemon's
// executable, the renames of the move and the session over the socket. Each
// call is recorded in the fake host's log.
type cpFake struct {
	exe        string
	renameErrs map[int]error // the n-th rename (from 1) fails with this error
	renames    int
	session    func(ctx context.Context, sock string) (bool, int64, error)
}

func cpSeams(t testing.TB, a *Agent, f *fakeHost) *cpFake {
	t.Helper()
	cf := &cpFake{exe: filepath.Join(t.TempDir(), "supapaced"), renameErrs: map[int]error{}}
	cpBinary(t, cf, "cp archive binary v1")
	mkdirs(t, a.p.ProjectsDir())
	saved := []func(){
		swap(&repoSetQuota, func(mount string, id, mb int) error {
			f.record(fmt.Sprintf("repoSetQuota %s %d %d", mount, id, mb))
			return nil
		}),
		swap(&ensureRepoDir, func(p nodecfg.Paths, subject string, uid, gid, mb int) error {
			f.record(fmt.Sprintf("ensureRepoDir %s %d:%d %d", subject, uid, gid, mb))
			return nil
		}),
		swap(&removeEmptyFetchDir, func(p nodecfg.Paths, subject string) error {
			f.record("removeEmptyFetchDir " + subject)
			return os.Remove(filepath.Join(p.RepoDir(subject), "fetch"))
		}),
		swap(&daemonExe, func() (string, error) { return cf.exe, nil }),
		swap(&cpPoll, time.Millisecond),
		swap(&cpRename, func(from, to string) error {
			cf.renames++
			f.record("rename " + from + " " + to)
			if err := cf.renameErrs[cf.renames]; err != nil {
				return err
			}
			return os.Rename(from, to)
		}),
		swap(&cpSession, func(ctx context.Context, sock string) (bool, int64, error) {
			f.record("session " + sock)
			if cf.session == nil {
				// The server answers, its first start having initialised the
				// data directory (as the image's entrypoint does).
				data := filepath.Join(a.p.CPProjectDir(), "data")
				if _, err := os.Lstat(filepath.Join(data, "PG_VERSION")); err != nil {
					os.WriteFile(filepath.Join(data, "PG_VERSION"), []byte("17\n"), 0o600)
				}
				return false, 0, nil
			}
			return cf.session(ctx, sock)
		}),
	}
	t.Cleanup(func() {
		for _, r := range saved {
			r()
		}
	})
	// The control plane's removal tasks: the tree-removal helper empties
	// <repo>/cp/<dir> only when the task runs at that tree's owner (repo/
	// 70:70, fetch/ 65530:70); it exits 0 either way, so a task at the
	// wrong ids leaves the tree full.
	owner := map[string]string{"repo": "70:70", "fetch": "65530:70"}
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		name := clLast(args)
		if args[0] == "run" {
			name = flagValue(args, "--name")
		}
		dir, ok := strings.CutPrefix(name, "task-cp-purge-")
		switch {
		case !ok:
			return "", nil, false
		case args[0] == "run":
			if flagValue(args, "--user") == owner[dir] && slices.Contains(args, a.cfg.Images.ControlPlane) {
				p := filepath.Join(a.p.RepoDir("cp"), dir)
				ents, _ := os.ReadDir(p)
				for _, e := range ents {
					os.RemoveAll(filepath.Join(p, e.Name()))
				}
			}
			return "", nil, false
		case args[0] == "inspect":
			return "exited 0\n", nil, true
		case args[0] == "logs":
			return "", nil, true
		}
		return "", nil, false
	}
	return cf
}

// cpBinary writes the archive binary beside the fake daemon executable.
func cpBinary(t testing.TB, cf *cpFake, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(cf.exe), archBinary), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// cpSetup is a test agent ready for EnsureControlPlaneDB: the fake Docker,
// the seccomp profile and the control plane's host seams.
func cpSetup(t *testing.T) (*Agent, *fakeHost, *cpFake) {
	t.Helper()
	a, f, _ := newTestAgent(t)
	writeSeccomp(t, a)
	return a, f, cpSeams(t, a, f)
}

// cpMark writes the restore marker.
func cpMark(t testing.TB, a *Agent) {
	t.Helper()
	mkdirs(t, a.p.CPDir())
	if err := os.Chmod(a.p.CPDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.p.CPRestoring(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// cpTree writes a small data directory at dir: nested directories, files
// of several modes. tree returns what is there, path → mode and content.
func cpTree(t testing.TB, dir string) map[string]string {
	t.Helper()
	files := map[string]string{"PG_VERSION": "17\n", "global/pg_control": "control bytes", "base/1/1259": "relation pages",
		"pg_wal/000000010000000000000001": "wal bytes", "postgresql.auto.conf": "# auto\n"}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, "PG_VERSION"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "base"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return tree(t, dir)
}

func tree(t testing.TB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		v := fi.Mode().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[rel] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// cpStamped makes the node one whose control-plane database exists: a
// data directory with PG_VERSION on the projects filesystem and the stamp.
func cpStamped(t testing.TB, a *Agent) {
	t.Helper()
	data := filepath.Join(a.p.CPProjectDir(), "data")
	mkdirs(t, a.p.CPDir(), data)
	for _, d := range []string{a.p.CPDir(), a.p.CPProjectDir(), data} {
		os.Chmod(d, 0o700)
	}
	if err := os.WriteFile(filepath.Join(data, "PG_VERSION"), []byte("17\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.cpStampPath(), nil, 0o444); err != nil {
		t.Fatal(err)
	}
}
