package agent

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// endedContextFails makes the fake Docker refuse a call made on an ended
// context, as the real client does: its child is never started.
func endedContextFails(t *testing.T) {
	t.Helper()
	run, out := dockerRun, dockerRunOutput
	dockerRun = func(ctx context.Context, args ...string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return run(ctx, args...)
	}
	dockerRunOutput = func(ctx context.Context, args ...string) (string, string, error) {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		return out(ctx, args...)
	}
	t.Cleanup(func() { dockerRun, dockerRunOutput = run, out })
}

// A job that runs longer than the bound of the removals after it: its
// result is read all the same, and a stop asked for then is still graceful.
func TestRunJob_AJobLongerThanTheCleanupBoundKeepsItsResult(t *testing.T) {
	const polls = 90 // seconds of a job, above jobCleanup
	t.Run("ends by itself", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := newJobEnv(t)
			endedContextFails(t)
			taskPoll = time.Second
			name := "job-" + testRef + "-backup"
			s := e.m.script(name)
			s.polls, s.stdout = polls, `{"ok":true}`+"\n"
			t0 := time.Now()
			res, err := e.a.RunJob(context.Background(), e.spec(t, "backup", testRef, 9))
			if time.Since(t0) < jobCleanup {
				t.Fatalf("control: the job lasted %v", time.Since(t0))
			}
			if err != nil || string(res.Result) != `{"ok":true}` {
				t.Fatalf("after %v: result %q, %v", time.Since(t0), res.Result, err)
			}
		})
	})
	t.Run("stopped", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			e := newJobEnv(t)
			endedContextFails(t)
			taskPoll = time.Second
			name := "job-" + testRef + "-serve"
			ctx, cancel := context.WithCancel(context.Background())
			s := e.m.script(name)
			n := 0
			s.polls, s.stdout = -1, `{"ok":true,"served":3}`+"\n"
			s.onPoll = func() {
				if n++; n == polls {
					cancel()
				}
			}
			res, err := e.a.RunJob(ctx, e.spec(t, "serve", testRef, 9))
			if err != nil || string(res.Result) != `{"ok":true,"served":3}` {
				t.Fatalf("result %q, %v", res.Result, err)
			}
			if stops := e.f.argv("stop"); len(stops) != 1 || !slices.Equal(stops[0], []string{"stop", "-t", "10", "--", name}) {
				t.Fatalf("stops %q", stops)
			}
		})
	})
}

// The jobs directory is root's alone (it holds the environment and
// credential files); a job's own directory is readable by the job's uid,
// which reads its input there.
func TestRunJob_ModesOfTheJobsDirectoryAndTheJobDirectory(t *testing.T) {
	e := newJobEnv(t)
	jd := e.a.p.JobsDir()
	name := "job-" + testRef + "-push"
	var jobs, own fs.FileMode
	e.m.script(name).polls = 1
	e.m.script(name).onPoll = func() {
		if fi, err := os.Lstat(jd); err == nil {
			jobs = fi.Mode()
		}
		if fi, err := os.Lstat(filepath.Join(jd, "9")); err == nil {
			own = fi.Mode()
		}
	}
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err != nil {
		t.Fatal(err)
	}
	if jobs != fs.ModeDir|0o700 || own != fs.ModeDir|0o755 {
		t.Fatalf("jobs directory %v, want drwx------; job directory %v, want drwxr-xr-x", jobs, own)
	}
}

// Removing a probe's container by its subject removes its files, the
// credential file with both key pairs among them.
func TestKillJobs_AProbesFilesGoWithIt(t *testing.T) {
	e := newJobEnv(t)
	jd := e.a.p.JobsDir()
	e.leftover("job-probe-cp", "probe-cp", "0", "probe")
	mkdirs(t, jd, filepath.Join(jd, "probe-cp"), filepath.Join(jd, "probe-projects"))
	for _, f := range []string{"probe-cp.cred", "probe-cp/input.json", "probe-projects.cred"} {
		if err := os.WriteFile(filepath.Join(jd, f), nil, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.a.KillJobs(context.Background(), "probe-cp"); err != nil {
		t.Fatal(err)
	}
	if !e.gone("job-probe-cp") {
		t.Fatal("the probe's container stays")
	}
	ents, _ := os.ReadDir(jd)
	var names []string
	for _, x := range ents {
		names = append(names, x.Name())
	}
	if !slices.Equal(names, []string{"probe-projects", "probe-projects.cred"}) {
		t.Fatalf("job files after the removal: %q", names)
	}
}

// A first fetch: fetch/ does not exist until the launcher has it made, and
// its absence before that is no refusal.
func TestRunJob_FetchDirAbsentIsMadeNotRefused(t *testing.T) {
	e := newJobEnv(t)
	dir := filepath.Join(e.a.p.RepoDir(testRef), "fetch")
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	ensureFetchDir = func(nodecfg.Paths, string, int, int) error { return os.Mkdir(dir, 0o750) }
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "fetch", testRef, 9)); err != nil {
		t.Fatalf("a first fetch: %v", err)
	}
	if len(e.runs()) != 1 {
		t.Fatalf("%d runs", len(e.runs()))
	}
}
