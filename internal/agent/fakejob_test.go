package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/jobio"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// The job containers' part of the fake Docker: `inspect` of a container's
// state and `logs` (registered in fakeVerbs), and what a job does once
// `run -d` has started it — how many polls it runs, its exit code, what it
// writes and whether it honours the stop signal. A job with no script exits
// 0 at its first poll and writes nothing.
type jobScript struct {
	polls      int    // polls answered "running" before it exits; -1: never exits by itself
	exit       int    // its exit code
	stdout     string // what `docker logs` returns as its standard output
	stderr     string
	logsErr    error
	ignoreTerm bool   // a stop leaves it without a result line (the kill at the grace's end)
	onPoll     func() // called at each poll while it runs, with f.mu held
}

type jobModel struct {
	mu       sync.Mutex
	scripts  map[string]*jobScript // by container name
	envAtRun map[string]string     // the environment file's content when `run` was called, by container name
	envMode  map[string]fs.FileMode
}

var jobModels sync.Map // *fakeHost → *jobModel

func modelOf(f *fakeHost) *jobModel {
	m, _ := jobModels.Load(f)
	jm, _ := m.(*jobModel)
	return jm
}

func (m *jobModel) script(name string) *jobScript {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.scripts[name]
	if s == nil {
		s = &jobScript{}
		m.scripts[name] = s
	}
	return s
}

func init() {
	fakeVerbs["inspect"] = func(f *fakeHost, args []string, _ []byte) (string, error) {
		jm := modelOf(f)
		if jm == nil || flagValue(args, "--format") != "{{.State.Status}} {{.State.ExitCode}}" {
			f.t.Errorf("fake docker: unmodelled inspect %q", args)
			return "", errors.New("fake: unmodelled inspect")
		}
		name := positional(args)[0]
		c, ok := f.ctrs[name]
		if !ok {
			return "", errors.New("Error: No such object: " + name)
		}
		s := jm.script(name)
		if c.Running && s.polls != 0 {
			if s.polls > 0 {
				s.polls--
			}
			if s.onPoll != nil {
				s.onPoll() // with f.mu held: it must not call into the fake
			}
			return "running 0\n", nil
		}
		if c.Running { // it exits by itself now
			c.Running, c.Pid = false, 0
		}
		return fmt.Sprintf("exited %d\n", s.exit), nil
	}
	fakeVerbs["logs"] = func(f *fakeHost, args []string, _ []byte) (string, error) {
		jm := modelOf(f)
		if jm == nil {
			f.t.Errorf("fake docker: unmodelled logs %q", args)
			return "", errors.New("fake: unmodelled logs")
		}
		s := jm.script(positional(args)[0])
		if s.logsErr != nil {
			return "", s.logsErr
		}
		out := s.stdout
		if n := flagValue(args, "--tail"); n != "" {
			// Docker keeps a long line as records of 16 KiB: a tail counts them.
			k, _ := strconv.Atoi(n)
			var recs []string
			for rest := out; rest != ""; {
				i := strings.IndexByte(rest, '\n')
				line := rest
				if i >= 0 {
					line, rest = rest[:i+1], rest[i+1:]
				} else {
					rest = ""
				}
				for len(line) > 16<<10 {
					recs = append(recs, line[:16<<10])
					line = line[16<<10:]
				}
				recs = append(recs, line)
			}
			out = strings.Join(recs[max(0, len(recs)-k):], "")
		}
		return out, nil
	}
}

// jobEnv is a node prepared for RunJob: the agent and fake, a project spec,
// every mount source of every kind in place with the owner the platform
// gives it, and an lstat that reports those owners.
type jobEnv struct {
	a      *Agent
	f      *fakeHost
	s      Spec
	m      *jobModel
	exe    string
	owners map[string][2]int // path → uid, gid as lstat reports them
	fetch  []string          // ensureFetchDir calls
}

func newJobEnv(t *testing.T) *jobEnv {
	t.Helper()
	a, f, s := newTestAgent(t)
	e := &jobEnv{a: a, f: f, s: s, owners: map[string][2]int{},
		m: &jobModel{scripts: map[string]*jobScript{}, envAtRun: map[string]string{}, envMode: map[string]fs.FileMode{}}}
	jobModels.Store(f, e.m)
	t.Cleanup(func() { jobModels.Delete(f) })
	p := a.p
	mkdirs(t, filepath.Dir(p.PlatformDir()), p.PlatformDir(), filepath.Dir(p.ProjectsDir()), p.ProjectsDir())
	for _, subj := range []string{s.Ref, nodecfg.ControlPlaneSubject} {
		uid, gid := s.UID, s.GID
		pd := p.ProjectDir(subj)
		if subj == nodecfg.ControlPlaneSubject {
			uid, gid = nodecfg.ControlPlaneUID, nodecfg.ControlPlaneUID
		}
		mkdirs(t, pd, p.RepoRoot(), p.RepoDir(subj))
		for _, d := range []string{"data", "sock", "spool", "rspool"} {
			mkdirs(t, filepath.Join(pd, d))
			e.owners[filepath.Join(pd, d)] = [2]int{uid, gid}
		}
		mkdirs(t, filepath.Join(p.RepoDir(subj), "repo"), filepath.Join(p.RepoDir(subj), "fetch"))
		e.owners[filepath.Join(p.RepoDir(subj), "repo")] = [2]int{uid, gid}
		e.owners[filepath.Join(p.RepoDir(subj), "fetch")] = [2]int{nodecfg.ReplicatorUID, gid}
		idx := p.IndexFile(subj)
		mkdirs(t, filepath.Dir(idx))
		if err := os.WriteFile(idx, nil, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	mkdirs(t, filepath.Join(p.CPDir(), "sock"))
	e.owners[filepath.Join(p.CPDir(), "sock")] = [2]int{nodecfg.ControlPlaneUID, nodecfg.ControlPlaneUID}
	e.exe = filepath.Join(a.p.Root, "usr/local/bin/supapaced")
	mkdirs(t, filepath.Dir(e.exe))
	if err := os.WriteFile(e.exe, []byte("exe"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{"1", "2", "3", "7", "9", "probe-projects", "probe-cp"} {
		e.owners[filepath.Join(p.JobsDir(), base+".cred")] = [2]int{nodecfg.ReplicatorUID, nodecfg.ReplicatorUID}
	}
	t.Cleanup(swap(&lstat, func(path string) (fs.FileInfo, error) {
		fi, err := os.Lstat(path)
		if o, ok := e.owners[path]; ok && err == nil {
			return ownedFI{fi, o}, nil
		}
		return fi, err
	}))
	t.Cleanup(swap(&daemonExe, func() (string, error) { return e.exe, nil }))
	t.Cleanup(swap(&ensureFetchDir, func(p nodecfg.Paths, subject string, uid, gid int) error {
		e.fetch = append(e.fetch, fmt.Sprintf("%s %d:%d", subject, uid, gid))
		return nil
	}))
	t.Cleanup(swap(&taskPoll, time.Millisecond))
	// Like the real client, a call on an ended context starts nothing.
	inner := dockerRun
	t.Cleanup(swap(&dockerRun, func(ctx context.Context, args ...string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return inner(ctx, args...)
	}))
	t.Cleanup(swap(&dockerRunOutput, func(ctx context.Context, args ...string) (string, string, error) {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		out, err := f.run(args, nil)
		if args[0] == "logs" {
			return out, e.m.script(positional(args)[0]).stderr, err
		}
		return out, "", err
	}))
	f.before = func(args []string) {
		if args[0] != "run" {
			return
		}
		if env := flagValue(args, "--env-file"); env != "" {
			b, _ := os.ReadFile(env)
			fi, _ := os.Lstat(env)
			e.m.mu.Lock()
			e.m.envAtRun[flagValue(args, "--name")] = string(b)
			if fi != nil {
				e.m.envMode[flagValue(args, "--name")] = fi.Mode()
			}
			e.m.mu.Unlock()
		}
	}
	return e
}

// ownedFI reports another owner than the file's.
type ownedFI struct {
	fs.FileInfo
	o [2]int
}

func (o ownedFI) Sys() any {
	st := *o.FileInfo.Sys().(*syscall.Stat_t)
	st.Uid, st.Gid = uint32(o.o[0]), uint32(o.o[1])
	return &st
}

// spec is a job of kind for the project (or "cp"), with a valid input and
// the secrets the runner gives that kind.
func (e *jobEnv) spec(t *testing.T, kind, subject string, id int64) JobSpec {
	t.Helper()
	uid, gid := e.s.UID, e.s.GID
	if subject == nodecfg.ControlPlaneSubject {
		uid, gid = nodecfg.ControlPlaneUID, nodecfg.ControlPlaneUID
	}
	in := jobio.Input{Job: id, Kind: kind, Subject: subject, Stanza: subject + "-1", UID: uid, Timelines: []uint32{1}}
	j := JobSpec{ID: id, Subject: subject, Kind: kind, UID: uid, GID: gid, Deadline: time.Hour}
	switch kind {
	case "push", "stanza-create", "backup", "check", "restore", "serve":
		j.SecretEnv = map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": "pass-" + strings.Repeat("s", 20)}
	}
	switch kind {
	case "push":
		in.MaxEntries = 56
	case "backup":
		in.Type = "full"
	case "restore":
		in.Set, in.Mode = "20261119-120000F", "none"
	case "serve":
		in.MaxAnswers = 8
	case "replicate", "fetch", "probe":
		j.Cred = []byte("AKIDEXAMPLEKEY01\nsecret-key-material-0123456789")
		if kind == "probe" {
			j.Cred = append(j.Cred, "\nAKIDEXAMPLEREAD1\nread-secret-material-0123456789"...)
			in.Timelines, in.Subject = nil, subject
		}
		j.Addrs = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:9443")}
		j.Env = map[string]string{"SUPAPACE_S3_ENDPOINT": "https://s3.sp.test:9443", "SUPAPACE_S3_REGION": "us-east-1",
			"SUPAPACE_S3_BUCKET": "sp-projects", "SUPAPACE_S3_PREFIX": "", "SUPAPACE_S3_PATH_STYLE": "1",
			"SUPAPACE_S3_ADDRS": "192.0.2.10:9443"}
		switch kind {
		case "replicate":
			in.Repl = &jobio.ReplInput{Mode: "copy", MaxFiles: 2048, MaxEntries: 250000, MaxBytes: 1 << 30, BudgetBytes: -1, BudgetObjects: -1,
				InfoSHA256: map[string]string{}}
		case "probe":
			in.Repl = &jobio.ReplInput{Mode: "probe", InfoSHA256: map[string]string{}}
		case "fetch":
			in.MaxBytes = 1 << 30
		}
	}
	b, err := jobio.MarshalInput(in)
	if err != nil {
		t.Fatal(err)
	}
	j.Input = b
	return j
}

// runs returns the argv of every `docker run` call.
func (e *jobEnv) runs() [][]string { return e.f.argv("run") }

// gone reports whether name no longer exists in the fake.
func (e *jobEnv) gone(name string) bool {
	c, _ := dockerInspectContainer(context.Background(), name)
	return c == nil
}

// leftover adds a job container as a killed launcher leaves it: running.
func (e *jobEnv) leftover(name, ref, id, kind string) {
	e.f.ctr(fakeCtr{Name: name, Running: true, Labels: map[string]string{labelRole: "job", labelRef: ref, labelJob: id, labelKind: kind}})
}
