package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
	"github.com/Amphoze/supapace/internal/nodecfg"
)

// kindArgs is what one kind's container is given (the per-kind table of
// job.go): the parts of the argv that differ by kind.
type kindArgs struct {
	user, group string   // --user and the one --group-add ("" none)
	networked   bool     // the backup network, else none
	mounts      []string // the -v values before the executable's and the job directory's, in order
	mem, pids   string
	tmpfs       string
	cmd         []string // after the image
}

// jobTable pins every kind's argument list. A change that adds per-kind flags
// adds them here.
func jobTable(e *jobEnv, subject string) map[string]kindArgs {
	p := e.a.p
	pd, rd, sock := p.ProjectDir(subject), p.RepoDir(subject), p.ProjectDir(subject)+"/sock"
	ug := fmt.Sprintf("%d:%d", e.s.UID, e.s.GID)
	g := fmt.Sprint(e.s.GID)
	if subject == nodecfg.ControlPlaneSubject {
		pd, sock, ug, g = p.CPProjectDir(), p.CPDir()+"/sock", "70:70", "70"
	}
	cred := p.JobsDir() + "/9.cred:/cred:ro"
	work := func(m ...string) []string { return m }
	return map[string]kindArgs{
		"push": {user: ug, mounts: work(pd+"/spool:/spool", rd+"/repo:/repo"), mem: "512m", pids: "256", tmpfs: "128m", cmd: []string{"job", "push"}},
		"stanza-create": {user: ug, mounts: work(pd+"/data:/var/lib/postgresql/data:ro", sock+":/var/run/postgresql", pd+"/spool:/spool", rd+"/repo:/repo"),
			mem: "512m", pids: "256", tmpfs: "128m", cmd: []string{"job", "stanza-create"}},
		"backup": {user: ug, mounts: work(pd+"/data:/var/lib/postgresql/data:ro", sock+":/var/run/postgresql", pd+"/spool:/spool", rd+"/repo:/repo"),
			mem: "512m", pids: "256", tmpfs: "128m", cmd: []string{"job", "backup"}},
		"check": {user: ug, mounts: work(pd+"/data:/var/lib/postgresql/data:ro", sock+":/var/run/postgresql", pd+"/spool:/spool", rd+"/repo:/repo"),
			mem: "512m", pids: "256", tmpfs: "128m", cmd: []string{"job", "check"}},
		"restore": {user: ug, mounts: work(pd+"/data:/var/lib/postgresql/data", rd+"/repo:/repo:ro"), mem: "512m", pids: "256", tmpfs: "128m",
			cmd: []string{"job", "restore"}},
		"serve": {user: ug, mounts: work(pd+"/data:/var/lib/postgresql/data:ro", pd+"/rspool:/rspool", rd+"/repo:/repo:ro"), mem: "512m", pids: "256",
			tmpfs: "128m", cmd: []string{"job", "serve"}},
		"seed": {user: ug, mounts: work(rd+"/repo:/repo", rd+"/fetch:/fetch:ro"), mem: "128m", pids: "64", tmpfs: "16m", cmd: []string{"job", "seed"}},
		"replicate": {user: "65530:65530", group: g, networked: true, mounts: work(rd+"/repo:/repo:ro", p.IndexFile(subject)+":/index:ro", cred),
			mem: "256m", pids: "64", tmpfs: "64m", cmd: []string{"replicate", "copy"}},
		"fetch": {user: "65530:65530", group: g, networked: true, mounts: work(rd+"/fetch:/fetch", cred), mem: "256m", pids: "64", tmpfs: "64m",
			cmd: []string{"replicate", "fetch"}},
		"probe": {user: "65530:65530", networked: true, mounts: work(p.JobsDir() + "/probe-projects.cred:/cred:ro"), mem: "256m", pids: "64", tmpfs: "64m",
			cmd: []string{"replicate", "probe"}},
	}
}

// wantArgv is the whole `docker run` argv of a kind.
func wantArgv(e *jobEnv, kind, subject string) []string {
	k := jobTable(e, subject)[kind]
	base, ref, name := "9", subject, "job-"+subject+"-"+kind
	if kind == "probe" {
		base, ref, name = "probe-projects", "probe-projects", "job-probe-projects"
	}
	args := []string{"run", "-d", "--name", name, "--user", k.user}
	if k.group != "" {
		args = append(args, "--group-add", k.group)
	}
	args = append(args, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp="+e.a.seccompFile(),
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size="+k.tmpfs, "--memory", k.mem, "--memory-swap", k.mem, "--cpus", "1",
		"--pids-limit", k.pids, "--ulimit", "core=0", "--ulimit", "nofile=65536:65536", "--no-healthcheck", "--ipc", "none",
		"--label", "supapace.job=9", "--label", "supapace.kind="+kind, "--label", "supapace.ref="+ref, "--label", "supapace.role=job")
	if k.networked {
		args = append(args, "--network", "backup", "--sysctl", "net.ipv6.conf.all.disable_ipv6=1", "--sysctl", "net.ipv4.ping_group_range=1 0",
			"--dns", "192.0.2.1")
	} else {
		args = append(args, "--network", "none")
	}
	mem, _ := strconv.Atoi(strings.TrimSuffix(k.mem, "m"))
	args = append(args, "--env-file", e.a.p.JobsDir()+"/"+base+".env", "-e", fmt.Sprintf("GOMEMLIMIT=%dMiB", mem-32))
	for _, m := range k.mounts {
		args = append(args, "-v", m)
	}
	args = append(args, "-v", e.exe+":/supapaced:ro", "-v", e.a.p.JobsDir()+"/"+base+":/job:ro", "--entrypoint", "/supapaced", "--",
		nodecfg.WorkerImage)
	return append(args, k.cmd...)
}

func probeSpec(t *testing.T, e *jobEnv) JobSpec {
	j := e.spec(t, "probe", "projects", 9)
	return j
}

// runKind runs one job of kind for subject and compares its argv with the table.
func runKind(t *testing.T, kind, subject string) {
	t.Helper()
	e := newJobEnv(t)
	j := e.spec(t, kind, subject, 9)
	if kind == "probe" {
		j = probeSpec(t, e)
	}
	if _, err := e.a.RunJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	runs := e.runs()
	if len(runs) != 1 {
		t.Fatalf("%d runs", len(runs))
	}
	if want := wantArgv(e, kind, subject); !slices.Equal(runs[0], want) {
		t.Fatalf("argv\n got %q\nwant %q", runs[0], want)
	}
	// No other -v: the table's, the executable's and the job directory's.
	if n, want := strings.Count(" "+strings.Join(runs[0], " ")+" ", " -v "), len(jobTable(e, subject)[kind].mounts)+2; n != want {
		t.Fatalf("%d -v, want %d", n, want)
	}
}

func TestRunJob_Push(t *testing.T) {
	runKind(t, "push", testRef)
	runKind(t, "push", nodecfg.ControlPlaneSubject)
}
func TestRunJob_Backup(t *testing.T) {
	runKind(t, "backup", testRef)
	runKind(t, "backup", nodecfg.ControlPlaneSubject)
	runKind(t, "stanza-create", testRef)
	runKind(t, "check", testRef)
}
func TestRunJob_Restore(t *testing.T) { runKind(t, "restore", testRef) }
func TestRunJob_Serve(t *testing.T)   { runKind(t, "serve", testRef) }
func TestRunJob_Seed(t *testing.T)    { runKind(t, "seed", testRef) }
func TestRunJob_Replicate(t *testing.T) {
	runKind(t, "replicate", testRef)
	runKind(t, "replicate", nodecfg.ControlPlaneSubject)
}
func TestRunJob_Fetch(t *testing.T) { runKind(t, "fetch", testRef) }
func TestRunJob_Probe(t *testing.T) { runKind(t, "probe", "projects") }

// The rebuild mode follows the input; the replication memory follows MemMB.
func TestRunJob_ReplicateModeAndMemoryFromTheSpec(t *testing.T) {
	e := newJobEnv(t)
	j := e.spec(t, "replicate", testRef, 9)
	j.Input = []byte(strings.Replace(string(j.Input), `"mode":"copy"`, `"mode":"rebuild"`, 1))
	j.MemMB = 300
	if _, err := e.a.RunJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	r := e.runs()[0]
	if !slices.Equal(r[len(r)-2:], []string{"replicate", "rebuild"}) || flagValue(r, "--memory") != "300m" || flagValue(r, "--memory-swap") != "300m" {
		t.Fatalf("argv %q", r)
	}
	// Another kind's input, or another mode, is refused before anything runs.
	for name, in := range map[string]string{"kind": strings.Replace(string(j.Input), `"kind":"replicate"`, `"kind":"fetch"`, 1),
		"mode": strings.Replace(string(j.Input), `"mode":"rebuild"`, `"mode":"probe"`, 1)} {
		e.f.resetLog()
		j.Input = []byte(in)
		if _, err := e.a.RunJob(context.Background(), j); err == nil || len(e.f.mutations()) != 0 {
			t.Fatalf("%s: %v %q", name, err, e.f.mutations())
		}
	}
}

// jobFlags is an argv's flags (before --) as flag → values, without the
// ones a job sets by kind or by name.
func jobFlags(args []string) map[string][]string {
	skip := map[string]bool{"--name": true, "--user": true, "--group-add": true, "--label": true, "-v": true, "--network": true,
		"--ip": true, "-e": true, "--env-file": true, "--entrypoint": true, "--dns": true}
	m := map[string][]string{}
	for i := 1; i < len(args) && args[i] != "--"; i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		v := ""
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			v = args[i+1]
			i++
		}
		if a == "-d" || skip[a] {
			continue
		}
		m[a] = append(m[a], v)
	}
	return m
}

func TestRunJob_EveryKindCarriesTheClusterFlags(t *testing.T) {
	for _, kind := range []string{"push", "stanza-create", "backup", "check", "restore", "serve", "seed", "replicate", "fetch", "probe"} {
		t.Run(kind, func(t *testing.T) {
			e := newJobEnv(t)
			clImageFiles(t, e.a)
			writeSeccomp(t, e.a)
			r := e.a.p.RenderDir(testRef)
			mkdirs(t, filepath.Join(r, "conf.d"))
			for _, n := range []string{"conf.d/zz-supapace.conf", "supautils.conf", "pg_hba.conf", "pg_ident.conf", "passwd", "group"} {
				os.WriteFile(filepath.Join(r, n), []byte("x"), 0o644) // only hashed into the label
			}
			s := e.s
			s.Layout = 2
			cl, err := e.a.clusterRunArgs(s, true)
			if err != nil {
				t.Fatal(err)
			}
			subject := testRef
			j := e.spec(t, kind, subject, 9)
			if kind == "probe" {
				j = probeSpec(t, e)
			}
			if _, err := e.a.RunJob(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			want, got := jobFlags(cl), jobFlags(e.runs()[0])
			k := jobTable(e, subject)[kind]
			// The named differences: the three sizes; no shared memory (no /dev/shm
			// at all), no stop timeout, no host name; the sysctls only with a network.
			want["--memory"], want["--memory-swap"], want["--pids-limit"] = []string{k.mem}, []string{k.mem}, []string{k.pids}
			want["--tmpfs"] = []string{"/tmp:rw,noexec,nosuid,size=" + k.tmpfs}
			want["--ipc"] = []string{"none"}
			for _, f := range []string{"--shm-size", "--stop-timeout", "--hostname"} {
				delete(want, f)
			}
			if !k.networked {
				delete(want, "--sysctl")
			}
			if len(want) != len(got) {
				t.Errorf("flags %v, want %v", got, want)
			}
			for f, v := range want {
				if !slices.Equal(got[f], v) {
					t.Errorf("%s = %q, want %q (cluster %q)", f, got[f], v, cl)
				}
			}
		})
	}
}

func TestRunJob_NetworkedJobHasTheClusterSysctlsAndLimits(t *testing.T) {
	for _, kind := range []string{"replicate", "fetch", "probe"} {
		e := newJobEnv(t)
		j := e.spec(t, kind, testRef, 9)
		if kind == "probe" {
			j = probeSpec(t, e)
		}
		if _, err := e.a.RunJob(context.Background(), j); err != nil {
			t.Fatal(err)
		}
		r := e.runs()[0]
		if !slices.Equal(flagValues(r, "--sysctl"), []string{"net.ipv6.conf.all.disable_ipv6=1", "net.ipv4.ping_group_range=1 0"}) ||
			flagValue(r, "--memory-swap") != flagValue(r, "--memory") || flagValue(r, "--tmpfs") != "/tmp:rw,noexec,nosuid,size=64m" ||
			flagValue(r, "--dns") != "192.0.2.1" || flagValue(r, "--network") != nodecfg.BackupNetwork {
			t.Fatalf("%s: %q", kind, r)
		}
	}
}

func TestRunJob_WorkersHaveNoNetwork(t *testing.T) {
	for _, kind := range []string{"push", "stanza-create", "backup", "check", "restore", "serve", "seed"} {
		e := newJobEnv(t)
		if _, err := e.a.RunJob(context.Background(), e.spec(t, kind, testRef, 9)); err != nil {
			t.Fatal(err)
		}
		r := e.runs()[0]
		if !slices.Equal(flagValues(r, "--network"), []string{"none"}) || flagValue(r, "--dns") != "" || len(flagValues(r, "--sysctl")) != 0 ||
			len(flagValues(r, "--group-add")) != 0 {
			t.Fatalf("%s: %q", kind, r)
		}
		if slices.ContainsFunc(e.f.calls(), func(c string) bool {
			return strings.HasPrefix(c, "inspect network") || strings.HasPrefix(c, "docker network")
		}) {
			t.Fatalf("%s: touched the backup network: %q", kind, e.f.calls())
		}
	}
}

func TestRunJob_PushHasNoDataMount(t *testing.T) {
	e := newJobEnv(t)
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err != nil {
		t.Fatal(err)
	}
	for _, v := range flagValues(e.runs()[0], "-v") {
		if strings.Contains(v, "/data:") || strings.Contains(v, "/sock:") || strings.Contains(v, "/rspool:") {
			t.Fatalf("push mounts %q", v)
		}
	}
}

func TestRunJob_NetworkedJobGetsItsCredentialAsAFile_NothingSecretInItsEnvironment(t *testing.T) {
	for _, kind := range []string{"replicate", "fetch", "probe"} {
		t.Run(kind, func(t *testing.T) {
			e := newJobEnv(t)
			j := e.spec(t, kind, testRef, 9)
			base := "9"
			if kind == "probe" {
				j, base = probeSpec(t, e), "probe-projects"
			}
			cred := filepath.Join(e.a.p.JobsDir(), base+".cred")
			name := "job-" + testRef + "-" + kind
			if kind == "probe" {
				name = "job-probe-projects"
			}
			var credDuring error
			e.m.script(name).polls = 1
			e.m.script(name).onPoll = func() { _, credDuring = os.Lstat(cred) }
			if _, err := e.a.RunJob(context.Background(), j); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(flagValues(e.runs()[0], "-v"), cred+":/cred:ro") {
				t.Fatalf("no read-only /cred: %q", e.runs()[0])
			}
			w, ok := e.f.writes[cred]
			if !ok || w.Mode != 0o400 || w.UID != nodecfg.ReplicatorUID || w.GID != nodecfg.ReplicatorUID || string(w.Data) != string(j.Cred) {
				t.Fatalf("credential file %+v (written %v)", w, ok)
			}
			env := e.m.envAtRun[name]
			if env == "" || !strings.Contains(env, "SUPAPACE_S3_BUCKET=sp-projects\n") {
				t.Fatalf("control: environment file %q", env)
			}
			for _, line := range strings.Split(string(j.Cred), "\n") {
				if strings.Contains(env, line) || strings.Contains(strings.Join(e.runs()[0], " "), line) {
					t.Fatalf("a key in the environment or the argv: %q", line)
				}
			}
			if credDuring != nil {
				t.Fatalf("the credential file was gone while the job ran: %v", credDuring)
			}
			if _, err := os.Lstat(cred); !os.IsNotExist(err) {
				t.Fatalf("credential file left: %v", err)
			}
		})
	}
}

func TestRunJob_SecretsOnlyInEnvFile_0600(t *testing.T) {
	e := newJobEnv(t)
	j := e.spec(t, "backup", testRef, 9)
	pass := j.SecretEnv["PGBACKREST_REPO1_CIPHER_PASS"]
	if _, err := e.a.RunJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	name := "job-" + testRef + "-backup"
	env := e.f.writes[filepath.Join(e.a.p.JobsDir(), "9.env")]
	if env.Mode != 0o600 || env.UID != 0 || env.GID != 0 {
		t.Fatalf("environment file %o %d:%d", env.Mode, env.UID, env.GID)
	}
	if got := e.m.envAtRun[name]; got != "PGBACKREST_REPO1_CIPHER_PASS="+pass+"\n" || e.m.envMode[name].Perm() != 0o600 {
		t.Fatalf("environment file at run: %q %v", got, e.m.envMode[name])
	}
	for _, c := range e.f.calls() {
		if strings.Contains(c, pass) {
			t.Fatalf("the passphrase in a docker call: %q", c)
		}
	}
	for p, w := range e.f.writes {
		if strings.Contains(string(w.Data), pass) && p != filepath.Join(e.a.p.JobsDir(), "9.env") {
			t.Fatalf("the passphrase in %s", p)
		}
	}
	if c := e.f.ctrs[name]; c != nil {
		t.Fatal("container left")
	}
}

func TestRunJob_EnvFileGoneOnceStarted(t *testing.T) {
	e := newJobEnv(t)
	env := filepath.Join(e.a.p.JobsDir(), "9.env")
	name := "job-" + testRef + "-push"
	var during error
	e.m.script(name).polls = 1
	e.m.script(name).onPoll = func() { _, during = os.Lstat(env) }
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err != nil {
		t.Fatal(err)
	}
	if e.m.envAtRun[name] == "" {
		t.Fatal("control: no environment file at run")
	}
	if !os.IsNotExist(during) {
		t.Fatalf("environment file present while the job ran: %v", during)
	}
	// docker run fails: the file is gone too, and the container is removed.
	e.f.failVerb["run"] = errors.New("docker: no space")
	e.f.resetLog()
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err == nil {
		t.Fatal("a failed run succeeded")
	}
	if _, err := os.Lstat(env); !os.IsNotExist(err) {
		t.Fatalf("environment file after a failed run: %v", err)
	}
	if ents, _ := os.ReadDir(e.a.p.JobsDir()); len(ents) != 0 {
		t.Fatalf("job files after a failed run: %v", ents)
	}
	if m := e.f.mutations(); m[len(m)-1] != "docker rm -f -v -- "+name {
		t.Fatalf("no removal after the failed run: %q", m)
	}
}

func TestRunJob_EnvValueWithNewlineRefused(t *testing.T) {
	for name, change := range map[string]func(j *JobSpec){
		"secret newline": func(j *JobSpec) { j.SecretEnv["PGBACKREST_REPO1_CIPHER_PASS"] = "a\nPGBACKREST_CONFIG=/x" },
		"env newline":    func(j *JobSpec) { j.Env = map[string]string{"SUPAPACE_X": "a\nb"} },
		"env control":    func(j *JobSpec) { j.Env = map[string]string{"SUPAPACE_X": "a\x00"} },
		"bad name":       func(j *JobSpec) { j.Env = map[string]string{"A=B": "c"} },
		"empty name":     func(j *JobSpec) { j.Env = map[string]string{"": "c"} },
		"twice":          func(j *JobSpec) { j.Env = map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": "x"} },
	} {
		t.Run(name, func(t *testing.T) {
			e := newJobEnv(t)
			j := e.spec(t, "push", testRef, 9)
			jobControl(t, e, j)
			change(&j)
			if _, err := e.a.RunJob(context.Background(), j); err == nil {
				t.Fatal("accepted")
			}
			if len(e.f.calls()) != 0 || len(e.f.writes) != 0 {
				t.Fatalf("something ran or was written: %q %v", e.f.calls(), e.f.writes)
			}
		})
	}
}

// Secrets only where the table puts them.
func TestRunJob_SecretsByKindRefusedElsewhere(t *testing.T) {
	for name, c := range map[string]struct {
		kind   string
		change func(j *JobSpec)
	}{
		"passphrase in a networked job": {"replicate", func(j *JobSpec) { j.SecretEnv = map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": "x"} }},
		"passphrase in seed":            {"seed", func(j *JobSpec) { j.SecretEnv = map[string]string{"PGBACKREST_REPO1_CIPHER_PASS": "x"} }},
		"another secret":                {"push", func(j *JobSpec) { j.SecretEnv["AWS_SECRET_ACCESS_KEY"] = "x" }},
		"credential in a worker":        {"push", func(j *JobSpec) { j.Cred = []byte("a\nb") }},
		"networked without credential":  {"fetch", func(j *JobSpec) { j.Cred = nil }},
		"key-like name, networked":      {"replicate", func(j *JobSpec) { j.Env["AWS_ACCESS_KEY_ID"] = "x" }},
		"token-like name, networked":    {"probe", func(j *JobSpec) { j.Env["session_token"] = "x" }},
		"memory in a worker":            {"push", func(j *JobSpec) { j.MemMB = 1024 }},
		"no deadline":                   {"push", func(j *JobSpec) { j.Deadline = 0 }},
		"file named like the input":     {"push", func(j *JobSpec) { j.Files = map[string][]byte{"input.json": nil} }},
		"file with a path":              {"replicate", func(j *JobSpec) { j.Files = map[string][]byte{"../ca.pem": nil} }},
		"project with platform ids":     {"push", func(j *JobSpec) { j.UID, j.GID = 70, 70 }},
		"cp with project ids":           {"push", func(j *JobSpec) { j.Subject = nodecfg.ControlPlaneSubject }},
		"project gid of the platform":   {"push", func(j *JobSpec) { j.GID = 70 }},
		"bad subject":                   {"push", func(j *JobSpec) { j.Subject = "../x" }},
		"no id":                         {"push", func(j *JobSpec) { j.ID = 0 }},
		"probe of another bucket":       {"probe", func(j *JobSpec) { j.Subject = testRef }},
		"TMPDIR":                        {"push", func(j *JobSpec) { j.Env = map[string]string{"TMPDIR": "/tmp/x"} }},
		"LD_PRELOAD":                    {"push", func(j *JobSpec) { j.Env = map[string]string{"LD_PRELOAD": "/tmp/x.so"} }},
		"PGBACKREST_CONFIG":             {"push", func(j *JobSpec) { j.Env = map[string]string{"PGBACKREST_CONFIG": "/tmp/x"} }},
		"SSL_CERT_FILE":                 {"replicate", func(j *JobSpec) { j.Env["SSL_CERT_FILE"] = "/job/ca.pem" }},
		"lower-case SUPAPACE name":      {"push", func(j *JobSpec) { j.Env = map[string]string{"SUPAPACE_x": "1"} }},
		"input of another subject": {"push", func(j *JobSpec) {
			j.Input = []byte(strings.Replace(string(j.Input), testRef, "zzzzzzzzzzzzzzzzzzzz", 1))
		}},
		"input of another job":            {"push", func(j *JobSpec) { j.Input = []byte(strings.Replace(string(j.Input), `"job":9`, `"job":8`, 1)) }},
		"credential with a final newline": {"replicate", func(j *JobSpec) { j.Cred = append(j.Cred, '\n') }},
		"credential with an empty field":  {"replicate", func(j *JobSpec) { j.Cred = []byte("\nsecret") }},
		"GOMEMLIMIT from the caller":      {"replicate", func(j *JobSpec) { j.Env["GOMEMLIMIT"] = "1GiB" }},
		"one key pair for a probe":        {"probe", func(j *JobSpec) { j.Cred = []byte("a\nb\n") }},
		"three lines for a copy":          {"replicate", func(j *JobSpec) { j.Cred = []byte("a\nb\nc") }},
		"a tiny replication memory":       {"replicate", func(j *JobSpec) { j.MemMB = 64 }},
	} {
		t.Run(name, func(t *testing.T) {
			e := newJobEnv(t)
			j := e.spec(t, c.kind, testRef, 9)
			if c.kind == "probe" {
				j = probeSpec(t, e)
			}
			jobControl(t, e, j)
			c.change(&j)
			if _, err := e.a.RunJob(context.Background(), j); err == nil || errors.Is(err, ErrHostState) || len(e.f.calls()) != 0 {
				t.Fatalf("%v, calls %q", err, e.f.calls())
			}
		})
	}
}

func TestRunJob_MissingSourceRefusedNothingCreated(t *testing.T) {
	e := newJobEnv(t)
	spool := filepath.Join(e.a.p.ProjectDir(testRef), "spool")
	os.Remove(spool)
	_, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9))
	if !errors.Is(err, ErrHostState) || err.Error() == ErrHostState.Error() {
		t.Fatalf("%v", err)
	}
	if _, err := os.Lstat(spool); !os.IsNotExist(err) {
		t.Fatalf("source created: %v", err)
	}
	if len(e.f.calls()) != 0 || len(e.f.writes) != 0 {
		t.Fatalf("docker calls or writes: %q %v", e.f.calls(), e.f.writes)
	}
	if _, err := os.Lstat(e.a.p.JobsDir()); !os.IsNotExist(err) {
		t.Fatal("jobs directory created")
	}
	// The executable is a source too.
	e2 := newJobEnv(t)
	os.Remove(e2.exe)
	if _, err := e2.a.RunJob(context.Background(), e2.spec(t, "push", testRef, 9)); !errors.Is(err, ErrHostState) || len(e2.f.calls()) != 0 {
		t.Fatalf("no executable: %v %q", err, e2.f.calls())
	}
}

func TestRunJob_SourceIsLinkRefused(t *testing.T) {
	for _, which := range []string{"spool", "repo", "index", "exe"} {
		t.Run(which, func(t *testing.T) {
			e := newJobEnv(t)
			kind, path := "push", map[string]string{"spool": filepath.Join(e.a.p.ProjectDir(testRef), "spool"),
				"repo": filepath.Join(e.a.p.RepoDir(testRef), "repo"), "index": e.a.p.IndexFile(testRef), "exe": e.exe}[which]
			if which == "index" {
				kind = "replicate"
			}
			target := path + ".real"
			os.Rename(path, target)
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			if _, err := e.a.RunJob(context.Background(), e.spec(t, kind, testRef, 9)); !errors.Is(err, ErrHostState) || len(e.f.calls()) != 0 {
				t.Fatalf("%v %q", err, e.f.calls())
			}
		})
	}
}

func TestRunJob_SourceOfAnotherOwnerRefused(t *testing.T) {
	for _, c := range []struct{ kind, which string }{{"push", "spool"}, {"push", "repo"}, {"backup", "data"}, {"backup", "sock"},
		{"serve", "rspool"}, {"seed", "fetch"}, {"replicate", "index"}, {"replicate", "cred"}, {"push", "exe"}} {
		t.Run(c.kind+" "+c.which, func(t *testing.T) {
			e := newJobEnv(t)
			pd, rd := e.a.p.ProjectDir(testRef), e.a.p.RepoDir(testRef)
			path := map[string]string{"spool": pd + "/spool", "data": pd + "/data", "sock": pd + "/sock", "rspool": pd + "/rspool",
				"repo": rd + "/repo", "fetch": rd + "/fetch", "index": e.a.p.IndexFile(testRef), "exe": e.exe,
				"cred": filepath.Join(e.a.p.JobsDir(), "9.cred")}[c.which]
			// The other id of the pair is right, so that uid and gid are each checked.
			o, ok := e.owners[path]
			if !ok {
				o = [2]int{os.Geteuid(), os.Getegid()}
			}
			for _, other := range [][2]int{{o[0] + 1, o[1]}, {o[0], o[1] + 1}} {
				e.f.resetLog()
				e.owners[path] = other
				_, err := e.a.RunJob(context.Background(), e.spec(t, c.kind, testRef, 9))
				if !errors.Is(err, ErrHostState) || slices.ContainsFunc(e.f.calls(), func(s string) bool { return strings.HasPrefix(s, "docker run") }) {
					t.Fatalf("owner %v: %v %q", other, err, e.f.calls())
				}
			}
			e.owners[path] = o
			e.f.resetLog()
			if _, err := e.a.RunJob(context.Background(), e.spec(t, c.kind, testRef, 9)); err != nil {
				t.Fatalf("control: %v", err)
			}
			if c.which == "cred" {
				if ents, _ := os.ReadDir(e.a.p.JobsDir()); len(ents) != 0 {
					t.Fatalf("job files left: %v", ents)
				}
			}
		})
	}
}

func TestRunJob_SourceNotADirectoryRefused(t *testing.T) {
	e := newJobEnv(t)
	spool := filepath.Join(e.a.p.ProjectDir(testRef), "spool")
	os.Remove(spool)
	os.WriteFile(spool, nil, 0o600)
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); !errors.Is(err, ErrHostState) || len(e.f.calls()) != 0 {
		t.Fatalf("file as spool: %v %q", err, e.f.calls())
	}
	// A directory where a file belongs.
	e2 := newJobEnv(t)
	idx := e2.a.p.IndexFile(testRef)
	os.Remove(idx)
	os.Mkdir(idx, 0o700)
	if _, err := e2.a.RunJob(context.Background(), e2.spec(t, "replicate", testRef, 9)); !errors.Is(err, ErrHostState) || len(e2.f.calls()) != 0 {
		t.Fatalf("directory as index: %v %q", err, e2.f.calls())
	}
}

func TestRunJob_DeadlineKillsAndRemoves(t *testing.T) {
	e := newJobEnv(t)
	name := "job-" + testRef + "-push"
	e.m.script(name).polls = -1
	j := e.spec(t, "push", testRef, 9)
	j.Deadline = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // far above the deadline under test
	defer cancel()
	res, err := e.a.RunJob(ctx, j)
	if err != nil || !res.TimedOut || len(res.Result) != 0 || ctx.Err() != nil {
		t.Fatalf("%+v %v (ctx %v)", res, err, ctx.Err())
	}
	if !e.gone(name) {
		t.Fatal("container left")
	}
	m := e.f.mutations()
	if m[len(m)-1] != "docker rm -f -v -- "+name || slices.ContainsFunc(m, func(s string) bool { return strings.HasPrefix(s, "docker stop") }) {
		t.Fatalf("mutations %q", m)
	}
	if ents, _ := os.ReadDir(e.a.p.JobsDir()); len(ents) != 0 {
		t.Fatalf("job files left: %v", ents)
	}
}

func TestRunJob_ResultIsTheLastTerminatedLineOfTheWholeOutput(t *testing.T) {
	e := newJobEnv(t)
	name := "job-" + testRef + "-push"
	line := `{"ok":true,"x":"` + strings.Repeat("a", 40<<10) + `"}`
	s := e.m.script(name)
	s.stdout, s.stderr, s.exit = "an earlier line\n"+line+"\n", "warn: "+strings.Repeat("e", 8<<10)+"\x1b[31mend", 0
	res, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9))
	if err != nil || string(res.Result) != line || res.ExitCode != 0 {
		t.Fatalf("result %d bytes %v exit %d", len(res.Result), err, res.ExitCode)
	}
	if len(res.Stderr) > 4096 || !strings.HasSuffix(res.Stderr, "[31mend") || strings.ContainsAny(res.Stderr, "\x1b\n") {
		t.Fatalf("stderr %q", res.Stderr)
	}
	logs := e.f.argv("logs")
	if len(logs) != 1 || slices.Contains(logs[0], "--tail") || !slices.Equal(logs[0], []string{"logs", "--", name}) {
		t.Fatalf("logs %q", logs)
	}
	// An unterminated tail after the line does not replace it; nothing
	// terminated at all is no result.
	for out, want := range map[string]string{line + "\npartial": line, "no newline": "", "": "", "\n": "", "a\n\n": ""} {
		e.m.script(name).stdout = out
		res, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9))
		if err != nil || string(res.Result) != want {
			t.Errorf("output %.20q: result %.20q %v", out, res.Result, err)
		}
	}
	e.m.script(name).stdout, e.m.script(name).exit = "{\"ok\":false}\n", 1
	if res, _ := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); res.ExitCode != 1 {
		t.Fatalf("exit code %d", res.ExitCode)
	}
}

func TestRunJob_OutputAboveTheCapIsAnEmptyResult(t *testing.T) {
	e := newJobEnv(t)
	name := "job-" + testRef + "-push"
	e.m.script(name).logsErr = fmt.Errorf("docker logs: %w", dockerx.ErrOutputTooLarge)
	res, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9))
	if err != nil || len(res.Result) != 0 || !e.gone(name) {
		t.Fatalf("%+v %v", res, err)
	}
	// Any other failure to read the output is an error, the container still removed.
	e.m.script(name).logsErr = errors.New("docker logs: daemon gone")
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err == nil || !e.gone(name) {
		t.Fatalf("logs failure: %v", err)
	}
}

func TestRunJob_LineAboveOneMiBIsEmpty(t *testing.T) {
	e := newJobEnv(t)
	name := "job-" + testRef + "-push"
	for n, want := range map[int]int{1 << 20: 1 << 20, 1<<20 + 1: 0} {
		e.m.script(name).stdout = strings.Repeat("x", n) + "\n"
		res, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9))
		if err != nil || len(res.Result) != want {
			t.Fatalf("line of %d: result %d %v", n, len(res.Result), err)
		}
	}
}

func TestRunJob_RemovesEveryLeftoverJobOfTheSubjectFirst(t *testing.T) {
	e := newJobEnv(t)
	e.leftover("job-"+testRef+"-backup", testRef, "7", "backup")
	e.leftover("job-zzzzzzzzzzzzzzzzzzzz-push", "zzzzzzzzzzzzzzzzzzzz", "3", "push")
	e.leftover("job-probe-projects", "probe-projects", "0", "probe")
	jd := e.a.p.JobsDir()
	mkdirs(t, jd, filepath.Join(jd, "7"), filepath.Join(jd, "3"))
	os.WriteFile(filepath.Join(jd, "7.cred"), nil, 0o400)
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err != nil {
		t.Fatal(err)
	}
	m := e.f.mutations()
	if i, k := slices.Index(m, "docker rm -f -v -- job-"+testRef+"-backup"), slices.IndexFunc(m, func(s string) bool { return strings.HasPrefix(s, "docker run") }); i < 0 || k < i {
		t.Fatalf("leftover not removed before the run: %q", m)
	}
	for _, other := range []string{"job-zzzzzzzzzzzzzzzzzzzz-push", "job-probe-projects"} {
		if e.gone(other) {
			t.Errorf("%s removed", other)
		}
	}
	if _, err := os.Lstat(filepath.Join(jd, "7")); !os.IsNotExist(err) {
		t.Error("the leftover's job directory stays")
	}
	if _, err := os.Lstat(filepath.Join(jd, "7.cred")); !os.IsNotExist(err) {
		t.Error("the leftover's credential stays")
	}
	if _, err := os.Lstat(filepath.Join(jd, "3")); err != nil {
		t.Error("another subject's job directory removed")
	}
	// A leftover that cannot be removed: nothing is started.
	e.leftover("job-"+testRef+"-check", testRef, "8", "check")
	e.f.resetLog()
	e.f.failVerb["rm"] = errors.New("docker: device busy")
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err == nil || len(e.runs()) != 0 {
		t.Fatalf("started beside a leftover: %v %q", err, e.runs())
	}
	// A listing that fails starts nothing either.
	delete(e.f.failVerb, "rm")
	e.f.resetLog()
	inner := dockerListContainers
	dockerListContainers = func(context.Context, string) ([]dockerx.Container, error) { return nil, errors.New("docker: down") }
	defer func() { dockerListContainers = inner }()
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err == nil || len(e.runs()) != 0 {
		t.Fatalf("started without the listing: %v", err)
	}
}

func TestRunJob_AlwaysDetached_RemovedByName(t *testing.T) {
	e := newJobEnv(t)
	name := "job-" + testRef + "-push"
	e.m.script(name).polls = 3
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err != nil {
		t.Fatal(err)
	}
	r := e.runs()[0]
	if r[1] != "-d" || slices.Contains(r, "--rm") || flagValue(r, "--restart") != "" {
		t.Fatalf("argv %q", r)
	}
	var seq []string
	for _, c := range e.f.argv() {
		if slices.Contains(c, name) {
			seq = append(seq, c[0])
		}
	}
	if want := []string{"run", "inspect", "inspect", "inspect", "inspect", "logs", "rm"}; !slices.Equal(seq, want) {
		t.Fatalf("calls %q, want %q", seq, want)
	}
	if !e.gone(name) {
		t.Fatal("container left")
	}
	if ents, _ := os.ReadDir(e.a.p.JobsDir()); len(ents) != 0 {
		t.Fatalf("job files left: %v", ents)
	}
}

func TestRunJob_CancelledContextStopsGracefully_ResultStillRead(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignores the signal %v", ignore), func(t *testing.T) {
			e := newJobEnv(t)
			name := "job-" + testRef + "-serve"
			ctx, cancel := context.WithCancel(context.Background())
			s := e.m.script(name)
			s.polls, s.onPoll, s.exit = -1, cancel, 0
			s.stdout = `{"ok":true,"served":3}` + "\n"
			if ignore {
				s.stdout, s.exit = "", 137
			}
			res, err := e.a.RunJob(ctx, e.spec(t, "serve", testRef, 9))
			stops := e.f.argv("stop")
			if len(stops) != 1 || !slices.Equal(stops[0], []string{"stop", "-t", "10", "--", name}) {
				t.Fatalf("stops %q", stops)
			}
			if res.TimedOut || !e.gone(name) {
				t.Fatalf("%+v gone %v", res, e.gone(name))
			}
			if !ignore && (err != nil || string(res.Result) != `{"ok":true,"served":3}`) {
				t.Fatalf("result %q %v", res.Result, err)
			}
			if ignore && (len(res.Result) != 0 || !errors.Is(err, context.Canceled) || res.ExitCode != 137) {
				t.Fatalf("a job that ignored the signal: %+v %v", res, err)
			}
		})
	}
}

func TestRunJob_FetchCreatesFetchDir(t *testing.T) {
	e := newJobEnv(t)
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "fetch", testRef, 9)); err != nil {
		t.Fatal(err)
	}
	if want := []string{fmt.Sprintf("%s %d:%d", testRef, nodecfg.ReplicatorUID, e.s.GID)}; !slices.Equal(e.fetch, want) {
		t.Fatalf("ensureFetchDir %q, want %q", e.fetch, want)
	}
	// Its failure launches nothing.
	ensureFetchDir = func(nodecfg.Paths, string, int, int) error { return errors.New("no subject directory") }
	e.f.resetLog()
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "fetch", testRef, 9)); err == nil || len(e.f.calls()) != 0 {
		t.Fatalf("%v %q", err, e.f.calls())
	}
	// Only fetch creates it.
	e2 := newJobEnv(t)
	if _, err := e2.a.RunJob(context.Background(), e2.spec(t, "seed", testRef, 9)); err != nil || len(e2.fetch) != 0 {
		t.Fatalf("seed: %v %q", err, e2.fetch)
	}
}

func TestRunJob_UnknownKindRefused(t *testing.T) {
	e := newJobEnv(t)
	jobControl(t, e, e.spec(t, "push", testRef, 9))
	for _, k := range []string{"", "verify", "Push", "rmtree", "job push"} {
		j := e.spec(t, "push", testRef, 9)
		j.Kind = k
		if _, err := e.a.RunJob(context.Background(), j); err == nil || len(e.f.calls()) != 0 {
			t.Fatalf("%q: %v", k, err)
		}
	}
}

func TestRunJob_RecoverKindRefused(t *testing.T) {
	e := newJobEnv(t)
	j := e.spec(t, "push", testRef, 9)
	j.Kind = "recover"
	if _, err := e.a.RunJob(context.Background(), j); err == nil || !strings.Contains(err.Error(), "recover") || len(e.f.calls()) != 0 {
		t.Fatalf("%v %q", err, e.f.calls())
	}
}

func TestRunJob_ProbeNamedLabelledAndFiledApart(t *testing.T) {
	e := newJobEnv(t)
	// A queued job whose id would collide with nothing: its files and its
	// container stay.
	e.leftover("job-"+testRef+"-replicate", testRef, "0", "replicate")
	jd := e.a.p.JobsDir()
	mkdirs(t, jd, filepath.Join(jd, "0"))
	j := e.spec(t, "probe", "projects", 0)
	j.Files = map[string][]byte{"ca.pem": []byte("pem")}
	name := "job-probe-projects"
	var during []string
	e.m.script(name).polls = 1
	e.m.script(name).onPoll = func() {
		ents, _ := os.ReadDir(jd)
		for _, x := range ents {
			during = append(during, x.Name())
		}
	}
	if _, err := e.a.RunJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	r := e.runs()[0]
	if flagValue(r, "--name") != name || !slices.Contains(flagValues(r, "--label"), "supapace.ref=probe-projects") ||
		!slices.Contains(flagValues(r, "-v"), jd+"/probe-projects:/job:ro") {
		t.Fatalf("argv %q", r)
	}
	if !slices.Equal(during, []string{"0", "probe-projects", "probe-projects.cred"}) {
		t.Fatalf("job files while it ran: %q", during)
	}
	if string(e.f.writes[filepath.Join(jd, "probe-projects", "ca.pem")].Data) != "pem" {
		t.Fatalf("ca.pem not written")
	}
	if e.gone("job-"+testRef+"-replicate") || !dirExists(filepath.Join(jd, "0")) {
		t.Fatal("the probe removed a queued job's container or files")
	}
	// The control plane's bucket.
	j = e.spec(t, "probe", nodecfg.ControlPlaneSubject, 0)
	if _, err := e.a.RunJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if r := e.runs()[1]; flagValue(r, "--name") != "job-probe-cp" || !slices.Contains(flagValues(r, "--label"), "supapace.ref=probe-cp") {
		t.Fatalf("argv %q", r)
	}
}

func dirExists(p string) bool { fi, err := os.Lstat(p); return err == nil && fi.IsDir() }

func TestRunJob_FilesWrittenReadOnlyInTheJobDirectory(t *testing.T) {
	e := newJobEnv(t)
	j := e.spec(t, "replicate", testRef, 9)
	j.Files = map[string][]byte{"ca.pem": []byte("pem"), "plan": []byte("rows")}
	// What an earlier attempt of the same id left is not handed to this job.
	mkdirs(t, filepath.Join(e.a.p.JobsDir(), "9"))
	os.WriteFile(filepath.Join(e.a.p.JobsDir(), "9", "stale"), nil, 0o644)
	var during error
	e.m.script("job-" + testRef + "-replicate").polls = 1
	e.m.script("job-" + testRef + "-replicate").onPoll = func() { _, during = os.Lstat(filepath.Join(e.a.p.JobsDir(), "9", "stale")) }
	if _, err := e.a.RunJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	jd := filepath.Join(e.a.p.JobsDir(), "9")
	for name, data := range map[string][]byte{"input.json": j.Input, "ca.pem": []byte("pem"), "plan": []byte("rows")} {
		w, ok := e.f.writes[filepath.Join(jd, name)]
		if !ok || w.Mode != 0o444 || w.UID != 0 || w.GID != 0 || string(w.Data) != string(data) {
			t.Errorf("%s: %+v %v", name, w, ok)
		}
	}
	if !os.IsNotExist(during) {
		t.Errorf("a stale file in the job directory while it ran: %v", during)
	}
	if !slices.Contains(e.f.calls(), "chown "+jd+" 0:0") {
		t.Errorf("job directory not made root's: %q", e.f.calls())
	}
}

func TestRunJob_NetworkedRefusedWhileContainmentFailed(t *testing.T) {
	e := newJobEnv(t)
	e.a.SetContainmentFailed(true)
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "replicate", testRef, 9)); !errors.Is(err, ErrContainment) || len(e.runs()) != 0 {
		t.Fatalf("%v", err)
	}
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 9)); err != nil {
		t.Fatalf("control: a push: %v", err)
	}
}

// A networked job is attached only to a backup network that is ours.
func TestRunJob_NetworkedNeedsThePlatformsBackupNetwork(t *testing.T) {
	e := newJobEnv(t)
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "fetch", testRef, 9)); err != nil {
		t.Fatal(err)
	}
	if len(e.f.argv("network", "create")) != 1 {
		t.Fatalf("backup network not ensured: %q", e.f.calls())
	}
	e.f.nets[nodecfg.BackupNetwork].Internal = true
	e.f.resetLog()
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "fetch", testRef, 9)); !errors.Is(err, ErrContainment) || len(e.runs()) != 0 {
		t.Fatalf("%v", err)
	}
}

func TestKillJobs_AllAndPhaseRAndJobFiles(t *testing.T) {
	e := newJobEnv(t)
	e.leftover("job-"+testRef+"-push", testRef, "7", "push")
	e.leftover("job-cp-backup", "cp", "8", "backup")
	e.leftover("job-probe-cp", "probe-cp", "0", "probe")
	e.f.ctr(fakeCtr{Name: "pg-" + testRef, Running: true, Labels: map[string]string{labelRole: "cluster", labelRef: testRef, labelPhase: "R"}})
	e.f.ctr(fakeCtr{Name: "pg-zzzzzzzzzzzzzzzzzzzz", Running: true, Labels: map[string]string{labelRole: "cluster", labelRef: "zzzzzzzzzzzzzzzzzzzz", labelPhase: "B"}})
	e.f.ctr(fakeCtr{Name: "task-" + testRef + "-purge", Running: true, Labels: map[string]string{labelRole: "task", labelRef: testRef}})
	jd := e.a.p.JobsDir()
	fill := func() {
		mkdirs(t, jd, filepath.Join(jd, "7"), filepath.Join(jd, "8"), filepath.Join(jd, "probe-cp"), filepath.Join(jd, "42"))
		for _, f := range []string{"7.env", "7.cred", "8/input.json", "42.env", "stray"} {
			os.WriteFile(filepath.Join(jd, f), nil, 0o600)
		}
	}
	fill()
	// One subject: its job containers and their files only.
	if err := e.a.KillJobs(context.Background(), testRef); err != nil {
		t.Fatal(err)
	}
	if !e.gone("job-"+testRef+"-push") || e.gone("job-cp-backup") || e.gone("pg-"+testRef) {
		t.Fatalf("subject: containers %v", sortedKeys(e.f.ctrs))
	}
	if ents, _ := os.ReadDir(jd); len(ents) != 5 || dirExists(filepath.Join(jd, "7")) {
		t.Fatalf("subject: files %v", ents)
	}
	// Every job container, every recovery cluster, every job file.
	fill()
	if err := e.a.KillJobs(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if got := sortedKeys(e.f.ctrs); !slices.Equal(got, []string{"pg-zzzzzzzzzzzzzzzzzzzz", "task-" + testRef + "-purge"}) {
		t.Fatalf("containers left %q", got)
	}
	if ents, err := os.ReadDir(jd); err != nil || len(ents) != 0 {
		t.Fatalf("files left %v %v", ents, err)
	}
	// Idempotent: nothing left, no jobs directory at all.
	os.Remove(jd)
	e.f.resetLog()
	if err := e.a.KillJobs(context.Background(), ""); err != nil || len(e.f.mutations()) != 0 {
		t.Fatalf("second call: %v %q", err, e.f.mutations())
	}
	// A container that will not go is an error.
	e.leftover("job-"+testRef+"-push", testRef, "7", "push")
	e.f.failVerb["rm"] = errors.New("docker: device or resource busy")
	if err := e.a.KillJobs(context.Background(), ""); err == nil {
		t.Fatal("a container that stays is not an error")
	}
	// A removal that reports success while the container is still listed, too.
	delete(e.f.failVerb, "rm")
	e.f.onRun = func(args []string, _ []byte) (string, error, bool) { return "", nil, args[0] == "rm" }
	if err := e.a.KillJobs(context.Background(), testRef); err == nil {
		t.Fatal("a container still there after its removal is not an error")
	}
	e.f.onRun = nil
	if err := e.a.KillJobs(context.Background(), "../x"); err == nil {
		t.Fatal("a bad subject accepted")
	}
}

func TestSetReplicatorQuota(t *testing.T) {
	e := newJobEnv(t)
	var got []string
	t.Cleanup(swap(&repoSetQuota, func(mount string, id, mb int) error {
		got = append(got, fmt.Sprintf("%s %d %d", mount, id, mb))
		if mb == 3 {
			return errors.New("quota tool failed")
		}
		return nil
	}))
	if err := e.a.SetReplicatorQuota(context.Background(), 16384); err != nil {
		t.Fatal(err)
	}
	if err := e.a.SetReplicatorQuota(context.Background(), 3); err == nil {
		t.Fatal("error lost")
	}
	if want := []string{e.a.p.RepoRoot() + " 65530 16384", e.a.p.RepoRoot() + " 65530 3"}; !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
}

func TestEnsureBackupNetwork_RefusesOtherOptions(t *testing.T) {
	e := newJobEnv(t)
	ctx := context.Background()
	if err := e.a.EnsureBackupNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"network", "create", "--driver", "bridge", "--subnet", e.a.cfg.BackupSubnet, "--ipv6=false",
		"-o", "com.docker.network.bridge.name=spb0", "--", "backup"}
	if c := e.f.argv("network", "create"); len(c) != 1 || !slices.Equal(c[0], want) {
		t.Fatalf("create %q", c)
	}
	e.f.resetLog()
	if err := e.a.EnsureBackupNetwork(ctx); err != nil || len(e.f.mutations()) != 0 {
		t.Fatalf("existing: %v %q", err, e.f.mutations())
	}
	n := e.f.nets["backup"]
	saved := *n
	saved.Options = map[string]string{"com.docker.network.bridge.name": "spb0"}
	for name, change := range map[string]func(){
		"internal":     func() { n.Internal = true },
		"bridge name":  func() { n.BridgeName = "br-1" },
		"subnet":       func() { n.Subnet = "10.212.10.0/24" },
		"extra option": func() { n.Options["com.docker.network.bridge.enable_icc"] = "false" },
		"gateway mode": func() { n.Options["com.docker.network.bridge.gateway_mode_ipv4"] = "routed" },
		"ipv6":         func() { n.IPv6 = true },
	} {
		change()
		e.f.resetLog()
		if err := e.a.EnsureBackupNetwork(ctx); !errors.Is(err, ErrContainment) || len(e.f.mutations()) != 0 {
			t.Errorf("%s: %v %q", name, err, e.f.mutations())
		}
		*n = saved
		n.Options = map[string]string{"com.docker.network.bridge.name": "spb0"}
	}
	e.f.failInspect["backup"] = errors.New("docker: down")
	if err := e.a.EnsureBackupNetwork(ctx); err == nil {
		t.Fatal("inspect error lost")
	}
}

// jobControl: the unchanged spec runs; then the log, the writes and the
// job files are cleared for the refusal that follows.
func jobControl(t *testing.T, e *jobEnv, j JobSpec) {
	t.Helper()
	if _, err := e.a.RunJob(context.Background(), j); err != nil || len(e.runs()) != 1 {
		t.Fatalf("control: %v", err)
	}
	e.f.resetLog()
	e.f.mu.Lock()
	e.f.writes = map[string]fakeWrite{}
	e.f.mu.Unlock()
	os.RemoveAll(e.a.p.JobsDir())
}

// Every job program gets the Go runtime's soft limit 32 MiB under its
// container's memory limit; a replication job's follows its MemMB.
func TestRunJob_GoMemLimitFollowsTheMemoryLimit(t *testing.T) {
	for kind, want := range map[string]string{"push": "480MiB", "seed": "96MiB", "fetch": "224MiB", "replicate": "224MiB"} {
		e := newJobEnv(t)
		if _, err := e.a.RunJob(context.Background(), e.spec(t, kind, testRef, 9)); err != nil {
			t.Fatal(err)
		}
		if got := flagValues(e.runs()[0], "-e"); !slices.Equal(got, []string{"GOMEMLIMIT=" + want}) {
			t.Errorf("%s: %q, want GOMEMLIMIT=%s", kind, got, want)
		}
	}
	e := newJobEnv(t)
	j := e.spec(t, "replicate", testRef, 9)
	j.MemMB = 1000
	if _, err := e.a.RunJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	if r := e.runs()[0]; flagValue(r, "--memory") != "1000m" || flagValue(r, "-e") != "GOMEMLIMIT=968MiB" {
		t.Fatalf("%q", r)
	}
	// TMPDIR is never in a job's environment.
	if env := e.m.envAtRun["job-"+testRef+"-replicate"]; strings.Contains(env, "TMPDIR") || strings.Contains(env, "GOMEMLIMIT") {
		t.Fatalf("environment file %q", env)
	}
}

// A removal that fails after a normal exit keeps the result; the container
// it left is removed before the subject's next job, which then starts.
func TestRunJob_AFailedRemovalKeepsTheResult_TheLeftoverGoesBeforeTheNextJob(t *testing.T) {
	e := newJobEnv(t)
	name := "job-" + testRef + "-backup"
	e.m.script(name).stdout = `{"ok":true}` + "\n"
	fail := true
	e.f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if args[0] == "rm" && fail {
			fail = false
			return "", errors.New("docker: device or resource busy"), true
		}
		return "", nil, false
	}
	res, err := e.a.RunJob(context.Background(), e.spec(t, "backup", testRef, 9))
	if err != nil || string(res.Result) != `{"ok":true}` {
		t.Fatalf("%q %v", res.Result, err)
	}
	if e.gone(name) {
		t.Fatal("control: the failed removal left no container")
	}
	if ents, _ := os.ReadDir(e.a.p.JobsDir()); len(ents) != 0 {
		t.Fatalf("job files left: %v", ents)
	}
	e.f.resetLog()
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "push", testRef, 10)); err != nil {
		t.Fatal(err)
	}
	m := e.f.mutations()
	if i, k := slices.Index(m, "docker rm -f -v -- "+name), slices.IndexFunc(m, func(s string) bool { return strings.HasPrefix(s, "docker run") }); i < 0 || k < i {
		t.Fatalf("the leftover was not removed before the next job: %q", m)
	}
	if !e.gone(name) {
		t.Fatal("the leftover stays")
	}
}

// A fetch job whose executable is refused makes no fetch/ directory.
func TestRunJob_FetchDirMadeOnlyAfterTheOtherSources(t *testing.T) {
	e := newJobEnv(t)
	os.Remove(e.exe)
	if _, err := e.a.RunJob(context.Background(), e.spec(t, "fetch", testRef, 9)); !errors.Is(err, ErrHostState) || len(e.fetch) != 0 {
		t.Fatalf("%v, ensureFetchDir %q", err, e.fetch)
	}
}

// Two first launches: the one whose create loses finds the other's network
// and checks it like any.
func TestEnsureBackupNetwork_ACreateThatLosesTheRace(t *testing.T) {
	e := newJobEnv(t)
	e.f.onRun = func(args []string, _ []byte) (string, error, bool) {
		if len(args) > 1 && args[0] == "network" && args[1] == "create" {
			e.f.mu.Lock()
			e.f.nets["backup"] = parseNetCreate(args) // the other launch's
			e.f.mu.Unlock()
			return "", errors.New("Error response from daemon: network with name backup already exists"), true
		}
		return "", nil, false
	}
	if err := e.a.EnsureBackupNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Without a network afterwards the create's error stands.
	delete(e.f.nets, "backup")
	e.f.onRun = func(args []string, _ []byte) (string, error, bool) {
		return "", errors.New("docker: no address pool"), args[0] == "network" && args[1] == "create"
	}
	if err := e.a.EnsureBackupNetwork(context.Background()); err == nil {
		t.Fatal("a failed create succeeded")
	}
}
