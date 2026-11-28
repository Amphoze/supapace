package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/poolcfg"
)

// pdbFake replaces the provisioning session over the platform database's
// socket: each call is recorded in the fake host's log; err, when set, is
// returned instead of success.
type pdbFake struct {
	verifiers []string
	err       func(n int) error // the n-th call (from 1)
}

// pdbNode is a test agent on a node with a pooler label: the fake Docker,
// the platform network, the seccomp profile and the provisioning seam.
func pdbNode(t *testing.T) (*Agent, *fakeHost, *pdbFake, poolcfg.Addrs) {
	t.Helper()
	a, f, s := newTestAgent(t)
	healthy(a, f, s)
	writeSeccomp(t, a)
	a.cfg.PoolerLabel = "db"
	ad, err := poolcfg.For(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	pf := &pdbFake{}
	// The initdb task: it leaves a database in the data directory and exits 0.
	f.onRun = func(args []string, _ []byte) (string, error, bool) {
		switch {
		case args[0] == "run" && flagValue(args, "--name") == pdbTask:
			f.record("initdb task")
			os.WriteFile(filepath.Join(pdbDirOf(a), "data", "PG_VERSION"), []byte("17\n"), 0o600)
		case args[0] == "inspect" && clLast(args) == pdbTask:
			return "exited 0\n", nil, true
		}
		return "", nil, false
	}
	t.Cleanup(swap(&dockerRunOutput, func(context.Context, ...string) (string, string, error) { return "", "", nil }))
	t.Cleanup(swap(&cpPoll, time.Millisecond))
	t.Cleanup(swap(&pdbProvision, func(ctx context.Context, sock, verifier string) error {
		f.record("provision " + sock)
		pf.verifiers = append(pf.verifiers, verifier)
		if pf.err != nil {
			return pf.err(len(pf.verifiers))
		}
		return nil
	}))
	return a, f, pf, ad
}

const pdbTask = "task-pdb-initdb"

func pdbDirOf(a *Agent) string { return filepath.Join(a.p.PlatformDir(), "pdb") }

func metaPasswordPath(a *Agent) string { return filepath.Join(a.p.PoolerSecrets(), "meta.password") }

// Without a pooler label nothing is created: no container, no directory, no
// secret, no session, no node-check row. A configuration poolcfg.For refuses
// creates nothing either and says why. Control: with the label the container
// is made.
func TestPlatformDB_WithoutLabelNothingIsCreated(t *testing.T) {
	nothing := func(t *testing.T, a *Agent, f *fakeHost) {
		t.Helper()
		if m := f.mutations(); len(m) != 0 {
			t.Errorf("docker changes: %q", m)
		}
		for _, p := range []string{pdbDirOf(a), a.p.PoolerSecrets()} {
			if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s exists (%v)", p, err)
			}
		}
		for _, c := range f.calls() {
			if strings.HasPrefix(c, "provision ") {
				t.Errorf("a session was opened: %q", c)
			}
		}
	}
	a, f, _, _ := pdbNode(t)
	a.cfg.PoolerLabel = ""
	f.resetLog()
	if err := a.EnsurePlatformDB(context.Background()); err != nil {
		t.Fatalf("no label: %v", err)
	}
	nothing(t, a, f)
	if r := a.CheckPlatformDB(context.Background()); len(r) != 0 {
		t.Errorf("no label: rows %+v, want none", r)
	}
	if _, ok := rows(t, a)[rowPlatformDB]; ok {
		t.Error("no label: the node check has the row platform-db")
	}

	// Refused by poolcfg.For: the project uid range holds the platform
	// database's uid.
	a.cfg.PoolerLabel = "db"
	a.cfg.UIDBase, a.cfg.UIDCount = 65000, 700000
	if _, err := poolcfg.For(a.cfg); err == nil {
		t.Fatal("fixture: poolcfg.For accepts")
	}
	err := a.EnsurePlatformDB(context.Background())
	if err == nil || !strings.Contains(err.Error(), "65525") {
		t.Fatalf("refused configuration: %v, want the refusal", err)
	}
	nothing(t, a, f)
	if r := a.CheckPlatformDB(context.Background()); len(r) != 1 || r[0].Name != rowPlatformDB || r[0].OK || Blocking(r[0]) {
		t.Fatalf("refused configuration: rows %+v, want one failing, not blocking platform-db", r)
	}

	// Control.
	def := nodecfg.Default("sp.test")
	a.cfg.UIDBase, a.cfg.UIDCount = def.UIDBase, def.UIDCount
	if err := a.EnsurePlatformDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := f.ctrs[poolcfg.PlatformDBName]; c == nil || !c.Running {
		t.Fatalf("control: no running %s", poolcfg.PlatformDBName)
	}
}

// The two access files are exactly the stated lines, root 0444, and the
// server is told to read them; a changed file on disk is another
// configuration (the row says so) and the next ensure writes it back and
// makes the container again.
func TestPlatformDB_AccessFileExact(t *testing.T) {
	a, f, _, ad := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(pdbDirOf(a), "etc")
	want := map[string]string{
		"pg_hba.conf":   "local all postgres peer map=agent\nhost supavisor supavisor_meta " + ad.Pooler.String() + "/32 scram-sha-256\n",
		"pg_ident.conf": "agent root postgres\n",
	}
	for name, content := range want {
		p := filepath.Join(etc, name)
		w, ok := f.writes[p]
		if !ok || string(w.Data) != content || w.Mode != 0o444 || w.UID != os.Geteuid() {
			t.Errorf("%s: written %+v (%q), want %q root 0444", name, w, w.Data, content)
		}
		if b, _ := os.ReadFile(p); string(b) != content {
			t.Errorf("%s on disk: %q", name, b)
		}
	}
	argv := f.argv("run", "-d", "--name", poolcfg.PlatformDBName)
	if len(argv) != 1 {
		t.Fatalf("runs: %q", argv)
	}
	for _, kv := range []string{"hba_file=/etc/sp/pg_hba.conf", "ident_file=/etc/sp/pg_ident.conf"} {
		if !hasPair(argv[0], "-c", kv) {
			t.Errorf("command lacks -c %s: %q", kv, argv[0])
		}
	}
	if !hasPair(argv[0], "-v", etc+":/etc/sp:ro") {
		t.Errorf("the access files are not mounted read-only: %q", argv[0])
	}
	if r := a.CheckPlatformDB(ctx); len(r) != 1 || !r[0].OK {
		t.Fatalf("control: row %+v after the ensure", r)
	}

	// A line added on disk.
	hba := filepath.Join(etc, "pg_hba.conf")
	os.Chmod(hba, 0o644)
	if err := os.WriteFile(hba, []byte(want["pg_hba.conf"]+"host all all 0.0.0.0/0 trust\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if r := a.CheckPlatformDB(ctx); len(r) != 1 || r[0].OK || !strings.Contains(r[0].Detail, "another configuration") {
		t.Fatalf("changed access file: row %+v, want another configuration", r)
	}
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(hba); string(b) != want["pg_hba.conf"] {
		t.Errorf("not written back: %q", b)
	}
	if m := f.mutations(); !slices.ContainsFunc(m, func(c string) bool { return strings.HasPrefix(c, "docker rm ") }) ||
		!slices.ContainsFunc(m, func(c string) bool { return strings.HasPrefix(c, "docker run ") }) {
		t.Errorf("not made again: %q", m)
	}
	if r := a.CheckPlatformDB(ctx); len(r) != 1 || !r[0].OK {
		t.Fatalf("after the repair: row %+v", r)
	}
}

func hasPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

// The container's arguments: its uid, one network at one address, the
// control-plane database's hardening, its limits and restart policy, its
// role label, the server settings; no secret anywhere in them.
func TestPlatformDB_CreateArguments(t *testing.T) {
	a, f, _, ad := pdbNode(t)
	if err := a.EnsurePlatformDB(context.Background()); err != nil {
		t.Fatal(err)
	}
	argv := f.argv("run", "-d", "--name", poolcfg.PlatformDBName)
	if len(argv) != 1 {
		t.Fatalf("runs: %q", argv)
	}
	got := argv[0]
	pd := pdbDirOf(a)
	opts := got[:slices.Index(got, "--")]
	cmd := got[slices.Index(got, "--")+1:]
	wantOpts := []string{"run", "-d", "--name", "sp-platform-db", "--network", "platform", "--ip", ad.PlatformDB.String(),
		"--user", "65525:65525", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "seccomp=" + a.seccompFile(),
		"--read-only", "--tmpfs", "/tmp", "--memory", "256m", "--pids-limit", "128", "--ulimit", "core=0",
		"--restart", "unless-stopped", "--label", "supapace.role=platform-db",
		"-v", pd + "/data:/var/lib/postgresql/data", "-v", pd + "/sock:/var/run/postgresql", "-v", pd + "/etc:/etc/sp:ro"}
	label := opts[len(opts)-1]
	if !strings.HasPrefix(label, "supapace.config=") || !slices.Equal(opts[:len(opts)-2], wantOpts) || opts[len(opts)-2] != "--label" {
		t.Errorf("options:\n got %q\nwant %q + the configuration label", opts, wantOpts)
	}
	wantCmd := []string{a.cfg.Images.ControlPlane, "postgres", "-c", "listen_addresses=" + ad.PlatformDB.String(),
		"-c", "max_connections=40", "-c", "password_encryption=scram-sha-256",
		"-c", "hba_file=/etc/sp/pg_hba.conf", "-c", "ident_file=/etc/sp/pg_ident.conf"}
	if !slices.Equal(cmd, wantCmd) {
		t.Errorf("command:\n got %q\nwant %q", cmd, wantCmd)
	}
	pw, err := os.ReadFile(metaPasswordPath(a))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls() {
		if strings.Contains(c, string(pw)) {
			t.Errorf("the password is in a call: %q", c)
		}
	}
	for _, d := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{{pd, 0o700, -1, -1}, {pd + "/data", 0o700, 65525, 65525}, {pd + "/sock", 0o700, 65525, 65525}, {pd + "/etc", 0o755, -1, -1}} {
		fi, err := os.Lstat(d.path)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != d.mode {
			t.Errorf("%s: %v %v, want a directory %o", d.path, fi, err, d.mode)
		}
		owned := slices.Contains(f.calls(), fmt.Sprintf("chown %s %d:%d", d.path, d.uid, d.gid))
		if d.uid >= 0 != owned {
			t.Errorf("%s: chown to %d:%d recorded %v", d.path, d.uid, d.gid, owned)
		}
	}
}

// meta.password is made once (root 0600, 64 hex characters, in a root 0700
// directory) and never replaced; the role is given a SCRAM verifier of it,
// never the password. A file that is not root 0600 or not of that form is
// refused before any container is made.
func TestPlatformDB_SecretMadeOnceAndChecked(t *testing.T) {
	a, f, pf, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	p := metaPasswordPath(a)
	pw, err := os.ReadFile(p)
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).Match(pw) {
		t.Fatalf("meta.password %q: %v", pw, err)
	}
	if fi, _ := os.Lstat(p); fi.Mode() != 0o600 {
		t.Errorf("meta.password mode %v", fi.Mode())
	}
	if fi, _ := os.Lstat(a.p.PoolerSecrets()); fi.Mode().Perm() != 0o700 || !fi.IsDir() {
		t.Errorf("secrets directory mode %v", fi.Mode())
	}
	if len(pf.verifiers) != 1 {
		t.Fatalf("sessions: %d", len(pf.verifiers))
	}
	if !verifies(t, pf.verifiers[0], string(pw)) {
		t.Errorf("verifier %q is not of meta.password", pf.verifiers[0])
	}
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(p); !bytes.Equal(again, pw) {
		t.Error("meta.password replaced")
	}
	if len(pf.verifiers) != 2 || !verifies(t, pf.verifiers[1], string(pw)) {
		t.Errorf("second ensure: verifiers %q", pf.verifiers)
	}

	for what, bad := range map[string]func(){
		"mode 0644": func() { os.Chmod(p, 0o644) },
		"short":     func() { os.WriteFile(p, pw[:32], 0o600) },
		"not hex":   func() { os.WriteFile(p, bytes.ToUpper(pw), 0o600) },
		"a newline": func() { os.WriteFile(p, append(slices.Clone(pw), '\n'), 0o600) },
		"a link":    func() { os.Remove(p); os.Symlink(filepath.Join(t.TempDir(), "x"), p) },
		"directory": func() { os.Remove(p); os.Mkdir(p, 0o700) },
	} {
		t.Run(what, func(t *testing.T) {
			delete(f.ctrs, poolcfg.PlatformDBName)
			bad()
			f.resetLog()
			err := a.EnsurePlatformDB(ctx)
			if err == nil || strings.Contains(err.Error(), string(pw)) {
				t.Fatalf("got %v, want a refusal without the password", err)
			}
			if m := f.mutations(); len(m) != 0 {
				t.Errorf("docker changes: %q", m)
			}
			os.RemoveAll(p)
			os.Chmod(a.p.PoolerSecrets(), 0o700)
			os.WriteFile(p, pw, 0o600)
			os.Chmod(p, 0o600)
		})
	}
}

// verifies reports whether v is the SCRAM-SHA-256 verifier of password with
// v's own salt.
func verifies(t *testing.T, v, password string) bool {
	t.Helper()
	m := regexp.MustCompile(`^SCRAM-SHA-256\$4096:([A-Za-z0-9+/=]+)\$`).FindStringSubmatch(v)
	if m == nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		return false
	}
	want, err := pgsock.ScramVerifier(password, salt)
	return err == nil && want == v
}

// A container of this daemon's configuration is adopted (started when
// stopped, nothing made again); one of another configuration, at another
// address or on a second network is made again.
func TestPlatformDB_AdoptsOrMakesAgain(t *testing.T) {
	a, f, _, ad := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	c := f.ctrs[poolcfg.PlatformDBName]
	if got := c.Nets; len(got) != 1 || got["platform"] != ad.PlatformDB.String() {
		t.Fatalf("networks %v", got)
	}
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Errorf("adopted: changes %q", m)
	}
	c.Running = false
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if m := f.mutations(); !slices.Equal(m, []string{"docker start -- sp-platform-db"}) {
		t.Errorf("stopped: changes %q", m)
	}
	for what, change := range map[string]func(c *fakeCtr){
		"configuration":  func(c *fakeCtr) { c.Labels[labelConfig] = "other" },
		"address":        func(c *fakeCtr) { c.Nets["platform"] = "10.212.6.20" },
		"second network": func(c *fakeCtr) { c.Nets["ingress"] = "10.212.4.9" },
	} {
		change(f.ctrs[poolcfg.PlatformDBName])
		f.resetLog()
		if err := a.EnsurePlatformDB(ctx); err != nil {
			t.Fatal(err)
		}
		m := f.mutations()
		if len(m) != 3 || m[0] != "docker stop -t 30 -- sp-platform-db" || m[1] != "docker rm -- sp-platform-db" || !strings.HasPrefix(m[2], "docker run ") {
			t.Errorf("%s: changes %q, want stop, rm, run", what, m)
		}
	}
}

// The ensure waits for the server to answer: a session that cannot connect
// is tried again; a container that stops meanwhile, or another error of the
// session, ends the ensure with an error.
func TestPlatformDB_WaitsForTheServer(t *testing.T) {
	a, f, pf, _ := pdbNode(t)
	ctx := context.Background()
	pf.err = func(n int) error {
		if n < 3 {
			return fmt.Errorf("%w: dial", errPDBNotUp)
		}
		return nil
	}
	if err := a.EnsurePlatformDB(ctx); err != nil || len(pf.verifiers) != 3 {
		t.Fatalf("not up twice: %v after %d sessions", err, len(pf.verifiers))
	}
	pf.verifiers = nil
	pf.err = func(n int) error {
		f.ctrs[poolcfg.PlatformDBName].Running = false
		return errPDBNotUp
	}
	if err := a.EnsurePlatformDB(ctx); err == nil || !strings.Contains(err.Error(), "stopped") || len(pf.verifiers) != 1 {
		t.Fatalf("stopped: %v after %d sessions", err, len(pf.verifiers))
	}
	boom := errors.New("permission denied for database supavisor")
	pf.err = func(int) error { return boom }
	if err := a.EnsurePlatformDB(ctx); !errors.Is(err, boom) {
		t.Fatalf("session error: %v", err)
	}
}

// platform-members accepts sp-platform-db at its address with its role
// label on a node with a pooler label only; on any other node, at another
// address or without the label it is a stranger.
func TestPlatformMembers_PlatformDBOnlyWithALabel(t *testing.T) {
	a, f := goodNode(t)
	ad := poolcfg.Static(a.cfg)
	c := f.ctr(fakeCtr{Name: poolcfg.PlatformDBName, Running: true, Restart: "unless-stopped", CapDrop: []string{"ALL"},
		Labels: map[string]string{labelRole: pdbRole}, Nets: map[string]string{"platform": ad.PlatformDB.String()}})
	fails := func(what string) {
		t.Helper()
		r := rows(t, a)["platform-members"]
		if r.OK || !Blocking(r) || !strings.Contains(r.Detail, poolcfg.PlatformDBName) {
			t.Errorf("%s: row %+v, want a blocking failure naming %s", what, r, poolcfg.PlatformDBName)
		}
	}
	fails("no pooler label")
	a.cfg.PoolerLabel = "db"
	if r := rows(t, a)["platform-members"]; !r.OK {
		t.Fatalf("with a label: %+v", r)
	}
	c.Labels[labelRole] = "postgrest"
	fails("another role label")
	delete(c.Labels, labelRole)
	fails("no role label")
	c.Labels[labelRole] = pdbRole
	c.Nets["platform"] = ad.Pooler.String()
	fails("at the pooler's address")
	c.Nets["platform"] = ad.PlatformDB.String()
	a.cfg.UIDBase, a.cfg.UIDCount = 65000, 700000
	fails("a configuration poolcfg.For refuses")
}

// Only sp-platform-db may hold the platform database's address on
// platform, on every node: another holder, running or created, refuses the
// start; the owner there passes.
func TestGate_ForeignHolderOfThePlatformDBAddressRefuses(t *testing.T) {
	for _, label := range []string{"", "db"} {
		a, f, s := newTestAgent(t)
		a.cfg.PoolerLabel = label
		healthy(a, f, s)
		tenants(a, f, s)
		addr := poolcfg.Static(a.cfg).PlatformDB.String()
		ctx := context.Background()
		f.ctr(fakeCtr{Name: "squatter", Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": addr}})
		err := a.CheckAdopted(ctx, s)
		wantContainment(t, err, "another name at "+addr)
		if errors.Is(err, ErrCheckIncomplete) || !strings.Contains(err.Error(), "squatter holds "+addr) ||
			!strings.Contains(err.Error(), poolcfg.PlatformDBName) {
			t.Errorf("label %q: got %v, want a finding naming the holder, the address and %s", label, err, poolcfg.PlatformDBName)
		}
		delete(f.ctrs, "squatter")
		// Created, not started: its configured address counts.
		f.ctr(fakeCtr{Name: "pg-" + s.Ref, Running: false, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": addr}})
		wantContainment(t, a.CheckAdopted(ctx, s), "a created tenant container configured at "+addr)
		tenants(a, f, s)
		f.ctr(fakeCtr{Name: poolcfg.PlatformDBName, Running: true, CapDrop: []string{"ALL"}, Nets: map[string]string{"platform": addr}})
		if err := a.CheckAdopted(ctx, s); err != nil {
			t.Errorf("label %q: %s at %s refused: %v", label, poolcfg.PlatformDBName, addr, err)
		}
	}
}

// An empty data directory is initialised once, by a task container at the
// platform database's uid with no network and the data directory alone
// mounted, before the server's container is made; a stamped data directory
// whose database is gone is emptied and initialised again, the container
// that ran on it removed first. A failed initialisation makes no container
// and no stamp (an interrupted one: TestPlatformDB_StampIsWrittenLast).
func TestPlatformDB_InitialisesOnceByTask(t *testing.T) {
	a, f, _, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(pdbDirOf(a), "data")
	tasks := f.argv("run", "-d", "--name", pdbTask)
	if len(tasks) != 1 {
		t.Fatalf("initdb tasks: %q", tasks)
	}
	task := tasks[0]
	if flagValue(task, "--user") != "65525:65525" || flagValue(task, "--network") != "none" || flagValue(task, "--entrypoint") != "sh" ||
		!slices.Equal(flagValues(task, "-v"), []string{data + ":/var/lib/postgresql/data"}) ||
		!slices.Equal(positional(task), []string{a.cfg.Images.ControlPlane, "-c", pdbInitScript}) {
		t.Errorf("initdb task: %q", task)
	}
	calls := f.calls()
	if i, j := slices.Index(calls, "initdb task"), slices.IndexFunc(calls, func(c string) bool {
		return strings.HasPrefix(c, "docker run -d --name "+poolcfg.PlatformDBName)
	}); i < 0 || j < i {
		t.Errorf("the server's container before the initialisation: %q", calls)
	}
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.calls(), "initdb task") {
		t.Error("initialised again over a database")
	}

	// The database gone under a stamp, the container running on it.
	os.Remove(filepath.Join(data, "PG_VERSION"))
	os.WriteFile(filepath.Join(data, "leftover"), nil, 0o600)
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	m := f.mutations()
	if len(m) < 3 || m[0] != "docker stop -t 30 -- sp-platform-db" || m[1] != "docker rm -- sp-platform-db" {
		t.Errorf("container not removed first: %q", m)
	}
	if _, err := os.Lstat(filepath.Join(data, "leftover")); !errors.Is(err, os.ErrNotExist) || !slices.Contains(f.calls(), "initdb task") {
		t.Errorf("not emptied and initialised again: %v", err)
	}

	// A failing initialisation.
	delete(f.ctrs, poolcfg.PlatformDBName)
	os.Remove(filepath.Join(data, "PG_VERSION"))
	run := f.onRun
	f.onRun = func(args []string, in []byte) (string, error, bool) {
		if args[0] == "inspect" && clLast(args) == pdbTask {
			return "exited 1\n", nil, true
		}
		if args[0] == "run" && flagValue(args, "--name") == pdbTask {
			return "", nil, false
		}
		return run(args, in)
	}
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err == nil || !strings.Contains(err.Error(), "initdb task failed") {
		t.Fatalf("failing initdb: %v", err)
	}
	if _, ok := f.ctrs[poolcfg.PlatformDBName]; ok {
		t.Error("a container was made after a failed initialisation")
	}
	if _, err := os.Lstat(filepath.Join(pdbDirOf(a), "initialised")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a stamp after a failed initialisation: %v", err)
	}
}

// The provisioning session refuses a verifier that is not one before it
// connects: it is placed in a statement's literal.
func TestPlatformDB_ProvisionRefusesAMalformedVerifier(t *testing.T) {
	sock := t.TempDir() // nothing listens here
	for _, v := range []string{"", "secret", "SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5'x"} {
		if err := provisionPlatformDB(context.Background(), sock, v); err == nil || errors.Is(err, errPDBNotUp) || !strings.Contains(err.Error(), "malformed verifier") {
			t.Errorf("%q: %v, want malformed verifier before any connection", v, err)
		}
	}
	// Control: a well-formed one goes on to the connection, which fails here.
	if err := provisionPlatformDB(context.Background(), sock, "SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5"); !errors.Is(err, errPDBNotUp) {
		t.Errorf("well-formed: %v, want the connection's failure", err)
	}
}

// "Initialised" is the root-owned stamp, written only after the task
// succeeded: a version file without it (initdb writes PG_VERSION first, so an
// interrupted task leaves one) is not a database — the left-over task is
// removed by its name, then the directory emptied and initialised again; a
// stamp with the version file is a database and nothing is initialised.
func TestPlatformDB_StampIsWrittenLast(t *testing.T) {
	a, f, _, _ := pdbNode(t)
	ctx := context.Background()
	pd := pdbDirOf(a)
	data, stamp := filepath.Join(pd, "data"), filepath.Join(pd, "initialised")
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if w, ok := f.writes[stamp]; !ok || w.Mode != 0o444 || w.UID != os.Geteuid() || len(w.Data) != 0 {
		t.Fatalf("stamp written %+v (%v), want an empty root 0444 file", w, ok)
	}
	calls := f.calls()
	if i, j := slices.Index(calls, "initdb task"), slices.Index(calls, fmt.Sprintf("write %s 444 %d:%d", stamp, os.Geteuid(), os.Getegid())); i < 0 || j < i {
		t.Fatalf("the stamp before the task: %q", calls)
	}

	// Stamp present, version file present: a database.
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.calls(), "initdb task") || slices.Contains(f.calls(), "docker rm -f -v -- "+pdbTask) {
		t.Errorf("stamped database touched: %q", f.calls())
	}

	// An interrupted initialisation: the version file and a partial tree, no
	// stamp, the task container still there and the server's container
	// running on the directory.
	os.Remove(stamp)
	os.WriteFile(filepath.Join(data, "partial"), nil, 0o600)
	f.ctr(fakeCtr{Name: pdbTask, Running: true})
	emptiedFirst, seen := false, false
	run := f.onRun
	f.onRun = func(args []string, in []byte) (string, error, bool) {
		if slices.Equal(args, []string{"rm", "-f", "-v", "--", pdbTask}) && !seen { // the first removal of the task
			_, err := os.Lstat(filepath.Join(data, "partial"))
			emptiedFirst, seen = err != nil, true
		}
		return run(args, in)
	}
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	m := f.mutations()
	if len(m) < 4 || m[0] != "docker stop -t 30 -- sp-platform-db" || m[1] != "docker rm -- sp-platform-db" || m[2] != "docker rm -f -v -- "+pdbTask {
		t.Errorf("changes %q, want the server's container, then the left-over task removed", m)
	}
	if emptiedFirst {
		t.Error("the directory was emptied before the left-over task was removed")
	}
	if _, err := os.Lstat(filepath.Join(data, "partial")); !errors.Is(err, os.ErrNotExist) || !slices.Contains(f.calls(), "initdb task") {
		t.Errorf("not emptied and initialised again: %v", err)
	}
	if _, err := os.Lstat(stamp); err != nil {
		t.Errorf("no stamp after the repair: %v", err)
	}
}

// The wait's two bounds: a container this call made or started gets the long
// one; one found running gets the short one, so a crash loop does not hold
// the caller.
func TestPlatformDB_ShortBoundForARunningContainer(t *testing.T) {
	a, f, pf, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(swap(&pdbShortWait, 30*time.Millisecond))
	t.Cleanup(swap(&pdbAnswerWait, 300*time.Millisecond))
	pf.err = func(int) error { return errPDBNotUp } // never answers
	for what, arrange := range map[string]func(){
		"found running": func() {},
		"started":       func() { f.ctrs[poolcfg.PlatformDBName].Running = false },
		"made":          func() { delete(f.ctrs, poolcfg.PlatformDBName) },
	} {
		arrange()
		want := "within 300ms"
		if what == "found running" {
			want = "within 30ms"
		}
		if err := a.EnsurePlatformDB(ctx); err == nil || !strings.Contains(err.Error(), "did not answer "+want) {
			t.Errorf("%s: %v, want %q", what, err, want)
		}
	}
}

// The row in a restart loop names it and the last log line.
func TestNodeCheck_PlatformDBRowInARestartLoop(t *testing.T) {
	a, f, _, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if r := a.CheckPlatformDB(ctx); len(r) != 1 || !r[0].OK {
		t.Fatalf("control: %+v", r)
	}
	run := f.onRun
	f.onRun = func(args []string, in []byte) (string, error, bool) {
		if flagValue(args, "--format") == restartFormat && clLast(args) == poolcfg.PlatformDBName {
			return fmt.Sprintf("%s true 7 %s\n", f.ctrs[poolcfg.PlatformDBName].ID, time.Now().UTC().Format(time.RFC3339Nano)), nil, true
		}
		return run(args, in)
	}
	t.Cleanup(swap(&dockerRunOutput, func(context.Context, ...string) (string, string, error) {
		return "", "FATAL: could not open file\n", nil
	}))
	r := a.CheckPlatformDB(ctx)
	if len(r) != 1 || r[0].OK || Blocking(r[0]) || !strings.Contains(r[0].Detail, "sp-platform-db is restarting; its last log line: \"FATAL: could not open file\"") {
		t.Fatalf("row %+v, want the restart rule's text, not blocking", r)
	}
}

// A maker that dies between writing and placing the secret leaves no file at
// its name: the next call makes it; many makers at once all return the one
// secret, none an error.
func TestPlatformDB_SecretPlacedWhole(t *testing.T) {
	a, _, _, _ := pdbNode(t)
	boom := errors.New("killed")
	restore := swap(&linkSecret, func(string, string) error { return boom })
	if _, err := a.metaPassword(); !errors.Is(err, boom) {
		t.Fatalf("interrupted: %v", err)
	}
	restore()
	if _, err := os.Lstat(metaPasswordPath(a)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a file at the secret's name after an interrupted make: %v", err)
	}
	ents, _ := os.ReadDir(a.p.PoolerSecrets())
	if len(ents) != 0 {
		t.Errorf("left in the directory: %v", ents)
	}
	pw, err := a.metaPassword()
	if err != nil || !metaPasswordRE.MatchString(pw) {
		t.Fatalf("next call: %q %v", pw, err)
	}

	os.Remove(metaPasswordPath(a))
	const n = 16
	got, errs := make([]string, n), make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = a.metaPassword()
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || got[i] != got[0] {
			t.Errorf("maker %d: %v, a value of its own %v", i, errs[i], got[i] != got[0])
		}
	}
}
