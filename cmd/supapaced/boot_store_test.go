package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

// The tests that need the real store share one throw-away control-plane
// database container (labelled supapace.test=1, no network, unix socket),
// started on first use and removed by TestMain or, if the process dies, by
// a detached watchdog. Without Docker they are skipped.
var cpdb struct {
	once      sync.Once
	name, dir string // container, Paths root
	err       error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if cpdb.name != "" {
		exec.Command("docker", "rm", "-f", "-v", cpdb.name).Run()
	}
	if cpdb.dir != "" {
		os.RemoveAll(cpdb.dir)
	}
	os.Exit(code)
}

func startCPDB() (name, root string, err error) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		return "", "", fmt.Errorf("docker unavailable: %v", err)
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		return "", "", err
	}
	root, err = os.MkdirTemp("", "serve-db-")
	if err != nil {
		return "", "", err
	}
	sock := filepath.Join(nodecfg.Paths{Root: root}.CPDir(), "sock")
	if err := os.MkdirAll(sock, 0o700); err != nil {
		return "", root, err
	}
	if err := os.Chmod(sock, 0o777); err != nil { // the server (uid 70) creates its socket here
		return "", root, err
	}
	b := make([]byte, 6)
	rand.Read(b)
	name = "sp-test-serve-" + hex.EncodeToString(b)
	w := exec.Command("sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 1; done
		docker rm -f -v "$2" >/dev/null 2>&1; sleep 5; docker rm -f -v "$2" >/dev/null 2>&1; rm -rf "$3"`,
		"sh", strconv.Itoa(os.Getpid()), name, root)
	w.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := w.Start(); err != nil {
		return "", root, err
	}
	w.Process.Release()
	pw := make([]byte, 16)
	rand.Read(pw)
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--label", "supapace.test=1",
		"--network", "none", "--user", "70:70", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp", "--tmpfs", "/var/lib/postgresql/data:uid=70,gid=70,mode=0700",
		"-v", sock+":/var/run/postgresql",
		"-e", "POSTGRES_USER=supapaced", "-e", "POSTGRES_DB=supapaced", "-e", "POSTGRES_PASSWORD="+hex.EncodeToString(pw),
		"--entrypoint", "timeout", im.ControlPlane, "-s", "INT", "14400",
		"docker-entrypoint.sh", "postgres", "-c", "listen_addresses=", "-c", "fsync=off").CombinedOutput()
	if err != nil {
		return name, root, fmt.Errorf("docker run: %v: %s", err, bytes.TrimSpace(out))
	}
	for end := time.Now().Add(90 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if bytes.Contains(logs, []byte("PostgreSQL init process complete")) {
			if c, err := dbConn(root); err == nil {
				c.Close(context.Background())
				return name, root, nil
			}
		}
	}
	return name, root, fmt.Errorf("control-plane test database not ready")
}

func dbConn(root string) (*pgx.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return pgx.Connect(ctx, "host="+filepath.Join(nodecfg.Paths{Root: root}.CPDir(), "sock")+" user=supapaced dbname=supapaced")
}

// realStore returns Paths whose control-plane socket is the test database,
// emptied (no schema), and a store migrated on it unless empty is set.
func realStore(t *testing.T, empty bool) (nodecfg.Paths, nodecfg.Config, *store.Store) {
	t.Helper()
	cpdb.once.Do(func() { cpdb.name, cpdb.dir, cpdb.err = startCPDB() })
	if cpdb.err != nil {
		t.Skip(cpdb.err)
	}
	c, err := dbConn(cpdb.dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Exec(context.Background(), "drop schema public cascade; create schema public")
	c.Close(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := nodecfg.Paths{Root: cpdb.dir}
	cfg := nodecfg.Default("sp.test")
	cfg.MemAllocMB, cfg.PidsAlloc, cfg.Uplinks = 1<<20, 1<<20, nil
	if empty {
		return p, cfg, nil
	}
	st, err := openStore(context.Background(), p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return p, cfg, st
}

func TestBoot_FirstRunCreatesNodeRowAndEpoch(t *testing.T) {
	p, cfg, _ := realStore(t, true)
	for run := 1; run <= 2; run++ { // a second start changes nothing
		st, err := openStore(context.Background(), p, cfg)
		if err != nil {
			t.Fatalf("start %d: %v", run, err)
		}
		e, err := st.Epoch(context.Background())
		st.Close()
		if err != nil || e != 1 {
			t.Fatalf("start %d: epoch %d %v", run, e, err)
		}
		c, err := dbConn(cpdb.dir)
		if err != nil {
			t.Fatal(err)
		}
		var n, next int
		err = c.QueryRow(context.Background(), "select count(*), max(next_uid) from node where id = $1", cfg.NodeID).Scan(&n, &next)
		c.Close(context.Background())
		if err != nil || n != 1 || next != cfg.UIDBase {
			t.Fatalf("start %d: node rows %d next_uid %d %v", run, n, next, err)
		}
	}
}

// activeProject creates ref through the store's own path to `active`.
func activeProject(t *testing.T, st *store.Store, ref string) {
	t.Helper()
	ctx := context.Background()
	id, err := st.CreateProject(ctx, store.NewProject{Ref: ref, Name: "demo",
		Config: store.ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{}}, Params: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Place(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := st.StartOperation(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishCreate(ctx, id); err != nil {
		t.Fatal(err)
	}
	if p, err := st.GetProject(ctx, ref); err != nil || p.State != "active" {
		t.Fatalf("%s: %+v %v", ref, p, err)
	}
}

// storeWorld is a world on the real store.
func storeWorld(t *testing.T, refs ...string) (*world, *store.Store) {
	_, _, st := realStore(t, false)
	for _, r := range refs {
		activeProject(t, st, r)
	}
	w := newWorld(t)
	w.d.st, w.d.rn = st, &fakeRunner{c: w.c, st: st}
	if err := w.d.refill(context.Background()); err != nil {
		t.Fatal(err)
	}
	return w, st
}

// A delete of A has run D1–D2 and holds the ref lock when a round fires;
// after the delete finishes the loop reads `deleted` under the lock and
// makes no call for A.
func TestEnsureActive_SkipsProjectBeingDeleted(t *testing.T) {
	A, B := refN(1), refN(2)
	w, st := storeWorld(t, A, B)
	ctx := context.Background()
	del, err := st.SubmitOperation(ctx, A, "delete", nil, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := st.LockRef(ctx, A) // the worker
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.StartOperation(ctx, del))
	must(st.SetProjectState(ctx, A, "deleting")) // D1
	must(st.AdvanceStep(ctx, del, "D2"))

	w.d.ensureActive(ctx) // the recovery round, beside the delete
	if w.c.index("EnsureCluster:"+A) >= 0 || w.c.index("EnsurePostgREST:"+A) >= 0 || w.c.index("SetRoute:"+A) >= 0 {
		t.Fatalf("agent called for A while its delete held the lock: %q", w.c.all())
	}
	if w.ag.route(B) != "active" {
		t.Fatal("B not ensured")
	}
	_, err = st.MarkDeleted(ctx, A, time.Hour) // D5
	must(err)
	must(st.FinishOperation(ctx, del, "done", ""))
	unlock()

	w.d.ensureActive(ctx)
	for _, s := range w.c.all() {
		if strings.HasPrefix(s, "EnsurePostgREST:"+A) || strings.HasPrefix(s, "SetRoute:"+A) || strings.HasPrefix(s, "EnsureCluster:"+A) {
			t.Fatalf("deleted A ensured: %q", w.c.all())
		}
	}
	if w.d.isPending(A) {
		t.Fatal("deleted A left in the pending set")
	}
}

// A restart of A is at R3 and holds the lock with project.generation at g+1:
// the round leaves A alone; when the restart ends it re-reads A — active at
// g+1 → ensured at g+1 (adopting the container R3 started); restarting (the
// restart failed) → skipped.
func TestEnsureActive_WaitsForRunningRestart(t *testing.T) {
	for _, outcome := range []string{"done", "failed"} {
		t.Run(outcome, func(t *testing.T) {
			A := refN(1)
			w, st := storeWorld(t, A)
			ctx := context.Background()
			p, _ := st.GetProject(ctx, A)
			params := json.RawMessage(`{"base_generation":1,"prev":{},"next":{}}`)
			op, err := st.SubmitOperation(ctx, A, "restart", params, p.Generation, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			unlock, err := st.LockRef(ctx, A)
			if err != nil {
				t.Fatal(err)
			}
			cfg := p.Config
			cfg.GUC = map[string]string{"max_connections": "130"}
			for _, err := range []error{st.StartOperation(ctx, op), st.BeginRestart(ctx, A, 2, cfg), st.AdvanceStep(ctx, op, "R2")} {
				if err != nil {
					t.Fatal(err)
				}
			}
			w.d.ensureActive(ctx)
			if w.c.index("EnsureCluster:"+A) >= 0 {
				t.Fatalf("ensured beside the restart: %q", w.c.all())
			}
			if outcome == "done" {
				if err := st.SetProjectState(ctx, A, "active"); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.FinishOperation(ctx, op, outcome, ""); err != nil {
				t.Fatal(err)
			}
			unlock()
			w.d.ensureActive(ctx)
			got := w.c.index("EnsureCluster:" + A + ":2:")
			switch {
			case outcome == "done" && (got < 0 || w.c.index("EnsureCluster:"+A+":1:") >= 0 || w.ag.route(A) != "active"):
				t.Fatalf("finished restart: want one ensure at generation 2: %q", w.c.all())
			case outcome == "failed" && (w.c.index("EnsureCluster:"+A) >= 0 || w.d.isPending(A)):
				t.Fatalf("failed restart: project touched or kept pending: %q", w.c.all())
			}
		})
	}
}
