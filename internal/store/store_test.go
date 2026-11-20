package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// The tests run against a throw-away postgres:17-alpine container (the
// control-plane image, pinned by digest) with no network, reached through a
// unix-socket directory. They are skipped when Docker is unavailable.
var (
	sockDir  string
	noDocker string // reason the tests are skipped; "" when the container is up
)

func TestMain(m *testing.M) {
	code := func() int {
		name, dir, err := startDB()
		if name != "" {
			defer exec.Command("docker", "rm", "-f", "-v", name).Run()
		}
		if dir != "" {
			defer os.RemoveAll(dir)
		}
		if err != nil {
			noDocker = err.Error()
		}
		sockDir = dir
		return m.Run()
	}()
	os.Exit(code)
}

func startDB() (name, dir string, err error) {
	if err := exec.Command("docker", "version").Run(); err != nil {
		return "", "", fmt.Errorf("docker unavailable: %v", err)
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		return "", "", err
	}
	dir, err = os.MkdirTemp("", "sp-store-")
	if err != nil {
		return "", "", err
	}
	// The server runs as the image's postgres user (70) and must create its
	// socket here; the test process must be able to remove it afterwards.
	if err := os.Chmod(dir, 0o777); err != nil {
		return "", dir, err
	}
	b := make([]byte, 6)
	rand.Read(b)
	name = "sp-test-store-" + hex.EncodeToString(b)
	// A test that panics or times out, or a kill of the whole process group,
	// skips TestMain's cleanup. A watchdog in its own session, with no tie to
	// this process's stdio, removes the container and the socket directory
	// once this process is gone; the second removal catches a container the
	// daemon finished creating after an interrupted "docker run".
	w := exec.Command("sh", "-c", `while kill -0 "$1" 2>/dev/null; do sleep 1; done
		docker rm -f -v "$2" >/dev/null 2>&1; sleep 5; docker rm -f -v "$2" >/dev/null 2>&1; rm -rf "$3"`,
		"sh", strconv.Itoa(os.Getpid()), name, dir)
	w.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := w.Start(); err != nil {
		return "", dir, err
	}
	w.Process.Release()
	pw := make([]byte, 16)
	rand.Read(pw)
	// Last resort if even the watchdog dies: the server stops itself after
	// 30 minutes and --rm removes the container.
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--label", "supapace.test=1",
		"--network", "none", "--user", "70:70", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp", "--tmpfs", "/var/lib/postgresql/data:uid=70,gid=70,mode=0700",
		"-v", dir+":/var/run/postgresql",
		"-e", "POSTGRES_USER=supapaced", "-e", "POSTGRES_DB=supapaced",
		"-e", "POSTGRES_PASSWORD="+hex.EncodeToString(pw),
		"--entrypoint", "timeout", im.ControlPlane, "-s", "INT", "1800",
		"docker-entrypoint.sh", "postgres", "-c", "listen_addresses=", "-c", "fsync=off").CombinedOutput()
	if err != nil {
		return name, dir, fmt.Errorf("docker run: %v: %s", err, bytes.TrimSpace(out))
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		// The entrypoint's temporary init server also listens on the socket;
		// wait until it has gone and the real server is up.
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if bytes.Contains(logs, []byte("PostgreSQL init process complete")) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s, err := Open(ctx, dir)
			cancel()
			if err == nil {
				s.Close()
				return name, dir, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return name, dir, fmt.Errorf("control-plane test database not ready")
}

func testConfig() nodecfg.Config {
	c := nodecfg.Default("sp.test")
	c.MemAllocMB, c.PidsAlloc, c.Uplinks = 1<<20, 1<<20, nil
	return c
}

// newStore returns a store on an empty, migrated database whose node row is c.
func newStore(t *testing.T, c nodecfg.Config) *Store {
	t.Helper()
	if noDocker != "" {
		t.Skip(noDocker)
	}
	ctx := context.Background()
	s, err := Open(ctx, sockDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.pool.Exec(ctx, "drop schema public cascade; create schema public"); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureNode(ctx, c); err != nil {
		t.Fatal(err)
	}
	// The connection and descriptor ceilings out of the way, as testConfig's
	// memory and process ceilings are; the tests of those terms set their own.
	if err := s.SetNodeAllocs(ctx, 1<<30, 1<<50); err != nil {
		t.Fatal(err)
	}
	return s
}

func ref(n int) string { return fmt.Sprintf("proj%016d", n) }

var defaultConfig = ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{}}

func mustCreate(t *testing.T, s *Store, r string) int64 {
	t.Helper()
	id, err := s.CreateProject(context.Background(), NewProject{Ref: r, Name: "demo", Config: defaultConfig})
	if err != nil {
		t.Fatalf("CreateProject(%s): %v", r, err)
	}
	return id
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func mustPlace(t *testing.T, s *Store, r string) Placement {
	t.Helper()
	p, err := s.Place(context.Background(), r)
	if err != nil {
		t.Fatalf("Place(%s): %v", r, err)
	}
	return p
}

// activate finishes the create operation and makes the project active.
func activate(t *testing.T, s *Store, r string, createOp int64) {
	t.Helper()
	ctx := context.Background()
	must(t, s.StartOperation(ctx, createOp))
	must(t, s.FinishOperation(ctx, createOp, "done", ""))
	must(t, s.SetProjectState(ctx, r, "active"))
}

func markDeleted(t *testing.T, s *Store, r string) int64 {
	t.Helper()
	ctx := context.Background()
	must(t, s.SetProjectState(ctx, r, "deleting"))
	id, err := s.MarkDeleted(ctx, r, 0)
	must(t, err)
	return id
}

func nextUID(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	must(t, s.pool.QueryRow(context.Background(), "select next_uid from node").Scan(&n))
	return n
}

func count(t *testing.T, s *Store, q string, args ...any) int {
	t.Helper()
	var n int
	must(t, s.pool.QueryRow(context.Background(), q, args...).Scan(&n))
	return n
}

func TestMigrate_Idempotent(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	must(t, s.Migrate(ctx))
	must(t, s.Migrate(ctx))
	e, err := s.Epoch(ctx)
	must(t, err)
	if e != 1 {
		t.Fatalf("epoch = %d, want 1", e)
	}
	if n := count(t, s, "select count(*) from cp_meta"); n != 1 {
		t.Fatalf("cp_meta rows = %d", n)
	}
	if n, want := count(t, s, "select count(*) from information_schema.tables where table_schema = 'public'"), len(schemaTables(t)); n != want {
		t.Fatalf("tables = %d, want %d", n, want)
	}
}

func TestEnsureNode_InsertOnceThenStable(t *testing.T) {
	c := testConfig()
	s := newStore(t, c)
	ctx := context.Background()
	must(t, s.EnsureNode(ctx, c))
	if n := count(t, s, "select count(*) from node"); n != 1 {
		t.Fatalf("node rows = %d", n)
	}
	if got := nextUID(t, s); got != c.UIDBase {
		t.Fatalf("next_uid = %d, want %d", got, c.UIDBase)
	}
	d := c
	d.UIDBase = c.UIDBase + 1
	if err := s.EnsureNode(ctx, d); err == nil {
		t.Fatal("EnsureNode with a different uid range succeeded")
	}
	d = c
	d.ProjectBlock, d.SlicePrefix = "10.213.0.0/17", 27
	if err := s.EnsureNode(ctx, d); err == nil {
		t.Fatal("EnsureNode with a different project block succeeded")
	}
}

func TestCreateProject_RejectsBadRef(t *testing.T) {
	s := newStore(t, testConfig())
	for _, r := range []string{"abcdefghij012345678", "ABCDEFGHIJ0123456789", "abcdefghij-123456789", "abcdefghij.123456789", "abcdefghij01234567890", ""} {
		_, err := s.CreateProject(context.Background(), NewProject{Ref: r, Name: "x", Config: defaultConfig})
		if !errors.Is(err, ErrBadRef) {
			t.Errorf("ref %q: error = %v, want ErrBadRef", r, err)
		}
	}
}

func TestCreateProject_RefNeverReused(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	np := NewProject{Ref: ref(1), Name: "a", Config: defaultConfig}
	op := mustCreate(t, s, np.Ref)
	_, err := s.CreateProject(ctx, np)
	wantErr(t, err, ErrRefExists)
	mustPlace(t, s, np.Ref)
	activate(t, s, np.Ref, op)
	markDeleted(t, s, np.Ref)
	must(t, s.MarkPurged(ctx, np.Ref))
	_, err = s.CreateProject(ctx, np)
	wantErr(t, err, ErrRefExists)

	mustCreate(t, s, ref(2))
	mustPlace(t, s, ref(2))
	must(t, s.MarkAborted(ctx, ref(2)))
	_, err = s.CreateProject(ctx, NewProject{Ref: ref(2), Name: "b", Config: defaultConfig})
	wantErr(t, err, ErrRefExists)
}

func TestCreateProject_AdmissionInputs(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	opID := mustCreate(t, s, ref(1))
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.MemMB != 768 || p.Pids != 576 {
		t.Fatalf("mem_mb, pids = %d, %d; want 768, 576", p.MemMB, p.Pids)
	}
	if p.State != "provisioning" || p.Generation != 1 || p.AppliedGen != 0 || p.Epoch != 1 || p.NodeID != "local" {
		t.Fatalf("project = %+v", p)
	}
	if p.UID != nil || p.SubnetIndex != nil {
		t.Fatalf("placed at create: %+v", p)
	}
	if len(p.UserRoles) != 1 || p.UserRoles[0] != "authenticated" {
		t.Fatalf("user_roles = %v", p.UserRoles)
	}
	if p.Config.DiskQuotaMB != 8192 || p.Config.MemMB != 512 || p.Config.GUC == nil {
		t.Fatalf("config = %+v", p.Config)
	}
	op, err := s.GetOperation(ctx, opID)
	must(t, err)
	if op.Kind != "create" || op.State != "pending" || op.Step != "1" || op.Generation != 1 || op.Epoch != 1 {
		t.Fatalf("operation = %+v", op)
	}
	_, err = s.GetProject(ctx, ref(9))
	wantErr(t, err, ErrNotFound)
}

func TestPlace_Idempotent(t *testing.T) {
	c := testConfig()
	s := newStore(t, c)
	mustCreate(t, s, ref(1))
	a := mustPlace(t, s, ref(1))
	b := mustPlace(t, s, ref(1))
	if a != b || a.UID != c.UIDBase || a.GID != a.UID || a.SubnetIndex != 0 {
		t.Fatalf("placements %+v, %+v", a, b)
	}
	if got := nextUID(t, s); got != c.UIDBase+1 {
		t.Fatalf("next_uid = %d, want %d", got, c.UIDBase+1)
	}
}

func TestPlace_UIDMonotonic(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	op := mustCreate(t, s, ref(1))
	a := mustPlace(t, s, ref(1))
	activate(t, s, ref(1), op)
	markDeleted(t, s, ref(1))
	must(t, s.MarkPurged(ctx, ref(1)))
	mustCreate(t, s, ref(2))
	b := mustPlace(t, s, ref(2))
	if b.UID <= a.UID {
		t.Fatalf("uid after purge %d, first %d", b.UID, a.UID)
	}
	if b.SubnetIndex != a.SubnetIndex {
		t.Fatalf("slice %d not reused after purge (first %d)", b.SubnetIndex, a.SubnetIndex)
	}
	s.Close()
	s2, err := Open(ctx, sockDir)
	must(t, err)
	defer s2.Close()
	mustCreate(t, s2, ref(3))
	c := mustPlace(t, s2, ref(3))
	if c.UID <= b.UID {
		t.Fatalf("uid after reopen %d, previous %d", c.UID, b.UID)
	}
	p, err := s2.GetProject(ctx, ref(1))
	must(t, err)
	if p.UID == nil || *p.UID != a.UID || p.SubnetIndex != nil || p.State != "purged" {
		t.Fatalf("purged project = %+v", p)
	}
}

func TestPlace_SliceReleasedOnlyAtPurge(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	opA := mustCreate(t, s, ref(1))
	if got := mustPlace(t, s, ref(1)).SubnetIndex; got != 0 {
		t.Fatalf("A slice %d", got)
	}
	mustCreate(t, s, ref(2))
	if got := mustPlace(t, s, ref(2)).SubnetIndex; got != 1 {
		t.Fatalf("B slice %d", got)
	}
	activate(t, s, ref(1), opA)
	markDeleted(t, s, ref(1))
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.SubnetIndex == nil || *p.SubnetIndex != 0 {
		t.Fatalf("deleted project lost its slice: %+v", p)
	}
	mustCreate(t, s, ref(3))
	if got := mustPlace(t, s, ref(3)).SubnetIndex; got != 2 {
		t.Fatalf("C slice %d, want 2 (0 still held by the deleted project)", got)
	}
	must(t, s.MarkPurged(ctx, ref(1)))
	mustCreate(t, s, ref(4))
	if got := mustPlace(t, s, ref(4)).SubnetIndex; got != 0 {
		t.Fatalf("D slice %d, want 0 (freed by purge)", got)
	}
}

func TestPlace_ConcurrentLastSlot(t *testing.T) {
	c := testConfig()
	c.ProjectBlock = "10.213.0.0/25" // two slices
	s := newStore(t, c)
	mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	for i := 0; i < 20; i++ {
		a, b := ref(100+2*i), ref(101+2*i)
		mustCreate(t, s, a)
		mustCreate(t, s, b)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for j, r := range []string{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[j] = s.Place(context.Background(), r)
			}()
		}
		wg.Wait()
		var ok, full int
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrNodeFull):
				full++
			default:
				t.Fatalf("round %d: %v", i, err)
			}
		}
		if ok != 1 || full != 1 {
			t.Fatalf("round %d: %d succeeded, %d node-full; errors %v", i, ok, full, errs)
		}
		// Free the slot again for the next round: abort the winner.
		winner := a
		if errs[0] != nil {
			winner = b
		}
		must(t, s.MarkAborted(context.Background(), winner))
	}
}

func TestPlace_Exhaustion(t *testing.T) {
	c := testConfig()
	c.ProjectBlock, c.UIDCount = "10.213.0.0/26", 1 // one slice, one uid
	s := newStore(t, c)
	ctx := context.Background()
	mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	must(t, s.MarkAborted(ctx, ref(1))) // slice free again, uid retired
	mustCreate(t, s, ref(2))
	_, err := s.Place(ctx, ref(2))
	wantErr(t, err, ErrNodeFull)
	if got := nextUID(t, s); got != c.UIDBase+1 {
		t.Fatalf("next_uid = %d, want %d (unchanged)", got, c.UIDBase+1)
	}
	p, err := s.GetProject(ctx, ref(2))
	must(t, err)
	if p.UID != nil || p.SubnetIndex != nil || p.State != "provisioning" {
		t.Fatalf("project after ErrNodeFull = %+v", p)
	}
}

func TestPlace_AdmissionDoesNotCountSelfTwice(t *testing.T) {
	c := testConfig()
	c.MemAllocMB = 768 // exactly one default project
	s := newStore(t, c)
	ctx := context.Background()
	mustCreate(t, s, ref(1))
	mustCreate(t, s, ref(2))
	mustPlace(t, s, ref(1))
	mustPlace(t, s, ref(1)) // idempotent: not admitted against itself
	_, err := s.Place(ctx, ref(2))
	wantErr(t, err, ErrNodeFull)
	// An aborted project no longer counts.
	must(t, s.MarkAborted(ctx, ref(1)))
	mustPlace(t, s, ref(2))
}

func TestLockRef_Serialises(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	unlock, err := s.LockRef(ctx, ref(1))
	must(t, err)
	other, err := s.LockRef(ctx, ref(2)) // a different ref does not block
	must(t, err)
	other()

	var mu sync.Mutex
	var events []string
	log := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	done := make(chan error, 1)
	go func() {
		u, err := s.LockRef(ctx, ref(1))
		if err == nil {
			log("second locked")
			u()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("second locker did not block (err %v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	log("first unlocking")
	unlock()
	unlock() // idempotent
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("second locker never acquired the lock")
	}
	if strings.Join(events, ",") != "first unlocking,second locked" {
		t.Fatalf("events %v", events)
	}
	// A cancelled wait returns an error and leaves the lock usable.
	unlock, err = s.LockRef(ctx, ref(1))
	must(t, err)
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = s.LockRef(cctx, ref(1))
	cancel()
	if err == nil {
		t.Fatal("LockRef with an expired context succeeded while the lock was held")
	}
	unlock()
	u, err := s.LockRef(ctx, ref(1))
	must(t, err)
	u()
}

func TestNextOperation_QueueOrder(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	opA := mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	activate(t, s, ref(1), opA)
	del, err := s.SubmitOperation(ctx, ref(1), "delete", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, del))
	must(t, s.SetProjectState(ctx, ref(1), "deleting"))
	purge, err := s.MarkDeleted(ctx, ref(1), 0) // second open operation on the ref, due now
	must(t, err)
	if purge <= del {
		t.Fatalf("purge id %d not after delete %d", purge, del)
	}
	// Another ref's operation in the future is skipped.
	opB := mustCreate(t, s, ref(2))
	must(t, s.StartOperation(ctx, opB))
	must(t, s.FailAttempt(ctx, opB, "internal: x", time.Now().Add(time.Hour)))

	op, ok, err := s.NextOperation(ctx)
	must(t, err)
	if !ok || op.ID != del || op.State != "running" || op.Kind != "delete" {
		t.Fatalf("first = %+v, %v; want the running delete %d", op, ok, del)
	}
	// Held ref lock: nothing else is ready.
	unlock, err := s.LockRef(ctx, ref(1))
	must(t, err)
	_, ok, err = s.NextOperation(ctx)
	must(t, err)
	unlock()
	if ok {
		t.Fatal("NextOperation returned an operation whose ref is locked")
	}
	must(t, s.FinishOperation(ctx, del, "done", ""))
	op, ok, err = s.NextOperation(ctx)
	must(t, err)
	if !ok || op.ID != purge || op.Kind != "purge" {
		t.Fatalf("second = %+v, %v; want purge %d", op, ok, purge)
	}
	must(t, s.StartOperation(ctx, purge))
	must(t, s.FinishOperation(ctx, purge, "done", ""))
	_, ok, err = s.NextOperation(ctx)
	must(t, err)
	if ok {
		t.Fatal("future operation returned before not_before")
	}
}

func TestSubmitOperation_StateRules(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	op := mustCreate(t, s, ref(1))
	_, err := s.SubmitOperation(ctx, ref(1), "delete", nil, 1, time.Now())
	wantErr(t, err, ErrConflict) // provisioning
	mustPlace(t, s, ref(1))
	activate(t, s, ref(1), op)
	must(t, s.SetProjectState(ctx, ref(1), "restarting"))
	_, err = s.SubmitOperation(ctx, ref(1), "delete", nil, 1, time.Now())
	wantErr(t, err, ErrConflict)
	must(t, s.SetProjectState(ctx, ref(1), "active"))
	markDeleted(t, s, ref(1))
	_, err = s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
	wantErr(t, err, ErrConflict)
	_, err = s.SubmitOperation(ctx, ref(9), "delete", nil, 1, time.Now())
	wantErr(t, err, ErrNotFound)

	op2 := mustCreate(t, s, ref(2))
	activate(t, s, ref(2), op2)
	for _, k := range []string{"create", "purge", "bogus"} {
		_, err = s.SubmitOperation(ctx, ref(2), k, nil, 1, time.Now())
		wantErr(t, err, ErrConflict)
	}
	// One open restart or delete at a time: a second would be stamped with the same target.
	_, err = s.SubmitOperation(ctx, ref(2), "restart", nil, 1, time.Now())
	must(t, err)
	_, err = s.SubmitOperation(ctx, ref(2), "restart", nil, 1, time.Now())
	wantErr(t, err, ErrConflict)
	_, err = s.SubmitOperation(ctx, ref(2), "delete", nil, 1, time.Now())
	wantErr(t, err, ErrConflict)
}

func TestSubmitOperation_RestartOnlyFromActive(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	op := mustCreate(t, s, ref(1))
	_, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
	wantErr(t, err, ErrConflict) // provisioning
	activate(t, s, ref(1), op)
	for _, st := range []string{"restarting", "provisioning", "deleting", "deleted"} {
		must(t, s.SetProjectState(ctx, ref(1), st))
		_, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
		if !errors.Is(err, ErrConflict) {
			t.Errorf("restart from %s: %v, want ErrConflict", st, err)
		}
	}
	must(t, s.SetProjectState(ctx, ref(1), "active"))
	id, err := s.SubmitOperation(ctx, ref(1), "restart", json.RawMessage(`{"next":{}}`), 1, time.Now())
	must(t, err)
	if id == 0 {
		t.Fatal("no operation id")
	}
}

func TestSubmitOperation_StampsGeneration(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	activate(t, s, ref(1), mustCreate(t, s, ref(1)))
	params := json.RawMessage(`{"next": {"mem_mb": 512}}`)
	rid, err := s.SubmitOperation(ctx, ref(1), "restart", params, 1, time.Now())
	must(t, err)
	op, err := s.GetOperation(ctx, rid)
	must(t, err)
	if op.Generation != 2 || op.Epoch != 1 || op.State != "pending" || op.Kind != "restart" || op.Step != "" {
		t.Fatalf("restart op = %+v", op)
	}
	var got, want any
	must(t, json.Unmarshal(op.Params, &got))
	must(t, json.Unmarshal(params, &want))
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("params %s", op.Params)
	}
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.Generation != 1 {
		t.Fatalf("project generation changed to %d", p.Generation)
	}
	must(t, s.StartOperation(ctx, rid))
	must(t, s.FinishOperation(ctx, rid, "done", ""))
	did, err := s.SubmitOperation(ctx, ref(1), "delete", nil, 1, time.Now())
	must(t, err)
	op, err = s.GetOperation(ctx, did)
	must(t, err)
	if op.Generation != 1 || string(op.Params) != "{}" {
		t.Fatalf("delete op = %+v", op)
	}
}

func TestBumpGeneration_Guarded(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	mustCreate(t, s, ref(1))
	next := ProjectConfig{DiskQuotaMB: 16384, MemMB: 512, GUC: map[string]string{"max_connections": "200"}}
	must(t, s.BumpGeneration(ctx, ref(1), 1, next)) // target = current: no-op
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.Generation != 1 || p.Config.DiskQuotaMB != 8192 {
		t.Fatalf("no-op bump changed %+v", p)
	}
	must(t, s.BumpGeneration(ctx, ref(1), 2, next))
	must(t, s.BumpGeneration(ctx, ref(1), 2, defaultConfig)) // resumed step: no-op
	must(t, s.BumpGeneration(ctx, ref(1), 1, defaultConfig)) // older: no-op
	p, err = s.GetProject(ctx, ref(1))
	must(t, err)
	if p.Generation != 2 || p.Config.DiskQuotaMB != 16384 || p.Config.GUC["max_connections"] != "200" {
		t.Fatalf("after bump %+v", p)
	}
	wantErr(t, s.BumpGeneration(ctx, ref(9), 2, next), ErrNotFound)
}

func TestStartOperation_ResumesRunning(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	must(t, s.StartOperation(ctx, id))
	must(t, s.StartOperation(ctx, id)) // a crashed worker's operation resumes
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if op.State != "running" || op.Attempts != 2 {
		t.Fatalf("op = %+v", op)
	}
	must(t, s.FinishOperation(ctx, id, "done", ""))
	wantErr(t, s.StartOperation(ctx, id), ErrConflict)
	wantErr(t, s.StartOperation(ctx, 999999), ErrNotFound)
}

func TestOperationWrites_OnlyWhenRunning(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	must(t, s.StartOperation(ctx, id))
	must(t, s.AdvanceStep(ctx, id, "2"))
	wantErr(t, s.FinishOperation(ctx, id, "aborted", ""), ErrConflict) // running
	if _, err := s.RequestAbort(ctx, ref(1)); err != nil {
		t.Fatal(err)
	}
	wantErr(t, s.AdvanceStep(ctx, id, "3"), ErrConflict)
	wantErr(t, s.FinishOperation(ctx, id, "done", ""), ErrConflict)
	wantErr(t, s.FinishOperation(ctx, id, "failed", "internal: x"), ErrConflict)
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if op.State != "aborting" || op.Step != "2" {
		t.Fatalf("op = %+v", op)
	}
	must(t, s.FinishOperation(ctx, id, "aborted", ""))
	op, err = s.GetOperation(ctx, id)
	must(t, err)
	if op.State != "aborted" {
		t.Fatalf("op = %+v", op)
	}
	wantErr(t, s.FinishOperation(ctx, id, "pending", ""), ErrConflict)
	wantErr(t, s.AdvanceStep(ctx, 999999, "3"), ErrNotFound)

	// FailAttempt on a running operation hands it back to the queue.
	id2 := mustCreate(t, s, ref(2))
	must(t, s.StartOperation(ctx, id2))
	retry := time.Now().Add(5 * time.Second)
	must(t, s.FailAttempt(ctx, id2, "timeout: t", retry))
	op, err = s.GetOperation(ctx, id2)
	must(t, err)
	if op.State != "pending" || op.LastError != "timeout: t" || op.NotBefore.Sub(retry).Abs() > time.Millisecond {
		t.Fatalf("op = %+v", op)
	}
	must(t, s.SetOperationParams(ctx, id2, json.RawMessage(`{"rollback_gen":3}`)))
	op, err = s.GetOperation(ctx, id2)
	must(t, err)
	if !strings.Contains(string(op.Params), `"rollback_gen": 3`) {
		t.Fatalf("params %s", op.Params)
	}
}

func TestFailAttempt_AbortingStaysAbortingWithBackoff(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	must(t, s.StartOperation(ctx, id))
	if _, err := s.RequestAbort(ctx, ref(1)); err != nil {
		t.Fatal(err)
	}
	op, ok, err := s.NextOperation(ctx)
	must(t, err)
	if !ok || op.ID != id || op.State != "aborting" {
		t.Fatalf("aborting op not offered: %+v %v", op, ok)
	}
	must(t, s.FailAttempt(ctx, id, "internal: purge failed", time.Now().Add(time.Hour)))
	op, err = s.GetOperation(ctx, id)
	must(t, err)
	if op.State != "aborting" || op.LastError != "internal: purge failed" {
		t.Fatalf("op = %+v", op)
	}
	if _, ok, err := s.NextOperation(ctx); err != nil || ok {
		t.Fatalf("backed-off aborting operation offered (ok %v, err %v)", ok, err)
	}
	must(t, s.FailAttempt(ctx, id, "internal: again", time.Now().Add(-time.Second)))
	op, ok, err = s.NextOperation(ctx)
	must(t, err)
	if !ok || op.ID != id || op.State != "aborting" {
		t.Fatalf("aborting op not offered after not_before: %+v %v", op, ok)
	}
	must(t, s.FinishOperation(ctx, id, "aborted", ""))
	wantErr(t, s.FailAttempt(ctx, id, "x", time.Now()), ErrConflict)

	id2 := mustCreate(t, s, ref(2))
	must(t, s.StartOperation(ctx, id2))
	must(t, s.FinishOperation(ctx, id2, "done", ""))
	wantErr(t, s.FailAttempt(ctx, id2, "x", time.Now()), ErrConflict)
}

func TestRequestAbort_OnlyCreate(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	// A failed create can be aborted.
	id := mustCreate(t, s, ref(1))
	must(t, s.StartOperation(ctx, id))
	must(t, s.FinishOperation(ctx, id, "failed", "internal: x"))
	got, err := s.RequestAbort(ctx, ref(1))
	must(t, err)
	if got != id {
		t.Fatalf("abort id %d, want %d", got, id)
	}
	// A pending create can be aborted.
	id2 := mustCreate(t, s, ref(2))
	got, err = s.RequestAbort(ctx, ref(2))
	must(t, err)
	if got != id2 {
		t.Fatalf("abort id %d, want %d", got, id2)
	}
	// A finished create, an active project, or a restart cannot.
	id3 := mustCreate(t, s, ref(3))
	activate(t, s, ref(3), id3)
	_, err = s.RequestAbort(ctx, ref(3))
	wantErr(t, err, ErrConflict)
	_, err = s.SubmitOperation(ctx, ref(3), "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.SetProjectState(ctx, ref(3), "restarting"))
	_, err = s.RequestAbort(ctx, ref(3))
	wantErr(t, err, ErrConflict)
	_, err = s.RequestAbort(ctx, ref(9))
	wantErr(t, err, ErrNotFound)
}

func TestRetryOperation_OnlyFailed(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	wantErr(t, s.RetryOperation(ctx, id), ErrConflict) // pending
	must(t, s.StartOperation(ctx, id))
	wantErr(t, s.RetryOperation(ctx, id), ErrConflict) // running
	must(t, s.StartOperation(ctx, id))
	must(t, s.FinishOperation(ctx, id, "failed", "timeout: t"))
	must(t, s.RetryOperation(ctx, id))
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if op.State != "pending" || op.Attempts != 0 {
		t.Fatalf("op = %+v", op)
	}
	must(t, s.StartOperation(ctx, id))
	must(t, s.FinishOperation(ctx, id, "done", ""))
	wantErr(t, s.RetryOperation(ctx, id), ErrConflict)
	wantErr(t, s.RetryOperation(ctx, 999999), ErrNotFound)
}

func TestDestroyKeys_OneStatementAndIdempotent(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	mustCreate(t, s, ref(1))
	must(t, s.PutDEK(ctx, ref(1), "kek1", []byte("nonce-123456"), []byte("wrapped")))
	must(t, s.PutSecret(ctx, ref(1), "pg.postgres.password", []byte("n"), []byte("c")))
	must(t, s.PutKey(ctx, KeyRow{Ref: ref(1), KID: "k1", Class: "anon", JWK: json.RawMessage(`{"kty":"RSA"}`)}))
	n, w, err := s.GetDEK(ctx, ref(1))
	must(t, err)
	if string(n) != "nonce-123456" || string(w) != "wrapped" {
		t.Fatalf("dek %q %q", n, w)
	}
	must(t, s.DestroyKeys(ctx, ref(1)))
	var destroyed bool
	must(t, s.pool.QueryRow(ctx, "select destroyed_at is not null and wrapped is null and nonce is null from project_dek where ref = $1", ref(1)).Scan(&destroyed))
	if !destroyed {
		t.Fatal("DEK not destroyed")
	}
	if count(t, s, "select count(*) from secret where ref = $1", ref(1)) != 0 ||
		count(t, s, "select count(*) from project_key where ref = $1", ref(1)) != 0 {
		t.Fatal("secret or key rows left")
	}
	var at1, at2 time.Time
	must(t, s.pool.QueryRow(ctx, "select destroyed_at from project_dek where ref = $1", ref(1)).Scan(&at1))
	must(t, s.DestroyKeys(ctx, ref(1)))
	must(t, s.pool.QueryRow(ctx, "select destroyed_at from project_dek where ref = $1", ref(1)).Scan(&at2))
	if !at1.Equal(at2) {
		t.Fatal("second DestroyKeys changed destroyed_at")
	}
	_, _, err = s.GetDEK(ctx, ref(1))
	wantErr(t, err, ErrDestroyed)
	// A destroyed DEK is not re-created.
	must(t, s.PutDEK(ctx, ref(1), "kek1", []byte("n2"), []byte("w2")))
	_, _, err = s.GetDEK(ctx, ref(1))
	wantErr(t, err, ErrDestroyed)
	// No DEK at all, and a project that does not exist.
	mustCreate(t, s, ref(2))
	_, _, err = s.GetDEK(ctx, ref(2))
	wantErr(t, err, ErrNotFound)
	must(t, s.DestroyKeys(ctx, ref(2)))
}

func TestPutKey_SameKidTwoProjects(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	mustCreate(t, s, ref(1))
	mustCreate(t, s, ref(2))
	jwk := json.RawMessage(`{"kty":"RSA","n":"abc","e":"AQAB"}`)
	must(t, s.PutKey(ctx, KeyRow{Ref: ref(1), KID: "iss", Class: "issuer", JWK: jwk}))
	must(t, s.PutKey(ctx, KeyRow{Ref: ref(2), KID: "iss", Class: "issuer", JWK: jwk}))
	must(t, s.PutKey(ctx, KeyRow{Ref: ref(1), KID: "iss", Class: "issuer", JWK: json.RawMessage(`{"e":"AQAB","n":"abc","kty":"RSA"}`)}))
	must(t, s.PutKey(ctx, KeyRow{Ref: ref(1), KID: "anon1", Class: "anon", JWK: jwk}))
	ks, err := s.ListKeys(ctx, ref(1))
	must(t, err)
	if len(ks) != 2 {
		t.Fatalf("keys %+v", ks)
	}
	for _, k := range ks {
		if k.Ref != ref(1) || (k.KID != "iss" && k.KID != "anon1") || len(k.JWK) == 0 {
			t.Fatalf("key %+v", k)
		}
	}
	err = s.PutKey(ctx, KeyRow{Ref: ref(9), KID: "iss", Class: "issuer", JWK: jwk})
	wantErr(t, err, ErrNotFound)
}

func TestPutKey_SameRefKidDifferentJWK(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	mustCreate(t, s, ref(1))
	must(t, s.PutKey(ctx, KeyRow{Ref: ref(1), KID: "k", Class: "issuer", JWK: json.RawMessage(`{"n":"a"}`)}))
	wantErr(t, s.PutKey(ctx, KeyRow{Ref: ref(1), KID: "k", Class: "issuer", JWK: json.RawMessage(`{"n":"b"}`)}), ErrConflict)
	wantErr(t, s.PutKey(ctx, KeyRow{Ref: ref(1), KID: "k", Class: "anon", JWK: json.RawMessage(`{"n":"a"}`)}), ErrConflict)
}

func TestPutSecret_NoOverwrite(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	mustCreate(t, s, ref(1))
	must(t, s.PutSecret(ctx, ref(1), "jwt.secret", []byte("n1"), []byte("c1")))
	must(t, s.PutSecret(ctx, ref(1), "jwt.secret", []byte("n2"), []byte("c2")))
	n, c, err := s.GetSecret(ctx, ref(1), "jwt.secret")
	must(t, err)
	if string(n) != "n1" || string(c) != "c1" {
		t.Fatalf("secret overwritten: %q %q", n, c)
	}
	_, _, err = s.GetSecret(ctx, ref(1), "token.anon")
	wantErr(t, err, ErrNotFound)
	wantErr(t, s.PutSecret(ctx, ref(9), "jwt.secret", []byte("n"), []byte("c")), ErrNotFound)
}

func TestMarkDeleted_CreatesPurgeOperation(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	activate(t, s, ref(1), mustCreate(t, s, ref(1)))
	wantErr(t, func() error { _, err := s.MarkDeleted(ctx, ref(1), time.Hour); return err }(), ErrConflict) // active
	must(t, s.SetProjectState(ctx, ref(1), "deleting"))
	before := time.Now()
	id, err := s.MarkDeleted(ctx, ref(1), 168*time.Hour)
	must(t, err)
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.State != "deleted" || p.DeletedAt == nil || p.PurgeAfter == nil {
		t.Fatalf("project = %+v", p)
	}
	if d := p.PurgeAfter.Sub(*p.DeletedAt); d != 168*time.Hour {
		t.Fatalf("purge_after - deleted_at = %v", d)
	}
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if op.Kind != "purge" || op.State != "pending" || !op.NotBefore.Equal(*p.PurgeAfter) || op.NotBefore.Before(before.Add(167*time.Hour)) {
		t.Fatalf("purge op = %+v", op)
	}
	if _, ok, err := s.NextOperation(ctx); err != nil || ok {
		t.Fatalf("purge offered before retention (ok %v, err %v)", ok, err)
	}
	must(t, s.SetPurgeNow(ctx, ref(1)))
	op, ok, err := s.NextOperation(ctx)
	must(t, err)
	if !ok || op.ID != id {
		t.Fatalf("purge not offered after SetPurgeNow: %+v %v", op, ok)
	}
	must(t, s.StartOperation(ctx, id))
	wantErr(t, s.SetPurgeNow(ctx, ref(1)), ErrConflict) // no pending purge any more
	must(t, s.MarkPurged(ctx, ref(1)))
	must(t, s.MarkPurged(ctx, ref(1))) // resumed P5
	wantErr(t, s.SetPurgeNow(ctx, ref(9)), ErrNotFound)
}

func TestMarkDeleted_Idempotent(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	activate(t, s, ref(1), mustCreate(t, s, ref(1)))
	must(t, s.SetProjectState(ctx, ref(1), "deleting"))
	a, err := s.MarkDeleted(ctx, ref(1), time.Hour)
	must(t, err)
	p1, err := s.GetProject(ctx, ref(1))
	must(t, err)
	b, err := s.MarkDeleted(ctx, ref(1), time.Hour)
	must(t, err)
	if a != b {
		t.Fatalf("second MarkDeleted returned %d, first %d", b, a)
	}
	if n := count(t, s, "select count(*) from operation where ref = $1 and kind = 'purge'", ref(1)); n != 1 {
		t.Fatalf("purge operations = %d", n)
	}
	p2, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if !p1.PurgeAfter.Equal(*p2.PurgeAfter) {
		t.Fatal("second MarkDeleted moved purge_after")
	}
}

func TestListProjectsAndOperations(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	a := mustCreate(t, s, ref(2))
	b := mustCreate(t, s, ref(1))
	ps, err := s.ListProjects(ctx)
	must(t, err)
	if len(ps) != 2 || ps[0].Ref != ref(1) || ps[1].Ref != ref(2) {
		t.Fatalf("projects %+v", ps)
	}
	ops, err := s.ListOperations(ctx, "")
	must(t, err)
	if len(ops) != 2 || ops[0].ID != b || ops[1].ID != a {
		t.Fatalf("operations %+v", ops)
	}
	ops, err = s.ListOperations(ctx, ref(2))
	must(t, err)
	if len(ops) != 1 || ops[0].ID != a {
		t.Fatalf("operations of %s: %+v", ref(2), ops)
	}
	must(t, s.SetApplied(ctx, ref(1), 1))
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.AppliedGen != 1 {
		t.Fatalf("applied_gen %d", p.AppliedGen)
	}
	wantErr(t, s.SetApplied(ctx, ref(9), 1), ErrNotFound)
	wantErr(t, s.SetProjectState(ctx, ref(9), "active"), ErrNotFound)
	if err := s.SetProjectState(ctx, ref(1), "bogus"); err == nil {
		t.Fatal("invalid state accepted")
	}
	_, err = s.GetOperation(ctx, 999999)
	wantErr(t, err, ErrNotFound)
}

// ---- concurrency and state-machine edges ----

// race runs f(i) in n goroutines started together and returns their errors.
func race(n int, f func(i int) error) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = f(i)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

func TestRace_PlaceManyRefsDistinctSlicesAndUIDs(t *testing.T) {
	c := testConfig()
	c.ProjectBlock = "10.213.0.0/24" // four slices
	s := newStore(t, c)
	ctx := context.Background()
	const n = 12
	for round := 0; round < 10; round++ {
		refs := make([]string, n)
		for i := range refs {
			refs[i] = ref(1000*round + i)
			mustCreate(t, s, refs[i])
		}
		before := nextUID(t, s)
		pls := make([]Placement, n)
		errs := race(n, func(i int) (err error) { pls[i], err = s.Place(ctx, refs[i]); return })
		slices, uids := map[int]bool{}, map[int]bool{}
		var won []string
		for i, err := range errs {
			switch {
			case err == nil:
				if slices[pls[i].SubnetIndex] || uids[pls[i].UID] {
					t.Fatalf("round %d: duplicate placement %+v", round, pls[i])
				}
				slices[pls[i].SubnetIndex], uids[pls[i].UID] = true, true
				if pls[i].UID < before {
					t.Fatalf("round %d: uid %d below counter %d", round, pls[i].UID, before)
				}
				won = append(won, refs[i])
			case errors.Is(err, ErrNodeFull):
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if len(won) != 4 {
			t.Fatalf("round %d: %d placed, want 4", round, len(won))
		}
		if got := nextUID(t, s); got != before+4 {
			t.Fatalf("round %d: next_uid %d, want %d", round, got, before+4)
		}
		for _, r := range won {
			must(t, s.MarkAborted(ctx, r))
		}
	}
}

func TestRace_PlaceAdmissionCeiling(t *testing.T) {
	c := testConfig()
	c.MemAllocMB = 2 * 768 // exactly two default projects; slices are plenty
	s := newStore(t, c)
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		refs := make([]string, 8)
		for i := range refs {
			refs[i] = ref(1000*round + i)
			mustCreate(t, s, refs[i])
		}
		errs := race(len(refs), func(i int) error { _, err := s.Place(ctx, refs[i]); return err })
		var won []string
		for i, err := range errs {
			if err == nil {
				won = append(won, refs[i])
			} else if !errors.Is(err, ErrNodeFull) {
				t.Fatal(err)
			}
		}
		if len(won) != 2 {
			t.Fatalf("round %d: %d admitted, ceiling is 2", round, len(won))
		}
		for _, r := range won {
			must(t, s.MarkAborted(ctx, r))
		}
	}
}

func TestRace_PlaceSameRefOneUID(t *testing.T) {
	c := testConfig()
	s := newStore(t, c)
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		r := ref(round)
		mustCreate(t, s, r)
		before := nextUID(t, s)
		pls := make([]Placement, 8)
		errs := race(8, func(i int) (err error) { pls[i], err = s.Place(ctx, r); return })
		for i, err := range errs {
			must(t, err)
			if pls[i] != pls[0] {
				t.Fatalf("placements differ: %+v vs %+v", pls[i], pls[0])
			}
		}
		if got := nextUID(t, s); got != before+1 {
			t.Fatalf("next_uid %d, want %d", got, before+1)
		}
	}
}

func TestRace_CreateProjectSameRef(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		r := ref(round)
		errs := race(8, func(int) error {
			_, err := s.CreateProject(ctx, NewProject{Ref: r, Name: "x", Config: defaultConfig})
			return err
		})
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, ErrRefExists) {
				t.Fatal(err)
			}
		}
		if ok != 1 || count(t, s, "select count(*) from operation where ref = $1", r) != 1 {
			t.Fatalf("round %d: %d creates succeeded", round, ok)
		}
	}
}

func TestRace_MarkDeletedOnePurge(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		r := ref(round)
		activate(t, s, r, mustCreate(t, s, r))
		must(t, s.SetProjectState(ctx, r, "deleting"))
		ids := make([]int64, 8)
		errs := race(8, func(i int) (err error) { ids[i], err = s.MarkDeleted(ctx, r, time.Hour); return })
		for i, err := range errs {
			must(t, err)
			if ids[i] != ids[0] {
				t.Fatalf("purge ids differ: %v", ids)
			}
		}
		if n := count(t, s, "select count(*) from operation where ref = $1 and kind = 'purge'", r); n != 1 {
			t.Fatalf("round %d: %d purge rows", round, n)
		}
	}
}

func TestRace_SubmitOneOpenOperationPerRef(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		r := ref(round)
		activate(t, s, r, mustCreate(t, s, r))
		errs := race(8, func(i int) error {
			k := "restart"
			if i%2 == 1 {
				k = "delete"
			}
			_, err := s.SubmitOperation(ctx, r, k, nil, 1, time.Now())
			return err
		})
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatal(err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d submissions accepted", round, ok)
		}
	}
}

// An abort racing the worker's bookkeeping: once RequestAbort has returned an
// id, no write of the worker's may move the operation out of aborting, and
// once the worker finished, the abort is refused.
func TestRace_AbortVersusWorkerWrites(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 30; round++ {
		r := ref(round)
		id := mustCreate(t, s, r)
		must(t, s.StartOperation(ctx, id))
		var abortErr, finishErr error
		race(2, func(i int) error {
			if i == 0 {
				_, abortErr = s.RequestAbort(ctx, r)
				return nil
			}
			if err := s.AdvanceStep(ctx, id, "11"); err != nil {
				finishErr = err
				return nil
			}
			finishErr = s.FinishOperation(ctx, id, "done", "")
			return nil
		})
		op, err := s.GetOperation(ctx, id)
		must(t, err)
		switch {
		case abortErr == nil && finishErr == nil:
			t.Fatalf("round %d: both the abort and the finish succeeded (op %s)", round, op.State)
		case abortErr == nil:
			wantErr(t, finishErr, ErrConflict)
			if op.State != "aborting" {
				t.Fatalf("round %d: abort accepted but op is %s", round, op.State)
			}
		default:
			wantErr(t, abortErr, ErrConflict)
			if op.State != "done" {
				t.Fatalf("round %d: abort refused but op is %s", round, op.State)
			}
		}
	}
}

// With every ref but one locked by other sessions, concurrent NextOperation
// calls only ever offer the free ref.
func TestRace_NextOperationNeverOffersLockedRef(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	const refs = 4
	for i := 0; i < refs; i++ {
		mustCreate(t, s, ref(i))
	}
	for free := 0; free < refs; free++ {
		var unlocks []func()
		for i := 0; i < refs; i++ {
			if i != free {
				u, err := s.LockRef(ctx, ref(i))
				must(t, err)
				unlocks = append(unlocks, u)
			}
		}
		for iter := 0; iter < 20; iter++ {
			ops := make([]Operation, 6)
			oks := make([]bool, 6)
			errs := race(6, func(i int) (err error) { ops[i], oks[i], err = s.NextOperation(ctx); return })
			for i, err := range errs {
				must(t, err)
				if oks[i] && ops[i].Ref != ref(free) {
					t.Fatalf("offered %s while it is locked (free %s)", ops[i].Ref, ref(free))
				}
			}
		}
		for _, u := range unlocks {
			u()
		}
	}
}

func TestLockRef_CancelledWaitsNeverLeakTheLock(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 50; round++ {
		unlock, err := s.LockRef(ctx, ref(1))
		must(t, err)
		cctx, cancel := context.WithTimeout(ctx, time.Duration(round%5)*time.Millisecond)
		done := make(chan error, 1)
		go func() {
			u, err := s.LockRef(cctx, ref(1))
			if err == nil {
				u()
			}
			done <- err
		}()
		// Release at about the moment the waiter's context expires, so that
		// some rounds have the lock granted just as the wait is cancelled.
		time.Sleep(time.Duration(round%5) * time.Millisecond)
		unlock()
		<-done
		cancel()
		lctx, lcancel := context.WithTimeout(ctx, 5*time.Second)
		u, err := s.LockRef(lctx, ref(1))
		lcancel()
		if err != nil {
			t.Fatalf("round %d: lock still held after a cancelled wait: %v", round, err)
		}
		u()
	}
	if n := count(t, s, "select count(*) from pg_locks where locktype = 'advisory'"); n != 0 {
		t.Fatalf("%d advisory locks left", n)
	}
}

func TestLockRef_ReleasedWhenConnectionLost(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	lost, err := s.LockRef(ctx, ref(1))
	must(t, err)
	// Unlock on the dead connection must not hang and must hand the
	// connection back, or Close would wait for it forever.
	defer lost()
	// The holder's session dies (a restarted database, a killed backend).
	must(t, func() error {
		_, err := s.pool.Exec(ctx, `select pg_terminate_backend(pid) from pg_locks
			where locktype = 'advisory' and classid = $1 and granted`, lockClassRef)
		return err
	}())
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u, err := s.LockRef(lctx, ref(1))
	must(t, err)
	u()
}

func TestNextOperation_LowerIdNotDueBlocksRef(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	activate(t, s, ref(1), mustCreate(t, s, ref(1)))
	del, err := s.SubmitOperation(ctx, ref(1), "delete", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, del))
	must(t, s.SetProjectState(ctx, ref(1), "deleting"))
	purge, err := s.MarkDeleted(ctx, ref(1), 0)
	must(t, err)
	must(t, s.FailAttempt(ctx, del, "timeout: t", time.Now().Add(time.Hour))) // delete backs off
	if op, ok, err := s.NextOperation(ctx); err != nil || ok {
		t.Fatalf("purge %d overtook its backed-off delete %d: %+v", purge, del, op)
	}
}

func TestOperationWrites_TerminalStatesRefuseEverything(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for _, final := range []string{"done", "failed", "aborted"} {
		r := ref(len(final))
		id := mustCreate(t, s, r)
		must(t, s.StartOperation(ctx, id))
		if final == "aborted" {
			_, err := s.RequestAbort(ctx, r)
			must(t, err)
			wantErr(t, s.StartOperation(ctx, id), ErrConflict) // the worker never restarts an abort
		}
		must(t, s.FinishOperation(ctx, id, final, ""))
		wantErr(t, s.StartOperation(ctx, id), ErrConflict)
		wantErr(t, s.AdvanceStep(ctx, id, "x"), ErrConflict)
		wantErr(t, s.FailAttempt(ctx, id, "x", time.Now()), ErrConflict)
		for _, f := range []string{"done", "failed", "aborted"} {
			wantErr(t, s.FinishOperation(ctx, id, f, ""), ErrConflict)
		}
		op, err := s.GetOperation(ctx, id)
		must(t, err)
		if op.State != final {
			t.Fatalf("%s operation moved to %s", final, op.State)
		}
	}
}

// An abort accepted after the create's last step but before the project was
// marked active must still be finishable: the compensation's MarkAborted is
// accepted from active while the create operation is aborting.
func TestMarkAborted_OnlyFromProvisioning(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	must(t, s.StartOperation(ctx, id))
	_, err := s.RequestAbort(ctx, ref(1))
	must(t, err)
	must(t, s.MarkAborted(ctx, ref(1)))
	must(t, s.MarkAborted(ctx, ref(1))) // repeated: no-op
	must(t, s.FinishOperation(ctx, id, "aborted", ""))
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.State != "aborted" || p.SubnetIndex != nil || p.UID == nil {
		t.Fatalf("project = %+v", p)
	}
	// An active project is never aborted, not even with an aborting create.
	id2 := mustCreate(t, s, ref(2))
	must(t, s.StartOperation(ctx, id2))
	_, err = s.RequestAbort(ctx, ref(2))
	must(t, err)
	must(t, s.SetProjectState(ctx, ref(2), "active"))
	wantErr(t, s.MarkAborted(ctx, ref(2)), ErrConflict)
}

// Retrying a failed restart while another restart is open would give two open
// operations with the same target generation.
func TestRetryOperation_RefusesWhileAnotherIsOpen(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	activate(t, s, ref(1), mustCreate(t, s, ref(1)))
	r1, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, r1))
	must(t, s.FinishOperation(ctx, r1, "failed", "internal: prevalidate")) // project still active
	r2, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
	must(t, err)
	wantErr(t, s.RetryOperation(ctx, r1), ErrConflict)
	// Once the other operation is closed the retry is accepted.
	must(t, s.StartOperation(ctx, r2))
	must(t, s.FinishOperation(ctx, r2, "done", ""))
	must(t, s.RetryOperation(ctx, r1))
}

func TestEnsureNode_EachRangeFieldChecked(t *testing.T) {
	c := testConfig()
	s := newStore(t, c)
	for name, mut := range map[string]func(*nodecfg.Config){
		"block":  func(d *nodecfg.Config) { d.ProjectBlock = "10.213.0.0/17" },
		"prefix": func(d *nodecfg.Config) { d.SlicePrefix = 27 },
		"base":   func(d *nodecfg.Config) { d.UIDBase++ },
		"count":  func(d *nodecfg.Config) { d.UIDCount-- },
	} {
		d := c
		mut(&d)
		if err := s.EnsureNode(context.Background(), d); err == nil {
			t.Errorf("EnsureNode with a different %s succeeded", name)
		}
	}
}

func TestMigrate_ConcurrentFirstRuns(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		_, err := s.pool.Exec(ctx, "drop schema public cascade; create schema public")
		must(t, err)
		stores := make([]*Store, 2)
		for i := range stores {
			stores[i], err = Open(ctx, sockDir)
			must(t, err)
			defer stores[i].Close()
		}
		for i, err := range race(2, func(i int) error { return stores[i].Migrate(ctx) }) {
			if err != nil {
				t.Fatalf("round %d, migrate %d: %v", round, i, err)
			}
		}
		if n := count(t, s, "select count(*) from cp_meta"); n != 1 {
			t.Fatalf("round %d: cp_meta rows = %d", round, n)
		}
	}
}

func TestEnsureNode_UpdatesCeilings(t *testing.T) {
	c := testConfig()
	c.MemAllocMB = 768
	s := newStore(t, c)
	ctx := context.Background()
	mustCreate(t, s, ref(1))
	mustCreate(t, s, ref(2))
	mustPlace(t, s, ref(1))
	_, err := s.Place(ctx, ref(2))
	wantErr(t, err, ErrNodeFull)
	c.MemAllocMB = 2 * 768
	must(t, s.EnsureNode(ctx, c))
	mustPlace(t, s, ref(2))
	c.PidsAlloc = 2 * 576
	must(t, s.EnsureNode(ctx, c))
	var mem, pids int
	must(t, s.pool.QueryRow(ctx, "select mem_alloc_mb, pids_alloc from node").Scan(&mem, &pids))
	if mem != 2*768 || pids != 2*576 {
		t.Fatalf("ceilings %d, %d", mem, pids)
	}
	mustCreate(t, s, ref(3))
	_, err = s.Place(ctx, ref(3))
	wantErr(t, err, ErrNodeFull)
}

func TestPlace_AdmissionCountsDeleting(t *testing.T) {
	c := testConfig()
	c.MemAllocMB = 768
	s := newStore(t, c)
	ctx := context.Background()
	op := mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	activate(t, s, ref(1), op)
	must(t, s.SetProjectState(ctx, ref(1), "deleting"))
	mustCreate(t, s, ref(2))
	_, err := s.Place(ctx, ref(2))
	wantErr(t, err, ErrNodeFull) // deleting: its containers may still run
	_, err = s.MarkDeleted(ctx, ref(1), time.Hour)
	must(t, err)
	mustPlace(t, s, ref(2)) // deleted: no longer counted
}

func TestCreateProject_EmptyUserRolesGetDefault(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	_, err := s.CreateProject(ctx, NewProject{Ref: ref(1), Name: "a", Config: defaultConfig, UserRoles: []string{}})
	must(t, err)
	_, err = s.CreateProject(ctx, NewProject{Ref: ref(2), Name: "b", Config: defaultConfig, UserRoles: []string{"app_user"}})
	must(t, err)
	for r, want := range map[string]string{ref(1): "authenticated", ref(2): "app_user"} {
		p, err := s.GetProject(ctx, r)
		must(t, err)
		if len(p.UserRoles) != 1 || p.UserRoles[0] != want {
			t.Fatalf("%s: user_roles = %v, want [%s]", r, p.UserRoles, want)
		}
	}
}

func TestOperation_Timestamps(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	before := time.Now().Add(-time.Minute)
	id := mustCreate(t, s, ref(1))
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if op.CreatedAt.Before(before) || op.UpdatedAt.Before(op.CreatedAt) {
		t.Fatalf("timestamps %v, %v", op.CreatedAt, op.UpdatedAt)
	}
	time.Sleep(10 * time.Millisecond)
	must(t, s.StartOperation(ctx, id))
	op2, err := s.GetOperation(ctx, id)
	must(t, err)
	if !op2.CreatedAt.Equal(op.CreatedAt) || !op2.UpdatedAt.After(op.UpdatedAt) {
		t.Fatalf("after start: %v, %v (before %v, %v)", op2.CreatedAt, op2.UpdatedAt, op.CreatedAt, op.UpdatedAt)
	}
	ops, err := s.ListOperations(ctx, ref(1))
	must(t, err)
	if len(ops) != 1 || !ops[0].UpdatedAt.Equal(op2.UpdatedAt) {
		t.Fatalf("list %+v", ops)
	}
}

func TestSubmitOperation_BadKindBeforeLookup(t *testing.T) {
	s := newStore(t, testConfig())
	_, err := s.SubmitOperation(context.Background(), ref(9), "bogus", nil, 1, time.Now())
	wantErr(t, err, ErrConflict)
	_, err = s.SubmitOperation(context.Background(), ref(9), "restart", nil, 1, time.Now())
	wantErr(t, err, ErrNotFound)
}

// A restart or delete is admitted only while the project is still at the
// generation its submitter read: two restarts merged from the same base
// cannot drop each other's settings.
func TestSubmitOperation_ExpectedGeneration(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	activate(t, s, ref(1), mustCreate(t, s, ref(1)))
	_, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 2, time.Now())
	wantErr(t, err, ErrConflict)
	_, err = s.SubmitOperation(ctx, ref(1), "delete", nil, 0, time.Now())
	wantErr(t, err, ErrConflict)
	if n := count(t, s, "select count(*) from operation where ref = $1 and kind <> 'create'", ref(1)); n != 0 {
		t.Fatalf("%d operations inserted by refused submissions", n)
	}
	id, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.BumpGeneration(ctx, ref(1), 2, defaultConfig))
	must(t, s.FinishOperation(ctx, id, "done", ""))
	// A second restart merged onto generation 1 is now stale.
	_, err = s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
	wantErr(t, err, ErrConflict)
	rid, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 2, time.Now())
	must(t, err)
	op, err := s.GetOperation(ctx, rid)
	must(t, err)
	if op.Generation != 3 {
		t.Fatalf("restart generation %d, want 3", op.Generation)
	}
}

func TestNextOperation_LeastRecentlyRunFirst(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	a := mustCreate(t, s, ref(1))
	b := mustCreate(t, s, ref(2))
	op, ok, err := s.NextOperation(ctx)
	must(t, err)
	if !ok || op.ID != a {
		t.Fatalf("first = %+v %v, want %d", op, ok, a)
	}
	// a ran an attempt and failed it, due again at once: b was run less recently.
	must(t, s.StartOperation(ctx, a))
	must(t, s.FailAttempt(ctx, a, "internal: x", time.Now().Add(-time.Second)))
	op, ok, err = s.NextOperation(ctx)
	must(t, err)
	if !ok || op.ID != b {
		t.Fatalf("after a's attempt = %+v %v, want %d", op, ok, b)
	}
	must(t, s.StartOperation(ctx, b))
	must(t, s.FailAttempt(ctx, b, "internal: x", time.Now().Add(-time.Second)))
	op, ok, err = s.NextOperation(ctx)
	must(t, err)
	if !ok || op.ID != a {
		t.Fatalf("after b's attempt = %+v %v, want %d", op, ok, a)
	}
}

func TestFailAttempt_AbortingCountsAttempts(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	must(t, s.StartOperation(ctx, id))
	must(t, s.FailAttempt(ctx, id, "internal: x", time.Now())) // running: not counted again
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if op.Attempts != 1 {
		t.Fatalf("attempts %d after a running FailAttempt", op.Attempts)
	}
	_, err = s.RequestAbort(ctx, ref(1))
	must(t, err)
	for i := 1; i <= 3; i++ {
		must(t, s.FailAttempt(ctx, id, "internal: compensation", time.Now()))
		op, err := s.GetOperation(ctx, id)
		must(t, err)
		if op.State != "aborting" || op.Attempts != i {
			t.Fatalf("run %d: %+v", i, op)
		}
	}
}

func TestParkAbort_OnlyAbortingAfterEight(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	wantErr(t, s.ParkAbort(ctx, id, "internal: x"), ErrConflict) // pending
	_, err := s.RequestAbort(ctx, ref(1))
	must(t, err)
	for i := 1; i < 8; i++ {
		must(t, s.FailAttempt(ctx, id, "internal: x", time.Now()))
		wantErr(t, s.ParkAbort(ctx, id, "internal: x"), ErrConflict)
	}
	must(t, s.FailAttempt(ctx, id, "internal: eighth", time.Now()))
	must(t, s.ParkAbort(ctx, id, "internal: parked"))
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if op.State != "failed" || op.LastError != "internal: parked" {
		t.Fatalf("op = %+v", op)
	}
	wantErr(t, s.ParkAbort(ctx, id, "internal: x"), ErrConflict) // failed
	wantErr(t, s.ParkAbort(ctx, 999999, "internal: x"), ErrNotFound)
}

func TestRequestAbort_ResetsAttempts(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for i, setup := range []func(id int64){
		func(id int64) {}, // pending
		func(id int64) { must(t, s.StartOperation(ctx, id)); must(t, s.StartOperation(ctx, id)) },                 // running
		func(id int64) { must(t, s.StartOperation(ctx, id)); must(t, s.FinishOperation(ctx, id, "failed", "x")) }, // failed
	} {
		r := ref(i + 1)
		id := mustCreate(t, s, r)
		setup(id)
		_, err := s.RequestAbort(ctx, r)
		must(t, err)
		op, err := s.GetOperation(ctx, id)
		must(t, err)
		if op.State != "aborting" || op.Attempts != 0 {
			t.Fatalf("case %d: %+v", i, op)
		}
	}
}

// An active project cannot be aborted, whatever its create's state; a
// provisioning project's parked (failed) create is re-armed, and while
// aborting the abort is idempotent.
func TestRequestAbort_RefusesActiveRearmsProvisioning(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for i, opState := range []string{"running", "failed", "aborting", "done"} {
		r := ref(10 + i)
		id := mustCreate(t, s, r)
		must(t, s.StartOperation(ctx, id))
		switch opState {
		case "failed":
			must(t, s.FinishOperation(ctx, id, "failed", "internal: x"))
		case "aborting":
			_, err := s.RequestAbort(ctx, r)
			must(t, err)
		case "done":
			must(t, s.FinishOperation(ctx, id, "done", ""))
		}
		must(t, s.SetProjectState(ctx, r, "active"))
		_, err := s.RequestAbort(ctx, r)
		wantErr(t, err, ErrConflict)
		op, err := s.GetOperation(ctx, id)
		must(t, err)
		if op.State != opState {
			t.Fatalf("refused abort changed the create: %+v", op)
		}
	}
	id := mustCreate(t, s, ref(1))
	_, err := s.RequestAbort(ctx, ref(1))
	must(t, err)
	got, err := s.RequestAbort(ctx, ref(1))
	must(t, err)
	if got != id {
		t.Fatalf("abort while aborting returned %d, want %d", got, id)
	}
	for range 8 {
		must(t, s.FailAttempt(ctx, id, "internal: x", time.Now()))
	}
	must(t, s.ParkAbort(ctx, id, "internal: parked"))
	got, err = s.RequestAbort(ctx, ref(1))
	must(t, err)
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if got != id || op.State != "aborting" || op.Attempts != 0 {
		t.Fatalf("re-armed op = %+v (id %d)", op, got)
	}
}

// Step 12 in one transaction: project active at the operation's generation
// and the operation done, only while it is running and the project
// provisioning; otherwise ErrConflict and nothing changes.
func TestFinishCreate_OneTransaction(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	wantErr(t, s.FinishCreate(ctx, id), ErrConflict) // pending
	must(t, s.StartOperation(ctx, id))
	must(t, s.FinishCreate(ctx, id))
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	op, err := s.GetOperation(ctx, id)
	must(t, err)
	if p.State != "active" || p.AppliedGen != 1 || op.State != "done" || op.Step != "12" || op.LastError != "" {
		t.Fatalf("project %+v, op %+v", p, op)
	}
	wantErr(t, s.FinishCreate(ctx, id), ErrConflict) // done
	// The abort wins: the project stays provisioning, the operation aborting.
	id2 := mustCreate(t, s, ref(2))
	must(t, s.StartOperation(ctx, id2))
	_, err = s.RequestAbort(ctx, ref(2))
	must(t, err)
	wantErr(t, s.FinishCreate(ctx, id2), ErrConflict)
	p, err = s.GetProject(ctx, ref(2))
	must(t, err)
	op, err = s.GetOperation(ctx, id2)
	must(t, err)
	if p.State != "provisioning" || p.AppliedGen != 0 || op.State != "aborting" {
		t.Fatalf("after a lost race: project %+v, op %+v", p, op)
	}
	// A project not provisioning (here: its row moved on) refuses too.
	id3 := mustCreate(t, s, ref(3))
	must(t, s.StartOperation(ctx, id3))
	must(t, s.SetProjectState(ctx, ref(3), "deleting"))
	wantErr(t, s.FinishCreate(ctx, id3), ErrConflict)
	op, err = s.GetOperation(ctx, id3)
	must(t, err)
	if op.State != "running" {
		t.Fatalf("op %+v", op)
	}
	// Only a create.
	activate(t, s, ref(4), mustCreate(t, s, ref(4)))
	rid, err := s.SubmitOperation(ctx, ref(4), "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, rid))
	must(t, s.SetProjectState(ctx, ref(4), "provisioning"))
	wantErr(t, s.FinishCreate(ctx, rid), ErrConflict)
	wantErr(t, s.FinishCreate(ctx, 999999), ErrNotFound)
}

// The lock-held check answers for the session that holds the lock: nil
// while its connection lives, an error once the connection is gone.
func TestLockRefChecked_DetectsLostLock(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	unlock, held, err := s.LockRefChecked(ctx, ref(1))
	must(t, err)
	defer unlock()
	must(t, held(ctx))
	if _, err := s.pool.Exec(ctx, "select pg_terminate_backend(pid) from pg_locks where locktype = 'advisory' and pid <> pg_backend_pid()"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for held(ctx) == nil {
		if time.Now().After(deadline) {
			t.Fatal("held reports a lock whose connection was terminated")
		}
		time.Sleep(10 * time.Millisecond)
	}
	u, ok, err := s.TryLockRef(ctx, ref(1))
	must(t, err)
	if !ok {
		t.Fatal("lock not free after its connection died")
	}
	u()
}

func TestBeginRestart_OneTransaction(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	activate(t, s, ref(1), mustCreate(t, s, ref(1)))
	next := ProjectConfig{DiskQuotaMB: 16384, MemMB: 512, GUC: map[string]string{"max_connections": "200"}}
	must(t, s.BeginRestart(ctx, ref(1), 2, next))
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.Generation != 2 || p.State != "restarting" || p.Config.GUC["max_connections"] != "200" {
		t.Fatalf("project = %+v", p)
	}
	must(t, s.BeginRestart(ctx, ref(1), 2, next)) // resumed R2: no-op
	// Another configuration at the same target is another restart's bump.
	wantErr(t, s.BeginRestart(ctx, ref(1), 2, defaultConfig), ErrConflict)
	p, err = s.GetProject(ctx, ref(1))
	must(t, err)
	if p.Generation != 2 || p.Config.DiskQuotaMB != 16384 {
		t.Fatalf("resumed bump changed %+v", p)
	}
	wantErr(t, s.BeginRestart(ctx, ref(1), 1, defaultConfig), ErrConflict) // older target
	must(t, s.SetProjectState(ctx, ref(1), "deleting"))
	wantErr(t, s.BeginRestart(ctx, ref(1), 3, defaultConfig), ErrConflict)
	p, err = s.GetProject(ctx, ref(1))
	must(t, err)
	if p.Generation != 2 {
		t.Fatalf("refused bump changed the generation to %d", p.Generation)
	}
	wantErr(t, s.BeginRestart(ctx, ref(9), 2, defaultConfig), ErrNotFound)
}

func TestBeginRestart_RollForwardFromRestarting(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	activate(t, s, ref(1), mustCreate(t, s, ref(1)))
	next := ProjectConfig{DiskQuotaMB: 8192, MemMB: 512, GUC: map[string]string{"max_connections": "200"}}
	must(t, s.BeginRestart(ctx, ref(1), 2, next))
	must(t, s.BeginRestart(ctx, ref(1), 3, defaultConfig))
	p, err := s.GetProject(ctx, ref(1))
	must(t, err)
	if p.Generation != 3 || p.State != "restarting" || len(p.Config.GUC) != 0 {
		t.Fatalf("project = %+v", p)
	}
}

func TestTryLockRef(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	unlock, ok, err := s.TryLockRef(ctx, ref(1))
	must(t, err)
	if !ok {
		t.Fatal("free lock not acquired")
	}
	if _, ok, err := s.TryLockRef(ctx, ref(1)); err != nil || ok {
		t.Fatalf("held lock acquired again (ok %v, err %v)", ok, err)
	}
	u2, ok, err := s.TryLockRef(ctx, ref(2))
	must(t, err)
	if !ok {
		t.Fatal("another ref's lock not acquired")
	}
	u2()
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = s.LockRef(cctx, ref(1))
	cancel()
	if err == nil {
		t.Fatal("LockRef acquired a lock TryLockRef holds")
	}
	unlock()
	unlock() // idempotent
	u, err := s.LockRef(ctx, ref(1))
	must(t, err)
	if _, ok, err := s.TryLockRef(ctx, ref(1)); err != nil || ok {
		t.Fatalf("TryLockRef acquired a lock LockRef holds (ok %v, err %v)", ok, err)
	}
	u()
	// Refused tries do not keep connections: far more than the pool size.
	u, err = s.LockRef(ctx, ref(3))
	must(t, err)
	for range 4 * maxConns {
		if _, ok, err := s.TryLockRef(ctx, ref(3)); err != nil || ok {
			t.Fatalf("ok %v, err %v", ok, err)
		}
	}
	u()
}

// A retry and a submission of the same ref racing: at most one of them
// leaves an open operation.
func TestRace_RetryVersusSubmit(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		r := ref(round)
		activate(t, s, r, mustCreate(t, s, r))
		id, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
		must(t, err)
		must(t, s.StartOperation(ctx, id))
		must(t, s.FinishOperation(ctx, id, "failed", "internal: x")) // the project stays active
		race(2, func(i int) error {
			if i == 0 {
				return s.RetryOperation(ctx, id)
			}
			_, err := s.SubmitOperation(ctx, r, "delete", nil, 1, time.Now())
			return err
		})
		if n := count(t, s, "select count(*) from operation where ref = $1 and state in "+openStates, r); n != 1 {
			t.Fatalf("round %d: %d open operations", round, n)
		}
	}
}

// MarkAborted and MarkPurged refuse every state they do not release from,
// and change nothing then.
func TestMarkAbortedPurged_RefusedTransitions(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	id := mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	wantErr(t, s.MarkPurged(ctx, ref(1)), ErrConflict) // provisioning
	activate(t, s, ref(1), id)
	for _, st := range []string{"active", "restarting", "deleting", "deleted"} {
		must(t, s.SetProjectState(ctx, ref(1), st))
		wantErr(t, s.MarkAborted(ctx, ref(1)), ErrConflict)
		if st != "deleted" {
			wantErr(t, s.MarkPurged(ctx, ref(1)), ErrConflict)
		}
		p, err := s.GetProject(ctx, ref(1))
		must(t, err)
		if p.State != st || p.SubnetIndex == nil {
			t.Fatalf("%s: refused transition changed %+v", st, p)
		}
	}
	must(t, s.MarkPurged(ctx, ref(1)))
	wantErr(t, s.MarkAborted(ctx, ref(1)), ErrConflict) // purged
	wantErr(t, s.MarkPurged(ctx, ref(9)), ErrNotFound)
	wantErr(t, s.MarkAborted(ctx, ref(9)), ErrNotFound)
}

// FinishCreate and RequestAbort take the project row first and the
// operation row second: run together they never deadlock; exactly one wins
// and the other gets ErrConflict.
func TestRace_FinishCreateVersusRequestAbort(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	for round := 0; round < 40; round++ {
		r := ref(round)
		id := mustCreate(t, s, r)
		mustPlace(t, s, r)
		must(t, s.StartOperation(ctx, id))
		errs := race(2, func(i int) error {
			if i == 0 {
				return s.FinishCreate(ctx, id)
			}
			_, err := s.RequestAbort(ctx, r)
			return err
		})
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, ErrConflict):
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok != 1 {
			t.Fatalf("round %d: %d winners (%v)", round, ok, errs)
		}
	}
}

func TestTryLockRefChecked_DetectsLostLock(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	unlock, held, ok, err := s.TryLockRefChecked(ctx, ref(1))
	must(t, err)
	if !ok {
		t.Fatal("free lock not acquired")
	}
	defer unlock()
	must(t, held(ctx))
	if _, _, ok, err := s.TryLockRefChecked(ctx, ref(1)); err != nil || ok {
		t.Fatalf("held lock acquired again (ok %v, err %v)", ok, err)
	}
	if _, err := s.pool.Exec(ctx, "select pg_terminate_backend(pid) from pg_locks where locktype = 'advisory' and pid <> pg_backend_pid()"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for held(ctx) == nil {
		if time.Now().After(deadline) {
			t.Fatal("held reports a lock whose connection was terminated")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A rolled-back restart ends aborted from running: final, not open, not
// retryable; other kinds still reach aborted only from aborting.
func TestFinishOperation_RolledBackRestartAborted(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	c := mustCreate(t, s, ref(1))
	must(t, s.StartOperation(ctx, c))
	wantErr(t, s.FinishOperation(ctx, c, "aborted", ""), ErrConflict) // a running create
	must(t, s.FinishOperation(ctx, c, "done", ""))
	must(t, s.SetProjectState(ctx, ref(1), "active"))
	d, err := s.SubmitOperation(ctx, ref(1), "delete", nil, 1, time.Now())
	must(t, err)
	wantErr(t, s.FinishOperation(ctx, d, "aborted", ""), ErrConflict) // pending
	must(t, s.StartOperation(ctx, d))
	wantErr(t, s.FinishOperation(ctx, d, "aborted", ""), ErrConflict) // a running delete
	must(t, s.FinishOperation(ctx, d, "failed", "internal: x"))

	activate(t, s, ref(2), mustCreate(t, s, ref(2)))
	r, err := s.SubmitOperation(ctx, ref(2), "restart", nil, 1, time.Now())
	must(t, err)
	wantErr(t, s.FinishOperation(ctx, r, "aborted", ""), ErrConflict) // pending
	must(t, s.StartOperation(ctx, r))
	must(t, s.FinishOperation(ctx, r, "aborted", "rolled_back: x"))
	op, err := s.GetOperation(ctx, r)
	must(t, err)
	if op.State != "aborted" || op.LastError != "rolled_back: x" {
		t.Fatalf("op = %+v", op)
	}
	wantErr(t, s.RetryOperation(ctx, r), ErrConflict)
	if _, err := s.SubmitOperation(ctx, ref(2), "restart", nil, 1, time.Now()); err != nil {
		t.Fatalf("next restart after a rolled-back one: %v", err)
	}
}

// TestOpenOperation_ConflictNamesIt: a refusal for an open operation names
// its id, kind and state, for a submit and for a retry.
func TestOpenOperation_ConflictNamesIt(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	op := mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	activate(t, s, ref(1), op)
	rid, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
	must(t, err)
	_, err = s.SubmitOperation(ctx, ref(1), "delete", nil, 1, time.Now())
	wantErr(t, err, ErrConflict)
	if want := fmt.Sprintf("operation %d (restart) of the project is pending", rid); !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q lacks %q", err, want)
	}
	// A failed restart is refused a retry while a delete is open.
	must(t, s.StartOperation(ctx, rid))
	must(t, s.FinishOperation(ctx, rid, "failed", "x"))
	did, err := s.SubmitOperation(ctx, ref(1), "delete", nil, 1, time.Now())
	must(t, err)
	err = s.RetryOperation(ctx, rid)
	wantErr(t, err, ErrConflict)
	if want := fmt.Sprintf("operation %d (delete) of the project is pending", did); !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q lacks %q", err, want)
	}
}

// TestCheckAdmission: the pre-check applies Place's rule, counts projects
// not placed yet, and names the figures.
func TestCheckAdmission(t *testing.T) {
	c := testConfig()
	c.MemAllocMB = 2 * 768 // two default projects
	s := newStore(t, c)
	ctx := context.Background()
	must(t, s.CheckAdmission(ctx, 512, defaultShare))
	mustCreate(t, s, ref(1))
	mustPlace(t, s, ref(1))
	must(t, s.CheckAdmission(ctx, 512, defaultShare))
	mustCreate(t, s, ref(2)) // not placed yet: counted all the same
	err := s.CheckAdmission(ctx, 512, defaultShare)
	wantErr(t, err, ErrNodeFull)
	if want := "2 projects hold 1536 of the node's 1536 MiB; a project needs 768 MiB"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q lacks %q", err, want)
	}
	// Place keeps its own rule: it counts placed projects only.
	mustPlace(t, s, ref(2))
	mustCreate(t, s, ref(3))
	_, err = s.Place(ctx, ref(3))
	wantErr(t, err, ErrNodeFull)
	if want := "2 projects hold 1536 of the node's 1536 MiB"; !strings.Contains(err.Error(), want) {
		t.Fatalf("Place: error %q lacks %q", err, want)
	}
	// An aborted project no longer counts.
	must(t, s.MarkAborted(ctx, ref(1)))
	must(t, s.MarkAborted(ctx, ref(3)))
	must(t, s.CheckAdmission(ctx, 512, defaultShare))
}

// TestCheckAdmission_Pids: the process ceiling refuses on its own, with its
// own figures, as Place's does.
func TestCheckAdmission_Pids(t *testing.T) {
	c := testConfig()
	c.PidsAlloc = 2*projectPids - 1 // room for one project's processes, not two
	s := newStore(t, c)
	ctx := context.Background()
	must(t, s.CheckAdmission(ctx, 512, defaultShare))
	mustCreate(t, s, ref(1))
	err := s.CheckAdmission(ctx, 512, defaultShare)
	wantErr(t, err, ErrNodeFull)
	if want := fmt.Sprintf("1 projects hold %d of the node's %d processes; a project needs %d", projectPids, 2*projectPids-1, projectPids); !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q lacks %q", err, want)
	}
}

// TestCheckAdmission_NoNode: without a node row the pre-check says the node
// is not initialised, not that a project is missing.
func TestCheckAdmission_NoNode(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	if _, err := s.pool.Exec(ctx, "delete from node"); err != nil {
		t.Fatal(err)
	}
	err := s.CheckAdmission(ctx, 512, defaultShare)
	wantErr(t, err, ErrConflict)
	if errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "not initialised") {
		t.Fatalf("error %v", err)
	}
}

// A project left restarting by a failed restart accepts one new restart, from
// the generation it is at, or a delete; while that one is open nothing else
// is accepted, the failed restart cannot be retried beside it, and a project
// that is restarting for any other reason is refused as before.
func TestSubmitOperation_AfterFailedRestart(t *testing.T) {
	s := newStore(t, testConfig())
	ctx := context.Background()
	cfg := ProjectConfig{DiskQuotaMB: 1024, MemMB: 512, GUC: map[string]string{}}
	// failedRestart leaves r restarting at generation 2 with its restart failed.
	failedRestart := func(r string) int64 {
		t.Helper()
		activate(t, s, r, mustCreate(t, s, r))
		id, err := s.SubmitOperation(ctx, r, "restart", nil, 1, time.Now())
		must(t, err)
		must(t, s.StartOperation(ctx, id))
		// Running and restarting: an open operation still blocks.
		must(t, s.BeginRestart(ctx, r, 2, cfg))
		for _, k := range []string{"restart", "delete"} {
			if _, err := s.SubmitOperation(ctx, r, k, nil, 2, time.Now()); !errors.Is(err, ErrConflict) ||
				!strings.Contains(err.Error(), fmt.Sprintf("operation %d (restart) of the project is running", id)) {
				t.Fatalf("%s beside a running restart: %v", k, err)
			}
		}
		must(t, s.FinishOperation(ctx, id, "failed", "internal: boom"))
		return id
	}
	failed := failedRestart(ref(1))
	_, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 1, time.Now())
	wantErr(t, err, ErrConflict) // merged onto the generation before the failed bump
	next, err := s.SubmitOperation(ctx, ref(1), "restart", nil, 2, time.Now())
	must(t, err)
	if op, err := s.GetOperation(ctx, next); err != nil || op.Generation != 3 || op.State != "pending" {
		t.Fatalf("takeover %+v, %v", op, err)
	}
	for _, k := range []string{"restart", "delete"} {
		if _, err := s.SubmitOperation(ctx, ref(1), k, nil, 2, time.Now()); !errors.Is(err, ErrConflict) {
			t.Fatalf("second %s beside the open takeover: %v", k, err)
		}
	}
	wantErr(t, s.RetryOperation(ctx, failed), ErrConflict)

	failedRestart(ref(2))
	_, err = s.SubmitOperation(ctx, ref(2), "delete", nil, 2, time.Now())
	must(t, err)

	// Restarting without a failed restart (no restart at all, or its last
	// restart done): refused, naming the way out.
	activate(t, s, ref(3), mustCreate(t, s, ref(3)))
	must(t, s.SetProjectState(ctx, ref(3), "restarting"))
	for _, k := range []string{"restart", "delete"} {
		_, err := s.SubmitOperation(ctx, ref(3), k, nil, 1, time.Now())
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "it is restarting") {
			t.Fatalf("%s of a restarting project without a failed restart: %v", k, err)
		}
	}
	id, err := s.SubmitOperation(ctx, ref(4), "restart", nil, 1, time.Now())
	wantErr(t, err, ErrNotFound)
	activate(t, s, ref(4), mustCreate(t, s, ref(4)))
	id, err = s.SubmitOperation(ctx, ref(4), "restart", nil, 1, time.Now())
	must(t, err)
	must(t, s.StartOperation(ctx, id))
	must(t, s.FinishOperation(ctx, id, "done", ""))
	must(t, s.SetProjectState(ctx, ref(4), "restarting"))
	_, err = s.SubmitOperation(ctx, ref(4), "delete", nil, 2, time.Now())
	wantErr(t, err, ErrConflict)
}

// CheckQuota: the smallest accepted quota is the usage, rounded up to MiB,
// plus the start headroom.
func TestCheckQuota_Bound(t *testing.T) {
	used := int64(2300<<20 + 1) // 2301 MiB rounded up
	min := 2301 + QuotaHeadroomMB
	if err := CheckQuota(min, used); err != nil {
		t.Fatalf("quota at the bound: %v", err)
	}
	err := CheckQuota(min-1, used)
	if !errors.Is(err, ErrQuotaBelowUsage) {
		t.Fatalf("quota below the bound: %v", err)
	}
	for _, s := range []string{fmt.Sprintf("disk_quota_mb %d", min-1), "usage of 2301 MiB", strconv.Itoa(QuotaHeadroomMB) + " MiB",
		fmt.Sprintf("smallest accepted value is %d", min)} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("message %q lacks %q", err, s)
		}
	}
	if err := CheckQuota(QuotaHeadroomMB, 0); err != nil {
		t.Fatalf("empty project: %v", err)
	}
}
