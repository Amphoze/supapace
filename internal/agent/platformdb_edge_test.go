package agent

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/poolcfg"
)

// A FIFO at the secret's path is refused without being opened: a read of it
// would wait for a writer for ever.
func TestPlatformDB_SecretAtAFIFOIsRefusedUnopened(t *testing.T) {
	a, f, _, _ := pdbNode(t)
	if err := os.Mkdir(a.p.PoolerSecrets(), 0o700); err != nil {
		t.Fatal(err)
	}
	p := metaPasswordPath(a)
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	f.resetLog()
	done := make(chan error, 1)
	go func() { done <- a.EnsurePlatformDB(context.Background()) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("got %v, want the refusal of a file that is not regular", err)
		}
	case <-time.After(10 * time.Second):
		// Let the blocked read end before the test does.
		if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		<-done
		t.Fatal("the ensure opened the FIFO and waited on it")
	}
	if m := f.mutations(); len(m) != 0 {
		t.Errorf("docker changes: %q", m)
	}
}

// Many makers at once leave one secret: each either returns the file's value
// or an error, never a value of its own.
func TestPlatformDB_SecretMadeByManyAtOnceIsOne(t *testing.T) {
	a, _, _, _ := pdbNode(t)
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
	final, err := os.ReadFile(metaPasswordPath(a))
	if err != nil || !metaPasswordRE.Match(final) {
		t.Fatalf("the file after all makers: %q, %v", final, err)
	}
	ok := 0
	for i := range n {
		switch {
		case errs[i] != nil:
			if strings.Contains(errs[i].Error(), string(final)) {
				t.Errorf("maker %d: the secret is in its error", i)
			}
		case got[i] != string(final):
			t.Errorf("maker %d returned a value that is not the file's", i)
		default:
			ok++
		}
	}
	if ok == 0 {
		t.Error("no maker returned the secret")
	}
}

// The row platform-db reads the container's platform address: at another one
// it fails, without blocking, and names the wanted address.
func TestNodeCheck_PlatformDBRowReadsTheAddress(t *testing.T) {
	a, f, _, ad := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	if r := a.CheckPlatformDB(ctx); len(r) != 1 || !r[0].OK {
		t.Fatalf("control: row %+v after the ensure", r)
	}
	f.ctrs[poolcfg.PlatformDBName].Nets["platform"] = ad.Pooler.String()
	r := a.CheckPlatformDB(ctx)
	if len(r) != 1 || r[0].OK || Blocking(r[0]) || !strings.Contains(r[0].Detail, ad.PlatformDB.String()) {
		t.Fatalf("at the pooler's address: row %+v, want failing, not blocking, naming %s", r, ad.PlatformDB)
	}
}

// Another image reference in the node file is another configuration: the row
// says so and the next ensure makes the container again on the same data.
func TestPlatformDB_AnotherImageReferenceMakesItAgain(t *testing.T) {
	a, f, _, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	a.cfg.Images.ControlPlane = "postgres@sha256:" + strings.Repeat("ab", 32)
	if r := a.CheckPlatformDB(ctx); len(r) != 1 || r[0].OK || !strings.Contains(r[0].Detail, "another configuration") {
		t.Fatalf("row %+v, want another configuration", r)
	}
	f.resetLog()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	m := f.mutations()
	if len(m) != 3 || m[0] != "docker stop -t 30 -- sp-platform-db" || m[1] != "docker rm -- sp-platform-db" ||
		!strings.HasPrefix(m[2], "docker run ") || !strings.Contains(m[2], a.cfg.Images.ControlPlane) {
		t.Errorf("changes %q, want stop, rm, run with the new reference", m)
	}
	if slices.Contains(f.calls(), "initdb task") {
		t.Error("the data directory was initialised again")
	}
}

// A secret file of another owner is refused (as root: a test that is not root
// cannot give a file away).
func TestPlatformDB_SecretOfAnotherOwnerIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	a, f, _, _ := pdbNode(t)
	ctx := context.Background()
	if err := a.EnsurePlatformDB(ctx); err != nil {
		t.Fatal(err)
	}
	p := metaPasswordPath(a)
	pw, _ := os.ReadFile(p)
	if err := os.Chown(p, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	f.resetLog()
	err := a.EnsurePlatformDB(ctx)
	if err == nil || !strings.Contains(err.Error(), "owned by the daemon's user") || strings.Contains(err.Error(), string(pw)) {
		t.Fatalf("got %v, want the refusal of another owner's file, without the secret", err)
	}
	if m := f.mutations(); len(m) != 0 {
		t.Errorf("docker changes: %q", m)
	}
}

// An initialisation task that ends with code 0 and leaves no database is a
// failure: no container is made on the directory.
func TestPlatformDB_InitialisationThatLeavesNoDatabaseFails(t *testing.T) {
	a, f, _, _ := pdbNode(t)
	run := f.onRun
	f.onRun = func(args []string, in []byte) (string, error, bool) {
		if args[0] == "run" && flagValue(args, "--name") == pdbTask {
			return "", nil, false // the task runs and writes nothing
		}
		return run(args, in)
	}
	err := a.EnsurePlatformDB(context.Background())
	if err == nil || !strings.Contains(err.Error(), "holds no database after initdb") {
		t.Fatalf("got %v, want a failure naming the directory without a database", err)
	}
	if _, ok := f.ctrs[poolcfg.PlatformDBName]; ok {
		t.Error("a container was made on a directory without a database")
	}
}
