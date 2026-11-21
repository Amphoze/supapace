package alert

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/store"
)

// The delivery tests run against a throw-away control-plane database
// container (the pinned image, no network, a unix-socket directory), so that
// the rows a sender reads and marks are the store's own. They are skipped
// when Docker is unavailable.
var (
	sockDir  string
	noDocker string
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
	if dir, err = os.MkdirTemp("", "sp-alert-"); err != nil {
		return "", "", err
	}
	// The server runs as the image's postgres user and creates its socket here.
	if err := os.Chmod(dir, 0o777); err != nil {
		return "", dir, err
	}
	b := make([]byte, 6)
	rand.Read(b)
	name = "sp-test-alert-" + hex.EncodeToString(b)
	// A watchdog in its own session removes the container and the socket
	// directory once this process is gone, whatever ended it.
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
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "--label", "supapace.test=1",
		"--network", "none", "--user", "70:70", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/tmp", "--tmpfs", "/var/lib/postgresql/data:uid=70,gid=70,mode=0700",
		"-v", dir+":/var/run/postgresql",
		"-e", "POSTGRES_USER=supapaced", "-e", "POSTGRES_DB=supapaced",
		"-e", "POSTGRES_PASSWORD="+hex.EncodeToString(pw),
		"--entrypoint", "timeout", im.ControlPlane, "-s", "INT", "14400",
		"docker-entrypoint.sh", "postgres", "-c", "listen_addresses=", "-c", "fsync=off").CombinedOutput()
	if err != nil {
		return name, dir, fmt.Errorf("docker run: %v: %s", err, bytes.TrimSpace(out))
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		if bytes.Contains(logs, []byte("PostgreSQL init process complete")) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s, err := store.Open(ctx, dir)
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

// testDB is a migrated, empty store and a direct connection beside it, for
// set-up and reads the store does not offer.
type testDB struct {
	st *store.Store
	db *pgx.Conn
}

func newDB(t *testing.T) testDB {
	t.Helper()
	if noDocker != "" {
		t.Skip(noDocker)
	}
	ctx := context.Background()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Host, cfg.Port, cfg.Database, cfg.User, cfg.Password = sockDir, 5432, "supapaced", "supapaced", ""
	cfg.TLSConfig, cfg.Fallbacks = nil, nil
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(context.Background()) })
	if _, err := db.Exec(ctx, "drop schema public cascade; create schema public"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, sockDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return testDB{st, db}
}

// age moves every last delivery d into the past, as if that long had passed.
func (x testDB) age(t *testing.T, d time.Duration) {
	t.Helper()
	for _, tbl := range []string{"alert", "backup_notice"} {
		if _, err := x.db.Exec(context.Background(), "update "+tbl+" set sent_at = sent_at - $1 * interval '1 microsecond'",
			d.Microseconds()); err != nil {
			t.Fatal(err)
		}
	}
}
