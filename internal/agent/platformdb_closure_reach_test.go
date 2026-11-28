//go:build reach

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/poolcfg"
)

// A server that cannot start loops under its restart policy. An ensure that
// finds it so returns within the short bound and makes nothing again; the
// row says that it restarts, without blocking.
func TestNode_PlatformDBInARestartLoop(t *testing.T) {
	a, _ := pdbOnNode(t)
	ctx := context.Background()
	insp := inspectPDB(t, poolcfg.PlatformDBName)
	id := nodeDocker(t, "inspect", "--format", "{{.Id}}", poolcfg.PlatformDBName)
	// The control file gone and the server killed, not stopped: Docker restarts it.
	if err := os.Remove(filepath.Join(a.pdbDir(), "data", "global", "pg_control")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(insp.State.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	for end := time.Now().Add(90 * time.Second); restarts < 2 && time.Now().Before(end); time.Sleep(time.Second) {
		restarts, _ = strconv.Atoi(nodeDocker(t, "inspect", "--format", "{{.RestartCount}}", poolcfg.PlatformDBName))
	}
	if restarts < 2 {
		t.Fatalf("fixture: %d restarts after 90 s", restarts)
	}
	start := time.Now()
	err := a.EnsurePlatformDB(ctx)
	if el := time.Since(start); err == nil || el > 60*time.Second {
		t.Errorf("ensure in a restart loop: %v after %v, want an error within the short bound", err, el.Round(time.Second))
	} else {
		t.Logf("ensure in a restart loop: %v after %v", err, el.Round(time.Millisecond))
	}
	if now := nodeDocker(t, "inspect", "--format", "{{.Id}}", poolcfg.PlatformDBName); now != id {
		t.Error("the ensure made the container again")
	}
	r := a.CheckPlatformDB(ctx)
	if len(r) != 1 || r[0].OK || Blocking(r[0]) || !strings.Contains(r[0].Detail, "restart") {
		t.Errorf("row %+v, want failing, not blocking, naming the restarts", r)
	} else {
		t.Logf("row: %s", r[0].Detail)
	}
}
