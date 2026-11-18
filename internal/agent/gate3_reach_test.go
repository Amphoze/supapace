//go:build reach

package agent

// Re-creation of the platform containers against real Docker in a bare
// node, as root: a changed seccomp profile re-creates both, and the
// control-plane database is shut down cleanly with its data kept.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodefs"
)

func TestNode_ProfileChangeRecreatesBothCleanly(t *testing.T) {
	a := nodeAgent(t)
	ctx := context.Background()
	g2Run(t, "tag", a.cfg.Images.ControlPlane, a.cfg.Images.Gateway)
	t.Cleanup(func() {
		nodeDockerQuiet("rm", "-f", gatewayName)
		nodeDockerQuiet("rm", "-f", cpName)
		nodeDockerQuiet("rmi", a.cfg.Images.Gateway)
		for _, n := range []string{platformNet, ingressNet} {
			nodeDockerQuiet("network", "rm", n)
		}
		os.RemoveAll("/etc/supapace")
		os.RemoveAll(a.p.CPDir())
		os.RemoveAll(a.p.PlatformDir())
	})
	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(a.p.TLSDir(), 0o700)
	os.WriteFile(filepath.Join(a.p.TLSDir(), "cert.pem"), []byte("CERT"), 0o600)
	os.WriteFile(filepath.Join(a.p.TLSDir(), "key.pem"), []byte("KEY"), 0o600)
	if err := a.EnsureImageFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	psql := func(sql string) (string, error) {
		var out []byte
		var err error
		for i := 0; i < 90; i++ {
			out, err = exec.Command("docker", "exec", "-u", "70:70", cpName, "psql", "-qAt", "-U", "supapaced", "-d", "supapaced", "-c", sql).CombinedOutput()
			if err == nil {
				return strings.TrimSpace(string(out)), nil
			}
			time.Sleep(time.Second)
		}
		return string(out), err
	}
	if out, err := psql("create table keep(v text); insert into keep values ('kept')"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	ids := func() (string, string) {
		return g2Run(t, "container", "inspect", "--format", "{{.Id}}", "--", cpName),
			g2Run(t, "container", "inspect", "--format", "{{.Id}}", "--", gatewayName)
	}
	cp1, gw1 := ids()
	// Follow the old server's log through its shutdown.
	var logs bytes.Buffer
	follow := exec.Command("docker", "logs", "-f", "--since", "1s", cp1)
	follow.Stdout, follow.Stderr = &logs, &logs
	if err := follow.Start(); err != nil {
		t.Fatal(err)
	}
	// A re-pinned profile (any other bytes) on disk.
	prof := append(bytes.Clone(seccompProfile), '\n')
	if err := nodefs.WriteFile(a.p, a.p.PlatformDir(), "seccomp.json", prof, 0o444, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	follow.Wait()
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	cp2, gw2 := ids()
	if cp2 == cp1 || gw2 == gw1 {
		t.Errorf("a changed profile kept a container: cp %v gateway %v", cp2 == cp1, gw2 == gw1)
	}
	t.Logf("old server's last log lines:\n%s", logs.String())
	if !strings.Contains(logs.String(), "database system is shut down") {
		t.Errorf("the old server was not shut down cleanly")
	}
	if out, err := psql("select v from keep"); err != nil || out != "kept" {
		t.Fatalf("row after re-creation: %v %q", err, out)
	}
	newLogs, _ := exec.Command("docker", "logs", cpName).CombinedOutput()
	if strings.Contains(string(newLogs), "end-of-recovery") || strings.Contains(string(newLogs), "not properly shut down") {
		t.Errorf("the new server ran crash recovery:\n%s", newLogs)
	}
}
