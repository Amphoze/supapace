//go:build reach

package agent

// More start-gate and platform-object cases against real Docker in a bare
// node, as root.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func g2Run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// A hardened container sharing a member's namespace, and a container with
// default capabilities sharing the first sharer's: the second is found.
// Then a host-network container with default capabilities, not joined to
// anything: every start is refused; a hardened one is accepted.
func TestNode_GateSharerChainsAndHostMode(t *testing.T) {
	a, s, _ := gnCase(t)
	ctx := context.Background()
	img := a.cfg.Images.ControlPlane
	names := []string{"sp-test-gate-m", "sp-test-gate-s1", "sp-test-gate-s2", "sp-test-gate-h", "sp-test-gate-hh"}
	t.Cleanup(func() {
		for i := len(names) - 1; i >= 0; i-- {
			nodeDockerQuiet("rm", "-f", names[i])
		}
	})
	g2Run(t, "run", "-d", "--name", names[0], "--label", "supapace.test=1", "--network", networkName(s.Ref), "--cap-drop", "ALL",
		"--entrypoint", "sleep", img, "300")
	g2Run(t, "run", "-d", "--name", names[1], "--label", "supapace.test=1", "--network", "container:"+names[0], "--cap-drop", "ALL",
		"--entrypoint", "sleep", img, "300")
	if err := a.CheckAdopted(ctx, s); err != nil {
		t.Fatalf("hardened sharer refused: %v", err)
	}
	g2Run(t, "run", "-d", "--name", names[2], "--label", "supapace.test=1", "--network", "container:"+names[1],
		"--entrypoint", "sleep", img, "300")
	mode := g2Run(t, "container", "inspect", "--format", "{{.HostConfig.NetworkMode}}", "--", names[2])
	t.Logf("sharer of a sharer recorded as %s", mode)
	if err := a.CheckAdopted(ctx, s); !errors.Is(err, ErrContainment) {
		t.Errorf("sharer of a sharer with default capabilities: %v", err)
	} else {
		t.Logf("gate: %v", err)
	}
	g2Run(t, "rm", "-f", names[2])
	// Stopped is enough: a created host-mode container with capabilities.
	g2Run(t, "create", "--name", names[3], "--label", "supapace.test=1", "--network", "host", "--entrypoint", "sleep", img, "300")
	if err := a.CheckAdopted(ctx, s); !errors.Is(err, ErrContainment) {
		t.Errorf("host-mode container with default capabilities: %v", err)
	} else {
		t.Logf("gate: %v", err)
	}
	g2Run(t, "rm", "-f", names[3])
	g2Run(t, "run", "-d", "--name", names[4], "--label", "supapace.test=1", "--network", "host", "--cap-drop", "ALL",
		"--entrypoint", "sleep", img, "300")
	if err := a.CheckAdopted(ctx, s); err != nil {
		t.Errorf("hardened host-mode container refused: %v", err)
	}
}

// The control-plane database keeps its data across a re-creation caused by
// a configuration label mismatch.
func TestNode_ControlPlaneDataSurvivesRecreation(t *testing.T) {
	a := nodeAgent(t)
	ctx := context.Background()
	t.Cleanup(func() {
		nodeDockerQuiet("rm", "-f", cpName)
		os.RemoveAll(a.p.CPDir())
		os.RemoveAll(a.p.CPProjectDir())
		os.RemoveAll(a.p.RepoDir("cp"))
		os.RemoveAll(a.p.PlatformDir())
	})
	if err := a.EnsureImageFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
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
	id1 := g2Run(t, "container", "inspect", "--format", "{{.Id}}", "--", cpName)
	// An older build's container on its own data path: other arguments, no
	// label. The ensure below moves the data to the projects filesystem.
	cp := a.p.CPDir()
	g2Run(t, "stop", "-t", "30", cpName)
	g2Run(t, "rm", cpName)
	if out, err := exec.Command("mv", filepath.Join(a.p.CPProjectDir(), "data"), filepath.Join(cp, "data")).CombinedOutput(); err != nil {
		t.Fatalf("back to the older path: %v %s", err, out)
	}
	g2Run(t, "run", "-d", "--name", cpName, "--network", "none", "--user", "70:70", "--memory", "300m",
		"-v", filepath.Join(cp, "data")+":/var/lib/postgresql/data", "-v", filepath.Join(cp, "sock")+":/var/run/postgresql",
		"-v", filepath.Join(cp, "etc")+":/etc/sp:ro", a.cfg.Images.ControlPlane,
		"postgres", "-c", "listen_addresses=", "-c", "hba_file=/etc/sp/pg_hba.conf", "-c", "ident_file=/etc/sp/pg_ident.conf")
	if out, err := psql("select v from keep"); err != nil || out != "kept" {
		t.Fatalf("older container: %v %q", err, out)
	}
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	id2 := g2Run(t, "container", "inspect", "--format", "{{.Id}} {{index .Config.Labels \"supapace.config\"}} {{.HostConfig.Memory}}", "--", cpName)
	t.Logf("before %s; after %s", id1[:12], id2)
	if out, err := psql("select v from keep"); err != nil || out != "kept" {
		t.Fatalf("row after re-creation: %v %q", err, out)
	}
	for _, p := range []string{filepath.Join(cp, "data.moved", "PG_VERSION"), filepath.Join(a.p.CPProjectDir(), "data", "PG_VERSION")} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("not moved: %v", err)
		}
	}
	logs, _ := exec.Command("docker", "logs", "--tail", "5", cpName).CombinedOutput()
	t.Logf("logs after re-creation: %s", logs)
	// Equal label: adopted, no change.
	if err := a.EnsureControlPlaneDB(ctx); err != nil {
		t.Fatal(err)
	}
	if id3 := g2Run(t, "container", "inspect", "--format", "{{.Id}} {{index .Config.Labels \"supapace.config\"}} {{.HostConfig.Memory}}", "--", cpName); id3 != id2 {
		t.Errorf("an equal label re-created the container: %s vs %s", id3, id2)
	}
}

// A replaced certificate re-creates the gateway; an unchanged one adopts it.
// The gateway image is a stand-in tagged in the node (only creation and
// arguments matter here).
func TestNode_GatewayCertificateChange(t *testing.T) {
	a := nodeAgent(t)
	ctx := context.Background()
	g2Run(t, "tag", a.cfg.Images.ControlPlane, a.cfg.Images.Gateway)
	t.Cleanup(func() {
		nodeDockerQuiet("rm", "-f", gatewayName)
		nodeDockerQuiet("rmi", a.cfg.Images.Gateway)
		for _, n := range []string{platformNet, ingressNet} {
			nodeDockerQuiet("network", "rm", n)
		}
		os.RemoveAll("/etc/supapace")
		os.RemoveAll(a.p.PlatformDir())
	})
	if err := a.EnsurePlatformNetworks(ctx); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(a.p.TLSDir(), 0o700)
	os.WriteFile(filepath.Join(a.p.TLSDir(), "cert.pem"), []byte("CERT1"), 0o600)
	os.WriteFile(filepath.Join(a.p.TLSDir(), "key.pem"), []byte("KEY1"), 0o600)
	if err := a.EnsureImageFiles(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	f := `{{.Id}} {{index .Config.Labels "supapace.config"}}`
	id1 := g2Run(t, "container", "inspect", "--format", f, "--", gatewayName)
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if id := g2Run(t, "container", "inspect", "--format", f, "--", gatewayName); id != id1 {
		t.Errorf("unchanged certificate re-created the gateway")
	}
	os.WriteFile(filepath.Join(a.p.TLSDir(), "key.pem"), []byte("KEY2"), 0o600)
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if id := g2Run(t, "container", "inspect", "--format", f, "--", gatewayName); id != id1 {
		t.Errorf("a key change alone re-created the gateway (the key must not be in the hash)")
	}
	os.WriteFile(filepath.Join(a.p.TLSDir(), "cert.pem"), []byte("CERT2"), 0o600)
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	id2 := g2Run(t, "container", "inspect", "--format", f, "--", gatewayName)
	t.Logf("before %s after %s", id1, id2)
	if id2 == id1 {
		t.Errorf("a renewed certificate did not re-create the gateway")
	}
	// A rebuilt image under the same tag: is the old container kept?
	g2Run(t, "tag", a.cfg.Images.Postgres, a.cfg.Images.Gateway)
	if err := a.EnsureGateway(ctx); err != nil {
		t.Fatal(err)
	}
	img := g2Run(t, "container", "inspect", "--format", "{{.Image}}", "--", gatewayName)
	cur := g2Run(t, "image", "inspect", "--format", "{{.Id}}", "--", a.cfg.Images.Gateway)
	t.Logf("gateway runs image %s; tag now names %s", img[:19], cur[:19])
	if img != cur {
		t.Errorf("a rebuilt gateway image under the same tag is not picked up")
	}
}

// A member named exactly like another container's id: Docker resolves an
// id before a name, so reading the member "by name" reads the other one.
func TestNode_GateNameLikeAnID(t *testing.T) {
	a, s, _ := gnCase(t)
	ctx := context.Background()
	img := a.cfg.Images.ControlPlane
	names := []string{"sp-test-gate-x"}
	t.Cleanup(func() { nodeDockerQuiet("rm", "-f", names[0]) })
	// x is unrelated (no network); a member is named exactly like x's id.
	idx := g2Run(t, "create", "--name", names[0], "--label", "supapace.test=1", "--network", "none", "--cap-drop", "ALL",
		"--entrypoint", "sleep", img, "300")
	out, err := exec.Command("docker", "run", "-d", "--name", idx, "--label", "supapace.test=1", "--network", networkName(s.Ref),
		"--cap-drop", "ALL", "--cap-add", "NET_RAW", "--entrypoint", "sleep", img, "300").CombinedOutput()
	t.Logf("a container named like an id: %v %s", err, strings.TrimSpace(string(out)))
	if err == nil {
		// Removed by its own id: its name would resolve to the other container.
		defer nodeDockerQuiet("rm", "-f", strings.TrimSpace(string(out)))
		err := a.CheckAdopted(ctx, s)
		t.Logf("gate with a NET_RAW member named like a hardened container's id: %v", err)
		if !errors.Is(err, ErrContainment) {
			t.Errorf("the gate judged another container than the member")
		}
	}
}
