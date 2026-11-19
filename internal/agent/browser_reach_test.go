//go:build reach

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The browser harness's container runs in the node's network namespace. With
// every capability dropped (and no-new-privileges, a read-only root) the start
// gate accepts it beside a project; the same container with Docker's default
// capabilities makes the gate refuse. Needs supapace-browsers:local in the node.
func TestNode_HostNamespaceContainerPassesTheGate(t *testing.T) {
	a, s, run := gnCase(t)
	const name = "sp-test-gate-browser"
	t.Cleanup(func() { nodeDockerQuiet("rm", "-f", name) })
	start := func(caps ...string) {
		nodeDockerQuiet("rm", "-f", name)
		args := append([]string{"run", "-d", "--name", name, "--label", "supapace.test=1", "--network", "host",
			"--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp", "--memory", "256m"}, caps...)
		run(append(args, "--entrypoint", "sleep", "supapace-browsers:local", "300")...)
		t.Logf("%s: %s", name, gnHostConfig(t, name))
	}
	start("--cap-drop", "ALL")
	if err := a.CheckAdopted(context.Background(), s); err != nil {
		t.Fatalf("hardened container in the node's namespace refused: %v", err)
	}
	start()
	err := a.CheckAdopted(context.Background(), s)
	t.Logf("gate with default capabilities: %v", err)
	if !errors.Is(err, ErrContainment) || !strings.Contains(err.Error(), name) {
		t.Fatalf("container with default capabilities in the node's namespace: %v", err)
	}
}
