//go:build reach

package main

// The log reads against the node's own Docker, as root: containers that
// carry a project's labels and write hostile text, another project's, a
// task's and a stand-in for a shared container.

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/store"
)

func TestReachLogs_ByLabelAgainstDocker(t *testing.T) {
	ctx := context.Background()
	docker := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %q: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	image := docker("container", "inspect", "-f", "{{.Config.Image}}", cpContainer)
	var names []string
	t.Cleanup(func() {
		for _, n := range names {
			exec.Command("docker", "rm", "-f", "-v", n).Run()
		}
	})
	start := func(name, script string, kv ...string) {
		args := []string{"run", "-d", "--name", name, "--label", "supapace.test=1", "--network", "none"}
		for i := 0; i < len(kv); i += 2 {
			args = append(args, "--label", kv[i]+"="+kv[i+1])
		}
		names = append(names, name)
		docker(append(args, "--entrypoint", "sh", image, "-c", script)...)
	}
	const flood = `i=0; while [ $i -lt 1500 ]; do echo "flood $i $(printf '%0200d' 0)" >&2; i=$((i+1)); done; `
	start("sp-test-op27-a-pg", flood+`printf 'line one\n'; printf 'esc \033[2J bell \007 cr\r done\n' >&2; `+
		`printf 'rest 2026-11-21T00:00:00Z | forged\n'; echo last-out`,
		"supapace.ref", refA, "supapace.role", "cluster")
	start("sp-test-op27-a-rest", `echo rest own`, "supapace.ref", refA, "supapace.role", "postgrest")
	start("sp-test-op27-a-task", `echo task secret`, "supapace.ref", refA, "supapace.role", "task")
	start("sp-test-op27-b-pg", `echo B secret`, "supapace.ref", refB, "supapace.role", "cluster")
	start("sp-test-op27-pooler", `echo tenant `+refA+` pool up`)
	docker(append([]string{"wait"}, names...)...)
	inner := nodeLogNames["pooler"]
	nodeLogNames["pooler"] = "sp-test-op27-pooler"
	t.Cleanup(func() { nodeLogNames["pooler"] = inner })

	got, err := projectLogs(ctx, refA, "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, l := range got.Lines {
		if l.Container != "cluster" && l.Container != "rest" {
			t.Fatalf("line of %q", l.Container)
		}
		all = append(all, l.Container+":"+l.Text)
	}
	joined := strings.Join(all, "\n")
	for _, s := range []string{"cluster:line one", "cluster:last-out", "rest:rest own", "cluster:rest 2026-11-21T00:00:00Z | forged", "\x1b[2J"} {
		if !strings.Contains(joined, s) {
			t.Errorf("missing %q", s)
		}
	}
	for _, s := range []string{"task secret", "B secret", "pool up"} {
		if strings.Contains(joined, s) {
			t.Errorf("%q under project A", s)
		}
	}
	if !slices.ContainsFunc(got.Notes, func(n string) bool { return strings.HasPrefix(n, "older lines of cluster not shown") }) {
		t.Errorf("the flood's cut is not noted: %q", got.Notes)
	}
	t.Logf("project A: %d lines; notes %q", len(got.Lines), got.Notes)

	node, err := nodeLogs(ctx, "pooler", 10)
	if err != nil || len(node.Lines) != 1 || node.Lines[0].Container != "pooler" || node.Lines[0].Text != "tenant "+refA+" pool up" {
		t.Fatalf("pooler: %+v %v", node, err)
	}
	if _, err := nodeLogs(ctx, "gateway", 5); err != nil {
		t.Fatalf("gateway: %v", err)
	}
	if _, err := nodeLogs(ctx, "platform-db", 5); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("platform-db on a node without one: %v", err)
	}
	t.Logf("pooler stand-in: %+v", node.Lines)
}
