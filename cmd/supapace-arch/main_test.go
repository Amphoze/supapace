package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The binary runs inside an untrusted cluster: it carries nothing of the
// platform but the name rules and the command itself.
func TestBinary_ImportsOnlyStdlibAndWalname(t *testing.T) {
	out, err := exec.Command("go", "list", "-buildvcs=false", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	got := strings.Fields(string(out))
	want := map[string]bool{
		"github.com/Amphoze/supapace/internal/walname":  true,
		"github.com/Amphoze/supapace/internal/arch":     true,
		"github.com/Amphoze/supapace/cmd/supapace-arch": true,
	}
	if len(got) != len(want) {
		t.Fatalf("non-standard dependencies %v, want exactly %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected dependency %s", p)
		}
	}
}
