package agent

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/layout1.golden from the code as it is")

// layout1Snapshot runs a create's first boot and the first networked start of
// a layout-1 project and returns, as text with the temporary root replaced by
// ROOT and the throwaway first-boot password masked: both create argvs (the
// second carries the configuration label) and every rendered file but the
// pgsodium key, with its mode.
func layout1Snapshot(t *testing.T, layout int) string {
	t.Helper()
	a, f, s, _ := clSetup(t)
	s.Layout = layout
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	s.FirstBoot = false
	if err := a.EnsureCluster(context.Background(), s); err != nil {
		t.Fatalf("first networked start: %v", err)
	}
	var b strings.Builder
	pw := regexp.MustCompile(`POSTGRES_PASSWORD=[0-9a-f]{64}`)
	for i, run := range clRuns(f, "pg-"+s.Ref) {
		b.WriteString("== create " + string(rune('A'+i)) + "\n")
		// The label hashes the temporary root: it is checked against the
		// independent computation of the as-built inputs, and printed so.
		label := "supapace.config=" + clHash(t, a, s, run)
		for _, arg := range run {
			switch {
			case arg == label:
				arg = "supapace.config=<the as-built hash of the argv and the eight files>"
			case strings.HasPrefix(arg, "supapace.config="):
				arg = "supapace.config=<other inputs>"
			}
			b.WriteString(pw.ReplaceAllString(arg, "POSTGRES_PASSWORD=<masked>") + "\n")
		}
	}
	r := a.p.RenderDir(s.Ref)
	var files []string
	filepath.WalkDir(r, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, path)
		return nil
	})
	slices.Sort(files)
	for _, path := range files {
		rel, _ := filepath.Rel(r, path)
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("== file " + rel + " " + fi.Mode().String() + "\n")
		if !fi.Mode().IsRegular() || rel == "pgsodium_root.key" || rel == stateFile {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
		b.WriteString("\n")
	}
	return strings.ReplaceAll(b.String(), a.p.Root, "ROOT")
}

// TestClusterArgs_Layout1Golden: a layout-1 project (and one created before
// layouts, layout 0) is rendered byte for byte as before backups: both
// create argvs, the configuration label and every rendered file.
func TestClusterArgs_Layout1Golden(t *testing.T) {
	golden := filepath.Join("testdata", "layout1.golden")
	got := layout1Snapshot(t, 1)
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	for _, layout := range []int{0, 1} {
		if layout == 0 {
			got = layout1Snapshot(t, 0)
		}
		if got != string(want) {
			t.Errorf("layout %d differs from %s:\n%s", layout, golden, firstDiff(got, string(want)))
		}
	}
}

// firstDiff names the first line where got and want differ.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("line %d:\n got  %s\n want %s", i+1, gl, wl)
		}
	}
	return "(no line differs)"
}
