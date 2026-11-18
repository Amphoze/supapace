package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNft puts an nft on PATH that keeps its tables in files of its own
// directory: `-f -` installs both tables, `list tables` lists the installed
// ones, `-s list table F N` prints the table's listing. It returns that
// directory, so a test can drop a table or change a listing.
func fakeNft(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
d=${0%/*}
case "$*" in
"-f -") cat >"$d/loaded"
	printf 'table inet supapace {\n\tchain input {\n\t}\n}\n' >"$d/inet supapace"
	printf 'table bridge supapace {\n\tchain forward {\n\t\tdrop comment "B9"\n\t}\n}\n' >"$d/bridge supapace" ;;
"list tables") for t in "inet supapace" "bridge supapace"; do [ ! -e "$d/$t" ] || echo "table $t"; done ;;
"-s list table "*) t=${*#-s list table }
	[ -e "$d/$t" ] || { echo "Error: No such file or directory" >&2; exit 1; }
	cat "$d/$t" ;;
*) echo "Error: unexpected arguments" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func TestNftCmd_LoadThenCheck(t *testing.T) {
	if _, err := os.Stat("/proc/sys/net/bridge"); err == nil {
		t.Skip("br_netfilter is loaded on this machine: Load would write its switches")
	}
	n := newNode(t)
	n.mustInit(devArgs...)
	dir := fakeNft(t)

	if code, out, errs := n.run("", "nft", "check"); code != exitAbsent || !oneLine(errs) || !strings.Contains(errs, "absent") || out != "" {
		t.Fatalf("check before load: exit %d, stderr %q; want %d and one line", code, errs, exitAbsent)
	}
	if code, out, errs := n.run("", "nft", "load"); code != 0 || !strings.Contains(out, "loaded") {
		t.Fatalf("load: exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if loaded, _ := os.ReadFile(filepath.Join(dir, "loaded")); string(loaded) != string(n.read("etc/supapace/nftables.nft")) {
		t.Fatal("load did not feed the rendered ruleset file to nft")
	}
	n.wantMode("etc/supapace/nft.sha256", 0o600)
	if code, out, errs := n.run("", "nft", "check"); code != 0 || !strings.Contains(out, "verified") {
		t.Fatalf("check after load: exit %d, stdout %q, stderr %q", code, out, errs)
	}

	check := func(name string, want int, word string) {
		t.Helper()
		code, out, errs := n.run("", "nft", "check")
		if code != want || !oneLine(errs) || !strings.Contains(errs, word) || out != "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit %d and one line naming %q", name, code, out, errs, want, word)
		}
	}
	reload := func() {
		t.Helper()
		if code, _, errs := n.run("", "nft", "load"); code != 0 {
			t.Fatalf("reload: exit %d, stderr %q", code, errs)
		}
	}

	// One rule deleted: the listing no longer matches the recorded sum.
	if err := os.WriteFile(filepath.Join(dir, "bridge supapace"), []byte("table bridge supapace {\n\tchain forward {\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	check("rule deleted", exitDrift, "drift")
	reload()

	// The ruleset file edited after the load.
	if err := os.WriteFile(n.p.NftFile(), []byte("table inet supapace {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("file edited", exitDrift, "drift")
	n.mustInit(devArgs...)
	reload()

	// A table deleted.
	if err := os.Remove(filepath.Join(dir, "inet supapace")); err != nil {
		t.Fatal(err)
	}
	check("table deleted", exitAbsent, "absent")
	reload()

	// nft fails, or is not on PATH at all.
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\necho 'netlink: Error: cache initialization failed'>&2\necho second line >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	check("nft fails", exitUnverified, "not verified")
	t.Setenv("PATH", t.TempDir())
	check("nft not on PATH", exitUnverified, "not verified")
	if code, _, errs := n.run("", "nft", "load"); code != exitUnverified || !oneLine(errs) {
		t.Errorf("load without nft: exit %d, stderr %q; want %d", code, errs, exitUnverified)
	}
}

func TestNftCmd_LoadWithoutFile(t *testing.T) {
	n := newNode(t)
	fakeNft(t)
	code, _, errs := n.run("", "nft", "load")
	if code != 1 || !oneLine(errs) || !strings.Contains(errs, "nftables.nft") {
		t.Fatalf("load without a ruleset file: exit %d, stderr %q", code, errs)
	}
}

func oneLine(s string) bool { return strings.Count(s, "\n") == 1 && strings.HasSuffix(s, "\n") }
