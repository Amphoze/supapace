package nft

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

const childEnv = "SPNFT_CHILD"

// ───────── child modes of this binary: a second process using the package ─────────

func init() {
	if os.Getenv(childEnv) == "" {
		return
	}
	os.Exit(childMain(os.Args[1:]))
}

// childMain: install ROOT PROCSYS ELEM… | rotate ROOT PROCSYS DURATION ELEM ELEM.
// install prints "busy" when it finds the lock held, then "ok" or "error …".
// rotate installs {ELEM} and {ELEM} alternately once a second for DURATION and
// prints "rotated N".
func childMain(a []string) int {
	if len(a) < 3 {
		fmt.Println("error usage", a)
		return 3
	}
	p := nodecfg.Paths{Root: a[1]}
	procSys = a[2]
	c := nodecfg.Default("sp.test")
	testHook = func(point string) {
		if point == "busy" {
			fmt.Println("busy")
		}
	}
	elems := func(ss []string) []netip.AddrPort {
		var set []netip.AddrPort
		for _, s := range ss {
			set = append(set, netip.MustParseAddrPort(s))
		}
		return set
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	switch {
	case a[0] == "install":
		if err := InstallSet(ctx, p, c, elems(a[3:])); err != nil {
			fmt.Println("error", err)
			return 1
		}
		fmt.Println("ok")
		return 0
	case a[0] == "rotate" && len(a) == 6:
		dur, err := time.ParseDuration(a[3])
		if err != nil {
			fmt.Println("error", err)
			return 3
		}
		n := 0
		for end := time.Now().Add(dur); time.Now().Before(end); n++ {
			if err := InstallSet(ctx, p, c, elems(a[4+n%2:5+n%2])); err != nil {
				fmt.Println("error", err)
				return 1
			}
			time.Sleep(time.Second)
		}
		fmt.Println("rotated", n)
		return 0
	}
	fmt.Println("error usage", a)
	return 3
}

// childProc is a running child: its output lines and its exit.
type childProc struct {
	cmd   *exec.Cmd
	lines chan string
	done  chan error
}

// child starts this binary in a child mode, in its own process group. The
// group is killed when the test ends, whatever state the child is in.
func child(t *testing.T, args ...string) *childProc {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &childProc{cmd: cmd, lines: make(chan string, 64), done: make(chan error, 1)}
	go func() {
		s := bufio.NewScanner(out)
		for s.Scan() {
			c.lines <- s.Text()
		}
		close(c.lines)
		c.done <- cmd.Wait()
	}()
	t.Cleanup(func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-c.done:
		case <-time.After(30 * time.Second):
			t.Errorf("child %d did not end", cmd.Process.Pid)
		}
	})
	return c
}

// line waits for the child's next output line.
func (c *childProc) line(t *testing.T) string {
	t.Helper()
	select {
	case l, ok := <-c.lines:
		if !ok {
			t.Fatal("child ended without the expected line")
		}
		return l
	case <-time.After(60 * time.Second):
		t.Fatal("no line from the child within 60 s")
	}
	return ""
}

// kill ends the child's whole process group and waits for it.
func (c *childProc) kill(t *testing.T) {
	t.Helper()
	syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
	for range c.lines {
	}
	<-c.done
	c.done <- nil // for the cleanup's wait
}

// waitFile waits until path exists.
func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Lstat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not appear within 60 s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ───────── a stateful nft ─────────

// tablesNft puts on PATH an nft that keeps its tables in its own directory:
// `-f -` installs the file it is given (the inet listing is that file), `list
// tables` lists them while installed. Flag files in the directory change it:
// "poison" (a load whose input holds its text fails), "block-load" and
// "block-list" (the call creates "loading" or "listing" and waits up to 60 s
// for "release"), "unstable" (every bridge listing differs). Every call is
// appended to "calls"; at each load the off-site addresses file's content, or
// "absent", is appended to "addrs-at-load". It returns the directory.
func tablesNft(t *testing.T, p nodecfg.Paths) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
d=${0%/*}
echo "$*" >>"$d/calls"
hold() { touch "$d/$1"; i=0; while [ ! -e "$d/release" ] && [ $i -lt 6000 ]; do sleep 0.01; i=$((i+1)); done; }
case "$*" in
"-f -") cat >"$d/in"
	if [ -e "$d/poison" ] && grep -qF "$(cat "$d/poison")" "$d/in"; then echo "Error: syntax error" >&2; exit 1; fi
	{ cat "$SPNFT_ADDRS" 2>/dev/null || echo absent; echo --; } >>"$d/addrs-at-load"
	[ ! -e "$d/block-load" ] || hold loading
	mv "$d/in" "$d/loaded" ;;
"list tables") [ ! -e "$d/block-list" ] || hold listing
	[ ! -e "$d/loaded" ] || printf 'table inet supapace\ntable bridge supapace\n' ;;
"-s list table inet supapace") [ -e "$d/loaded" ] || { echo "Error: No such file or directory" >&2; exit 1; }
	cat "$d/loaded" ;;
"-s list table bridge supapace") [ -e "$d/loaded" ] || { echo "Error: No such file or directory" >&2; exit 1; }
	if [ -e "$d/unstable" ]; then od -An -N8 -tx1 /dev/urandom; else echo bridge; fi ;;
*) echo "Error: unexpected arguments" >&2; exit 1 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SPNFT_ADDRS", p.OffsiteAddrs())
	return dir
}

// freshNode is a node root with its configuration directory and nothing in
// it, the stateful nft and no bridge-nf switches. It returns the paths, the
// nft's directory and the procSys root a child must use.
func freshNode(t *testing.T) (nodecfg.Paths, string, string) {
	t.Helper()
	p := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(filepath.Dir(p.NftFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	return p, tablesNft(t, p), fakeProcSys(t, nil)
}

func set(ss ...string) []netip.AddrPort {
	var s []netip.AddrPort
	for _, e := range ss {
		s = append(s, netip.MustParseAddrPort(e))
	}
	return s
}

const (
	elemA = "192.0.2.10:443"
	elemB = "198.51.100.7:9443"
	elemC = "203.0.113.5:443"
)

func renderSet(t *testing.T, ss ...string) []byte {
	t.Helper()
	b, err := RenderWith(defaultConfig(t), set(ss...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readOr(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "<absent>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func wantFile(t *testing.T, what, path string, want []byte) {
	t.Helper()
	if got := readOr(t, path); got != string(want) {
		t.Errorf("%s:\n%s\nwant:\n%s", what, got, want)
	}
}

func wantSaved(t *testing.T, p nodecfg.Paths, ss ...string) {
	t.Helper()
	got, err := SavedSet(p)
	if err != nil {
		t.Fatalf("SavedSet: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint(set(ss...)) {
		t.Errorf("saved set %v, want %v", got, set(ss...))
	}
}

func install(t *testing.T, p nodecfg.Paths, ss ...string) {
	t.Helper()
	if err := InstallSet(t.Context(), p, defaultConfig(t), set(ss...)); err != nil {
		t.Fatalf("InstallSet %v: %v", ss, err)
	}
	if err := Check(t.Context(), p); err != nil {
		t.Fatalf("Check after InstallSet %v: %v", ss, err)
	}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func loads(t *testing.T, dir string) int {
	t.Helper()
	return strings.Count(readOr(t, filepath.Join(dir, "calls")), "-f -\n")
}

// ───────── the saved set ─────────

func TestSavedSet_AbsentIsEmpty_MalformedRefused(t *testing.T) {
	p, _, _ := freshNode(t)
	got, err := SavedSet(p)
	if err != nil || got != nil {
		t.Fatalf("SavedSet without a file: %v, %v; want none, nil", got, err)
	}
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(p.OffsiteAddrs(), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("")
	if got, err := SavedSet(p); err != nil || len(got) != 0 {
		t.Errorf("SavedSet of an empty file: %v, %v; want none, nil", got, err)
	}
	write(elemB + "\n" + elemA + "\n")
	if got, err := SavedSet(p); err != nil || fmt.Sprint(got) != fmt.Sprint(set(elemB, elemA)) {
		t.Errorf("SavedSet: %v, %v; want %v", got, err, set(elemB, elemA))
	}
	for _, bad := range []string{
		elemA,                   // no final newline
		elemA + "\n\n",          // an empty line
		"192.0.2.10\n",          // no port
		"192.0.2.10:0\n",        // port 0
		"[2001:db8::1]:443\n",   // IPv6
		"192.0.2.10:0443\n",     // not canonical
		" 192.0.2.10:443\n",     // blank
		"192.0.2.10:443 # x\n",  // trailing text
		"host.example:443\n",    // a name
		elemA + "\n" + "junk\n", // one bad line among good ones
		// too large, and still well formed where a truncated read would end
		"192.0.2.100:4430\n" + strings.Repeat(elemA+"\n", 5000),
	} {
		write(bad)
		if got, err := SavedSet(p); err == nil {
			t.Errorf("SavedSet of %.40q: %v, nil error", bad, got)
		}
	}
	if err := os.Remove(p.OffsiteAddrs()); err != nil {
		t.Fatal(err)
	}
	// Not a regular file: refused, and a FIFO does not block the read.
	if err := syscall.Mkfifo(p.OffsiteAddrs(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SavedSet(p); err == nil {
		t.Error("SavedSet of a FIFO: nil error")
	}
	os.Remove(p.OffsiteAddrs())
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), p.OffsiteAddrs()); err != nil {
		t.Fatal(err)
	}
	if _, err := SavedSet(p); err == nil {
		t.Error("SavedSet of a link: nil error")
	}
}

func TestRenderSaved_EqualsRenderWithoutAFile(t *testing.T) {
	p, _, _ := freshNode(t)
	c := defaultConfig(t)
	got, err := RenderSaved(c, p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != render(t, c) {
		t.Error("without an addresses file RenderSaved differs from Render")
	}
	if err := os.WriteFile(p.OffsiteAddrs(), []byte(elemB+"\n"+elemA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = RenderSaved(c, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, renderSet(t, elemA, elemB)) {
		t.Error("RenderSaved is not RenderWith of the saved set")
	}
	if err := os.WriteFile(p.OffsiteAddrs(), []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := RenderSaved(c, p); err == nil {
		t.Errorf("RenderSaved with a malformed addresses file: %d bytes, nil error", len(b))
	}
}

// ───────── InstallSet ─────────

func TestInstallSet_WritesRulesLoadsThenSavesTheSet_OnlyWhenDifferent(t *testing.T) {
	p, dir, _ := freshNode(t)
	c := defaultConfig(t)
	install(t, p, elemB, elemA, elemB)
	want := renderSet(t, elemA, elemB)
	wantFile(t, "ruleset file", p.NftFile(), want)
	wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), want)
	wantFile(t, "addresses file", p.OffsiteAddrs(), []byte(elemA+"\n"+elemB+"\n"))
	wantFile(t, "addresses file at the load", filepath.Join(dir, "addrs-at-load"), []byte("absent\n--\n"))
	for _, f := range []string{p.NftFile(), p.OffsiteAddrs(), p.NftSum(), p.NftLock()} {
		if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, mode %v; want 0600", f, err, fi.Mode())
		}
	}
	if calls := readOr(t, filepath.Join(dir, "calls")); !strings.HasPrefix(calls, "-f -\nlist tables\n") {
		t.Errorf("nft calls %q, want the load first", calls)
	}

	// The same set again: neither file is written.
	rulesIno, addrsIno := inode(t, p.NftFile()), inode(t, p.OffsiteAddrs())
	install(t, p, elemA, elemB)
	if inode(t, p.NftFile()) != rulesIno || inode(t, p.OffsiteAddrs()) != addrsIno {
		t.Error("an unchanged set rewrote the ruleset or the addresses file")
	}

	// A new set: at its load the addresses file still names the old one.
	os.Remove(filepath.Join(dir, "addrs-at-load"))
	install(t, p, elemC)
	wantFile(t, "addresses file at the second load", filepath.Join(dir, "addrs-at-load"), []byte(elemA+"\n"+elemB+"\n--\n"))
	wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemC))
	wantSaved(t, p, elemC)

	// An element that is not an IPv4 address and port: nothing is written or loaded.
	n := loads(t, dir)
	for _, bad := range [][]netip.AddrPort{{netip.MustParseAddrPort("[2001:db8::1]:443")}, {netip.MustParseAddrPort("192.0.2.1:0")}, {{}}} {
		if err := InstallSet(t.Context(), p, c, bad); err == nil {
			t.Errorf("InstallSet %v: nil error", bad)
		}
	}
	if loads(t, dir) != n {
		t.Error("a refused set was loaded")
	}
	wantSaved(t, p, elemC)
	wantFile(t, "ruleset file after refusals", p.NftFile(), renderSet(t, elemC))
}

func TestInstallSet_AFailedLoadPutsThePreviousRulesetBack_TheSavedSetIsUntouched(t *testing.T) {
	t.Run("load fails", func(t *testing.T) {
		p, dir, _ := freshNode(t)
		install(t, p, elemA)
		addrs := readOr(t, p.OffsiteAddrs())
		if err := os.WriteFile(filepath.Join(dir, "poison"), []byte("198.51.100.7"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemB)); err == nil {
			t.Fatal("InstallSet with a failing load: nil error")
		}
		wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemA))
		wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemA))
		wantFile(t, "addresses file", p.OffsiteAddrs(), []byte(addrs))
		if err := Check(t.Context(), p); err != nil {
			t.Errorf("Check after a failed install: %v", err)
		}
		leftovers(t, p)
	})
	t.Run("addresses write fails", func(t *testing.T) {
		p, dir, _ := freshNode(t)
		if _, err := EnsureRules(t.Context(), p, defaultConfig(t), true); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p.OffsiteAddrs(), 0o700); err != nil {
			t.Fatal(err)
		}
		n := loads(t, dir)
		if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemB)); err == nil {
			t.Fatal("InstallSet with an unwritable addresses file: nil error")
		}
		if got := loads(t, dir) - n; got != 2 {
			t.Errorf("%d loads, want 2: the new set and the previous one again", got)
		}
		wantFile(t, "ruleset file", p.NftFile(), []byte(render(t, defaultConfig(t))))
		wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), []byte(render(t, defaultConfig(t))))
		if fi, err := os.Lstat(p.OffsiteAddrs()); err != nil || !fi.IsDir() {
			t.Errorf("the addresses path was touched: %v", err)
		}
		if err := Check(t.Context(), p); err != nil {
			t.Errorf("Check after a failed install: %v", err)
		}
	})
	t.Run("checksum write fails", func(t *testing.T) {
		p, dir, _ := freshNode(t)
		install(t, p, elemA)
		addrs := readOr(t, p.OffsiteAddrs())
		if err := os.Remove(p.NftSum()); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p.NftSum(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemB)); err == nil {
			t.Fatal("InstallSet with an unwritable checksum file: nil error")
		}
		wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemA))
		wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemA))
		wantFile(t, "addresses file (put back)", p.OffsiteAddrs(), []byte(addrs))
	})
	t.Run("first set, load fails: no ruleset file is left behind", func(t *testing.T) {
		p, dir, _ := freshNode(t)
		if err := os.WriteFile(filepath.Join(dir, "poison"), []byte("198.51.100.7"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemB)); err == nil {
			t.Fatal("InstallSet with a failing load: nil error")
		}
		wantFile(t, "ruleset file", p.NftFile(), []byte("<absent>"))
		wantFile(t, "addresses file", p.OffsiteAddrs(), []byte("<absent>"))
	})
}

// leftovers fails the test when a temporary file is left in the
// configuration directory.
func leftovers(t *testing.T, p nodecfg.Paths) {
	t.Helper()
	ents, err := os.ReadDir(filepath.Dir(p.NftFile()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}
}

func TestInstallSet_StoppedAfterTheLoad_TheNextEnsureRulesReturnsToTheSavedSet(t *testing.T) {
	p, dir, ps := freshNode(t)
	install(t, p, elemA)
	if err := os.WriteFile(filepath.Join(dir, "block-list"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ch := child(t, "install", p.Root, ps, elemB)
	waitFile(t, filepath.Join(dir, "listing")) // the load is in, the addresses not yet written
	ch.kill(t)
	os.Remove(filepath.Join(dir, "block-list"))

	wantFile(t, "loaded tables after the stop", filepath.Join(dir, "loaded"), renderSet(t, elemB))
	wantSaved(t, p, elemA)
	if err := Check(t.Context(), p); !errors.Is(err, ErrDrift) {
		t.Fatalf("Check with the tables one set ahead of the saved one: %v, want ErrDrift", err)
	}
	changed, err := EnsureRules(t.Context(), p, defaultConfig(t), true)
	if err != nil || !changed {
		t.Fatalf("EnsureRules: %v, %v; want changed, nil", changed, err)
	}
	wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemA))
	wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemA))
	wantSaved(t, p, elemA)
	if err := Check(t.Context(), p); err != nil {
		t.Errorf("Check after EnsureRules: %v", err)
	}
}

// ───────── EnsureRules ─────────

func TestEnsureRules_WithLoad_LoadsWhenTheFileChangedOrTheCheckFails(t *testing.T) {
	p, dir, _ := freshNode(t)
	c := defaultConfig(t)
	ensure := func(what string, wantChanged bool, wantLoads int) {
		t.Helper()
		n := loads(t, dir)
		changed, err := EnsureRules(t.Context(), p, c, true)
		if err != nil || changed != wantChanged {
			t.Fatalf("%s: EnsureRules %v, %v; want changed=%v, nil", what, changed, err, wantChanged)
		}
		if got := loads(t, dir) - n; got != wantLoads {
			t.Errorf("%s: %d loads, want %d", what, got, wantLoads)
		}
		if err := Check(t.Context(), p); err != nil {
			t.Errorf("%s: Check afterwards: %v", what, err)
		}
	}
	ensure("no file, no tables", true, 1)
	wantFile(t, "ruleset file", p.NftFile(), []byte(render(t, c)))
	ensure("file and tables in place", false, 0)
	os.Remove(filepath.Join(dir, "loaded")) // as after a reboot
	ensure("unchanged file over absent tables", false, 1)
	if err := os.WriteFile(p.OffsiteAddrs(), []byte(elemA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ensure("a saved set the file does not hold", true, 1)
	wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemA))
	if err := os.Chmod(p.NftFile(), 0o644); err != nil {
		t.Fatal(err)
	}
	ensure("the file's mode changed", true, 1)

	// A check that still fails after the load is the error.
	if err := os.WriteFile(filepath.Join(dir, "unstable"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "loaded"))
	if _, err := EnsureRules(t.Context(), p, c, true); !errors.Is(err, ErrDrift) {
		t.Errorf("EnsureRules with a check failing after the load: %v, want ErrDrift", err)
	}
	// A malformed saved set: nothing is written or loaded.
	os.Remove(filepath.Join(dir, "unstable"))
	before, n := readOr(t, p.NftFile()), loads(t, dir)
	if err := os.WriteFile(p.OffsiteAddrs(), []byte("junk\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureRules(t.Context(), p, c, true); err == nil {
		t.Error("EnsureRules with a malformed addresses file: nil error")
	}
	if readOr(t, p.NftFile()) != before || loads(t, dir) != n {
		t.Error("EnsureRules wrote or loaded with a malformed addresses file")
	}
}

func TestEnsureRules_WithoutLoadWritesOnly_NoWriteWhenEqual(t *testing.T) {
	p, dir, _ := freshNode(t)
	c := defaultConfig(t)
	changed, err := EnsureRules(t.Context(), p, c, false)
	if err != nil || !changed {
		t.Fatalf("EnsureRules on a node without a file: %v, %v; want changed, nil", changed, err)
	}
	wantFile(t, "ruleset file", p.NftFile(), []byte(render(t, c)))
	if fi, _ := os.Stat(p.NftFile()); fi.Mode().Perm() != 0o600 {
		t.Errorf("ruleset file mode %v, want 0600", fi.Mode())
	}
	ino := inode(t, p.NftFile())
	if changed, err := EnsureRules(t.Context(), p, c, false); err != nil || changed {
		t.Fatalf("EnsureRules again: %v, %v; want unchanged, nil", changed, err)
	}
	if inode(t, p.NftFile()) != ino {
		t.Error("an equal file was written again")
	}
	if err := os.WriteFile(p.OffsiteAddrs(), []byte(elemA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := EnsureRules(t.Context(), p, c, false); err != nil || !changed {
		t.Fatalf("EnsureRules with a saved set: %v, %v; want changed, nil", changed, err)
	}
	wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemA))
	if calls := readOr(t, filepath.Join(dir, "calls")); calls != "<absent>" {
		t.Errorf("EnsureRules without load ran nft: %q", calls)
	}
	leftovers(t, p)
}

// ───────── the lock ─────────

// holdLock takes the lock on its own open file description, as another
// process would, and returns its release.
func holdLock(t *testing.T, p nodecfg.Paths, how int) func() {
	t.Helper()
	f, err := os.OpenFile(p.NftLock(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return func() { f.Close() }
}

func TestLock_NotObtainedBeforeTheContextEnds_CheckIsUnverified(t *testing.T) {
	p, dir, _ := freshNode(t)
	c := defaultConfig(t)
	install(t, p, elemA)
	n := loads(t, dir)
	release := holdLock(t, p, syscall.LOCK_EX)
	short := func() context.Context {
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		t.Cleanup(cancel)
		return ctx
	}
	err := Check(short(), p)
	if !errors.Is(err, ErrUnverified) {
		t.Errorf("Check with the lock held elsewhere: %v, want ErrUnverified", err)
	}
	for _, v := range []error{ErrAbsent, ErrDrift, ErrBridgeNF} {
		if errors.Is(err, v) {
			t.Errorf("Check: %v is also %v", err, v)
		}
	}
	if err := Load(short(), p); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Load with the lock held elsewhere: %v, want the context's error", err)
	}
	if err := InstallSet(short(), p, c, set(elemB)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("InstallSet with the lock held elsewhere: %v, want the context's error", err)
	}
	if _, err := EnsureRules(short(), p, c, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("EnsureRules with the lock held elsewhere: %v, want the context's error", err)
	}
	old := savedWait
	savedWait = 300 * time.Millisecond
	t.Cleanup(func() { savedWait = old })
	if _, err := SavedSet(p); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("SavedSet with the lock held elsewhere: %v, want a deadline error", err)
	}
	if _, err := RenderSaved(c, p); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RenderSaved with the lock held elsewhere: %v, want a deadline error", err)
	}
	if loads(t, dir) != n {
		t.Error("nft was loaded without the lock")
	}
	wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemA))

	// A shared holder blocks the writers, not the readers.
	release()
	release = holdLock(t, p, syscall.LOCK_SH)
	if err := Check(short(), p); err != nil {
		t.Errorf("Check beside a shared holder: %v", err)
	}
	wantSaved(t, p, elemA)
	if err := Load(short(), p); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Load beside a shared holder: %v, want the context's error", err)
	}
	release()
	if err := Load(t.Context(), p); err != nil {
		t.Errorf("Load after the release: %v", err)
	}

	// The lock file is never followed through a link.
	if err := os.Remove(p.NftLock()); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(target, p.NftLock()); err != nil {
		t.Fatal(err)
	}
	if err := Check(t.Context(), p); !errors.Is(err, ErrUnverified) {
		t.Errorf("Check with a link at the lock path: %v, want ErrUnverified", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("the lock was created through a link")
	}
}

func TestLoad_TakesTheLock(t *testing.T) {
	p, dir, _ := freshNode(t)
	if _, err := EnsureRules(t.Context(), p, defaultConfig(t), false); err != nil {
		t.Fatal(err)
	}
	release := holdLock(t, p, syscall.LOCK_SH)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := Load(ctx, p); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Load with the lock held: %v, want the context's error", err)
	}
	if calls := readOr(t, filepath.Join(dir, "calls")); calls != "<absent>" {
		t.Errorf("Load ran nft without the lock: %q", calls)
	}
	release()
	if err := Load(t.Context(), p); err != nil {
		t.Fatalf("Load after the release: %v", err)
	}
	if loads(t, dir) != 1 {
		t.Error("Load did not load")
	}
}

// busySignal makes the next "busy" point of this process close the returned channel.
func busySignal(t *testing.T) <-chan struct{} {
	t.Helper()
	ch := make(chan struct{})
	first := true
	testHook = func(point string) {
		if point == "busy" && first {
			first = false
			close(ch)
		}
	}
	t.Cleanup(func() { testHook = func(string) {} })
	return ch
}

func TestCheck_WaitsForAnInstallInAnotherProcess(t *testing.T) {
	p, dir, ps := freshNode(t)
	install(t, p, elemA)
	if err := os.WriteFile(filepath.Join(dir, "block-load"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ch := child(t, "install", p.Root, ps, elemB)
	waitFile(t, filepath.Join(dir, "loading")) // the file is written, the load not done
	// Control: without the lock a check now sees the new file over the old tables.
	if err := checkLocked(t.Context(), p); !errors.Is(err, ErrDrift) {
		t.Fatalf("control: an unlocked check during the install: %v, want ErrDrift", err)
	}
	busy := busySignal(t)
	res := make(chan error, 1)
	go func() { res <- Check(t.Context(), p) }()
	select {
	case <-busy:
	case err := <-res:
		t.Fatalf("Check returned during the other process's install: %v", err)
	case <-time.After(60 * time.Second):
		t.Fatal("Check neither waited nor returned")
	}
	if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := <-res; err != nil {
		t.Errorf("Check that waited for the install: %v", err)
	}
	if l := ch.line(t); l != "ok" {
		t.Errorf("child: %q", l)
	}
	wantSaved(t, p, elemB)
}

func TestEnsureRules_UnderTheLock_AConcurrentInstallIsNeverOverwrittenWithTheOldSet(t *testing.T) {
	// The file is an older binary's (empty set) while A is saved and loaded,
	// so EnsureRules has something to write.
	setup := func(t *testing.T) (nodecfg.Paths, string, string) {
		p, dir, ps := freshNode(t)
		install(t, p, elemA)
		if err := os.WriteFile(p.NftFile(), []byte(render(t, defaultConfig(t))), 0o600); err != nil {
			t.Fatal(err)
		}
		return p, dir, ps
	}
	t.Run("control: without the lock the old set is written back", func(t *testing.T) {
		p, _, ps := setup(t)
		testHook = func(point string) {
			if point == "saved" { // the other process installs B completely, now
				ch := child(t, "install", p.Root, ps, elemB)
				if l := ch.line(t); l != "ok" {
					t.Errorf("child: %q", l)
				}
			}
		}
		t.Cleanup(func() { testHook = func(string) {} })
		if _, err := ensureRules(t.Context(), p, defaultConfig(t), true); err != nil {
			t.Fatal(err)
		}
		wantSaved(t, p, elemB)
		if got := readOr(t, p.NftFile()); got != string(renderSet(t, elemA)) {
			t.Fatal("control: the unlocked EnsureRules did not write the old set over the new one")
		}
	})
	t.Run("with the lock", func(t *testing.T) {
		p, dir, ps := setup(t)
		var ch *childProc
		testHook = func(point string) {
			if point == "saved" && ch == nil {
				ch = child(t, "install", p.Root, ps, elemB)
				if l := ch.line(t); l != "busy" { // it waits for this process's lock
					t.Errorf("child: %q, want busy", l)
				}
			}
		}
		t.Cleanup(func() { testHook = func(string) {} })
		if _, err := EnsureRules(t.Context(), p, defaultConfig(t), true); err != nil {
			t.Fatal(err)
		}
		if l := ch.line(t); l != "ok" {
			t.Fatalf("child: %q", l)
		}
		wantSaved(t, p, elemB)
		wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemB))
		wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemB))
		if err := Check(t.Context(), p); err != nil {
			t.Errorf("Check: %v", err)
		}
	})
}

func TestInstallSet_CallerCancelledAfterTheLoad_ThePreviousRulesetIsLoadedAgain(t *testing.T) {
	p, dir, _ := freshNode(t)
	install(t, p, elemA)
	addrs := readOr(t, p.OffsiteAddrs())
	if err := os.WriteFile(filepath.Join(dir, "block-list"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		// The new set is loaded, the listing not done (bounded: the fake's
		// own hold ends after 60 s).
		for i := 0; i < 6000; i++ {
			if _, err := os.Lstat(filepath.Join(dir, "listing")); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		os.Remove(filepath.Join(dir, "block-list"))
		os.WriteFile(filepath.Join(dir, "release"), nil, 0o644)
	}()
	if err := InstallSet(ctx, p, defaultConfig(t), set(elemB)); err == nil {
		t.Fatal("InstallSet whose context ended after the load: nil error")
	}
	os.Remove(filepath.Join(dir, "release"))
	wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemA))
	wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemA))
	wantFile(t, "addresses file", p.OffsiteAddrs(), []byte(addrs))
	if err := Check(t.Context(), p); err != nil {
		t.Errorf("Check after the cancelled install: %v", err)
	}
}

// A set is refused when its addresses file would be one SavedSet refuses:
// otherwise every later EnsureRules and RenderSaved fails on the node.
func TestInstallSet_RefusesASetItsAddressesFileCouldNotHold(t *testing.T) {
	p, dir, _ := freshNode(t)
	install(t, p, elemA)
	var big []netip.AddrPort
	for i := 0; i < 4096; i++ {
		big = append(big, netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 65535))
	}
	n := loads(t, dir)
	err := InstallSet(t.Context(), p, defaultConfig(t), big)
	if _, serr := SavedSet(p); serr != nil {
		t.Errorf("InstallSet of %d elements: %v; afterwards SavedSet: %v", len(big), err, serr)
	}
	if err == nil {
		t.Error("InstallSet of a set larger than the addresses file holds: nil error")
	} else if loads(t, dir) != n {
		t.Error("a refused set was loaded")
	}
}

func TestInstallSet_AtMost256Elements_NothingWrittenOrLoadedAbove(t *testing.T) {
	p, dir, _ := freshNode(t)
	c := defaultConfig(t)
	elems := func(n int) []netip.AddrPort {
		var s []netip.AddrPort
		for i := 0; i < n; i++ { // the longest lines: 22 bytes each
			s = append(s, netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(100 + i/250), byte(i%250 + 1)}), 65535))
		}
		return s
	}
	if err := InstallSet(t.Context(), p, c, elems(256)); err != nil {
		t.Fatalf("InstallSet of 256 elements: %v", err)
	}
	got, err := SavedSet(p)
	if err != nil || len(got) != 256 {
		t.Fatalf("SavedSet after 256: %d elements, %v", len(got), err)
	}
	rules, addrs := readOr(t, p.NftFile()), readOr(t, p.OffsiteAddrs())
	n := loads(t, dir)
	if err := InstallSet(t.Context(), p, c, elems(257)); err == nil {
		t.Fatal("InstallSet of 257 elements: nil error")
	}
	if loads(t, dir) != n || readOr(t, p.NftFile()) != rules || readOr(t, p.OffsiteAddrs()) != addrs {
		t.Error("a set of 257 elements was written or loaded")
	}
	if _, err := RenderWith(c, elems(257)); err == nil {
		t.Error("RenderWith of 257 elements: nil error")
	}
}

// A failed restore of the addresses file ends the put-back: the tables and both
// files stay at the new set, which Check reports, instead of a saved set that
// names addresses the tables do not hold beside a passing Check.
func TestInstallSet_AFailedAddressesRestoreStopsThePutBack(t *testing.T) {
	p, dir, _ := freshNode(t)
	install(t, p, elemA)
	// The checksum write fails (a directory in its place) …
	if err := os.Remove(p.NftSum()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.NftSum(), 0o700); err != nil {
		t.Fatal(err)
	}
	// … and so does the restore of the addresses file (a directory in its place).
	testHook = func(point string) {
		if point == "addresses" {
			if err := os.Remove(p.OffsiteAddrs()); err != nil {
				t.Error(err)
			}
			if err := os.Mkdir(p.OffsiteAddrs(), 0o700); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { testHook = func(string) {} })
	n := loads(t, dir)
	if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemB)); err == nil {
		t.Fatal("InstallSet with failing checksum and restore: nil error")
	}
	if got := loads(t, dir) - n; got != 1 {
		t.Errorf("%d loads, want 1: no reload of the previous ruleset after the failed restore", got)
	}
	wantFile(t, "ruleset file (not put back)", p.NftFile(), renderSet(t, elemB))
	wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemB))
	// Once the obstacles are gone, Check reports drift and EnsureRules converges.
	testHook = func(string) {}
	os.Remove(p.OffsiteAddrs())
	os.Remove(p.NftSum())
	if err := os.WriteFile(p.OffsiteAddrs(), []byte(elemB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(t.Context(), p); !errors.Is(err, ErrDrift) {
		t.Errorf("Check after the stopped put-back: %v, want ErrDrift", err)
	}
	if _, err := EnsureRules(t.Context(), p, defaultConfig(t), true); err != nil {
		t.Errorf("EnsureRules: %v", err)
	}
}

func TestSavedSet_RefusesAWrongModeOrOwner_LockRefusesANonRegularFile(t *testing.T) {
	p, _, _ := freshNode(t)
	if err := os.WriteFile(p.OffsiteAddrs(), []byte(elemA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantSaved(t, p, elemA)
	if err := os.Chmod(p.OffsiteAddrs(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := SavedSet(p); err == nil {
		t.Error("SavedSet of a 0644 addresses file: nil error")
	}
	if err := os.Chmod(p.OffsiteAddrs(), 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 { // only root can give the file away
		if err := os.Chown(p.OffsiteAddrs(), 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if _, err := SavedSet(p); err == nil {
			t.Error("SavedSet of an addresses file owned by another uid: nil error")
		}
	}
	// A FIFO or a directory at the lock path is refused, and the FIFO does not block.
	os.Remove(p.NftLock())
	if err := syscall.Mkfifo(p.NftLock(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(t.Context(), p); !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("Check with a FIFO at the lock path: %v, want ErrUnverified naming it", err)
	}
	if _, err := SavedSet(p); err == nil {
		t.Error("SavedSet with a FIFO at the lock path: nil error")
	}
}

// InstallSet, the only writer of the addresses file, repairs its mode even
// when the set is unchanged: otherwise SavedSet refuses it for good.
func TestInstallSet_RepairsTheAddressesFileMode(t *testing.T) {
	p, _, _ := freshNode(t)
	install(t, p, elemA)
	if err := os.Chmod(p.OffsiteAddrs(), 0o644); err != nil {
		t.Fatal(err)
	}
	install(t, p, elemA)
	wantSaved(t, p, elemA)
}

// A path that is not a regular file is replaced, never read: a FIFO would block
// a plain read, and a link would lead the read, or the write, elsewhere. Every
// reader refuses such a path, so it holds no set: the put-back after a failure
// leaves no addresses file (none), never the FIFO or the link again.
func TestInstallSet_ANonRegularAddressesPathIsReplacedNotRead(t *testing.T) {
	// installNoBlock is InstallSet, failing the test instead of hanging when
	// the call blocks on what lies at the path.
	installNoBlock := func(t *testing.T, p nodecfg.Paths, ss ...string) error {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- InstallSet(t.Context(), p, defaultConfig(t), set(ss...)) }()
		select {
		case err := <-done:
			return err
		case <-time.After(time.Minute):
			t.Fatal("InstallSet blocked on the addresses path")
			return nil
		}
	}
	// node is freshNode whose nft does not read the addresses path at a load
	// (its own cat would block on a FIFO there).
	node := func(t *testing.T) (nodecfg.Paths, string) {
		p, dir, _ := freshNode(t)
		t.Setenv("SPNFT_ADDRS", filepath.Join(dir, "none"))
		return p, dir
	}
	wantRegular := func(t *testing.T, p nodecfg.Paths, ss ...string) {
		t.Helper()
		if fi, err := os.Lstat(p.OffsiteAddrs()); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("the addresses path after InstallSet: %v, %v; want a regular file", fi, err)
		}
		wantSaved(t, p, ss...)
		leftovers(t, p)
	}
	t.Run("fifo", func(t *testing.T) {
		p, dir := node(t)
		if err := syscall.Mkfifo(p.OffsiteAddrs(), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := installNoBlock(t, p, elemA); err != nil {
			t.Fatalf("InstallSet over a FIFO: %v", err)
		}
		wantRegular(t, p, elemA)
		wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemA))
	})
	t.Run("link to a fifo", func(t *testing.T) {
		p, _ := node(t)
		target := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(target, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p.OffsiteAddrs()); err != nil {
			t.Fatal(err)
		}
		if err := installNoBlock(t, p, elemA); err != nil {
			t.Fatalf("InstallSet over a link: %v", err)
		}
		wantRegular(t, p, elemA)
		if fi, err := os.Lstat(target); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
			t.Errorf("the link's target was replaced: %v, %v", fi, err)
		}
	})
	t.Run("link to a file", func(t *testing.T) {
		p, _ := node(t)
		target := filepath.Join(t.TempDir(), "addrs")
		if err := os.WriteFile(target, []byte(elemA+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p.OffsiteAddrs()); err != nil {
			t.Fatal(err)
		}
		if err := installNoBlock(t, p, elemA); err != nil {
			t.Fatalf("InstallSet over a link: %v", err)
		}
		wantRegular(t, p, elemA)
		wantFile(t, "the link's target", target, []byte(elemA+"\n"))
	})
	t.Run("larger than the bound", func(t *testing.T) {
		p, _ := node(t)
		big := bytes.Repeat([]byte(elemC+"\n"), maxAddrsFile/len(elemC)+1)
		if err := os.WriteFile(p.OffsiteAddrs(), big, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := installNoBlock(t, p, elemA); err != nil {
			t.Fatalf("InstallSet over an oversized file: %v", err)
		}
		wantRegular(t, p, elemA)
	})
	t.Run("put-back after a failure leaves no addresses file", func(t *testing.T) {
		p, dir := node(t)
		install(t, p, elemA)
		if err := os.Remove(p.OffsiteAddrs()); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p.OffsiteAddrs(), 0o600); err != nil {
			t.Fatal(err)
		}
		// The checksum write fails (a directory in its place).
		if err := os.Remove(p.NftSum()); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p.NftSum(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := installNoBlock(t, p, elemB); err == nil {
			t.Fatal("InstallSet with an unwritable checksum file: nil error")
		}
		wantFile(t, "ruleset file", p.NftFile(), renderSet(t, elemA))
		wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemA))
		wantFile(t, "addresses file (put back as none)", p.OffsiteAddrs(), []byte("<absent>"))
		wantSaved(t, p)
		leftovers(t, p)
	})
}

// The other kinds a previous addresses path can be: a socket and a device are
// removed without being read and replaced; an oversized file is put back as
// none after a failure (never its content); a directory stays an error and is
// left as it is.
func TestInstallSet_OtherPreviousAddressesPaths(t *testing.T) {
	node := func(t *testing.T) (nodecfg.Paths, string) {
		p, dir, _ := freshNode(t)
		t.Setenv("SPNFT_ADDRS", filepath.Join(dir, "none"))
		return p, dir
	}
	failSum := func(t *testing.T, p nodecfg.Paths) {
		t.Helper()
		os.Remove(p.NftSum())
		if err := os.Mkdir(p.NftSum(), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("socket", func(t *testing.T) {
		p, _ := node(t)
		l, err := net.Listen("unix", p.OffsiteAddrs())
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemA)); err != nil {
			t.Fatalf("InstallSet over a socket: %v", err)
		}
		wantSaved(t, p, elemA)
	})
	t.Run("device", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("creating a device node needs root")
		}
		p, _ := node(t)
		// the null device's numbers: harmless if opened
		if err := syscall.Mknod(p.OffsiteAddrs(), syscall.S_IFCHR|0o600, 1<<8|3); err != nil {
			t.Fatal(err)
		}
		if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemA)); err != nil {
			t.Fatalf("InstallSet over a device: %v", err)
		}
		wantSaved(t, p, elemA)
	})
	t.Run("oversized file, put back as none", func(t *testing.T) {
		p, dir := node(t)
		install(t, p, elemA)
		big := bytes.Repeat([]byte(elemC+"\n"), maxAddrsFile/len(elemC)+1)
		if err := os.WriteFile(p.OffsiteAddrs(), big, 0o600); err != nil {
			t.Fatal(err)
		}
		failSum(t, p)
		if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemB)); err == nil {
			t.Fatal("InstallSet with an unwritable checksum file: nil error")
		}
		wantFile(t, "addresses file (put back as none)", p.OffsiteAddrs(), []byte("<absent>"))
		wantFile(t, "loaded tables", filepath.Join(dir, "loaded"), renderSet(t, elemA))
		leftovers(t, p)
	})
	t.Run("directory: an error, left as it is", func(t *testing.T) {
		p, _ := node(t)
		install(t, p, elemA)
		os.Remove(p.OffsiteAddrs())
		if err := os.Mkdir(p.OffsiteAddrs(), 0o700); err != nil {
			t.Fatal(err)
		}
		inner := filepath.Join(p.OffsiteAddrs(), "keep")
		if err := os.WriteFile(inner, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := InstallSet(t.Context(), p, defaultConfig(t), set(elemB)); err == nil {
			t.Fatal("InstallSet over a directory: nil error")
		}
		if _, err := os.Stat(inner); err != nil {
			t.Errorf("the directory's content was touched: %v", err)
		}
		if err := Check(t.Context(), p); err != nil {
			t.Errorf("Check after the refused install: %v", err)
		}
	})
}
