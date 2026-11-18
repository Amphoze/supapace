package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// runRmtree runs `supapaced rmtree args...` with the node's paths pointing at
// a root whose node.json is a FIFO: reading any configuration would block,
// and the deadline fails the test.
func runRmtree(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	cfg := nodecfg.Paths{Root: t.TempDir()}
	if err := os.MkdirAll(filepath.Dir(cfg.NodeJSON()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(cfg.NodeJSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	oldPaths, oldOut, oldErr := paths, stdout, stderr
	paths, stdout, stderr = cfg, &out, &errb
	defer func() { paths, stdout, stderr = oldPaths, oldOut, oldErr }()
	done := make(chan int, 1)
	go func() { done <- run(append([]string{"rmtree"}, args...)) }()
	select {
	case code := <-done:
		return code, out.String(), errb.String()
	case <-time.After(30 * time.Second):
		t.Fatal("rmtree blocked: it read a configuration file")
		return 0, "", ""
	}
}

// tree makes dir/f and dir/sub/f and returns dir.
func tree(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"f", "sub/f"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func gone(p string) bool {
	_, err := os.Lstat(p)
	return os.IsNotExist(err)
}

func TestRmtreeCmd_Success(t *testing.T) {
	base := t.TempDir()
	a, b := tree(t, filepath.Join(base, "a")), tree(t, filepath.Join(base, "b"))
	code, out, errs := runRmtree(t, a, filepath.Join(base, "absent"), b)
	if code != 0 || out != "" || errs != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 0 and no output", code, out, errs)
	}
	if !gone(a) || !gone(b) {
		t.Fatal("a tree is still there")
	}
}

func TestRmtreeCmd_Usage(t *testing.T) {
	base := t.TempDir()
	keep := tree(t, filepath.Join(base, "keep"))
	for _, args := range [][]string{{}, {"rel"}, {keep, "rel/x"}, {"--keep-root"}, {"--", "rel"}, {"--keep-root", "rel"}, {keep, "--keep-root"}} {
		code, out, errs := runRmtree(t, args...)
		if code != 2 || out != "" || !oneLine(errs) {
			t.Errorf("args %q: exit %d, stdout %q, stderr %q; want 2 and one line", args, code, out, errs)
		}
	}
	// The flag package prints its usage for these.
	for _, args := range [][]string{{"-h"}, {"--bogus", keep}, {"--keep-root=maybe", keep}} {
		if code, out, errs := runRmtree(t, args...); code != 2 || out != "" || errs == "" {
			t.Errorf("args %q: exit %d, stdout %q, stderr %q; want 2", args, code, out, errs)
		}
	}
	if gone(keep) {
		t.Fatal("a usage error removed a tree")
	}
}

func TestRmtreeCmd_FirstFailureStops(t *testing.T) {
	base := t.TempDir()
	a, c := tree(t, filepath.Join(base, "a")), tree(t, filepath.Join(base, "c"))
	file := filepath.Join(base, "file\x1b[2J")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runRmtree(t, a, file, c)
	if code != 1 || out != "" || !oneLine(errs) || !strings.Contains(errs, "not a directory") {
		t.Fatalf("exit %d, stdout %q, stderr %q; want 1 and one line", code, out, errs)
	}
	if strings.Contains(errs, "\x1b") {
		t.Fatalf("stderr carries a raw escape byte: %q", errs)
	}
	if !gone(a) || gone(file) || gone(c) {
		t.Fatal("paths not handled in order up to the first failure")
	}
	if code, _, errs := runRmtree(t, base+"/c/"); code != 2 || !strings.Contains(errs, "clean") {
		t.Fatalf("unclean path: exit %d, stderr %q", code, errs)
	}
}

// TestRmtreeCmd_RefusesUID0 runs the command as uid 0 of a user namespace of
// its own (a child process mapping uid 0 to the test's uid): the refusal of
// the rmtree package is what the command shows, and nothing is removed.
func TestRmtreeCmd_RefusesUID0(t *testing.T) {
	keep := tree(t, filepath.Join(t.TempDir(), "keep"))
	cmd := exec.Command(os.Args[0], "-test.run=^TestRmtreeCmdAsUID0$", "-test.v")
	cmd.Env = append(os.Environ(), "RMTREE_UID0_HELPER="+keep)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		t.Skipf("cannot create a user namespace here: %v", err)
	}
	if err != nil || !strings.Contains(string(out), "HELPER-OK") {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if gone(keep) {
		t.Fatal("removed as uid 0")
	}
}

// TestRmtreeCmdAsUID0 runs only as the child of TestRmtreeCmd_RefusesUID0.
func TestRmtreeCmdAsUID0(t *testing.T) {
	keep := os.Getenv("RMTREE_UID0_HELPER")
	if keep == "" {
		t.Skip("helper of TestRmtreeCmd_RefusesUID0")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("euid %d in the helper; want 0", os.Geteuid())
	}
	for _, args := range [][]string{{keep}, {"--keep-root", keep}} {
		code, out, errs := runRmtree(t, args...)
		if code != 1 || out != "" || !oneLine(errs) || !strings.Contains(errs, "uid 0") {
			t.Fatalf("args %q: exit %d, stdout %q, stderr %q; want 1 and a refusal", args, code, out, errs)
		}
	}
	fmt.Println("HELPER-OK")
}

func TestRmtreeCmd_KeepRoot(t *testing.T) {
	base := t.TempDir()
	a, b := tree(t, filepath.Join(base, "a")), tree(t, filepath.Join(base, "b"))
	for _, args := range [][]string{{"--keep-root", a, b}, {"--keep-root", "--", a}, {"-keep-root", b}} {
		if code, out, errs := runRmtree(t, args...); code != 0 || out != "" || errs != "" {
			t.Fatalf("args %q: exit %d, stdout %q, stderr %q; want 0 and no output", args, code, out, errs)
		}
	}
	for _, p := range []string{a, b} {
		if es, err := os.ReadDir(p); err != nil || len(es) != 0 {
			t.Fatalf("%s after --keep-root: %v, %d entries", p, err, len(es))
		}
	}
	code, _, errs := runRmtree(t, "--keep-root", a, filepath.Join(base, "absent"))
	if code != 1 || !oneLine(errs) || !strings.Contains(errs, "no such file") {
		t.Fatalf("absent path under --keep-root: exit %d, stderr %q; want 1", code, errs)
	}
	if gone(a) {
		t.Fatal("--keep-root removed a root")
	}
}

// TestRmtreeCmd_PathsCheckedBeforeAnyRemoval gives a valid path and then one
// that is absolute but not clean: a usage error, and nothing is removed.
func TestRmtreeCmd_PathsCheckedBeforeAnyRemoval(t *testing.T) {
	base := t.TempDir()
	a := tree(t, filepath.Join(base, "a"))
	tree(t, filepath.Join(base, "b"))
	for _, args := range [][]string{{a, base + "/b/"}, {a, base + "//b"}, {"--keep-root", a, base + "/./b"}, {a, "/"}, {"--keep-root", a, "/"}} {
		code, out, errs := runRmtree(t, args...)
		if code != 2 || out != "" || !oneLine(errs) {
			t.Errorf("args %q: exit %d, stdout %q, stderr %q; want 2 and one line", args, code, out, errs)
		}
		if es, err := os.ReadDir(a); err != nil || len(es) != 2 {
			t.Fatalf("args %q: a usage error changed an earlier path: %v, %d entries", args, err, len(es))
		}
	}
}

func TestRmtreeCmd_UsageQuotesThePath(t *testing.T) {
	code, _, errs := runRmtree(t, "rel\x1b[2J\n")
	if code != 2 || !oneLine(errs) || strings.ContainsAny(errs, "\x1b") {
		t.Fatalf("exit %d, stderr %q; want 2 and the path quoted", code, errs)
	}
}
