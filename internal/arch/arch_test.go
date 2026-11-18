package arch

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const seg = "00000002000000010000003F"

// syncRecorder replaces the fsync seam and records the path of every call.
func syncRecorder(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	old := fsync
	fsync = func(f *os.File) error {
		calls = append(calls, f.Name())
		return f.Sync()
	}
	t.Cleanup(func() { fsync = old })
	return &calls
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n []string
	for _, e := range es {
		n = append(n, e.Name())
	}
	return n
}

// source makes a WAL file outside the spool and returns its path.
func source(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wal")
	writeFile(t, p, b)
	return p
}

func TestPush_NewSegment(t *testing.T) {
	spool := t.TempDir()
	calls := syncRecorder(t)
	data := bytes.Repeat([]byte("w"), 1<<20)
	if err := push(spool, source(t, data), seg); err != nil {
		t.Fatal(err)
	}
	if got := entries(t, spool); len(got) != 1 || got[0] != seg {
		t.Fatalf("spool holds %v, want only %s", got, seg)
	}
	if !bytes.Equal(readFile(t, filepath.Join(spool, seg)), data) {
		t.Fatal("content differs")
	}
	fi, _ := os.Stat(filepath.Join(spool, seg))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	// The temporary file before the link, then the directory after the unlink.
	if len(*calls) != 2 || !strings.HasPrefix(filepath.Base((*calls)[0]), ".tmp-"+seg+"-") || (*calls)[1] != spool {
		t.Fatalf("fsync calls %v", *calls)
	}
}

func TestPush_IdenticalIsSuccessAndSynced(t *testing.T) {
	spool := t.TempDir()
	data := []byte("segment content")
	writeFile(t, filepath.Join(spool, seg), data)
	calls := syncRecorder(t)
	if err := push(spool, source(t, data), seg); err != nil {
		t.Fatal(err)
	}
	if got := entries(t, spool); len(got) != 1 {
		t.Fatalf("spool holds %v", got)
	}
	n := len(*calls)
	if n < 2 || (*calls)[n-2] != filepath.Join(spool, seg) || (*calls)[n-1] != spool {
		t.Fatalf("fsync calls %v: want the target, then the directory, last", *calls)
	}
}

func TestPush_DifferentContentFails(t *testing.T) {
	spool := t.TempDir()
	writeFile(t, filepath.Join(spool, seg), []byte("first"))
	for _, other := range [][]byte{[]byte("other"), []byte("firs"), []byte("first+")} {
		if err := push(spool, source(t, other), seg); err == nil {
			t.Fatalf("%q over %q accepted", other, "first")
		}
	}
	if got := readFile(t, filepath.Join(spool, seg)); string(got) != "first" {
		t.Fatalf("target changed to %q", got)
	}
	// Lengths that differ only past a whole read buffer.
	big := filepath.Join(spool, "000000010000000000000001")
	writeFile(t, big, make([]byte, 64<<10))
	if err := push(spool, source(t, make([]byte, 64<<10+1)), filepath.Base(big)); err == nil {
		t.Fatal("longer content accepted")
	}
	if err := push(spool, source(t, make([]byte, 64<<10)), filepath.Base(big)); err != nil {
		t.Fatalf("control: identical refused: %v", err)
	}
	os.Remove(big)
	if got := entries(t, spool); len(got) != 1 {
		t.Fatalf("spool holds %v", got)
	}
}

func TestPush_TargetIsLinkFails(t *testing.T) {
	spool := t.TempDir()
	data := []byte("same")
	elsewhere := filepath.Join(t.TempDir(), "f")
	writeFile(t, elsewhere, data)
	if err := os.Symlink(elsewhere, filepath.Join(spool, seg)); err != nil {
		t.Fatal(err)
	}
	if err := push(spool, source(t, data), seg); err == nil {
		t.Fatal("a link at the final name was accepted")
	}
	fi, err := os.Lstat(filepath.Join(spool, seg))
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link replaced")
	}
	if got := entries(t, spool); len(got) != 1 {
		t.Fatalf("spool holds %v", got)
	}
}

func TestPush_LinkAtTemporaryNameDrawsAnother(t *testing.T) {
	spool := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	writeFile(t, victim, []byte("untouched"))
	draws := []string{"aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"}
	old := randHex
	randHex = func() (string, error) { s := draws[0]; draws = draws[1:]; return s, nil }
	t.Cleanup(func() { randHex = old })
	planted := filepath.Join(spool, ".tmp-"+seg+"-aaaaaaaaaaaaaaaa")
	if err := os.Symlink(victim, planted); err != nil {
		t.Fatal(err)
	}
	if err := push(spool, source(t, []byte("wal")), seg); err != nil {
		t.Fatal(err)
	}
	if len(draws) != 0 {
		t.Fatal("no second draw")
	}
	if string(readFile(t, victim)) != "untouched" {
		t.Fatal("written through the link")
	}
	if string(readFile(t, filepath.Join(spool, seg))) != "wal" {
		t.Fatal("segment not archived")
	}
	if fi, err := os.Lstat(planted); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("planted link disturbed")
	}
}

func TestPush_DrawsAreBounded(t *testing.T) {
	spool := t.TempDir()
	old := randHex
	randHex = func() (string, error) { return "cccccccccccccccc", nil }
	t.Cleanup(func() { randHex = old })
	if err := os.Symlink("/nonexistent", filepath.Join(spool, ".tmp-"+seg+"-cccccccccccccccc")); err != nil {
		t.Fatal(err)
	}
	if err := push(spool, source(t, []byte("wal")), seg); err == nil {
		t.Fatal("endless collisions accepted")
	}
}

func TestPush_KilledBeforeLinkLeavesNoFinalName(t *testing.T) {
	if spool := os.Getenv("SP_ARCH_KILL_SPOOL"); spool != "" {
		beforeLink = func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }
		_ = push(spool, os.Getenv("SP_ARCH_KILL_SRC"), seg)
		os.Exit(0) // not reached
	}
	spool := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPush_KilledBeforeLinkLeavesNoFinalName$")
	cmd.Env = append(os.Environ(), "SP_ARCH_KILL_SPOOL="+spool, "SP_ARCH_KILL_SRC="+source(t, []byte("wal")))
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("child not killed at the seam: %v", err)
	}
	got := entries(t, spool)
	// Control: the child reached the seam with its temporary file written.
	if len(got) != 1 || !strings.HasPrefix(got[0], ".tmp-"+seg+"-") {
		t.Fatalf("spool holds %v, want only one temporary file", got)
	}
}

func TestPush_RefusesNames(t *testing.T) {
	spool := t.TempDir()
	src := source(t, []byte("wal"))
	for _, n := range []string{"", "--config=x", "-" + seg[1:], strings.ToLower(seg), strings.ToLower(seg) + ".partial", "../" + seg, "x/" + seg, seg + "0", "latest"} {
		if err := push(spool, src, n); !errors.Is(err, errRefused) {
			t.Errorf("push(%q) = %v, want refused", n, err)
		}
	}
	if got := entries(t, spool); len(got) != 0 {
		t.Fatalf("spool holds %v", got)
	}
	if err := push(spool, src, seg+".00000028.backup"); err != nil {
		t.Fatalf("control: label refused: %v", err)
	}
}

// rspool makes a restore spool with req/ and out/.
func rspool(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for _, s := range []string{"req", "out"} {
		if err := os.Mkdir(filepath.Join(d, s), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestGet_ServedSegment(t *testing.T) {
	rs := rspool(t)
	dest := filepath.Join(t.TempDir(), "RECOVERYXLOG")
	data := bytes.Repeat([]byte("s"), maxAnswer) // the bound itself is served
	// The answer arrives only after the request is seen.
	done := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(rs, "req", seg)); err == nil {
				tmp := filepath.Join(rs, "out", ".t")
				if err := os.WriteFile(tmp, data, 0o600); err != nil {
					done <- err
					return
				}
				done <- os.Rename(tmp, filepath.Join(rs, "out", seg))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		done <- errors.New("request never seen")
	}()
	if err := get(rs, seg, dest, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, dest), data) {
		t.Fatal("content differs")
	}
	if got := entries(t, filepath.Dir(dest)); len(got) != 1 {
		t.Fatalf("destination directory holds %v", got)
	}
	if e := append(entries(t, filepath.Join(rs, "req")), entries(t, filepath.Join(rs, "out"))...); len(e) != 0 {
		t.Fatalf("request or answer left: %v", e)
	}
}

func TestGet_NoneMarkerExits1(t *testing.T) {
	rs := rspool(t)
	useRSpool(t, rs)
	writeFile(t, filepath.Join(rs, "out", seg+".none"), nil)
	dest := filepath.Join(t.TempDir(), "d")
	if code := Main([]string{"supapace-arch.test", "get", seg, dest}, os.Stderr); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if _, err := os.Lstat(dest); err == nil {
		t.Fatal("destination written")
	}
	if e := append(entries(t, filepath.Join(rs, "req")), entries(t, filepath.Join(rs, "out"))...); len(e) != 0 {
		t.Fatalf("request or marker left: %v", e)
	}
	// Control: the same path with an answer exits 0.
	writeFile(t, filepath.Join(rs, "out", seg), []byte("x"))
	if code := Main([]string{"supapace-arch.test", "get", seg, dest}, os.Stderr); code != 0 {
		t.Fatalf("control: exit %d", code)
	}
}

func shortTimeout(t *testing.T) {
	old := getTimeout
	getTimeout = 300 * time.Millisecond
	t.Cleanup(func() { getTimeout = old })
}

func TestGet_TimeoutExits200(t *testing.T) {
	rs := rspool(t)
	useRSpool(t, rs)
	shortTimeout(t)
	if code := Main([]string{"supapace-arch.test", "get", seg, filepath.Join(t.TempDir(), "d")}, os.Stderr); code != 200 {
		t.Fatalf("exit %d, want 200", code)
	}
	if _, err := os.Lstat(filepath.Join(rs, "req", seg)); err != nil {
		t.Fatal("request not made")
	}
}

func TestGet_RefusesNames(t *testing.T) {
	rs := rspool(t)
	useRSpool(t, rs)
	dest := filepath.Join(t.TempDir(), "d")
	for _, n := range []string{"", "--config=x", seg + ".00000028.backup", strings.ToLower(seg), seg + ".partial", "../" + seg, "latest"} {
		// Never "not in the archive": the server would end recovery on it.
		if code := Main([]string{"supapace-arch.test", "get", n, dest}, os.Stderr); code != 201 {
			t.Errorf("get %q: exit %d, want 201", n, code)
		}
	}
	if e := entries(t, filepath.Join(rs, "req")); len(e) != 0 {
		t.Fatalf("requests made: %v", e)
	}
}

func TestGet_OutIsLinkIgnored(t *testing.T) {
	rs := rspool(t)
	elsewhere := filepath.Join(t.TempDir(), "f")
	writeFile(t, elsewhere, []byte("not an answer"))
	if err := os.Symlink(elsewhere, filepath.Join(rs, "out", seg)); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "d")
	if err := get(rs, seg, dest, 300*time.Millisecond); !errors.Is(err, errTimeout) {
		t.Fatalf("got %v, want a timeout", err)
	}
	if _, err := os.Lstat(dest); err == nil {
		t.Fatal("served through a link")
	}
}

func TestGet_OutIsFifoIgnored(t *testing.T) {
	rs := rspool(t)
	if err := syscall.Mkfifo(filepath.Join(rs, "out", seg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := get(rs, seg, filepath.Join(t.TempDir(), "d"), 300*time.Millisecond); !errors.Is(err, errTimeout) {
		t.Fatalf("got %v, want a timeout", err)
	}
}

func TestGet_OversizeRefused(t *testing.T) {
	rs := rspool(t)
	useRSpool(t, rs)
	writeFile(t, filepath.Join(rs, "out", seg), make([]byte, maxAnswer+1))
	dir := t.TempDir()
	if code := Main([]string{"supapace-arch.test", "get", seg, filepath.Join(dir, "d")}, os.Stderr); code != 201 {
		t.Fatalf("exit %d, want 201", code)
	}
	if e := entries(t, dir); len(e) != 0 {
		t.Fatalf("destination directory holds %v", e)
	}
}

func TestGet_RequestIsLinkNotFollowed(t *testing.T) {
	rs := rspool(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Symlink(victim, filepath.Join(rs, "req", seg)); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(rs, "out", seg), []byte("x"))
	if err := get(rs, seg, filepath.Join(t.TempDir(), "d"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(victim); err == nil {
		t.Fatal("created through the link")
	}
}

func TestGet_LinkAtTemporaryNameDrawsAnother(t *testing.T) {
	rs := rspool(t)
	writeFile(t, filepath.Join(rs, "out", seg), []byte("answer"))
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	writeFile(t, victim, []byte("untouched"))
	draws := []string{"aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"}
	old := randHex
	randHex = func() (string, error) { s := draws[0]; draws = draws[1:]; return s, nil }
	t.Cleanup(func() { randHex = old })
	if err := os.Symlink(victim, filepath.Join(dir, ".d.tmp-aaaaaaaaaaaaaaaa")); err != nil {
		t.Fatal(err)
	}
	if err := get(rs, seg, filepath.Join(dir, "d"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if string(readFile(t, victim)) != "untouched" || string(readFile(t, filepath.Join(dir, "d"))) != "answer" {
		t.Fatal("wrong file written")
	}
}

func TestMain_Usage(t *testing.T) {
	for _, a := range [][]string{{"a"}, {"a", "x"}, {"a", "push"}, {"a", "push", "p"}, {"a", "push", "p", seg, "extra"}} {
		if code := Main(a, os.Stderr); code != 2 {
			t.Errorf("%v: exit %d, want 2", a, code)
		}
	}
	// A wrong get line is an error, never "not in the archive".
	for _, a := range [][]string{{"a", "get"}, {"a", "get", seg}, {"a", "get", seg, "d", "extra"}} {
		if code := Main(a, os.Stderr); code != 201 {
			t.Errorf("%v: exit %d, want 201", a, code)
		}
	}
}

func useSpool(t *testing.T, d string) {
	old := spoolDir
	spoolDir = d
	t.Cleanup(func() { spoolDir = old })
}

func useRSpool(t *testing.T, d string) {
	old := rspoolDir
	rspoolDir = d
	t.Cleanup(func() { rspoolDir = old })
}

// The binary takes its directories from nowhere but its own variables: a
// variable of the environment changes nothing, under any program name.
func TestMain_ReadsNoEnvironment(t *testing.T) {
	spool := t.TempDir()
	t.Setenv("SUPAPACE_ARCH_SPOOL", spool)
	src := source(t, []byte("wal"))
	useSpool(t, filepath.Join(t.TempDir(), "absent"))
	for _, argv0 := range []string{"/opt/supapace/tools/supapace-arch", "/x/arch.test"} {
		if code := Main([]string{argv0, "push", src, seg}, os.Stderr); code != 1 {
			t.Fatalf("%s: exit %d, want 1 (no spool at the set path)", argv0, code)
		}
	}
	if e := entries(t, spool); len(e) != 0 {
		t.Fatalf("spool holds %v", e)
	}
	b, err := os.ReadFile("arch.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"Getenv", "LookupEnv", "Environ"} {
		if bytes.Contains(b, []byte(f)) {
			t.Errorf("arch.go calls os.%s", f)
		}
	}
	// Control: the same call with the directory set by the test.
	useSpool(t, spool)
	if code := Main([]string{"/x/arch.test", "push", src, seg}, os.Stderr); code != 0 {
		t.Fatalf("control: exit %d", code)
	}
	if e := entries(t, spool); len(e) != 1 {
		t.Fatalf("control: spool holds %v", e)
	}
}

// A .partial segment is acknowledged without touching anything: the source
// is never opened (a missing one also succeeds) and the spool is unchanged.
func TestPush_PartialAcceptedAndDiscarded(t *testing.T) {
	spool := t.TempDir()
	writeFile(t, filepath.Join(spool, seg), []byte("kept"))
	useSpool(t, spool)
	before := entries(t, spool)
	for _, src := range []string{source(t, []byte("wal")), filepath.Join(t.TempDir(), "absent")} {
		if code := Main([]string{"supapace-arch", "push", src, seg + ".partial"}, os.Stderr); code != 0 {
			t.Fatalf("push %s: exit %d, want 0", src, code)
		}
	}
	if got := entries(t, spool); strings.Join(got, ",") != strings.Join(before, ",") {
		t.Fatalf("spool holds %v, want %v", got, before)
	}
	if string(readFile(t, filepath.Join(spool, seg))) != "kept" {
		t.Fatal("spool content changed")
	}
	// Control: a segment name on the same path does reach the source.
	if code := Main([]string{"supapace-arch", "push", filepath.Join(t.TempDir(), "absent"), "000000010000000000000001"}, os.Stderr); code != 1 {
		t.Fatalf("control: exit %d, want 1", code)
	}
}

func TestPush_PartialShapesRefused(t *testing.T) {
	spool := t.TempDir()
	useSpool(t, spool)
	src := source(t, []byte("wal"))
	for _, n := range []string{
		"", ".partial", strings.ToLower(seg) + ".partial", seg[:23] + ".partial", seg + "0.partial",
		"-" + seg[1:] + ".partial", "x/" + seg + ".partial", "../" + seg + ".partial",
		seg + ".partial.partial", seg + ".00000028.backup.partial", "00000003.history.partial",
		seg + ".partial\x00",
	} {
		if code := Main([]string{"supapace-arch", "push", src, n}, os.Stderr); code != 1 {
			t.Errorf("push %q: exit %d, want 1", n, code)
		}
	}
	if e := entries(t, spool); len(e) != 0 {
		t.Fatalf("spool holds %v", e)
	}
}
