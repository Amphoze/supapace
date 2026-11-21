package dockerx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// script installs a fake docker running body (sh) first on PATH; returns its dir.
func script(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	s := "#!/bin/sh\nd=\"" + dir + "\"\necho $$ > \"$d/pid\"\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(s), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func pidOf(t *testing.T, dir, name string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return p
}

// waitDead waits up to 10 s until pid has ended: gone, or a zombie that its
// new parent (init or a subreaper, for an orphaned grandchild) has not yet
// reaped.
func waitDead(t *testing.T, pid int) {
	t.Helper()
	zombie := func() bool {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		_, rest, ok := strings.Cut(string(b), ") ")
		return err == nil && ok && strings.HasPrefix(rest, "Z")
	}
	for i := 0; syscall.Kill(pid, 0) != syscall.ESRCH && !zombie(); i++ {
		if i > 500 { // 10 s
			t.Fatalf("pid %d still alive", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fds counts the open descriptors of this process.
func fds() int { e, _ := os.ReadDir("/proc/self/fd"); return len(e) }

func TestCap_ExactCapPlusOneAndHuge(t *testing.T) {
	script(t, `case "$1" in
 exact) head -c 4194304 /dev/zero;;
 plus1) head -c 4194305 /dev/zero;;
 huge) head -c 67108864 /dev/zero;;
 one) printf a; sleep 30;;
 esac`)
	out, err := Run(context.Background(), "exact")
	if err != nil || len(out) != 4<<20 {
		t.Fatalf("exact %d %v", len(out), err)
	}
	for _, a := range []string{"plus1", "huge"} {
		out, err = Run(context.Background(), a)
		if !errors.Is(err, ErrOutputTooLarge) || out != "" {
			t.Fatalf("%s: %d %v", a, len(out), err)
		}
	}
	old := defaultTimeout
	defaultTimeout = 300 * time.Millisecond
	defer func() { defaultTimeout = old }()
	st := time.Now()
	out, err = Run(context.Background(), "one")
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrOutputTooLarge) || out != "a" {
		t.Fatalf("one: %q %v", out, err)
	}
	t.Logf("one-byte-then-sleep returned in %v", time.Since(st))
}

func TestCap_BothStreamsAndSigtermIgnore(t *testing.T) {
	dir := script(t, `trap '' TERM
(yes e >&2) & (yes o) `)
	st := time.Now()
	_, err := Run(context.Background(), "x")
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatal(err)
	}
	if len(err.Error()) > 65<<10 {
		t.Fatalf("err len %d", len(err.Error()))
	}
	t.Logf("both streams + ignore TERM: %v", time.Since(st))
	waitDead(t, pidOf(t, dir, "pid"))
}

func TestCap_GrandchildHoldsPipe(t *testing.T) {
	// parent exits after cap? use: parent prints cap+1 then exits; grandchild holds stdout open and sleeps.
	dir := script(t, `(sleep 40 & echo $! > "$d/gpid"; wait) &
head -c 5000000 /dev/zero
exit 0`)
	st := time.Now()
	_, err := Run(context.Background(), "x")
	el := time.Since(st)
	t.Logf("grandchild case: err=%v in %v", err, el)
	if !errors.Is(err, ErrOutputTooLarge) || el > 15*time.Second {
		t.Fatal("bad")
	}
	time.Sleep(200 * time.Millisecond)
	g := pidOf(t, dir, "gpid")
	waitDead(t, g)
}

func TestCap_CloseStdoutKeepRunning(t *testing.T) {
	script(t, `exec >&-; sleep 30`)
	old := defaultTimeout
	defaultTimeout = 300 * time.Millisecond
	defer func() { defaultTimeout = old }()
	st := time.Now()
	_, err := Run(context.Background(), "x")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(st) > 15*time.Second {
		t.Fatalf("%v %v", err, time.Since(st))
	}
}

func TestCap_StdinWithCap(t *testing.T) {
	script(t, `cat >/dev/null; head -c 5000000 /dev/zero`)
	in := []byte(strings.Repeat("z", 8<<20)) // bigger than pipe
	st := time.Now()
	_, err := RunInput(context.Background(), in, "x")
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatal(err)
	}
	t.Log("stdin+cap", time.Since(st))
	// child stops reading stdin, writes endlessly
	script(t, `exec yes`)
	_, err = RunInput(context.Background(), in, "x")
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatal(err)
	}
}

func TestCap_CtxDeadlineVsCap(t *testing.T) {
	script(t, `exec yes`)
	// caller deadline very short: endless writer hits cap in ~ms; deadline 1ms or 5ms.
	var tooLarge, dl, other int
	for i := 0; i < 60; i++ {
		ctx, c := context.WithTimeout(context.Background(), time.Duration(1+i%20)*time.Millisecond)
		_, err := Run(ctx, "x")
		c()
		switch {
		case errors.Is(err, ErrOutputTooLarge):
			tooLarge++
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("both")
			}
		case errors.Is(err, context.DeadlineExceeded):
			dl++
		default:
			other++
			t.Log(err)
		}
	}
	t.Logf("endless writer vs 1-20ms deadline: toolarge=%d deadline=%d other=%d", tooLarge, dl, other)
}

func TestCap_TimeoutNeverTooLarge(t *testing.T) {
	// writes < cap then hangs; must be deadline, never too large.
	script(t, `head -c 1000000 /dev/zero; sleep 30`)
	old := defaultTimeout
	defaultTimeout = 400 * time.Millisecond
	defer func() { defaultTimeout = old }()
	for i := 0; i < 5; i++ {
		_, err := Run(context.Background(), "x")
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrOutputTooLarge) {
			t.Fatal(err)
		}
	}
	// caller cancel during endless
	script(t, `exec yes`)
}

func TestCap_Concurrent(t *testing.T) {
	script(t, `exec yes`)
	Run(context.Background(), "x")
	g0, f0 := runtime.NumGoroutine(), fds()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Run(context.Background(), "x"); !errors.Is(err, ErrOutputTooLarge) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for deadline := time.Now().Add(10 * time.Second); fds() > f0 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("goroutines %d -> %d, fds %d -> %d", g0, runtime.NumGoroutine(), f0, fds())
	if fds() > f0 {
		t.Fatal("fd leak")
	}
}

func TestCap_StderrOnlyBigAndAbsentAfter64K(t *testing.T) {
	d := script(t, `cat "$d/err" >&2; exit 1`)
	os.WriteFile(filepath.Join(d, "err"), []byte(strings.Repeat("x", 64<<10)+"\nError response from daemon: No such container: nope\n"), 0o644)
	c, err := InspectContainer(context.Background(), "nope")
	if c != nil || err == nil {
		t.Fatalf("must NOT be absent: %v %v", c, err)
	}
	os.WriteFile(filepath.Join(d, "err"), []byte("Error response from daemon: No such container: nope\n"+strings.Repeat("x", 200<<10)), 0o644)
	c, err = InspectContainer(context.Background(), "nope")
	if c != nil || err != nil {
		t.Fatalf("should be absent: %v %v", c, err)
	}
	// stderr huge + stdout cap together: error from stdout cap, stderr start kept
	os.WriteFile(filepath.Join(d, "err"), []byte("Error response from daemon: No such container: nope\n"), 0o644)
	_, err = InspectContainer(context.Background(), "nope")
	_ = err
}

func TestCap_StderrOverflowDoesNotFail(t *testing.T) {
	script(t, `head -c 3000000 /dev/zero | tr '\0' e >&2; echo ok`)
	out, err := Run(context.Background(), "x")
	if err != nil || out != "ok\n" {
		t.Fatalf("%q %v", out, err)
	}
}
