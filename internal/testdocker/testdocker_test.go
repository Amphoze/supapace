package testdocker

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

func image(t *testing.T) string {
	t.Helper()
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("docker", "image", "inspect", im.ControlPlane).Run(); err != nil {
		t.Skipf("image %s not present", im.ControlPlane)
	}
	return im.ControlPlane
}

func name() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "sp-test-testdocker-" + hex.EncodeToString(b)
}

// present lists the containers (or, with volume, the volumes) of that name.
func present(n string, volume bool) string {
	args := []string{"ps", "-aq", "--filter", "name=^" + n + "$"}
	if volume {
		args = []string{"volume", "ls", "-q", "--filter", "name=^" + n + "$"}
	}
	out, _ := exec.Command("docker", args...).Output()
	return strings.TrimSpace(string(out))
}

// The child of TestWatchdog_RemovesWhatAKilledProcessLeft: it labels a
// running container and a volume, prints their name and waits to be killed.
func TestWatchdog_Child(t *testing.T) {
	n := os.Getenv("TESTDOCKER_CHILD")
	if n == "" {
		t.Skip("run by TestWatchdog_RemovesWhatAKilledProcessLeft")
	}
	l := Labels(t)
	if out, err := exec.Command("docker", slices.Concat([]string{"volume", "create"}, l, []string{n})...).CombinedOutput(); err != nil {
		t.Fatalf("volume: %v %s", err, out)
	}
	if out, err := exec.Command("docker", slices.Concat([]string{"run", "-d", "--name", n, "--network", "none"}, l,
		[]string{"-v", n + ":/v", "--entrypoint", "sleep", os.Getenv("TESTDOCKER_IMAGE"), "600"})...).CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	os.Stdout.WriteString("started\n")
	time.Sleep(10 * time.Minute)
}

// A test process killed with SIGKILL runs no cleanup: its watchdog removes
// its running container and its volume; another process's are not touched.
func TestWatchdog_RemovesWhatAKilledProcessLeft(t *testing.T) {
	img := image(t)
	n, other := name(), name()
	t.Cleanup(func() {
		exec.Command("docker", "rm", "-f", "-v", n, other).Run()
		exec.Command("docker", "volume", "rm", "-f", n).Run()
	})
	// Control: a container of this process, labelled as a test's, stays.
	if out, err := exec.Command("docker", slices.Concat([]string{"run", "-d", "--name", other, "--network", "none"}, Labels(t),
		[]string{"--entrypoint", "sleep", img, "600"})...).CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(exe, "-test.run", "^TestWatchdog_Child$", "-test.timeout", "15m")
	child.Env = append(os.Environ(), "TESTDOCKER_CHILD="+n, "TESTDOCKER_IMAGE="+img)
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	line := make(chan string, 1)
	go func() { l, _ := bufio.NewReader(out).ReadString('\n'); line <- l }()
	select {
	case l := <-line:
		if l != "started\n" {
			t.Fatalf("child: %q", l)
		}
	case <-time.After(2 * time.Minute):
		t.Fatal("the child did not start its container within 2 min")
	}
	if present(n, false) == "" || present(n, true) == "" {
		t.Fatal("helper: the child's container or volume is not there")
	}
	killed := time.Now()
	child.Process.Signal(syscall.SIGKILL)
	child.Wait()
	for present(n, false) != "" || present(n, true) != "" {
		if time.Since(killed) > time.Minute {
			t.Fatalf("container %s or its volume still there 1 min after its process was killed", n)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("removed %v after SIGKILL", time.Since(killed).Round(100*time.Millisecond))
	if present(other, false) == "" {
		t.Error("the watchdog of a killed process removed another process's container")
	}
}

// The backstop: the first process receives SIGINT after the lifetime and
// keeps the container's first pid.
func TestBounded_EndsTheFirstProcess(t *testing.T) {
	img := image(t)
	n := name()
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", n).Run() })
	// A first process that ends on SIGINT and, until then, answers.
	cmd := []string{"sh", "-c", `trap "exit 7" INT; echo $$ > /tmp/pid; while :; do sleep 1; done`}
	if out, err := exec.Command("docker", slices.Concat([]string{"run", "-d", "--name", n, "--network", "none"}, Labels(t),
		boundedFor(3*time.Second, img, cmd...))...).CombinedOutput(); err != nil {
		t.Fatalf("run: %v %s", err, out)
	}
	pid := ""
	for end := time.Now().Add(time.Minute); pid == ""; time.Sleep(100 * time.Millisecond) {
		b, _ := exec.Command("docker", "exec", n, "cat", "/tmp/pid").Output()
		pid = strings.TrimSpace(string(b))
		if pid == "" && time.Now().After(end) {
			t.Fatal("the command never ran")
		}
	}
	if pid != "1" {
		t.Errorf("the command runs as pid %s, want 1", pid)
	}
	for end := time.Now().Add(time.Minute); ; time.Sleep(200 * time.Millisecond) {
		out, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", n).Output()
		if s := strings.TrimSpace(string(out)); s == "false 7" {
			break
		} else if time.Now().After(end) {
			t.Fatalf("1 min after a lifetime of 3 s the container is %q, want ended by SIGINT (exit 7)", s)
		}
	}
	// Control: the lifetime in use is long.
	if a := Bounded(img, "true"); !slices.Contains(a, "14400") {
		t.Errorf("Bounded: %q, want a lifetime of 14400 s", a)
	}
}
