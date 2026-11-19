//go:build reach && linux && (amd64 || arm64)

// The tests of this file enter real namespaces: they run as root on the bare
// test node, where this test binary (static) also serves as the listener
// inside two containers. NSDIAL_IMAGE names any loaded image; only its root
// filesystem is used.

package nsdial

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/dockerx"
)

const (
	portName   = 7101 // loopback: answers the container's name
	portBridge = 7102 // the bridge address: counts connections by source
	portCount  = 7103 // loopback: answers "own=N other=M" for portBridge
	portFilter = 7104 // loopback: SYNs dropped by a rule in the container's namespace
	prefix     = "sp-test-nsdial-"
)

func TestMain(m *testing.M) {
	if name := os.Getenv("NSDIAL_HELPER_NAME"); name != "" {
		serveHelper(name)
		return
	}
	os.Exit(m.Run())
}

// serveHelper runs inside a container, as its init process.
func serveHelper(name string) {
	var own, other atomic.Int64
	serve := func(addr string, h func(net.Conn)) {
		l, err := net.Listen("tcp4", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper:", err)
			os.Exit(1)
		}
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					continue
				}
				go func() { defer c.Close(); h(c) }()
			}
		}()
	}
	var bridge string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			bridge = n.IP.String()
		}
	}
	if bridge == "" {
		fmt.Fprintln(os.Stderr, "helper: no bridge address")
		os.Exit(1)
	}
	serve(fmt.Sprintf("127.0.0.1:%d", portName), func(c net.Conn) { io.WriteString(c, name+"\n") })
	serve(fmt.Sprintf("%s:%d", bridge, portBridge), func(c net.Conn) {
		// A connection made from this namespace to its own address has the
		// same address at both ends.
		if c.RemoteAddr().(*net.TCPAddr).IP.Equal(c.LocalAddr().(*net.TCPAddr).IP) {
			own.Add(1)
		} else {
			other.Add(1)
		}
		io.WriteString(c, "k") // the caller reads it: the count is taken before it returns
	})
	serve(fmt.Sprintf("127.0.0.1:%d", portCount), func(c net.Conn) {
		fmt.Fprintf(c, "own=%d other=%d\n", own.Load(), other.Load())
	})
	select {}
}

type ctr struct {
	name   string
	bridge netip.Addr
}

func startHelper(t *testing.T, name string) ctr {
	t.Helper()
	img := os.Getenv("NSDIAL_IMAGE")
	if img == "" {
		t.Fatal("NSDIAL_IMAGE is not set: name a loaded image (e44.sh sets it)")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, _ = filepath.EvalSymlinks(exe)
	full := prefix + name
	ctx := context.Background()
	_, _ = dockerx.Run(ctx, "rm", "-f", full)
	if _, err := dockerx.Run(ctx, "run", "-d", "--name", full, "--label", "supapace.test=1",
		"--user", "65534:65534", "--read-only", "--cap-drop", "ALL", "--network", "bridge",
		"-e", "NSDIAL_HELPER_NAME="+name, "-v", exe+":/nsdial:ro", "--entrypoint", "/nsdial", img); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = dockerx.Run(context.Background(), "rm", "-f", full) })
	c, err := dockerx.InspectContainer(ctx, full)
	if err != nil || c == nil {
		t.Fatalf("inspect %s: %v", full, err)
	}
	a, err := netip.ParseAddr(c.IPs["bridge"])
	if err != nil {
		t.Fatalf("%s bridge address %q: %v", full, c.IPs["bridge"], err)
	}
	r := ctr{name: full, bridge: a}
	// Ready when its name listener answers through the function under test.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if got, err := ask(t, r, portName); err == nil && got == name {
			return r
		} else if time.Now().After(deadline) {
			t.Fatalf("%s did not answer: %q, %v", full, got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// inspect is what a caller does: Docker's pid, and that process's start time.
func inspect(ctx context.Context, name string) (Target, error) {
	c, err := dockerx.InspectContainer(ctx, name)
	if err != nil {
		return Target{}, err
	}
	if c == nil || !c.Running || c.Pid == 0 {
		return Target{}, fmt.Errorf("%s is not running", name)
	}
	return TargetOf(c.Pid)
}

func dialIn(ctx context.Context, name string, addr netip.AddrPort) (net.Conn, error) {
	t, err := inspect(ctx, name)
	if err != nil {
		return nil, err
	}
	return DialTCP(ctx, t, func(ctx context.Context) (Target, error) { return inspect(ctx, name) }, addr)
}

func loop(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}

// ask dials port on the container's loopback and returns its one-line answer.
func ask(t *testing.T, c ctr, port uint16) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialIn(ctx, c.name, loop(port))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(line), err
}

func counts(t *testing.T, c ctr) (own, other int) {
	t.Helper()
	got, err := ask(t, c, portCount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Sscanf(got, "own=%d other=%d", &own, &other); err != nil {
		t.Fatalf("counter answered %q: %v", got, err)
	}
	return own, other
}

func threads(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Threads:"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatal("no Threads line")
	return 0
}

func needRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("these tests enter namespaces and run as root on the test node")
	}
}

func TestDialTCP_ReachesOnlyTheTargetNamespace(t *testing.T) {
	needRoot(t)
	a, b := startHelper(t, "a"), startHelper(t, "b")
	for _, c := range []struct {
		ctr  ctr
		want string
	}{{a, "a"}, {b, "b"}, {a, "a"}} {
		got, err := ask(t, c.ctr, portName)
		if err != nil || got != c.want {
			t.Fatalf("dial into %s: %q, %v; want %q", c.ctr.name, got, err, c.want)
		}
	}
	// Control: the same address in this process's own namespace has no listener.
	c, err := net.DialTimeout("tcp", loop(portName).String(), 5*time.Second)
	if c != nil {
		c.Close()
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("%v in the host's namespace: %v; want connection refused (the control)", loop(portName), err)
	}
}

func TestDialTCP_NoOtherConnectionFromTheNamespace(t *testing.T) {
	needRoot(t)
	a := startHelper(t, "a")
	target := netip.AddrPortFrom(a.bridge, portBridge)
	// Host dialers and namespace dials go to the same address: from the host it
	// is reached over the bridge (another source address), from inside A it is
	// A's own address. A host dial made on a thread left in A's namespace would
	// be counted as A's own.
	const hostDialers, nsDials, nsWorkers = 64, 1000, 8
	const window = 30 * time.Second
	var hostOK, hostErr atomic.Int64
	var firstErr atomic.Value
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < hostDialers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: 5 * time.Second}
			buf := make([]byte, 1)
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := d.Dial("tcp", target.String())
				if err == nil {
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					_, err = io.ReadFull(c, buf)
					c.Close()
				}
				if err != nil {
					hostErr.Add(1)
					firstErr.CompareAndSwap(nil, err.Error())
					continue
				}
				hostOK.Add(1)
			}
		}()
	}
	timer := time.NewTimer(window)
	defer timer.Stop()

	var nsOK atomic.Int64
	jobs := make(chan struct{}, nsDials)
	for i := 0; i < nsDials; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	errs := make(chan error, nsDials)
	var nwg sync.WaitGroup
	for i := 0; i < nsWorkers; i++ {
		nwg.Add(1)
		go func() {
			defer nwg.Done()
			buf := make([]byte, 1)
			for range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				c, err := dialIn(ctx, a.name, target)
				cancel()
				if err == nil {
					_ = c.SetDeadline(time.Now().Add(10 * time.Second))
					_, err = io.ReadFull(c, buf)
					c.Close()
				}
				if err != nil {
					errs <- err
					continue
				}
				nsOK.Add(1)
			}
		}()
	}
	nwg.Wait()
	<-timer.C // the host dialers keep going for the whole window
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("namespace dial: %v", err)
	}
	if n := hostErr.Load(); n != 0 {
		t.Errorf("%d host dials failed; first: %v", n, firstErr.Load())
	}
	own, other := counts(t, a)
	t.Logf("namespace dials %d; host dials %d; counted own=%d other=%d", nsOK.Load(), hostOK.Load(), own, other)
	if int64(own) != nsOK.Load() || own != nsDials {
		t.Errorf("connections from A's namespace: %d; want exactly the %d namespace dials", own, nsDials)
	}
	// Control: the host dialers ran and were counted as another source.
	if int64(other) != hostOK.Load() || other == 0 {
		t.Errorf("connections from elsewhere: %d; want the %d host dials", other, hostOK.Load())
	}
}

func TestDialTCP_RestartBetweenInspectionAndEntryDetected(t *testing.T) {
	needRoot(t)
	a := startHelper(t, "a")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	before, err := inspect(ctx, a.name)
	if err != nil {
		t.Fatal(err)
	}
	// The dial goes to A's counting listener; recheck reads the count before
	// it restarts A: an entry made before recheck would already be counted.
	own0, _ := counts(t, a)
	restarted := false
	c, err := DialTCP(ctx, before, func(ctx context.Context) (Target, error) {
		if own, _ := counts(t, a); own != own0 {
			t.Errorf("a connection was made before recheck: own %d, was %d", own, own0)
		}
		if _, err := dockerx.Run(ctx, "restart", "-t", "0", a.name); err != nil {
			return Target{}, err
		}
		restarted = true
		return inspect(ctx, a.name)
	}, netip.AddrPortFrom(a.bridge, portBridge))
	if !restarted {
		t.Fatalf("the restart inside recheck failed: %v", err)
	}
	if !errors.Is(err, ErrChanged) || c != nil {
		t.Fatalf("restart inside recheck: got %v, %v; want ErrChanged and no connection", c, err)
	}

	// The stale target after the restart: the process is gone or its pid is another's.
	if c, err := DialTCP(ctx, before, func(ctx context.Context) (Target, error) { return before, nil }, loop(portName)); !errors.Is(err, ErrChanged) || c != nil {
		t.Fatalf("stale target: got %v, %v; want ErrChanged", c, err)
	}

	// Control: a fresh inspection reaches the restarted container.
	deadline := time.Now().Add(30 * time.Second)
	for {
		got, err := ask(t, a, portName)
		if err == nil && got == "a" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restarted container: %q, %v", got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestDialTCP_DeadlineInsideTheNamespace(t *testing.T) {
	needRoot(t)
	a := startHelper(t, "a")
	pid, err := inspect(context.Background(), a.name)
	if err != nil {
		t.Fatal(err)
	}
	// A rule inside A's namespace drops SYNs to portFilter (nft of the node).
	rule := fmt.Sprintf("table inet nsdialtest { chain c { type filter hook input priority 0; tcp dport %d drop; }; }", portFilter)
	if out, err := runNsenter(pid.PID, "nft", rule); err != nil {
		t.Fatalf("nft in A's namespace: %v: %s", err, out)
	}

	const limit = 2 * time.Second
	try := func(port uint16) (time.Duration, error) {
		ctx, cancel := context.WithTimeout(context.Background(), limit)
		defer cancel()
		start := time.Now()
		c, err := dialIn(ctx, a.name, loop(port))
		if c != nil {
			c.Close()
		}
		return time.Since(start), err
	}

	// Nothing listens: refused at once, not a timeout.
	if d, err := try(7199); err == nil || isTimeout(err) || d >= limit {
		t.Errorf("closed port: %v after %v; want a refusal before the deadline", err, d)
	}
	// Filtered: the deadline ends the dial.
	d, err := try(portFilter)
	if !isTimeout(err) {
		t.Errorf("filtered port: %v after %v; want the deadline", err, d)
	}
	if d < limit-100*time.Millisecond || d > limit+5*time.Second {
		t.Errorf("filtered port: returned after %v; want about %v", d, limit)
	}
	// Control: the listener of the same namespace still answers.
	if got, err := ask(t, a, portName); err != nil || got != "a" {
		t.Errorf("control: %q, %v", got, err)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

func TestDialTCP_ThreadsDoNotAccumulate(t *testing.T) {
	needRoot(t)
	a := startHelper(t, "a")
	// Warm the runtime and the docker path first, so the baseline holds the
	// threads any dial needs.
	for i := 0; i < 20; i++ {
		if _, err := ask(t, a, portName); err != nil {
			t.Fatal(err)
		}
	}
	before := threads(t)
	const n, workers = 1000, 8
	var wg sync.WaitGroup
	var failed atomic.Int64
	jobs := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				if got, err := ask(t, a, portName); err != nil || got != "a" {
					failed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if f := failed.Load(); f != 0 {
		t.Fatalf("%d of %d dials failed", f, n)
	}
	after := threads(t)
	t.Logf("threads before %d, after %d dials %d", before, n, after)
	// Each dial's thread ends with it; a kept thread would add one per dial.
	if after > before+2*workers {
		t.Fatalf("threads grew from %d to %d over %d dials", before, after, n)
	}
}

// runNsenter runs a node tool in the network namespace of pid.
func runNsenter(pid int, args ...string) ([]byte, error) {
	return exec.Command("nsenter", append([]string{"-t", strconv.Itoa(pid), "-n", "--"}, args...)...).CombinedOutput()
}
