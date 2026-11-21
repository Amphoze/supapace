package dockerx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fake installs a stub "docker" first on PATH. It appends its NUL-separated
// argv to argv.log, copies stdin to stdin.log, and replays <key>.out,
// <key>.err and <key>.rc from the fixture directory, where key is "ps" for
// "ps ..." and "<arg1>_<arg2>" otherwise ("version" alone for "version").
func fake(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
d="` + dir + `"
echo $$ > "$d/pid"
printf '%s\0' "$@" >> "$d/argv.log"; printf '\n' >> "$d/argv.log"
cat > "$d/stdin.log"
case "$1" in ps|version) k=$1;; *) k=$1_$2;; esac
if [ -f "$d/$k.sleep" ]; then sleep "$(cat "$d/$k.sleep")" & echo $! > "$d/gpid"; wait; fi
[ -f "$d/$k.endless" ] && exec yes aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[ -f "$d/$k.out" ] && cat "$d/$k.out"
[ -f "$d/$k.err" ] && cat "$d/$k.err" >&2
[ -f "$d/$k.rc" ] && exit "$(cat "$d/$k.rc")"
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func put(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func argvOf(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "argv.log"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\x00") {
		out = append(out, p)
	}
	return out[:len(out)-1]
}

const containerJSON = `[{
 "Id": "0f3c9a1b2d4e5f60718293a4b5c6d7e8f9011223344556677889900aabbccdd",
 "Name": "/pg-abcdefghij0123456789",
 "State": {"Status": "running", "Running": true, "Pid": 4242},
 "Config": {"Image": "example/postgres:17", "Labels": {"supapace.ref": "abcdefghij0123456789", "supapace.role": "pg"}},
 "HostConfig": {"RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
 "NetworkSettings": {"Networks": {
   "proj-abcdefghij0123456789": {"IPAddress": "10.212.7.2"},
   "detached": {"IPAddress": ""}}}
}]`

const networkJSON = `[{
 "Name": "proj-abcdefghij0123456789",
 "Id": "4e3d4dbbb68d58f249f7ef1ca1f9db9ba41c4d225e2b2ec18dcd06a8409cb10c",
 "Driver": "bridge",
 "IPAM": {"Driver": "default", "Config": [{"Subnet": "10.212.7.0/24", "Gateway": "10.212.7.1"}]},
 "Internal": true,
 "Options": {"com.docker.network.bridge.name": "spp7"},
 "Containers": {"aaa": {"Name": "pg-abcdefghij0123456789"}, "bbb": {"Name": "postgrest-abcdefghij0123456789"}}
}]`

func TestRun_NoShell(t *testing.T) {
	dir := fake(t)
	arg := "x; rm -rf /"
	if _, err := Run(context.Background(), "run", arg, "$(id)"); err != nil {
		t.Fatal(err)
	}
	got := argvOf(t, dir)
	if len(got) != 3 || got[0] != "run" || got[1] != arg || got[2] != "$(id)" {
		t.Fatalf("argv = %q", got)
	}
}

func TestRunInput_PassesStdin(t *testing.T) {
	dir := fake(t)
	put(t, dir, "exec_x.out", "ok")
	out, err := RunInput(context.Background(), []byte("secret-in"), "exec", "x")
	if err != nil || out != "ok" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "stdin.log"))
	if string(b) != "secret-in" {
		t.Fatalf("stdin = %q", b)
	}
}

func TestInspectContainer_Absent(t *testing.T) {
	dir := fake(t)
	put(t, dir, "container_inspect.out", "[]\n")
	put(t, dir, "container_inspect.err", "Error response from daemon: No such container: nope\n")
	put(t, dir, "container_inspect.rc", "1")
	c, err := InspectContainer(context.Background(), "nope")
	if c != nil || err != nil {
		t.Fatalf("c=%v err=%v", c, err)
	}
}

func TestInspectContainer_Parses(t *testing.T) {
	dir := fake(t)
	put(t, dir, "container_inspect.out", containerJSON)
	c, err := InspectContainer(context.Background(), "pg-abcdefghij0123456789")
	if err != nil || c == nil {
		t.Fatalf("c=%v err=%v", c, err)
	}
	if c.Name != "pg-abcdefghij0123456789" || c.Pid != 4242 || !c.Running || c.RestartPolicy != "no" ||
		c.Image != "example/postgres:17" || c.Labels["supapace.role"] != "pg" ||
		len(c.IPs) != 1 || c.IPs["proj-abcdefghij0123456789"] != "10.212.7.2" {
		t.Fatalf("parsed = %+v", c)
	}
}

func TestInspectNetwork_BridgeNameAndOptions(t *testing.T) {
	dir := fake(t)
	put(t, dir, "network_inspect.out", networkJSON)
	n, err := InspectNetwork(context.Background(), "proj-abcdefghij0123456789")
	if err != nil || n == nil {
		t.Fatalf("n=%v err=%v", n, err)
	}
	if n.BridgeName != "spp7" || n.Subnet != "10.212.7.0/24" || !n.Internal ||
		n.Options["com.docker.network.bridge.name"] != "spp7" ||
		strings.Join(n.Containers, ",") != "pg-abcdefghij0123456789,postgrest-abcdefghij0123456789" {
		t.Fatalf("parsed = %+v", n)
	}
	// Without the option the default bridge name is derived from the id.
	put(t, dir, "network_inspect.out", strings.Replace(networkJSON, `"com.docker.network.bridge.name": "spp7"`, `"x": "y"`, 1))
	n, _ = InspectNetwork(context.Background(), "n")
	if n.BridgeName != "br-4e3d4dbbb68d" {
		t.Fatalf("bridge = %q", n.BridgeName)
	}
}

func TestInspectNetwork_Absent(t *testing.T) {
	dir := fake(t)
	put(t, dir, "network_inspect.out", "[]\n")
	put(t, dir, "network_inspect.err", "Error response from daemon: network nope not found\n")
	put(t, dir, "network_inspect.rc", "1")
	if n, err := InspectNetwork(context.Background(), "nope"); n != nil || err != nil {
		t.Fatalf("n=%v err=%v", n, err)
	}
}

func TestListContainers_ByLabel(t *testing.T) {
	dir := fake(t)
	put(t, dir, "ps.out", "0f3c9a1b2d4e\n")
	put(t, dir, "container_inspect.out", containerJSON)
	cs, err := ListContainers(context.Background(), "supapace.ref=abcdefghij0123456789")
	if err != nil || len(cs) != 1 || cs[0].Pid != 4242 {
		t.Fatalf("cs=%+v err=%v", cs, err)
	}
	if !strings.Contains(strings.Join(argvOf(t, dir), " "), "label=supapace.ref=abcdefghij0123456789") {
		t.Fatalf("no label filter in argv")
	}
	// No match: no inspect call, empty result.
	put(t, dir, "ps.out", "")
	cs, err = ListContainers(context.Background(), "k=v")
	if err != nil || len(cs) != 0 {
		t.Fatalf("cs=%+v err=%v", cs, err)
	}
}

func TestServerVersion(t *testing.T) {
	dir := fake(t)
	put(t, dir, "version.out", "29.2.1\n")
	v, err := ServerVersion(context.Background())
	if err != nil || v != "29.2.1" {
		t.Fatalf("v=%q err=%v", v, err)
	}
}

func TestRun_TimeoutKills(t *testing.T) {
	dir := fake(t)
	put(t, dir, "slow_x.sleep", "30")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Run(ctx, "slow", "x")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 15*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
	b, rerr := os.ReadFile(filepath.Join(dir, "pid"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	g, rerr := os.ReadFile(filepath.Join(dir, "gpid"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	gpid, _ := strconv.Atoi(strings.TrimSpace(string(g)))
	for _, p := range []int{pid, gpid} {
		waitDead(t, p)
	}
}

func TestRun_StderrInError(t *testing.T) {
	dir := fake(t)
	put(t, dir, "run_-e.err", "boom: bad thing\n")
	put(t, dir, "run_-e.rc", "3")
	t.Setenv("SP_TEST_ENV_SECRET", "hunter2-value")
	_, err := Run(context.Background(), "run", "-e", "PW=arg-secret-value")
	if err == nil || !strings.Contains(err.Error(), "boom: bad thing") {
		t.Fatalf("err=%v", err)
	}
	for _, s := range []string{"hunter2-value", "SP_TEST_ENV_SECRET", "arg-secret-value", "PW="} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("%q leaked: %v", s, err)
		}
	}
}

// A daemon that cannot be reached is not "the container is absent".
func TestInspectContainer_DaemonUnreachableIsError(t *testing.T) {
	dir := fake(t)
	put(t, dir, "container_inspect.out", "[]\n")
	put(t, dir, "container_inspect.err", "failed to connect to the docker API at unix:///x/sock; check if the path is correct and if the daemon is running: dial unix /x/sock: connect: no such file or directory\n")
	put(t, dir, "container_inspect.rc", "1")
	c, err := InspectContainer(context.Background(), "pg-x")
	if err == nil {
		t.Fatalf("want error, got c=%v err=nil", c)
	}
}

func TestInspectNetwork_DaemonUnreachableIsError(t *testing.T) {
	dir := fake(t)
	put(t, dir, "network_inspect.err", "dial unix /x/sock: connect: no such file or directory\n")
	put(t, dir, "network_inspect.rc", "1")
	if n, err := InspectNetwork(context.Background(), "proj-x"); err == nil {
		t.Fatalf("want error, got n=%v", n)
	}
}

// With no docker binary on PATH the result must be an error, not "absent".
func TestInspect_NoDockerBinaryIsError(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if c, err := InspectContainer(context.Background(), "pg-x"); err == nil {
		t.Fatalf("container: want error, got %v", c)
	}
	if n, err := InspectNetwork(context.Background(), "proj-x"); err == nil {
		t.Fatalf("network: want error, got %v", n)
	}
}

// A name that merely contains "not found" in a non-absent failure.
func TestInspectContainer_OtherErrorMentioningNotFound(t *testing.T) {
	dir := fake(t)
	put(t, dir, "container_inspect.err", "Error response from daemon: runtime not found\n")
	put(t, dir, "container_inspect.rc", "1")
	if c, err := InspectContainer(context.Background(), "pg-x"); err == nil {
		t.Fatalf("want error, got %v", c)
	}
}

// A name starting with '-' must not be taken as an option.
func TestInspect_DashNameNotAnOption(t *testing.T) {
	dir := fake(t)
	put(t, dir, "container_inspect.out", "[]")
	put(t, dir, "network_inspect.out", "[]")
	InspectContainer(context.Background(), "-f")
	InspectNetwork(context.Background(), "-f")
	b, _ := os.ReadFile(dir + "/argv.log")
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Split(strings.TrimSuffix(line, "\x00"), "\x00")
		ok := false
		for i, a := range f {
			if a == "--" && i < len(f)-1 {
				ok = true
			}
		}
		if !ok {
			t.Errorf("argv %q has no -- before the name", f)
		}
	}
}

func TestListContainers_DashLabelStaysOneArg(t *testing.T) {
	dir := fake(t)
	ListContainers(context.Background(), "--all")
	got := argvOf(t, dir)
	if got[len(got)-1] != "label=--all" {
		t.Fatalf("argv = %q", got)
	}
}

func TestInspectContainer_EmptyAndMulti(t *testing.T) {
	dir := fake(t)
	put(t, dir, "container_inspect.out", "[]")
	if c, err := InspectContainer(context.Background(), "x"); c != nil || err != nil {
		t.Fatalf("empty: %v %v", c, err)
	}
	put(t, dir, "container_inspect.out", "not json")
	if c, err := InspectContainer(context.Background(), "x"); c != nil || err == nil {
		t.Fatalf("garbage: %v %v", c, err)
	}
	put(t, dir, "container_inspect.out", `[{"Name":"/a","State":{}},{"Name":"/b","State":{}}]`)
	c, err := InspectContainer(context.Background(), "x")
	if err != nil || c.Name != "a" || c.Labels == nil || c.IPs == nil {
		t.Fatalf("multi: %v %v", c, err)
	}
}

func TestInspectNetwork_NoIPAMNoOptions(t *testing.T) {
	dir := fake(t)
	put(t, dir, "network_inspect.out", `[{"Name":"n","Id":"abcdef","Containers":null}]`)
	n, err := InspectNetwork(context.Background(), "n")
	if err != nil || n.Options == nil || n.Subnet != "" || n.BridgeName != "" || len(n.Containers) != 0 {
		t.Fatalf("%+v %v", n, err)
	}
}

func TestListContainers_PsFailure(t *testing.T) {
	dir := fake(t)
	put(t, dir, "ps.err", "Cannot connect to the Docker daemon\n")
	put(t, dir, "ps.rc", "1")
	if cs, err := ListContainers(context.Background(), "a"); err == nil || cs != nil {
		t.Fatalf("%v %v", cs, err)
	}
}

// Cancellation (not timeout) kills too, and the grandchild dies with the group.
func TestRun_CancelKillsGroup(t *testing.T) {
	dir := fake(t)
	put(t, dir, "slow_x.sleep", "30")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	_, err := Run(ctx, "slow", "x")
	if err == nil || time.Since(start) > 15*time.Second || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

// Output larger than a pipe buffer is returned whole.
func TestRun_LargeStdout(t *testing.T) {
	dir := fake(t)
	put(t, dir, "run_x.out", strings.Repeat("a", 1<<20))
	out, err := Run(context.Background(), "run", "x")
	if err != nil || len(out) != 1<<20 {
		t.Fatalf("len=%d err=%v", len(out), err)
	}
}

func TestListContainers_RetriesOnceWhenContainerVanishes(t *testing.T) {
	dir := fake(t)
	put(t, dir, "ps.out", "0f3c9a1b2d4e\n")
	put(t, dir, "container_inspect.err", "Error response from daemon: No such container: 0f3c9a1b2d4e\n")
	put(t, dir, "container_inspect.rc", "1")
	cs, err := ListContainers(context.Background(), "k=v")
	if err == nil || cs != nil {
		t.Fatalf("cs=%v err=%v", cs, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "argv.log"))
	if n := strings.Count(string(b), "ps\x00"); n != 2 {
		t.Fatalf("ps ran %d times", n)
	}
}

func TestError_StderrCapped(t *testing.T) {
	dir := fake(t)
	put(t, dir, "run_x.err", "HEAD "+strings.Repeat("a", 200<<10)+"TAIL\n")
	put(t, dir, "run_x.rc", "1")
	_, err := Run(context.Background(), "run", "x")
	if err == nil || len(err.Error()) > 65<<10 || !strings.Contains(err.Error(), "HEAD ") || strings.Contains(err.Error(), "TAIL") {
		t.Fatalf("len=%d", len(err.Error()))
	}
}

func TestRun_StdoutCapReturnsError(t *testing.T) {
	dir := fake(t)
	put(t, dir, "run_x.out", strings.Repeat("a", 5<<20))
	put(t, dir, "run_y.out", "a")
	alloc := func(arg string) (string, error, uint64) {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		out, err := Run(context.Background(), "run", arg)
		runtime.ReadMemStats(&after)
		return out, err, after.TotalAlloc - before.TotalAlloc
	}
	alloc("y")               // warm up
	_, _, base := alloc("y") // cost of a call that returns almost nothing
	out, err, got := alloc("x")
	if !errors.Is(err, ErrOutputTooLarge) || out != "" || !strings.HasPrefix(err.Error(), "docker run: ") {
		t.Fatalf("out=%d err=%v", len(out), err)
	}
	if got > base+4<<20+64<<10 {
		t.Fatalf("allocated %d bytes (baseline call %d)", got, base)
	}
}

// A child that never stops writing is killed once the cap is hit.
func TestRun_StdoutCapKillsEndlessWriter(t *testing.T) {
	dir := fake(t)
	put(t, dir, "run_x.endless", "")
	start := time.Now()
	_, err := Run(context.Background(), "run", "x")
	if !errors.Is(err, ErrOutputTooLarge) || time.Since(start) > 10*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
	b, _ := os.ReadFile(filepath.Join(dir, "pid"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	waitDead(t, pid)
}

func TestRun_StdoutAtCapPasses(t *testing.T) {
	dir := fake(t)
	put(t, dir, "run_x.out", strings.Repeat("a", 4<<20))
	out, err := Run(context.Background(), "run", "x")
	if err != nil || len(out) != 4<<20 {
		t.Fatalf("len=%d err=%v", len(out), err)
	}
}

func TestRun_StderrTruncatedKeepsStart(t *testing.T) {
	dir := fake(t)
	put(t, dir, "container_inspect.err", "Error response from daemon: No such container: nope\n"+strings.Repeat("x", 1<<20))
	put(t, dir, "container_inspect.rc", "1")
	c, err := InspectContainer(context.Background(), "nope")
	if c != nil || err != nil {
		t.Fatalf("c=%v err=%v", c, err)
	}
	if _, err := Run(context.Background(), "container", "inspect", "nope"); err == nil || len(err.Error()) > 65<<10 {
		t.Fatalf("err len %d", len(err.Error()))
	}
}

func TestRun_StillCappedAt60s(t *testing.T) {
	if defaultTimeout != 60*time.Second {
		t.Fatalf("defaultTimeout = %v", defaultTimeout)
	}
	dir := fake(t)
	put(t, dir, "slow_x.sleep", "30")
	old := defaultTimeout
	defaultTimeout = 200 * time.Millisecond
	defer func() { defaultTimeout = old }()
	start := time.Now()
	_, err := Run(context.Background(), "slow", "x")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 15*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

func TestRun_CappedCallsLeakNothing(t *testing.T) {
	dir := fake(t)
	put(t, dir, "run_x.out", strings.Repeat("a", 5<<20))
	Run(context.Background(), "run", "x") // warm up
	base := runtime.NumGoroutine()
	for i := 0; i < 30; i++ {
		if _, err := Run(context.Background(), "run", "x"); !errors.Is(err, ErrOutputTooLarge) {
			t.Fatal(err)
		}
	}
	var n int
	for i := 0; i < 500; i++ { // 10 s for the pipes' goroutines to end
		if n = runtime.NumGoroutine(); n <= base {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines %d -> %d", base, n)
}

func TestInspect_NeverAbsentOnOtherErrors(t *testing.T) {
	cases := []struct{ name, out, err string }{
		{"mid-line", "", "Error: while reading: No such container: x\nnetwork x not found\n"},
		{"upper", "", "Error response from daemon: NO SUCH CONTAINER: x\nERROR RESPONSE FROM DAEMON: NETWORK X NOT FOUND\n"},
		{"lower", "", "error response from daemon: no such container: x\nnetwork x NOT found\nerror: no such object: x\n"},
		{"stdout-only", "Error response from daemon: No such container: x\nnetwork x not found\n", ""},
		{"after-other-error", "", "Cannot connect to the Docker daemon\nError response from daemon: No such container: x\nnetwork x not found\n"},
		{"socket-missing", "", "dial unix /x/sock: connect: no such file or directory\n"},
		{"no-executable", "", "exec: \"docker\": executable file not found in $PATH\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := fake(t)
			for _, k := range []string{"container_inspect", "network_inspect"} {
				put(t, dir, k+".out", c.out)
				put(t, dir, k+".err", c.err)
				put(t, dir, k+".rc", "1")
			}
			if ct, err := InspectContainer(context.Background(), "x"); err == nil {
				t.Errorf("container: got %v, nil error", ct)
			}
			if n, err := InspectNetwork(context.Background(), "x"); err == nil {
				t.Errorf("network: got %v, nil error", n)
			}
		})
	}
}

// RunOutput returns the call's stderr on success too, with the caps and
// errors of Run.
func TestRunOutput_ReturnsStderr(t *testing.T) {
	dir := fake(t)
	put(t, dir, "logs_--.out", "stdout line\n")
	put(t, dir, "logs_--.err", "helper: refused\n"+strings.Repeat("x", 1<<20))
	out, errOut, err := RunOutput(context.Background(), "logs", "--", "c")
	if err != nil || out != "stdout line\n" || !strings.HasPrefix(errOut, "helper: refused\n") || len(errOut) != 64<<10 {
		t.Fatalf("out %q, stderr %d bytes starting %.20q, err %v", out, len(errOut), errOut, err)
	}
	put(t, dir, "logs_--.rc", "1")
	if _, errOut, err := RunOutput(context.Background(), "logs", "--", "c"); err == nil || !strings.HasPrefix(errOut, "helper: refused") {
		t.Fatalf("failed call: stderr %.20q, err %v", errOut, err)
	}
	put(t, dir, "logs_--.rc", "0")
	put(t, dir, "logs_--.endless", "")
	if out, _, err := RunOutput(context.Background(), "logs", "--", "c"); !errors.Is(err, ErrOutputTooLarge) || out != "" {
		t.Fatalf("stdout over the cap: %d bytes, %v", len(out), err)
	}
}
