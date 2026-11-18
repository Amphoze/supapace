package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Environment variables by which a test re-executes the test binary: one
// installs a seccomp filter on itself and then runs `sys`; the other runs any
// subcommand (arguments separated by newlines) in a process of its own.
const (
	testFilterEnv = "SP_PROBE_TEST_FILTER"
	testArgsEnv   = "SP_PROBE_TEST_ARGS"
	// A probe the test binary adds to its children's list: its "errno" is the
	// child's PR_GET_DUMPABLE value at the moment the probed call runs.
	testDumpableProbe = "test-dumpable"
)

// TestMain lets the test binary stand in for sp-probe when `sys` re-executes
// itself to run one call in a child process.
func TestMain(m *testing.M) {
	if name := sysChildName(os.Args[1:], os.Getenv(sysChildEnv)); name != "" {
		if name == testDumpableProbe {
			sysProbes = append(sysProbes, sysProbe{name: name, call: func() syscall.Errno {
				r, _, _ := syscall.RawSyscall(syscall.SYS_PRCTL, 3, 0, 0) // PR_GET_DUMPABLE
				return syscall.Errno(r)
			}})
		}
		os.Exit(sysChild(name, os.Stdout))
	}
	if stage := os.Getenv(testFilterEnv); stage != "" {
		os.Exit(sysUnderTestFilter(stage))
	}
	if args := os.Getenv(testArgsEnv); args != "" {
		os.Exit(run(strings.Split(args, "\n"), os.Stdout))
	}
	// A race-enabled child would otherwise wait a second before exiting.
	os.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0")
	os.Exit(m.Run())
}

var sysCallOrder = []string{"getpid", "unshare-user", "keyctl", "add_key", "request_key", "mount", "bpf",
	"perf_event_open", "userfaultfd", "io_uring_setup", "kexec_load", "init_module", "open_by_handle_at",
	"clock_settime", "syslog", "socket-icmp", "socket-raw"}

var (
	sysHeader = []*regexp.Regexp{
		regexp.MustCompile(`^seccomp [012]$`),
		regexp.MustCompile(`^nonewprivs [01]$`),
		regexp.MustCompile(`^capeff [0-9a-f]{16}$`),
		regexp.MustCompile(`^capbnd [0-9a-f]{16}$`),
	}
	sysLine = regexp.MustCompile(`^sys (\S+) (ok|errno [0-9]+ E[A-Z0-9]+|signal 31 SIGSYS|unknown \S.*)$`)
)

func runSys(t *testing.T, args ...string) (int, []string) {
	t.Helper()
	code, out := probe(t, append([]string{"sys"}, args...)...)
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("output %q does not end in a newline", out)
	}
	return code, strings.Split(strings.TrimSuffix(out, "\n"), "\n")
}

// The line set, its order and the shape of every line are a contract that tests
// in other packages parse.
func TestSys_OutputContract(t *testing.T) {
	code, lines := runSys(t)
	if code != 0 || len(lines) != len(sysHeader)+len(sysCallOrder) {
		t.Fatalf("exit %d, %d lines %q", code, len(lines), lines)
	}
	for i, re := range sysHeader {
		if !re.MatchString(lines[i]) {
			t.Errorf("line %d %q does not match %s", i+1, lines[i], re)
		}
	}
	unconfined := lines[0] == "seccomp 0"
	for i, name := range sysCallOrder {
		line := lines[len(sysHeader)+i]
		m := sysLine.FindStringSubmatch(line)
		if m == nil || m[1] != name {
			t.Errorf("line %q, want sys %s with a verdict", line, name)
			continue
		}
		// Without a filter every call reaches the kernel: each must read as
		// permitted or as refused by a missing capability, never as unknown —
		// otherwise the argument or errno chosen for it is wrong for this kernel.
		if unconfined && strings.HasPrefix(m[2], "unknown") && !strings.HasPrefix(m[2], "unknown host ") {
			t.Errorf("without seccomp: %q", line)
		}
	}

	// The verdict of each outcome: permitted (the call ran, or failed in the
	// kernel's own argument checks), denied (EPERM from a filter or a missing
	// capability, EACCES for a ping socket, SIGSYS from a kill action) and
	// unknown (everything else — never read as denied).
	byName := map[string]sysProbe{}
	for _, p := range sysProbes {
		byName[p.name] = p
	}
	// No host switch is set in this table.
	oldSys, oldLock := procSys, lockdownFile
	procSys, lockdownFile = t.TempDir(), "/nonexistent"
	defer func() { procSys, lockdownFile = oldSys, oldLock }()
	for _, c := range []struct {
		name  string
		errno syscall.Errno
		sig   syscall.Signal
		err   error
		want  string
	}{
		{"getpid", 0, 0, nil, "ok"},
		{"keyctl", syscall.ENOKEY, 0, nil, "ok"},
		{"keyctl", syscall.EPERM, 0, nil, "errno 1 EPERM"},
		{"keyctl", syscall.EINVAL, 0, nil, "unknown errno 22 EINVAL"},
		{"keyctl", syscall.ENOSYS, 0, nil, "unknown errno 38 ENOSYS"},
		{"add_key", syscall.EINVAL, 0, nil, "ok"},
		{"request_key", syscall.ENOKEY, 0, nil, "ok"},
		{"mount", syscall.ENOENT, 0, nil, "ok"},
		{"mount", syscall.EPERM, 0, nil, "errno 1 EPERM"},
		{"bpf", syscall.EINVAL, 0, nil, "ok"},
		{"perf_event_open", syscall.EACCES, 0, nil, "unknown errno 13 EACCES"},
		{"unshare-user", syscall.ENOSPC, 0, nil, "unknown errno 28 ENOSPC"},
		{"unshare-user", syscall.EPERM, 0, nil, "errno 1 EPERM"},
		{"socket-icmp", syscall.EACCES, 0, nil, "errno 13 EACCES"},
		{"socket-icmp", syscall.EAFNOSUPPORT, 0, nil, "unknown errno 97 EAFNOSUPPORT"},
		{"socket-raw", syscall.EPERM, 0, nil, "errno 1 EPERM"},
		{"socket-raw", syscall.EACCES, 0, nil, "unknown errno 13 EACCES"},
		{"syslog", syscall.EINVAL, 0, nil, "unknown errno 22 EINVAL"},
		{"bpf", 0, syscall.SIGSYS, nil, "signal 31 SIGSYS"},
		{"bpf", 0, syscall.SIGKILL, nil, "unknown signal 9 SIGKILL"},
		{"bpf", 0, 0, errors.New("timeout"), "unknown timeout"},
		{"bpf", 0, 0, errors.New("two\nlines"), "unknown two lines"},
		{"keyctl", 4095, 0, nil, "unknown errno 4095 E4095"},
	} {
		if got := sysVerdict(byName[c.name], c.errno, c.sig, c.err, 0); got != c.want {
			t.Errorf("%s %v %v %v: %q, want %q", c.name, c.errno, c.sig, c.err, got, c.want)
		}
	}
}

// getpid is the positive control of every run: no sandbox refuses it.
func TestSys_GetpidOK(t *testing.T) {
	_, lines := runSys(t)
	if !strings.Contains("\n"+strings.Join(lines, "\n")+"\n", "\nsys getpid ok\n") {
		t.Fatalf("no getpid ok in %q", lines)
	}
}

// 0 when every line was printed; 3, with an error line and no verdicts, on a
// usage error or when the process status cannot be read.
func TestSys_ExitCodes(t *testing.T) {
	if code, _ := runSys(t); code != 0 {
		t.Errorf("sys: exit %d", code)
	}
	for _, args := range [][]string{{"extra"}, {"--timeout", "1s"}, {"--mode", "huge"}} {
		if code, lines := runSys(t, args...); code != 3 || len(lines) != 1 || !strings.HasPrefix(lines[0], "error ") {
			t.Errorf("sys %q: exit %d, output %q", args, code, lines)
		}
	}
	old := procStatus
	procStatus = filepath.Join(t.TempDir(), "missing")
	defer func() { procStatus = old }()
	if code, lines := runSys(t); code != 3 || len(lines) != 1 || !strings.HasPrefix(lines[0], "error ") {
		t.Errorf("unreadable status: exit %d, output %q", code, lines)
	}
}

// The system call numbers are the kernel's, for the architecture built: a wrong
// number silently probes another call. Cross-checked with the standard library
// where it has the call.
func TestSys_NumbersMatchKernelTables(t *testing.T) {
	got := map[string]uintptr{"getpid": sysGetpid, "syslog": sysSyslog, "mount": sysMount,
		"init_module": sysInitModule, "clock_settime": sysClockSettime, "kexec_load": sysKexecLoad,
		"add_key": sysAddKey, "request_key": sysRequestKey, "keyctl": sysKeyctl,
		"perf_event_open": sysPerfEventOpen, "open_by_handle_at": sysOpenByHandleAt, "bpf": sysBpf,
		"userfaultfd": sysUserfaultfd, "io_uring_setup": sysIoUringSetup}
	want := map[string]map[string]uintptr{
		// arch/x86/entry/syscalls/syscall_64.tbl
		"amd64": {"getpid": 39, "syslog": 103, "mount": 165, "init_module": 175, "clock_settime": 227,
			"kexec_load": 246, "add_key": 248, "request_key": 249, "keyctl": 250, "perf_event_open": 298,
			"open_by_handle_at": 304, "bpf": 321, "userfaultfd": 323, "io_uring_setup": 425},
		// include/uapi/asm-generic/unistd.h
		"arm64": {"getpid": 172, "syslog": 116, "mount": 40, "init_module": 105, "clock_settime": 112,
			"kexec_load": 104, "add_key": 217, "request_key": 218, "keyctl": 219, "perf_event_open": 241,
			"open_by_handle_at": 265, "bpf": 280, "userfaultfd": 282, "io_uring_setup": 425},
	}[runtime.GOARCH]
	std := map[string]uintptr{"getpid": syscall.SYS_GETPID, "syslog": syscall.SYS_SYSLOG,
		"mount": syscall.SYS_MOUNT, "init_module": syscall.SYS_INIT_MODULE,
		"clock_settime": syscall.SYS_CLOCK_SETTIME, "kexec_load": syscall.SYS_KEXEC_LOAD,
		"add_key": syscall.SYS_ADD_KEY, "request_key": syscall.SYS_REQUEST_KEY,
		"keyctl": syscall.SYS_KEYCTL, "perf_event_open": syscall.SYS_PERF_EVENT_OPEN}
	if len(got) != len(want) {
		t.Fatalf("%d numbers, want %d", len(got), len(want))
	}
	for name, nr := range got {
		if nr != want[name] {
			t.Errorf("%s: %d, want %d", name, nr, want[name])
		}
		if s, ok := std[name]; ok && nr != s {
			t.Errorf("%s: %d, the standard library has %d", name, nr, s)
		}
	}
}

func seccompMode(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Seccomp:"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatal("no Seccomp field")
	return ""
}

// Without a filter every call must be stopped by its own argument checks or a
// capability check, never succeed: the arguments are what keeps a run from
// changing anything. Where the kernel validates before any capability check, the
// errno is pinned — clock_settime with valid arguments would set the clock in a
// privileged run. mount is also run in a private user and mount namespace, where
// the capability check passes and only the nonexistent target stops it.
func TestSys_ArgumentsAreRejected(t *testing.T) {
	if m := seccompMode(t); m != "0" {
		t.Skipf("seccomp mode %s: the calls would not reach their argument checks", m)
	}
	exact := map[string]syscall.Errno{"keyctl": syscall.ENOKEY, "add_key": syscall.EINVAL,
		"request_key": syscall.ENOKEY, "perf_event_open": syscall.EINVAL, "clock_settime": syscall.EINVAL}
	for _, p := range sysProbes {
		// getpid, the kernel log size and a ping socket may succeed.
		if p.call == nil || p.name == "getpid" || p.name == "syslog" || p.name == "socket-icmp" {
			continue
		}
		errno, _, sig, err := runSysChild(p.name, 0)
		switch want, pinned := exact[p.name]; {
		case err != nil || sig != 0:
			t.Errorf("%s: signal %v, %v", p.name, sig, err)
		case errno == 0:
			t.Errorf("%s succeeded", p.name)
		case pinned && errno != want:
			t.Errorf("%s: errno %d, want %d", p.name, errno, want)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "sys")
	cmd.Env = append(os.Environ(), sysChildEnv+"=mount")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	out, err := cmd.Output()
	var errno syscall.Errno
	if errors.As(err, &errno) {
		t.Skipf("no private user namespace here (%v); mount not checked past its capability check", err)
	}
	if f := strings.Fields(string(out)); err != nil || len(f) != 2 || f[0] != "2" {
		t.Errorf("mount as root of a private namespace: output %q (%v), want errno 2 (ENOENT)", out, err)
	}
}

// sysUnderTestFilter installs a seccomp filter on the test binary itself and
// re-executes it to run `sys` under that filter (a filter installed with prctl
// covers one thread; one execve later it covers the process and its children).
func sysUnderTestFilter(stage string) int {
	if stage == "exec" {
		return run([]string{"sys"}, os.Stdout)
	}
	runtime.LockOSThread()
	type sockFilter struct {
		code   uint16
		jt, jf uint8
		k      uint32
	}
	type sockFprog struct {
		n      uint16
		filter *sockFilter
	}
	const (
		retAllow       = 0x7fff0000
		retErrno       = 0x00050000
		retKillThread  = 0
		retKillProcess = 0x80000000
	)
	ld := func(off uint32) sockFilter { return sockFilter{0x20, 0, 0, off} } // BPF_LD|BPF_W|BPF_ABS
	ret := func(k uint32) sockFilter { return sockFilter{0x06, 0, 0, k} }    // BPF_RET|BPF_K
	prog := []sockFilter{ld(0)}                                              // seccomp_data.nr
	for _, r := range []struct{ nr, action uint32 }{
		{syscall.SYS_KEYCTL, retErrno | uint32(syscall.EPERM)},
		{syscall.SYS_ADD_KEY, retErrno | uint32(syscall.ENOSYS)},
		{syscall.SYS_REQUEST_KEY, retErrno | uint32(syscall.EACCES)},
		{syscall.SYS_PERF_EVENT_OPEN, retKillThread},
		{sysBpf, retKillProcess},
	} {
		prog = append(prog, sockFilter{0x15, 0, 1, r.nr}, ret(r.action)) // BPF_JMP|BPF_JEQ|BPF_K
	}
	// syslog with SYSLOG_ACTION_SIZE_UNREAD (9) as its action: EUSERS, an errno
	// nothing else returns, so the line shows which action the probe passed.
	prog = append(prog, sockFilter{0x15, 0, 4, syscall.SYS_SYSLOG}, ld(16),
		sockFilter{0x15, 0, 1, 9}, ret(retErrno|uint32(syscall.EUSERS)), ret(retAllow))
	// clone with CLONE_NEWUSER in its flags (first argument, low word): EPERM.
	prog = append(prog, sockFilter{0x15, 0, 3, syscall.SYS_CLONE}, ld(16),
		sockFilter{0x45, 0, 1, syscall.CLONE_NEWUSER}, ret(retErrno|uint32(syscall.EPERM)), ret(retAllow))
	fp := sockFprog{uint16(len(prog)), &prog[0]}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 38, 1, 0); e != 0 { // PR_SET_NO_NEW_PRIVS
		os.Stdout.WriteString("error no_new_privs: " + e.Error() + "\n")
		return exitError
	}
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, 22, 2, uintptr(unsafe.Pointer(&fp))); e != 0 { // PR_SET_SECCOMP, filter
		os.Stdout.WriteString("error seccomp: " + e.Error() + "\n")
		return exitError
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, testFilterEnv+"=") {
			env = append(env, kv)
		}
	}
	err := syscall.Exec("/proc/self/exe", []string{"sp-probe"}, append(env, testFilterEnv+"=exec"))
	os.Stdout.WriteString("error exec: " + err.Error() + "\n")
	return exitError
}

// Under a real seccomp filter: an errno action with EPERM reads as denied, with
// ENOSYS or EACCES as unknown; a clone with CLONE_NEWUSER refused reads as
// unshare-user denied; a call whose thread the filter kills is cut off by the
// 2 s bound and reads as unknown; a call whose process the filter kills reads as
// SIGSYS (the child is not dumpable, so no core handler runs); unfiltered calls
// keep their verdicts.
func TestSys_UnderSeccompFilter(t *testing.T) {
	// The filter kills one child's process: were that child dumpable, the kill
	// would run the host's crash handler. Never run it then.
	if d := childDumpable(t); d != 0 {
		t.Fatalf("a sys child is dumpable (%d): not running the kill-process case", d)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = append(os.Environ(), testFilterEnv+"=install")
	t0 := time.Now()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sys under a filter: %v, output %q", err, out)
	}
	if d := time.Since(t0); d > 15*time.Second {
		t.Errorf("took %v: a killed call is not bounded", d)
	}
	text := "\n" + string(out)
	for _, want := range []string{"seccomp 2", "nonewprivs 1", "sys getpid ok", "sys keyctl errno 1 EPERM",
		"sys add_key unknown errno 38 ENOSYS", "sys request_key unknown errno 13 EACCES",
		"sys unshare-user errno 1 EPERM", "sys perf_event_open unknown timeout",
		"sys bpf signal 31 SIGSYS", "sys syslog unknown errno 87 EUSERS"} {
		if !strings.Contains(text, "\n"+want+"\n") {
			t.Errorf("no line %q in %q", want, out)
		}
	}
}

// childDumpable runs a probe through the real child path and returns the
// child's dumpable flag as the call sees it.
func childDumpable(t *testing.T) uintptr {
	t.Helper()
	errno, _, sig, err := runSysChild(testDumpableProbe, 0)
	if sig != 0 || err != nil {
		t.Fatalf("dumpability probe: signal %v, %v", sig, err)
	}
	return uintptr(errno)
}

// A child killed by a seccomp kill action must not dump core: the core pattern
// is host-wide, so a dump would run the host's crash handler.
func TestSys_ChildIsNotDumpable(t *testing.T) {
	if d := childDumpable(t); d != 0 {
		t.Fatalf("a sys child is dumpable (%d) when its call runs", d)
	}
}

// Only the sys subcommand with the marker in its environment runs one call: the
// variable alone, or other arguments, change nothing.
func TestSys_ChildNeedsArgvAndMarker(t *testing.T) {
	for _, c := range []struct {
		args []string
		env  string
		want string
	}{
		{[]string{"sys"}, "keyctl", "keyctl"},
		{[]string{"sys"}, "", ""},
		{nil, "keyctl", ""},
		{[]string{"tcp", "127.0.0.1:1"}, "keyctl", ""},
		{[]string{"sys", "extra"}, "keyctl", ""},
	} {
		if got := sysChildName(c.args, c.env); got != c.want {
			t.Errorf("%q with %q: %q, want %q", c.args, c.env, got, c.want)
		}
	}
}

// A host-wide switch that alone makes a call fail with EPERM — whatever the
// sandbox — turns the denied verdict into "unknown host SWITCH"; a switch that a
// capability the process holds overrides, a kernel where the switch no longer
// governs these arguments, and an unreadable setting do not.
func TestSys_HostSwitches(t *testing.T) {
	const (
		capModule = 1 << 16
		capPtrace = 1 << 19
		capAdmin  = 1 << 21
		capBoot   = 1 << 22
		capBPF    = 1 << 39
	)
	byName := map[string]sysProbe{}
	for _, p := range sysProbes {
		byName[p.name] = p
	}
	oldSys, oldLock := procSys, lockdownFile
	defer func() { procSys, lockdownFile = oldSys, oldLock }()
	for _, c := range []struct {
		name     string
		settings map[string]string // paths below /proc/sys, and "lockdown"
		capEff   uint64
		errno    syscall.Errno
		want     string
	}{
		{"io_uring_setup", map[string]string{"kernel/io_uring_disabled": "2"}, ^uint64(0), syscall.EPERM, "unknown host io_uring_disabled"},
		{"io_uring_setup", map[string]string{"kernel/io_uring_disabled": "1", "kernel/io_uring_group": "-1"}, 0, syscall.EPERM, "unknown host io_uring_disabled"},
		{"io_uring_setup", map[string]string{"kernel/io_uring_disabled": "1", "kernel/io_uring_group": "-1"}, capAdmin, syscall.EPERM, "errno 1 EPERM"},
		{"io_uring_setup", map[string]string{"kernel/io_uring_disabled": "0"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"io_uring_setup", map[string]string{"kernel/io_uring_disabled": "2"}, 0, syscall.EINVAL, "ok"},
		{"io_uring_setup", map[string]string{"kernel/io_uring_disabled": "2"}, 0, syscall.ENOSYS, "unknown errno 38 ENOSYS"},
		// kexec_load needs CAP_SYS_BOOT on every host: a switch explains EPERM only
		// for a process that holds it.
		{"kexec_load", map[string]string{"kernel/kexec_load_disabled": "1"}, capBoot, syscall.EPERM, "unknown host kexec_load_disabled"},
		{"kexec_load", map[string]string{"kernel/kexec_load_disabled": "1"}, ^uint64(0) &^ capBoot, syscall.EPERM, "errno 1 EPERM"},
		{"kexec_load", map[string]string{"kernel/kexec_load_disabled": "0", "kernel/kexec_load_limit_reboot": "-1", "lockdown": "[none] integrity confidentiality"}, capBoot, syscall.EPERM, "errno 1 EPERM"},
		{"kexec_load", map[string]string{"kernel/kexec_load_disabled": "0"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"kexec_load", map[string]string{"kernel/kexec_load_limit_reboot": "0"}, capBoot, syscall.EPERM, "unknown host kexec_load_limit_reboot"},
		{"kexec_load", map[string]string{"kernel/kexec_load_limit_reboot": "0"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"kexec_load", map[string]string{"kernel/kexec_load_disabled": "0", "kernel/kexec_load_limit_reboot": "-1", "lockdown": "[none] integrity confidentiality"}, capBoot, syscall.EPERM, "errno 1 EPERM"},
		// The probe loads no crash kernel, so the panic limit does not apply to it.
		{"kexec_load", map[string]string{"kernel/kexec_load_limit_panic": "0", "kernel/kexec_load_disabled": "0", "kernel/kexec_load_limit_reboot": "-1", "lockdown": "[none] integrity confidentiality"}, capBoot, syscall.EPERM, "errno 1 EPERM"},
		{"kexec_load", map[string]string{"lockdown": "none [integrity] confidentiality"}, capBoot, syscall.EPERM, "unknown host lockdown"},
		{"kexec_load", map[string]string{"lockdown": "none [integrity] confidentiality"}, 0, syscall.EPERM, "errno 1 EPERM"},
		// While the capability is held, a setting that cannot be read counts as
		// set (inside a container the lockdown file is never readable); without
		// it nothing is read.
		{"kexec_load", map[string]string{"kernel/kexec_load_disabled": "0", "kernel/kexec_load_limit_reboot": "-1"}, capBoot, syscall.EPERM, "unknown host lockdown"},
		{"kexec_load", map[string]string{"kernel/kexec_load_disabled": "0", "lockdown": "[none] integrity"}, capBoot, syscall.EPERM, "unknown host kexec_load_limit_reboot"},
		{"kexec_load", map[string]string{"kernel/kexec_load_limit_reboot": "-1", "lockdown": "[none] integrity"}, capBoot, syscall.EPERM, "unknown host kexec_load_disabled"},
		{"kexec_load", nil, capBoot, syscall.EPERM, "unknown host kexec_load_disabled"},
		{"kexec_load", nil, 0, syscall.EPERM, "errno 1 EPERM"},
		{"init_module", nil, capModule, syscall.EPERM, "unknown host modules_disabled"},
		{"init_module", nil, 0, syscall.EPERM, "errno 1 EPERM"},
		// init_module needs CAP_SYS_MODULE on every host; lockdown does not reach
		// an empty image.
		{"init_module", map[string]string{"kernel/modules_disabled": "1"}, capModule, syscall.EPERM, "unknown host modules_disabled"},
		{"init_module", map[string]string{"kernel/modules_disabled": "1"}, ^uint64(0) &^ capModule, syscall.EPERM, "errno 1 EPERM"},
		{"init_module", map[string]string{"kernel/modules_disabled": "0"}, capModule, syscall.EPERM, "errno 1 EPERM"},
		{"init_module", map[string]string{"kernel/modules_disabled": "0"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"init_module", map[string]string{"kernel/modules_disabled": "0", "lockdown": "none [integrity] confidentiality"}, capModule, syscall.EPERM, "errno 1 EPERM"},
		// Calls open to unprivileged processes unless a switch closes them: the
		// switch counts when set and no capability overriding it is held.
		{"bpf", map[string]string{"kernel/osrelease": "6.1.0", "kernel/unprivileged_bpf_disabled": "0"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"bpf", map[string]string{"kernel/osrelease": "6.1.0", "kernel/unprivileged_bpf_disabled": "1"}, capAdmin, syscall.EPERM, "errno 1 EPERM"},
		{"userfaultfd", map[string]string{"kernel/osrelease": "5.10.0", "vm/unprivileged_userfaultfd": "1"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"unshare-user", map[string]string{"kernel/unprivileged_userns_clone": "1"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"io_uring_setup", map[string]string{"kernel/io_uring_disabled": "1", "kernel/io_uring_group": "-1"}, ^uint64(0) &^ capAdmin, syscall.EPERM, "unknown host io_uring_disabled"},
		// No switch is read for the other calls.
		{"syslog", map[string]string{"kernel/dmesg_restrict": "1"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"perf_event_open", map[string]string{"kernel/perf_event_paranoid": "4", "lockdown": "none integrity [confidentiality]"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"bpf", map[string]string{"kernel/osrelease": "6.1.0-13-amd64", "kernel/unprivileged_bpf_disabled": "2"}, 0, syscall.EPERM, "unknown host unprivileged_bpf_disabled"},
		{"bpf", map[string]string{"kernel/osrelease": "6.1.0-13-amd64", "kernel/unprivileged_bpf_disabled": "2"}, capBPF, syscall.EPERM, "errno 1 EPERM"},
		{"bpf", map[string]string{"kernel/osrelease": "7.0.9-generic", "kernel/unprivileged_bpf_disabled": "2"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"userfaultfd", map[string]string{"kernel/osrelease": "5.10.0", "vm/unprivileged_userfaultfd": "0"}, 0, syscall.EPERM, "unknown host unprivileged_userfaultfd"},
		{"userfaultfd", map[string]string{"kernel/osrelease": "5.10.0", "vm/unprivileged_userfaultfd": "0"}, capPtrace, syscall.EPERM, "errno 1 EPERM"},
		{"userfaultfd", map[string]string{"kernel/osrelease": "5.15.0", "vm/unprivileged_userfaultfd": "0"}, 0, syscall.EPERM, "errno 1 EPERM"},
		{"unshare-user", map[string]string{"kernel/unprivileged_userns_clone": "0"}, 0, syscall.EPERM, "unknown host unprivileged_userns_clone"},
		{"unshare-user", map[string]string{"kernel/unprivileged_userns_clone": "0"}, capAdmin, syscall.EPERM, "errno 1 EPERM"},
		{"unshare-user", nil, 0, syscall.EPERM, "errno 1 EPERM"}, // unreadable: not set
		{"keyctl", map[string]string{"kernel/modules_disabled": "1"}, 0, syscall.EPERM, "errno 1 EPERM"},
	} {
		dir := t.TempDir()
		procSys, lockdownFile = dir, filepath.Join(dir, "lockdown")
		for k, v := range c.settings {
			path := filepath.Join(dir, k)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(v+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got := sysVerdict(byName[c.name], c.errno, 0, nil, c.capEff); got != c.want {
			t.Errorf("%s %v caps %x %v: %q, want %q", c.name, c.settings, c.capEff, c.errno, got, c.want)
		}
	}
}

// Each child reports its own effective capabilities, which is what a host
// switch is judged against.
func TestSys_ChildReportsItsCapabilities(t *testing.T) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	var own uint64
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
			fmt.Sscanf(strings.TrimSpace(v), "%x", &own)
		}
	}
	errno, capEff, sig, err := runSysChild("getpid", 0)
	if errno != 0 || sig != 0 || err != nil || capEff != own {
		t.Fatalf("child: errno %v, capeff %x, signal %v, %v; want capeff %x", errno, capEff, sig, err, own)
	}
}

// Lockdown refuses kexec_load to a process that holds CAP_SYS_BOOT. Where the
// lockdown state cannot be read (a container mounts no securityfs, privileged
// or not), EPERM with that capability held is not attributable to the sandbox
// and must not read as denied; without the capability it stays a denial.
func TestSys_LockdownUnreadableIsNotADenial(t *testing.T) {
	byName := map[string]sysProbe{}
	for _, p := range sysProbes {
		byName[p.name] = p
	}
	oldSys, oldLock := procSys, lockdownFile
	defer func() { procSys, lockdownFile = oldSys, oldLock }()
	procSys, lockdownFile = t.TempDir(), "/nonexistent/lockdown"
	if got := sysVerdict(byName["kexec_load"], syscall.EPERM, 0, nil, 1<<capSysBoot); !strings.HasPrefix(got, "unknown host ") {
		t.Errorf("CAP_SYS_BOOT held, lockdown unreadable: %q, want unknown host …", got)
	}
	if got := sysVerdict(byName["kexec_load"], syscall.EPERM, 0, nil, 0); got != "errno 1 EPERM" {
		t.Errorf("no CAP_SYS_BOOT, lockdown unreadable: %q, want errno 1 EPERM", got)
	}
}

// A switch is judged against the child's own capabilities, which may be fewer
// than the parent's; for unshare-user (its child lives in the new namespace)
// and when the child could not report them, against the parent's.
func TestSys_JudgedCapabilities(t *testing.T) {
	byName := map[string]sysProbe{}
	for _, p := range sysProbes {
		byName[p.name] = p
	}
	const parent, child = 0x3fffffffff, 0x1
	for _, c := range []struct {
		name        string
		child, want uint64
	}{
		{"kexec_load", child, child},
		{"bpf", child, child},
		{"kexec_load", ^uint64(0), parent},
		{"unshare-user", child, parent},
	} {
		if got := judgedCaps(byName[c.name], c.child, parent); got != c.want {
			t.Errorf("%s, child %x: %x, want %x", c.name, c.child, got, c.want)
		}
	}
}
