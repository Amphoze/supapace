package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var _ = sysNumbersExistOnlyForLinuxAmd64AndArm64

// Constants of the calls below, the same on every architecture
// (include/uapi/linux/keyctl.h, userfaultfd.h, perf_event.h, kexec.h, and
// kernel/printk/printk.c's syslog actions).
const (
	keyctlGetKeyringID        = 0  // KEYCTL_GET_KEYRING_ID
	keySpecThreadKeyring      = -1 // KEY_SPEC_THREAD_KEYRING
	uffdUserModeOnly          = 1  // UFFD_USER_MODE_ONLY
	syslogActionSizeUnread    = 9  // SYSLOG_ACTION_SIZE_UNREAD
	prSetDumpable             = 4  // PR_SET_DUMPABLE (include/uapi/linux/prctl.h)
	ioUringParamsSize         = 120
	bpfUndefinedCommand       = 0x7fffffff
	perfUndefinedFlag         = 1 << 31 // outside PERF_FLAG_ALL
	kexecUndefinedFlag        = 0x8000  // outside KEXEC_FLAGS and KEXEC_ARCH_MASK
	uffdUndefinedFlag         = 2       // outside O_CLOEXEC|O_NONBLOCK|UFFD_USER_MODE_ONLY
	sysChildEnv               = "SP_PROBE_SYS_CALL"
	sysChildTimeout           = 2 * time.Second
	sysNonexistentMountTarget = "/proc/self/sp-probe-nonexistent"
)

// procStatus is read for the header lines; a variable so a test can break it.
var procStatus = "/proc/self/status"

// sysProbe is one line of `sp-probe sys`. Its call runs in a child process and
// returns the errno of the system call (0: it succeeded). permitted lists the
// errnos that only the call's own argument checks return — the call passed any
// seccomp filter and every capability check made before those — and denied the
// errnos a sandbox returns for it: EPERM is what Docker's default seccomp
// profile (defaultErrnoRet 1) and a missing capability return. Any other errno is
// "unknown", never read as denied.
type sysProbe struct {
	name      string
	permitted []syscall.Errno
	denied    []syscall.Errno
	call      func() syscall.Errno
}

var eperm = []syscall.Errno{syscall.EPERM}

// The arguments change nothing outside the child when the call is allowed: read
// only actions, an undefined command or flag that the call rejects before doing
// anything, a path that cannot exist, and descriptors closed. Each is chosen so
// that its rejection comes before the call's capability check where the kernel
// allows (then "ok" says only that the call passed the filter) or comes after it
// (then a missing capability reads as EPERM).
var sysProbes = []sysProbe{
	{"getpid", nil, nil, func() syscall.Errno { return raw(sysGetpid) }},
	// Created by the parent as a child with CLONE_NEWUSER (a multi-threaded
	// process cannot unshare a user namespace); the namespace ends with the child.
	{"unshare-user", nil, eperm, nil},
	// No thread keyring exists and none is created (no create flag): ENOKEY.
	{"keyctl", []syscall.Errno{syscall.ENOKEY}, eperm, func() syscall.Errno {
		return raw(sysKeyctl, keyctlGetKeyringID, intptr(keySpecThreadKeyring), 0)
	}},
	// Keyring id 0 is invalid and is looked up before any key is made: EINVAL.
	{"add_key", []syscall.Errno{syscall.EINVAL}, eperm, func() syscall.Errno {
		return raw(sysAddKey, cstr("user"), cstr("sp-probe"), 0, 0, 0)
	}},
	// An undefined key type, rejected before any keyring is searched: ENOKEY.
	{"request_key", []syscall.Errno{syscall.ENOKEY}, eperm, func() syscall.Errno {
		return raw(sysRequestKey, cstr("sp-probe-undefined"), cstr("sp-probe"), 0, 0)
	}},
	// The target path is resolved before the capability check: ENOENT.
	{"mount", []syscall.Errno{syscall.ENOENT}, eperm, func() syscall.Errno {
		return raw(sysMount, cstr("none"), cstr(sysNonexistentMountTarget), cstr("tmpfs"), 0, 0)
	}},
	// An undefined command: EINVAL.
	{"bpf", []syscall.Errno{syscall.EINVAL}, eperm, func() syscall.Errno {
		return closeFd(sysBpf, bpfUndefinedCommand, 0, 0)
	}},
	// Undefined flags are rejected first, before the attributes are read: EINVAL.
	{"perf_event_open", []syscall.Errno{syscall.EINVAL}, eperm, func() syscall.Errno {
		return closeFd(sysPerfEventOpen, 0, 0, intptr(-1), intptr(-1), perfUndefinedFlag)
	}},
	// User-mode-only passes the unprivileged check; the undefined flag then: EINVAL.
	{"userfaultfd", []syscall.Errno{syscall.EINVAL}, eperm, func() syscall.Errno {
		return closeFd(sysUserfaultfd, uffdUserModeOnly|uffdUndefinedFlag)
	}},
	// Zero entries: EINVAL (EFAULT if the parameters were read first).
	{"io_uring_setup", []syscall.Errno{syscall.EINVAL, syscall.EFAULT}, eperm, func() syscall.Errno {
		var p [ioUringParamsSize]byte
		return closeFd(sysIoUringSetup, 0, uintptr(unsafe.Pointer(&p)))
	}},
	// CAP_SYS_BOOT is checked first; with it, the undefined flag: EINVAL.
	{"kexec_load", []syscall.Errno{syscall.EINVAL}, eperm, func() syscall.Errno {
		return raw(sysKexecLoad, 0, 0, 0, kexecUndefinedFlag)
	}},
	// CAP_SYS_MODULE is checked first; with it, an empty image: ENOEXEC.
	{"init_module", []syscall.Errno{syscall.ENOEXEC}, eperm, func() syscall.Errno {
		return raw(sysInitModule, 0, 0, cstr(""))
	}},
	// No handle and mount descriptor -1: EFAULT where the handle is read first,
	// EBADF where the descriptor is resolved first (kernels that check
	// CAP_DAC_READ_SEARCH before either return EPERM without it).
	{"open_by_handle_at", []syscall.Errno{syscall.EBADF, syscall.EFAULT}, eperm, func() syscall.Errno {
		return closeFd(sysOpenByHandleAt, intptr(-1), 0, syscall.O_RDONLY)
	}},
	// CLOCK_REALTIME with a negative nanosecond field is rejected before the
	// capability check, so the clock is never set: EINVAL.
	{"clock_settime", []syscall.Errno{syscall.EINVAL}, eperm, func() syscall.Errno {
		ts := syscall.Timespec{Nsec: -1}
		return raw(sysClockSettime, 0, uintptr(unsafe.Pointer(&ts)))
	}},
	// The number of unread bytes in the kernel log: reads nothing, and needs
	// CAP_SYSLOG whatever dmesg_restrict says.
	{"syslog", nil, eperm, func() syscall.Errno { return raw(sysSyslog, syslogActionSizeUnread, 0, 0) }},
	// A ping socket: EACCES when the group is outside net.ipv4.ping_group_range.
	{"socket-icmp", nil, []syscall.Errno{syscall.EPERM, syscall.EACCES}, func() syscall.Errno {
		return socket(syscall.SOCK_DGRAM)
	}},
	// A raw socket: EPERM without CAP_NET_RAW.
	{"socket-raw", nil, eperm, func() syscall.Errno { return socket(syscall.SOCK_RAW) }},
}

func intptr(v int) uintptr { return uintptr(v) }

// cstr returns a NUL-terminated copy of s. The memory is never freed: the child
// exits right after its one call.
func cstr(s string) uintptr {
	p, _ := syscall.BytePtrFromString(s)
	return uintptr(unsafe.Pointer(p))
}

func raw(nr uintptr, args ...uintptr) syscall.Errno {
	_, errno := rawFd(nr, args...)
	return errno
}

func rawFd(nr uintptr, args ...uintptr) (uintptr, syscall.Errno) {
	var a [6]uintptr
	copy(a[:], args)
	r, _, errno := syscall.Syscall6(nr, a[0], a[1], a[2], a[3], a[4], a[5])
	return r, errno
}

// closeFd makes a call that returns a descriptor on success and closes it.
func closeFd(nr uintptr, args ...uintptr) syscall.Errno {
	fd, errno := rawFd(nr, args...)
	if errno == 0 {
		syscall.Close(int(fd))
	}
	return errno
}

func socket(typ int) syscall.Errno {
	fd, err := syscall.Socket(syscall.AF_INET, typ, syscall.IPPROTO_ICMP)
	if err != nil {
		return err.(syscall.Errno)
	}
	syscall.Close(fd)
	return 0
}

// sysChildName returns the probe a process must run as a sys child: only
// `sp-probe sys` with the marker set in its environment is one.
func sysChildName(args []string, marker string) string {
	if len(args) == 1 && args[0] == "sys" {
		return marker
	}
	return ""
}

// sysChildSetup makes the child not dumpable: a child killed by a seccomp kill
// action then dumps no core, so the host-wide core pattern (often a crash
// handler run as root on the host) is never invoked.
func sysChildSetup() {
	syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
}

// sysChild runs one probe's call and prints its errno and its own effective
// capabilities ("-" when unreadable); the parent classifies them.
func sysChild(name string, stdout io.Writer) int {
	sysChildSetup()
	for _, p := range sysProbes {
		if p.name == name && p.call != nil {
			errno := p.call()
			capEff := "-"
			if h, err := sysStatus(); err == nil {
				capEff = strings.TrimPrefix(h[2], "capeff ")
			}
			fmt.Fprintln(stdout, int(errno), capEff)
			return exitOK
		}
	}
	return exitError
}

// sysStatus returns the header lines from the process status.
func sysStatus() ([]string, error) {
	f, err := os.Open(procStatus)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fields := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, _ := strings.Cut(s.Text(), ":")
		fields[k] = strings.TrimSpace(v)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	var out []string
	for _, h := range []struct{ key, word, valid string }{
		{"Seccomp", "seccomp", "^[012]$"},
		{"NoNewPrivs", "nonewprivs", "^[01]$"},
		{"CapEff", "capeff", "^[0-9a-f]{16}$"},
		{"CapBnd", "capbnd", "^[0-9a-f]{16}$"},
	} {
		v := fields[h.key]
		if !regexp.MustCompile(h.valid).MatchString(v) {
			return nil, fmt.Errorf("%s: field %s is %q", procStatus, h.key, v)
		}
		out = append(out, h.word+" "+v)
	}
	return out, nil
}

// sysCommand prints the header and one verdict line per probe, in order.
func sysCommand(stdout io.Writer) verdict {
	header, err := sysStatus()
	if err != nil {
		return errorVerdict("%v", err)
	}
	for _, l := range header {
		fmt.Fprintln(stdout, l)
	}
	capEff, _ := strconv.ParseUint(strings.TrimPrefix(header[2], "capeff "), 16, 64)
	for _, p := range sysProbes {
		name, flags := p.name, uintptr(0)
		if p.call == nil {
			name, flags = "getpid", syscall.CLONE_NEWUSER
		}
		errno, childCap, sig, err := runSysChild(name, flags)
		fmt.Fprintf(stdout, "sys %s %s\n", p.name, sysVerdict(p, errno, sig, err, judgedCaps(p, childCap, capEff)))
	}
	return verdict{code: exitOK}
}

// judgedCaps returns the capabilities a host switch is judged against: the
// child's own (it may hold fewer than this process), except for unshare-user —
// its child runs in the new user namespace, and the clone was made with this
// process's capabilities — and when the child could not report them (all bits).
func judgedCaps(p sysProbe, child, parent uint64) uint64 {
	if p.call == nil || child == ^uint64(0) {
		return parent
	}
	return child
}

// runSysChild runs probe name in a child process of this binary, created with
// cloneflags, and returns the call's errno and the child's effective
// capabilities (all bits set when the child could not read them). A failure to
// create the child is returned as its errno: for unshare-user that is the
// answer.
func runSysChild(name string, cloneflags uintptr) (syscall.Errno, uint64, syscall.Signal, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sysChildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	cmd.Args = []string{"sp-probe", "sys"}
	cmd.WaitDelay = sysChildTimeout
	cmd.Env = append(os.Environ(), sysChildEnv+"="+name)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: cloneflags}
	out, err := cmd.Output()
	var ee *exec.ExitError
	var errno syscall.Errno
	unknownCap := ^uint64(0)
	switch {
	case ctx.Err() != nil:
		return 0, unknownCap, 0, errors.New("timeout")
	case errors.As(err, &ee):
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 0, unknownCap, ws.Signal(), nil
		}
		return 0, unknownCap, 0, fmt.Errorf("child %v", ee.ProcessState)
	case errors.As(err, &errno):
		return errno, unknownCap, 0, nil
	case err != nil:
		return 0, unknownCap, 0, err
	}
	f := strings.Fields(string(out))
	n, err := 0, errors.New("short")
	if len(f) == 2 {
		n, err = strconv.Atoi(f[0])
	}
	if err != nil {
		return 0, unknownCap, 0, fmt.Errorf("child output %q", out)
	}
	if c, err := strconv.ParseUint(f[1], 16, 64); err == nil {
		unknownCap = c
	}
	return syscall.Errno(n), unknownCap, 0, nil
}

// sysVerdict is the text after "sys NAME ": "ok" (permitted), "errno N SYMBOL"
// (denied), "signal 31 SIGSYS" (denied: killed by a seccomp kill action) or
// "unknown …" (anything else).
//
// A denied verdict becomes "unknown host SWITCH" when a host-wide setting alone
// explains the errno for a process with capabilities capEff.
func sysVerdict(p sysProbe, errno syscall.Errno, sig syscall.Signal, err error, capEff uint64) string {
	switch {
	case err != nil:
		return "unknown " + strings.Join(strings.Fields(err.Error()), " ")
	case sig == syscall.SIGSYS:
		return "signal 31 SIGSYS"
	case sig != 0:
		return fmt.Sprintf("unknown signal %d %s", int(sig), signalName(sig))
	case errno == 0 || slices.Contains(p.permitted, errno):
		return "ok"
	case slices.Contains(p.denied, errno) && hostSwitches[p.name] != nil && hostSwitches[p.name](capEff) != "":
		return "unknown host " + hostSwitches[p.name](capEff)
	case slices.Contains(p.denied, errno):
		return fmt.Sprintf("errno %d %s", int(errno), errnoName(errno))
	}
	return fmt.Sprintf("unknown errno %d %s", int(errno), errnoName(errno))
}

// Where the host's settings are read; variables so a test can point them
// elsewhere.
var (
	procSys      = "/proc/sys"
	lockdownFile = "/sys/kernel/security/lockdown"
)

// Capability bits (include/uapi/linux/capability.h).
const (
	capSysModule = 16
	capSysPtrace = 19
	capSysAdmin  = 21
	capSysBoot   = 22
	capBPF       = 39
)

// setting returns a host setting below /proc/sys, trimmed; "" when unreadable,
// which counts as not set.
func setting(name string) string {
	b, _ := os.ReadFile(procSys + "/" + name)
	return strings.TrimSpace(string(b))
}

// kernelBefore reports a kernel release older than major.minor; false when
// the release is unreadable.
func kernelBefore(major, minor int) bool {
	var ma, mi int
	if _, err := fmt.Sscanf(setting("kernel/osrelease"), "%d.%d", &ma, &mi); err != nil {
		return false
	}
	return ma < major || ma == major && mi < minor
}

func hasCap(capEff uint64, bit uint) bool { return capEff&(1<<bit) != 0 }

// hostSwitches name, per call, the host-wide setting that is the only reason
// the call failed with EPERM — without it, and without a seccomp filter, the
// call would have got past its permission checks for this process — or "". For
// a call open to unprivileged processes, that is a switch set and not overridden
// by a capability held; for a call that needs a capability on every host, a
// switch set while that capability is held (without it, EPERM is a denial).
var hostSwitches = map[string]func(capEff uint64) string{
	// Debian's switch for unprivileged user namespaces.
	"unshare-user": func(c uint64) string {
		if setting("kernel/unprivileged_userns_clone") == "0" && !hasCap(c, capSysAdmin) {
			return "unprivileged_userns_clone"
		}
		return ""
	},
	// Before 6.5 the switch was checked first for every bpf command.
	"bpf": func(c uint64) string {
		if v := setting("kernel/unprivileged_bpf_disabled"); v != "" && v != "0" && kernelBefore(6, 5) &&
			!hasCap(c, capBPF) && !hasCap(c, capSysAdmin) {
			return "unprivileged_bpf_disabled"
		}
		return ""
	},
	// Before 5.11 there was no user-mode-only flag to pass the switch.
	"userfaultfd": func(c uint64) string {
		if setting("vm/unprivileged_userfaultfd") == "0" && kernelBefore(5, 11) && !hasCap(c, capSysPtrace) {
			return "unprivileged_userfaultfd"
		}
		return ""
	},
	// 2: off for everyone; 1: only for CAP_SYS_ADMIN and io_uring_group.
	"io_uring_setup": func(c uint64) string {
		switch setting("kernel/io_uring_disabled") {
		case "2":
			return "io_uring_disabled"
		case "1":
			if !hasCap(c, capSysAdmin) && !inGroup(setting("kernel/io_uring_group")) {
				return "io_uring_disabled"
			}
		}
		return ""
	},
	// Needs CAP_SYS_BOOT. The probe loads no crash kernel, so of the two load
	// limits only the reboot one applies; lockdown in any mode refuses kexec_load.
	"kexec_load": func(c uint64) string {
		if !hasCap(c, capSysBoot) {
			return ""
		}
		return gatedSwitch([]gate{
			{"kexec_load_disabled", procSys + "/kernel/kexec_load_disabled", func(v string) bool { return v == "1" }},
			{"kexec_load_limit_reboot", procSys + "/kernel/kexec_load_limit_reboot", func(v string) bool { return v == "0" }},
			{"lockdown", lockdownFile, func(v string) bool { return strings.Contains(v, "[") && !strings.Contains(v, "[none]") }},
		})
	},
	// Needs CAP_SYS_MODULE. Lockdown checks a module's signature, which an
	// empty image never reaches.
	"init_module": func(c uint64) string {
		if !hasCap(c, capSysModule) {
			return ""
		}
		return gatedSwitch([]gate{
			{"modules_disabled", procSys + "/kernel/modules_disabled", func(v string) bool { return v == "1" }},
		})
	},
}

// gate is a host switch of a call that needs a capability.
type gate struct {
	name, path string
	set        func(value string) bool
}

// gatedSwitch returns the first switch that is set, else the first one that
// cannot be read (it may be set: the process holds the capability, so only a
// switch can explain the refusal), else "".
func gatedSwitch(gates []gate) string {
	unreadable := ""
	for _, g := range gates {
		b, err := os.ReadFile(g.path)
		switch {
		case err != nil && unreadable == "":
			unreadable = g.name
		case err == nil && g.set(strings.TrimSpace(string(b))):
			return g.name
		}
	}
	return unreadable
}

// inGroup reports whether this process has group id gid (decimal).
func inGroup(gid string) bool {
	g, err := strconv.Atoi(gid)
	if err != nil || g < 0 {
		return false
	}
	groups, _ := os.Getgroups()
	return g == os.Getgid() || slices.Contains(groups, g)
}

// Errno numbers are the generic ones on both supported architectures.
var errnoNames = map[syscall.Errno]string{
	syscall.EPERM: "EPERM", syscall.ENOENT: "ENOENT", syscall.ESRCH: "ESRCH", syscall.EINTR: "EINTR",
	syscall.EIO: "EIO", syscall.ENXIO: "ENXIO", syscall.E2BIG: "E2BIG", syscall.ENOEXEC: "ENOEXEC",
	syscall.EBADF: "EBADF", syscall.EAGAIN: "EAGAIN", syscall.ENOMEM: "ENOMEM", syscall.EACCES: "EACCES",
	syscall.EFAULT: "EFAULT", syscall.EBUSY: "EBUSY", syscall.EEXIST: "EEXIST", syscall.ENODEV: "ENODEV",
	syscall.EINVAL: "EINVAL", syscall.EMFILE: "EMFILE", syscall.ENOSPC: "ENOSPC", syscall.ENOSYS: "ENOSYS",
	syscall.EUSERS: "EUSERS", syscall.EPROTONOSUPPORT: "EPROTONOSUPPORT",
	syscall.ESOCKTNOSUPPORT: "ESOCKTNOSUPPORT", syscall.EOPNOTSUPP: "EOPNOTSUPP",
	syscall.EAFNOSUPPORT: "EAFNOSUPPORT", syscall.ENOKEY: "ENOKEY", syscall.EKEYEXPIRED: "EKEYEXPIRED",
	syscall.EKEYREVOKED: "EKEYREVOKED", syscall.EKEYREJECTED: "EKEYREJECTED",
}

func errnoName(e syscall.Errno) string {
	if n, ok := errnoNames[e]; ok {
		return n
	}
	return fmt.Sprintf("E%d", int(e))
}

func signalName(s syscall.Signal) string {
	if n, ok := map[syscall.Signal]string{syscall.SIGKILL: "SIGKILL", syscall.SIGSEGV: "SIGSEGV",
		syscall.SIGABRT: "SIGABRT", syscall.SIGTERM: "SIGTERM", syscall.SIGBUS: "SIGBUS"}[s]; ok {
		return n
	}
	return "SIG" + strconv.Itoa(int(s))
}
