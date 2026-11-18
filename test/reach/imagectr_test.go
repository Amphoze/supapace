package reach

// Scratch objects for the containment tests: containers of a real project
// container's image with that container's own configuration, scratch bridges of
// the platform's classes, a routed neighbour, and the probes of a network
// namespace's own view. Untagged like helpers_test.go; nothing here needs the
// system under test except the containers it is pointed at.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

const (
	probeInImage = "/opt/sp/sp-probe" // where imageContainer mounts the probe
	idleListen   = "127.0.0.1:0"      // the idle process: the PostgREST image has no sleep
)

// ───────── a container's own configuration ─────────

// runFlags is a container's configuration as `docker run` options, read back
// from `docker inspect`. Callers change fields before args(): Seccomp
// "unconfined", User "" (root), CapDrop nil (Docker's default set), Binds nil.
type runFlags struct {
	User             string
	CapDrop, CapAdd  []string
	Privileged       bool
	NoNewPrivs       bool
	OtherSecurity    []string // security options other than seccomp and no-new-privileges
	Seccomp          string   // a profile file, "unconfined", or "" (Docker's built-in default)
	SeccompJSON      []byte   // the profile the container was created with; nil if none
	ReadOnly         bool
	Tmpfs            map[string]string
	Memory, Swap     int64
	NanoCPUs         int64
	PidsLimit        int64
	ShmSize          int64
	Ulimits          []string // name=soft:hard
	IpcMode          string
	Sysctls          map[string]string
	NoHealthcheck    bool
	Binds            []string
	RestartPolicy    string
	HealthcheckTests []string
}

type inspectConfig struct {
	Config struct {
		User        string
		Healthcheck *struct{ Test []string }
	}
	HostConfig struct {
		CapDrop, CapAdd []string
		Privileged      bool
		SecurityOpt     []string
		ReadonlyRootfs  bool
		Tmpfs           map[string]string
		Memory          int64
		MemorySwap      int64
		NanoCpus        int64
		PidsLimit       *int64
		ShmSize         int64
		Ulimits         []struct {
			Name       string
			Soft, Hard int64
		}
		IpcMode       string
		Sysctls       map[string]string
		Binds         []string
		RestartPolicy struct{ Name string }
	}
}

// containerFlags reads name's configuration as created. A seccomp profile is
// written to a file of its own, so a scratch container gets byte for byte the
// profile the real one runs under.
func containerFlags(t testing.TB, name string) runFlags {
	t.Helper()
	var c []inspectConfig
	if err := json.Unmarshal([]byte(docker(t, "inspect", "--type", "container", name)), &c); err != nil || len(c) != 1 {
		t.Fatalf("inspect %s: %v", name, err)
	}
	h := c[0].HostConfig
	f := runFlags{User: c[0].Config.User, CapDrop: h.CapDrop, CapAdd: h.CapAdd, Privileged: h.Privileged,
		ReadOnly: h.ReadonlyRootfs, Tmpfs: h.Tmpfs, Memory: h.Memory, Swap: h.MemorySwap, NanoCPUs: h.NanoCpus,
		ShmSize: h.ShmSize, IpcMode: h.IpcMode, Sysctls: h.Sysctls, Binds: h.Binds, RestartPolicy: h.RestartPolicy.Name}
	if h.PidsLimit != nil {
		f.PidsLimit = *h.PidsLimit
	}
	for _, u := range h.Ulimits {
		f.Ulimits = append(f.Ulimits, fmt.Sprintf("%s=%d:%d", u.Name, u.Soft, u.Hard))
	}
	if hc := c[0].Config.Healthcheck; hc != nil {
		f.HealthcheckTests = hc.Test
		f.NoHealthcheck = slices.Equal(hc.Test, []string{"NONE"})
	}
	for _, o := range h.SecurityOpt {
		switch {
		case o == "no-new-privileges" || o == "no-new-privileges:true" || o == "no-new-privileges=true":
			f.NoNewPrivs = true
		case o == "seccomp=unconfined" || o == "seccomp:unconfined":
			f.Seccomp = "unconfined"
		case strings.HasPrefix(o, "seccomp=") || strings.HasPrefix(o, "seccomp:"):
			f.SeccompJSON = []byte(o[len("seccomp="):])
			file, err := os.CreateTemp("", "reach-seccomp-*.json")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Remove(file.Name()) })
			file.Write(f.SeccompJSON)
			file.Close()
			f.Seccomp = file.Name()
		default:
			f.OtherSecurity = append(f.OtherSecurity, o)
		}
	}
	return f
}

// args renders the flags; the network, name and labels are the caller's.
func (f runFlags) args() []string {
	var a []string
	add := func(s ...string) { a = append(a, s...) }
	if f.User != "" {
		add("--user", f.User)
	}
	for _, c := range f.CapDrop {
		add("--cap-drop", c)
	}
	for _, c := range f.CapAdd {
		add("--cap-add", c)
	}
	if f.Privileged {
		add("--privileged")
	}
	if f.NoNewPrivs {
		add("--security-opt", "no-new-privileges")
	}
	for _, o := range f.OtherSecurity {
		add("--security-opt", o)
	}
	if f.Seccomp != "" {
		add("--security-opt", "seccomp="+f.Seccomp)
	}
	if f.ReadOnly {
		add("--read-only")
	}
	for _, k := range slices.Sorted(maps.Keys(f.Tmpfs)) {
		if v := f.Tmpfs[k]; v != "" {
			add("--tmpfs", k+":"+v)
		} else {
			add("--tmpfs", k)
		}
	}
	if f.Memory > 0 {
		add("--memory", strconv.FormatInt(f.Memory, 10))
	}
	if f.Swap != 0 {
		add("--memory-swap", strconv.FormatInt(f.Swap, 10))
	}
	if f.NanoCPUs > 0 {
		add("--cpus", strconv.FormatFloat(float64(f.NanoCPUs)/1e9, 'f', -1, 64))
	}
	if f.PidsLimit > 0 {
		add("--pids-limit", strconv.FormatInt(f.PidsLimit, 10))
	}
	if f.ShmSize > 0 {
		add("--shm-size", strconv.FormatInt(f.ShmSize, 10))
	}
	for _, u := range f.Ulimits {
		add("--ulimit", u)
	}
	if f.IpcMode != "" {
		add("--ipc", f.IpcMode)
	}
	for _, k := range slices.Sorted(maps.Keys(f.Sysctls)) {
		add("--sysctl", k+"="+f.Sysctls[k])
	}
	if f.NoHealthcheck {
		add("--no-healthcheck")
	}
	for _, b := range f.Binds {
		add("-v", b)
	}
	return a
}

// ───────── containers of a given image ─────────

// imageContainer runs image detached with the probe mounted read-only at
// /opt/sp/sp-probe and the probe's listener on loopback as its idle process
// (the PostgREST image has no sleep), with args as further `docker run`
// options and the label supapace.test=1; removed with its anonymous volumes in
// cleanup. It returns name once the container runs.
func imageContainer(t testing.TB, name, image string, args ...string) string {
	t.Helper()
	t.Cleanup(func() { rmIgnoringAbsent(t, "rm", "-f", "-v", name) })
	docker(t, slices.Concat([]string{"run", "-d", "--label", testLabel, "--name", name,
		"-v", probeBin + ":" + probeInImage + ":ro"}, args,
		[]string{"--entrypoint", probeInImage, image, "listen", "tcp", idleListen})...)
	containerPid(t, name) // running, or the test fails here
	return name
}

// imageSys runs `sp-probe sys` once as the entrypoint of a container of image
// (removed when it exits) with args as further `docker run` options, and
// returns its report.
func imageSys(t testing.TB, name, image string, args ...string) sysReport {
	t.Helper()
	t.Cleanup(func() { rmIgnoringAbsent(t, "rm", "-f", "-v", name) })
	r, err := run(cmdTimeout, nil, slices.Concat([]string{"docker", "run", "--rm", "--label", testLabel, "--name", name,
		"-v", probeBin + ":" + probeInImage + ":ro"}, args, []string{"--entrypoint", probeInImage, image, "sys"})...)
	if err != nil {
		t.Fatalf("sp-probe sys in a container of %s: %v", image, err)
	}
	return mustSys(t, "a container of "+image, r)
}

// execSys runs the probe at path inside the running container, at the
// container's configured user, through docker exec (its seccomp profile,
// capabilities and no-new-privileges apply).
func execSys(t testing.TB, container, path string) sysReport {
	t.Helper()
	argv := []string{"docker", "exec"}
	if _, user := containerPid(t, container); user != "" {
		argv = append(argv, "--user", user)
	}
	r, err := run(cmdTimeout, nil, append(argv, container, path, "sys")...)
	if err != nil {
		t.Fatalf("sp-probe sys in %s: %v", container, err)
	}
	return mustSys(t, container, r)
}

func mustSys(t testing.TB, where string, r result) sysReport {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("sp-probe sys in %s: exit %d (stdout %q, stderr %q)", where, r.code, brief(r.stdout), brief(r.stderr))
	}
	rep, err := parseSys(r.stdout)
	if err != nil {
		t.Fatalf("sp-probe sys in %s: %v (output %q)", where, err, brief(r.stdout))
	}
	return rep
}

// sysCalls is the fixed call list of `sp-probe sys`, in its output order.
var sysCalls = []string{"getpid", "unshare-user", "keyctl", "add_key", "request_key", "mount", "bpf",
	"perf_event_open", "userfaultfd", "io_uring_setup", "kexec_load", "init_module", "open_by_handle_at",
	"clock_settime", "syslog", "socket-icmp", "socket-raw"}

// sysReport is the output of `sp-probe sys`: the process's seccomp mode,
// no_new_privs, effective and bounding capability sets, and per call "ok" or
// "errno <n> <SYMBOL>".
type sysReport struct {
	Seccomp, NoNewPrivs int
	CapEff, CapBnd      uint64
	Calls               map[string]string
}

var sysLineRE = map[string]func(string) bool{
	"ok": func(s string) bool { return s == "ok" },
	"errno": func(s string) bool {
		f := strings.Fields(s)
		return len(f) == 3 && isUint(f[1]) && f[2] == strings.ToUpper(f[2])
	},
	"signal":  func(s string) bool { return s == "signal 31 SIGSYS" },
	"unknown": func(s string) bool { return len(s) > len("unknown ") && s != "unknown host" && s != "unknown host " },
}

// sysKind classifies one call's verdict: "ok" (the call went through),
// "refused" (an errno, or the kill of a seccomp kill action: refused for this
// process), "host" ("unknown host <switch>": refused by a host-wide setting,
// which says nothing about the sandbox) or "unknown" (the probe could not tell).
func sysKind(v string) string {
	switch {
	case v == "ok":
		return "ok"
	case strings.HasPrefix(v, "errno ") || v == "signal 31 SIGSYS":
		return "refused"
	case strings.HasPrefix(v, "unknown host "):
		return "host"
	}
	return "unknown"
}

// sysConfinedProblems is what is wrong with a confined run: getpid must be
// ok; every other call must not be ok, and may be refused or refused by a host
// setting, never unknown.
func sysConfinedProblems(calls map[string]string) []string {
	var out []string
	for _, c := range sysCalls {
		v := calls[c]
		switch k := sysKind(v); {
		case c == "getpid" && k != "ok":
			out = append(out, "getpid "+v)
		case c == "getpid":
		case k == "ok":
			out = append(out, c+" succeeded")
		case k == "unknown":
			out = append(out, c+" "+v+": the probe could not tell")
		}
	}
	return out
}

// sysDifferProblems compares a confined run with its seccomp-unconfined
// control for calls: each must be refused by the profile when confined
// ("errno 1 EPERM" or "signal 31 SIGSYS") and ok in the control; getpid must
// be ok in both. A host setting on either side prevents the comparison.
func sysDifferProblems(confined, unconfined map[string]string, calls []string) []string {
	var out []string
	if confined["getpid"] != "ok" || unconfined["getpid"] != "ok" {
		out = append(out, fmt.Sprintf("getpid confined %q, unconfined %q, want ok in both", confined["getpid"], unconfined["getpid"]))
	}
	for _, c := range calls {
		con, unc := confined[c], unconfined[c]
		switch {
		case sysKind(con) == "host" || sysKind(unc) == "host":
			out = append(out, fmt.Sprintf("%s confined %q, unconfined %q: a host setting prevents the comparison", c, con, unc))
		case con != "errno 1 EPERM" && con != "signal 31 SIGSYS":
			out = append(out, fmt.Sprintf("%s confined %q, want errno 1 EPERM or signal 31 SIGSYS", c, con))
		case unc != "ok":
			out = append(out, fmt.Sprintf("%s unconfined %q, want ok", c, unc))
		}
	}
	return out
}

// TestImagectr_SysVerdicts: each verdict form, and what the confined and
// control checks make of it.
func TestImagectr_SysVerdicts(t *testing.T) {
	for v, want := range map[string]string{
		"ok": "ok", "errno 1 EPERM": "refused", "errno 13 EACCES": "refused", "signal 31 SIGSYS": "refused",
		"unknown host kernel.unprivileged_userns_clone=0": "host", "unknown errno 22 EINVAL": "unknown",
		"unknown signal 9 SIGKILL": "unknown", "unknown timeout": "unknown",
	} {
		if got := sysKind(v); got != want {
			t.Errorf("sysKind(%q) = %q, want %q", v, got, want)
		}
	}
	base := func(over map[string]string) map[string]string {
		m := map[string]string{}
		for _, c := range sysCalls {
			m[c] = "errno 1 EPERM"
		}
		m["getpid"] = "ok"
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	for name, c := range map[string]struct {
		over map[string]string
		bad  bool
	}{
		"all refused":          {nil, false},
		"seccomp kill":         {map[string]string{"bpf": "signal 31 SIGSYS"}, false},
		"host switch":          {map[string]string{"unshare-user": "unknown host user.max_user_namespaces=0"}, false},
		"a call succeeded":     {map[string]string{"keyctl": "ok"}, true},
		"probe could not tell": {map[string]string{"mount": "unknown errno 22 EINVAL"}, true},
		"getpid refused":       {map[string]string{"getpid": "errno 1 EPERM"}, true},
	} {
		if got := sysConfinedProblems(base(c.over)); (len(got) > 0) != c.bad {
			t.Errorf("confined %s: %q", name, got)
		}
	}
	pair := []string{"keyctl", "unshare-user"}
	open := map[string]string{"getpid": "ok", "keyctl": "ok", "unshare-user": "ok"}
	for name, c := range map[string]struct {
		con, unc map[string]string
		bad      bool
	}{
		"profile refuses, control allows": {base(nil), open, false},
		"seccomp kill counts":             {base(map[string]string{"keyctl": "signal 31 SIGSYS"}), open, false},
		"other errno is not the profile":  {base(map[string]string{"keyctl": "errno 13 EACCES"}), open, true},
		"control refused too":             {base(nil), map[string]string{"getpid": "ok", "keyctl": "errno 1 EPERM", "unshare-user": "ok"}, true},
		"host setting confined":           {base(map[string]string{"unshare-user": "unknown host user.max_user_namespaces=0"}), open, true},
		"host setting in the control":     {base(nil), map[string]string{"getpid": "ok", "keyctl": "ok", "unshare-user": "unknown host user.max_user_namespaces=0"}, true},
		"getpid broken in the control":    {base(nil), map[string]string{"getpid": "errno 1 EPERM", "keyctl": "ok", "unshare-user": "ok"}, true},
	} {
		if got := sysDifferProblems(c.con, c.unc, pair); (len(got) > 0) != c.bad {
			t.Errorf("differ %s: %q", name, got)
		}
	}
}

func isUint(s string) bool { _, err := strconv.ParseUint(s, 10, 16); return err == nil }

// parseSys accepts exactly the output contract: four header lines, then one
// line per call of sysCalls in order, each newline-terminated.
func parseSys(out string) (sysReport, error) {
	if !strings.HasSuffix(out, "\n") {
		return sysReport{}, errors.New("output does not end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 4+len(sysCalls) {
		return sysReport{}, fmt.Errorf("%d lines, want %d", len(lines), 4+len(sysCalls))
	}
	rep := sysReport{Calls: map[string]string{}}
	head := []struct {
		key   string
		parse func(string) error
	}{
		{"seccomp", func(v string) (err error) { rep.Seccomp, err = small(v, 2); return }},
		{"nonewprivs", func(v string) (err error) { rep.NoNewPrivs, err = small(v, 1); return }},
		{"capeff", func(v string) (err error) { rep.CapEff, err = hex16(v); return }},
		{"capbnd", func(v string) (err error) { rep.CapBnd, err = hex16(v); return }},
	}
	for i, h := range head {
		v, ok := strings.CutPrefix(lines[i], h.key+" ")
		if !ok {
			return sysReport{}, fmt.Errorf("line %d is %q, want %q", i+1, lines[i], h.key+" …")
		}
		if err := h.parse(v); err != nil {
			return sysReport{}, fmt.Errorf("%s: %v", h.key, err)
		}
	}
	for i, name := range sysCalls {
		l := lines[4+i]
		v, ok := strings.CutPrefix(l, "sys "+name+" ")
		word, _, _ := strings.Cut(v, " ")
		if check := sysLineRE[word]; !ok || check == nil || !check(v) {
			return sysReport{}, fmt.Errorf("line %d is %q, want \"sys %s ok|errno <n> <SYMBOL>|signal 31 SIGSYS|unknown …\"", 5+i, l, name)
		}
		rep.Calls[name] = v
	}
	return rep, nil
}

func small(v string, maxv int) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > maxv || strconv.Itoa(n) != v {
		return 0, fmt.Errorf("%q is not 0…%d", v, maxv)
	}
	return n, nil
}

func hex16(v string) (uint64, error) {
	if len(v) != 16 {
		return 0, fmt.Errorf("%q is not 16 hex digits", v)
	}
	return strconv.ParseUint(v, 16, 64)
}

// TestImagectr_ParseSys pins the probe's output contract as the suite reads it.
func TestImagectr_ParseSys(t *testing.T) {
	var b strings.Builder
	b.WriteString("seccomp 2\nnonewprivs 1\ncapeff 0000000000000000\ncapbnd 00000000a80425fb\n")
	for _, c := range sysCalls {
		if c == "getpid" {
			b.WriteString("sys getpid ok\n")
		} else {
			b.WriteString("sys " + c + " errno 1 EPERM\n")
		}
	}
	good := b.String()
	rep, err := parseSys(good)
	if err != nil || rep.Seccomp != 2 || rep.NoNewPrivs != 1 || rep.CapEff != 0 || rep.CapBnd != 0xa80425fb ||
		rep.Calls["getpid"] != "ok" || rep.Calls["socket-raw"] != "errno 1 EPERM" || len(rep.Calls) != len(sysCalls) {
		t.Fatalf("good output: %v %+v", err, rep)
	}
	for _, form := range []string{"signal 31 SIGSYS", "unknown host kernel.unprivileged_userns_clone=0", "unknown errno 22 EINVAL"} {
		if rep, err := parseSys(strings.Replace(good, "sys bpf errno 1 EPERM", "sys bpf "+form, 1)); err != nil || rep.Calls["bpf"] != form {
			t.Errorf("%q: %v %q", form, err, rep.Calls["bpf"])
		}
	}
	for name, bad := range map[string]string{
		"no final newline": strings.TrimSuffix(good, "\n"),
		"seccomp 3":        strings.Replace(good, "seccomp 2", "seccomp 3", 1),
		"short capeff":     strings.Replace(good, "capeff 0000000000000000", "capeff 0", 1),
		"order swapped":    strings.Replace(strings.Replace(good, "sys keyctl", "sys XX", 1), "sys add_key", "sys keyctl", 1),
		"a call missing":   strings.Replace(good, "sys bpf errno 1 EPERM\n", "", 1),
		"extra line":       good + "sys extra ok\n",
		"bad errno":        strings.Replace(good, "sys bpf errno 1 EPERM", "sys bpf errno x EPERM", 1),
		"verdict word":     strings.Replace(good, "sys getpid ok", "sys getpid fine", 1),
		"host, no switch":  strings.Replace(good, "sys bpf errno 1 EPERM", "sys bpf unknown host", 1),
		"other signal":     strings.Replace(good, "sys bpf errno 1 EPERM", "sys bpf signal 9 SIGKILL", 1),
	} {
		if _, err := parseSys(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ───────── a namespace's own view ─────────

// ifAddr is an address of an interface in a network namespace.
type ifAddr struct {
	Ifname    string
	Kind      string       // link kind ("bridge", "veth", …; "" for none)
	Addr      netip.Addr   // with the interface as zone when link-local
	Prefix    netip.Prefix // the address and its prefix length (no zone)
	Tentative bool
}

// nsAddrs lists the addresses of container's network namespace ("" = the
// node's), read as root with `ip -j -d addr`.
func nsAddrs(t testing.TB, container string) []ifAddr {
	t.Helper()
	argv := []string{"ip", "-j", "-d", "addr"}
	if container != "" {
		pid, _ := containerPid(t, container)
		argv = append(nsenterArgv(fmt.Sprintf("/proc/%d/ns/net", pid), 0, 0), argv...)
	}
	var ifs []struct {
		Ifname   string `json:"ifname"`
		Linkinfo *struct {
			InfoKind string `json:"info_kind"`
		} `json:"linkinfo"`
		AddrInfo []struct {
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
			Tentative bool   `json:"tentative"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(must(t, cmdTimeout, argv...)), &ifs); err != nil {
		t.Fatalf("ip addr in %q: %v", container, err)
	}
	var out []ifAddr
	for _, i := range ifs {
		kind := ""
		if i.Linkinfo != nil {
			kind = i.Linkinfo.InfoKind
		}
		for _, a := range i.AddrInfo {
			ip, err := netip.ParseAddr(a.Local)
			if err != nil {
				t.Fatalf("ip addr in %q: address %q", container, a.Local)
			}
			if ip.Is6() && ip.IsLinkLocalUnicast() {
				ip = ip.WithZone(i.Ifname)
			}
			out = append(out, ifAddr{i.Ifname, kind, ip, netip.PrefixFrom(ip.WithZone(""), a.Prefixlen), a.Tentative})
		}
	}
	return out
}

// hasDefaultRoute reports whether container's namespace has a default route of
// the family ("-4" or "-6").
func hasDefaultRoute(t testing.TB, container, family string) bool {
	t.Helper()
	pid, _ := containerPid(t, container)
	out := must(t, cmdTimeout, append(nsenterArgv(fmt.Sprintf("/proc/%d/ns/net", pid), 0, 0), "ip", family, "route", "show", "default")...)
	return strings.TrimSpace(out) != ""
}

// nsListeners lists the listening sockets of container's namespace ("" = the
// node's), from `ss -Htlnu` run as root inside it.
func nsListeners(t testing.TB, container string) []Listener {
	t.Helper()
	argv := []string{"ss", "-Htlnu"}
	if container != "" {
		pid, _ := containerPid(t, container)
		argv = append(nsenterArgv(fmt.Sprintf("/proc/%d/ns/net", pid), 0, 0), argv...)
	}
	l, err := parseSS(must(t, cmdTimeout, argv...))
	if err != nil {
		t.Fatalf("ss in %q: %v", container, err)
	}
	return l
}

// containerLinks maps each bridge container is attached to onto the
// container's own interface on it, and returns the container's address there.
func containerLinks(t testing.TB, container string) map[string]struct {
	Ifname string
	Addr   netip.Addr
} {
	t.Helper()
	var nets map[string]struct{ IPAddress string }
	if err := json.Unmarshal([]byte(docker(t, "inspect", "-f", "{{json .NetworkSettings.Networks}}", container)), &nets); err != nil {
		t.Fatalf("inspect %s: %v", container, err)
	}
	addrs := nsAddrs(t, container)
	out := map[string]struct {
		Ifname string
		Addr   netip.Addr
	}{}
	for name, n := range nets {
		ip, err := netip.ParseAddr(n.IPAddress)
		if err != nil {
			continue // network none, or no IPv4 address
		}
		br := bridgeOf(t, name)
		for _, a := range addrs {
			if a.Addr == ip {
				out[br] = struct {
					Ifname string
					Addr   netip.Addr
				}{a.Ifname, ip}
			}
		}
		if _, ok := out[br]; !ok {
			t.Fatalf("%s: no interface holds its address on network %s", container, name)
		}
	}
	return out
}

// bridgeOf is a network's bridge interface: its bridge-name option, else
// Docker's br-<id> name (docker0 for the default network).
func bridgeOf(t testing.TB, network string) string {
	t.Helper()
	var n []struct {
		ID      string
		Name    string
		Driver  string
		Options map[string]string
	}
	if err := json.Unmarshal([]byte(docker(t, "network", "inspect", network)), &n); err != nil || len(n) != 1 {
		t.Fatalf("network inspect %s: %v", network, err)
	}
	switch {
	case n[0].Options["com.docker.network.bridge.name"] != "":
		return n[0].Options["com.docker.network.bridge.name"]
	case n[0].Name == "bridge":
		return "docker0"
	}
	return "br-" + n[0].ID[:12]
}

// probeVerdict is probe returning the verdict line itself ("timeout",
// "unreachable ENETUNREACH", …), so a test can require the exact form its
// barrier produces. The same agreement rules apply: one verdict line whose
// status is the exit status, never an "error".
func probeVerdict(t testing.TB, container string, args ...string) string {
	t.Helper()
	argv := slices.Concat(inContainer(t, container), []string{probeBin}, args)
	r, err := run(probeTimeout, nil, argv...)
	if err != nil {
		t.Fatalf("probe from %q: %v", container, err)
	}
	line, rest, _ := strings.Cut(r.stdout, "\n")
	want, ok := verdicts[strings.SplitN(line, " ", 2)[0]]
	if !ok || rest != "" || !strings.HasSuffix(r.stdout, "\n") || want != r.code {
		t.Fatalf("probe from %q %q: exit %d with output %q (stderr %q): not a probe verdict", container, args, r.code, brief(r.stdout), brief(r.stderr))
	}
	if want == 3 {
		t.Fatalf("probe from %q %q: %s", container, args, line)
	}
	return line
}

// wantVerdict probes and requires the verdict word (and errno, when want has
// one): "connected", "timeout", "unreachable ENETUNREACH", "refused" …
func wantVerdict(t testing.TB, what, container, want string, args ...string) {
	t.Helper()
	got := probeVerdict(t, container, args...)
	if got != want && !(strings.HasPrefix(got, want+" ") && !strings.Contains(want, " ")) {
		t.Errorf("%s: %s %s from %q: got %q, want %q", what, args[0], args[1], container, got, want)
	}
}

// waitV6 waits until no IPv6 address of interface ifname in container's
// namespace ("" = node) is tentative (duplicate address detection done); a
// bound socket on a tentative address fails.
func waitV6(t testing.TB, container, ifname string) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		busy := ""
		for _, a := range nsAddrs(t, container) {
			if a.Tentative && a.Ifname == ifname {
				busy = a.Prefix.String()
			}
		}
		if busy == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%q: address %s still tentative after 15 s", container, busy)
		}
	}
}

// bridgeLinkLocal is the node's fe80:: address on bridge, waited for.
func bridgeLinkLocal(t testing.TB, bridge string) netip.Addr {
	t.Helper()
	waitV6(t, "", bridge)
	for _, a := range nsAddrs(t, "") {
		if a.Ifname == bridge && a.Addr.Is6() && a.Addr.IsLinkLocalUnicast() {
			return a.Addr
		}
	}
	t.Fatalf("bridge %s has no fe80:: address", bridge)
	return netip.Addr{}
}

// ───────── scratch bridges of the platform's classes ─────────

// scratchBridge creates a labelled network whose bridge is named bridge
// (spp9999, spp9998, …): IPv4 only, with a host address on the bridge, internal
// or not. It returns the network name and the bridge's host address.
func scratchBridge(t testing.TB, bridge string, internal bool, opts ...string) (string, netip.Addr) {
	t.Helper()
	name := "sp-test-" + bridge
	args := []string{"--ipv6=false", "-o", "com.docker.network.bridge.name=" + bridge}
	if internal {
		args = append(args, "--internal")
	}
	scratchNet(t, name, append(args, opts...)...)
	return name, networkGateway(t, name)
}

// networkGateway is the host address Docker gave a network's bridge.
func networkGateway(t testing.TB, network string) netip.Addr {
	t.Helper()
	var cfg []struct{ Gateway string }
	if err := json.Unmarshal([]byte(docker(t, "network", "inspect", "-f", "{{json .IPAM.Config}}", network)), &cfg); err != nil {
		t.Fatalf("network inspect %s: %v", network, err)
	}
	for _, c := range cfg {
		if ip, err := netip.ParseAddr(c.Gateway); err == nil && ip.Is4() {
			return ip
		}
	}
	t.Fatalf("network %s has no IPv4 gateway address", network)
	return netip.Addr{}
}

// member runs a scratch member of network: the control-plane image asleep, all
// capabilities dropped, at uid 65534 unless args say otherwise.
func member(t testing.TB, name, network string, args ...string) string {
	t.Helper()
	base := []string{"--network", network, "--cap-drop", "ALL", "--user", "65534:65534"}
	return scratchContainer(t, name, append(base, args...)...)
}

// v6Member is a scratch member whose interface on network keeps its IPv6
// link-local address (Docker disables IPv6 on the interfaces of an IPv4-only
// network unless told otherwise). It returns the member and that address.
func v6Member(t testing.TB, name, network string) (string, netip.Addr) {
	t.Helper()
	scratchContainer(t, name, "--network", "name="+network+",driver-opt=com.docker.network.endpoint.sysctls=net.ipv6.conf.IFNAME.disable_ipv6=0",
		"--cap-drop", "ALL", "--user", "65534:65534")
	waitV6(t, name, "eth0")
	for _, a := range nsAddrs(t, name) {
		if a.Ifname != "lo" && a.Addr.IsLinkLocalUnicast() && a.Addr.Is6() {
			return name, a.Addr
		}
	}
	t.Fatalf("scratch member %s has no IPv6 link-local address", name)
	return "", netip.Addr{}
}

// neighbourName and the 10.215.0.0/30 link: a namespace reached by routing
// through the node over a veth, not over any bridge and not through Docker's
// inter-network rules, so a routed probe measures our forward rules alone.
const neighbourName = "sp-test-nb"

// The IPv4 LLMNR and mDNS groups.
var llmnr4, mdns4 = netip.MustParseAddr("224.0.0.252"), netip.MustParseAddr("224.0.0.251")

var (
	neighbourHost = netip.MustParseAddr("10.215.0.1")
	neighbourAddr = netip.MustParseAddr("10.215.0.2")
)

// neighbour creates the routed neighbour (a network-less scratch container that
// holds one end of a veth) and returns its address.
func neighbour(t testing.TB) netip.Addr {
	t.Helper()
	scratchContainer(t, neighbourName, "--network", "none", "--cap-drop", "ALL")
	pid, _ := containerPid(t, neighbourName)
	t.Cleanup(func() {
		if r, err := run(cmdTimeout, nil, "ip", "link", "del", "sp-nb0"); err != nil || (r.code != 0 && !strings.Contains(r.stderr, "Cannot find")) {
			t.Errorf("removing sp-nb0: %v %s", err, brief(r.stderr))
		}
	})
	must(t, cmdTimeout, "ip", "link", "add", "sp-nb0", "type", "veth", "peer", "name", "sp-nb1")
	must(t, cmdTimeout, "ip", "link", "set", "sp-nb1", "netns", strconv.Itoa(pid))
	must(t, cmdTimeout, "ip", "addr", "add", neighbourHost.String()+"/30", "dev", "sp-nb0")
	must(t, cmdTimeout, "ip", "link", "set", "sp-nb0", "up")
	in := nsenterArgv(fmt.Sprintf("/proc/%d/ns/net", pid), 0, 0)
	must(t, cmdTimeout, append(in, "ip", "addr", "add", neighbourAddr.String()+"/30", "dev", "sp-nb1")...)
	must(t, cmdTimeout, append(in, "ip", "link", "set", "sp-nb1", "up")...)
	must(t, cmdTimeout, append(in, "ip", "route", "add", "default", "via", neighbourHost.String())...)
	return neighbourAddr
}

// withTablesDeleted is withRuleDeleted for both of our tables at once: under
// the drift hold, `delete table inet supapace; delete table bridge supapace`,
// fn, then the reload (also in cleanup) and `supapaced nft check`.
func withTablesDeleted(t testing.TB, fn func()) {
	t.Helper()
	driftHold(t)
	restore := restoreRules(t)
	t.Cleanup(restore)
	defer restore()
	must(t, cmdTimeout, "nft", "delete table inet supapace; delete table bridge supapace")
	fn()
}

// ───────── capability and mount views ─────────

// capBits are the capability bits a bridge member must not hold.
const (
	capNetAdmin = 12
	capNetRaw   = 13
)

// procStatus reads fields of /proc/<pid>/status.
func procStatus(t testing.TB, pid int) map[string]string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("status of pid %d: %v", pid, err)
	}
	m := map[string]string{}
	for line := range strings.Lines(string(b)) {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// mountPoints is the set of mount points of pid's mount namespace (field 5 of
// /proc/<pid>/mountinfo).
func mountPoints(t testing.TB, pid int) []string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatalf("mountinfo of pid %d: %v", pid, err)
	}
	var out []string
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) > 4 {
			out = append(out, f[4])
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// devEntries lists /dev as pid sees it.
func devEntries(t testing.TB, pid int) []string {
	t.Helper()
	es, err := os.ReadDir(fmt.Sprintf("/proc/%d/root/dev", pid))
	if err != nil {
		t.Fatalf("/dev of pid %d: %v", pid, err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// sameJSON reports whether two JSON documents are equal as values.
func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// containsAny reports whether data holds any of the needles (each non-empty).
func containsAny(data []byte, needles [][]byte) int {
	for i, n := range needles {
		if len(n) > 0 && bytes.Contains(data, n) {
			return i
		}
	}
	return -1
}

// ───────── controls on scratch bridges: one rule, a path that has a route ─────────

// bound parses the address a listener reported.
func bound(t testing.TB, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("listener reported %q: %v", s, err)
	}
	return ap
}

// rxCounter counts, in container's network namespace, the packets of proto
// arriving for port, with a counter of its own table there (gone with the
// namespace); the returned function reads it. It is what the receiver saw,
// whatever the sender's verdict.
func rxCounter(t testing.TB, container, proto string, port uint16) func() uint64 {
	t.Helper()
	pid, _ := containerPid(t, container)
	in := nsenterArgv(fmt.Sprintf("/proc/%d/ns/net", pid), 0, 0)
	name := fmt.Sprintf("rx_%s_%d", proto, port)
	must(t, cmdTimeout, append(in, "nft", fmt.Sprintf(
		"add table inet sp_test_rx; add counter inet sp_test_rx %s; "+
			"add chain inet sp_test_rx input { type filter hook input priority 0; policy accept; }; "+
			"add rule inet sp_test_rx input %s dport %d counter name %q", name, proto, port, name))...)
	return func() uint64 {
		var doc struct {
			Nftables []struct {
				Counter *struct{ Packets uint64 } `json:"counter"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal([]byte(must(t, cmdTimeout, append(in, "nft", "-j", "list", "counter", "inet", "sp_test_rx", name)...)), &doc); err != nil {
			t.Fatalf("receiver counter %s: %v", name, err)
		}
		for _, o := range doc.Nftables {
			if o.Counter != nil {
				return o.Counter.Packets
			}
		}
		t.Fatalf("receiver counter %s: not listed", name)
		return 0
	}
}

// controlI2AndIPv6 is the input-rule and IPv6 control on a scratch internal,
// non-isolated project-class bridge spp9999 (the real project bridge has no
// host IPv4 address, so I2 is measured where one exists). With our tables a
// member's probes to the bridge's host address and, from a member with IPv6,
// to the bridge's fe80:: canary and its LLMNR and mDNS groups fail; with I2
// deleted the same probes reach. Member to member over IPv6 fails and reaches
// with an ip6 accept inserted for that bridge. Everything runs under the drift
// hold, taken before the first object exists and released after the last is
// gone.
func controlI2AndIPv6(t testing.TB) {
	t.Helper()
	driftHold(t)
	net9, gw := scratchBridge(t, "spp9999", true)
	m4 := member(t, "sp-test-i2-m4", net9)
	v6a, _ := v6Member(t, "sp-test-i2-v6a", net9)
	v6b, v6bAddr := v6Member(t, "sp-test-i2-v6b", net9)
	ll := bridgeLinkLocal(t, "spp9999")
	host4 := bound(t, listen(t, "", "tcp", netip.AddrPortFrom(gw, 0).String()))
	host6 := bound(t, listen(t, "", "tcp", netip.AddrPortFrom(ll, 0).String()))
	listen(t, "", "udp", netip.AddrPortFrom(ll, 5355).String(), "--join", "ff02::1:3")
	listen(t, "", "udp", netip.AddrPortFrom(ll, 5353).String(), "--join", "ff02::fb")
	peer := bound(t, listen(t, v6b, "tcp", netip.AddrPortFrom(v6bAddr.WithZone("eth0"), 0).String()))
	onLink := func(ap netip.AddrPort) string {
		return netip.AddrPortFrom(ap.Addr().WithZone("eth0"), ap.Port()).String()
	}
	// The canaries answer in the node's own namespace.
	wantVerdict(t, "control: host IPv4 canary from the node", "", "connected", "tcp", host4.String())
	wantVerdict(t, "control: fe80:: canary from the node", "", "connected", "tcp", netip.AddrPortFrom(ll, host6.Port()).String())

	type p struct {
		what, from, proto, dst string
	}
	toHost := []p{
		{"member → bridge host address", m4, "tcp", host4.String()},
		{"IPv6 member → bridge fe80::", v6a, "tcp", onLink(host6)},
		{"IPv6 member → LLMNR group", v6a, "udp", "[ff02::1:3%eth0]:5355"},
		{"IPv6 member → mDNS group", v6a, "udp", "[ff02::fb%eth0]:5353"},
	}
	m2m := p{"IPv6 member → IPv6 member", v6a, "tcp", onLink(peer)}
	reached := map[string]string{"tcp": "connected", "udp": "answered"}
	// Neighbour discovery between two members takes up to a second on its own:
	// the member-to-member probe waits three.
	for _, c := range toHost {
		wantVerdict(t, c.what+" (tables loaded)", c.from, "timeout", c.proto, c.dst)
	}
	wantVerdict(t, m2m.what+" (tables loaded)", m2m.from, "timeout", m2m.proto, m2m.dst, "--timeout", "3s")
	withRuleDeleted(t, "inet supapace", "input", "I2", func() {
		for _, c := range toHost {
			wantVerdict(t, "control: "+c.what+" with I2 deleted", c.from, reached[c.proto], c.proto, c.dst)
		}
		wantVerdict(t, m2m.what+" with only I2 deleted", m2m.from, "timeout", m2m.proto, m2m.dst, "--timeout", "3s")
	})
	withRuleInserted(t, "bridge supapace", "forward", `meta ibrname "spp9999" ether type ip6 accept`, func() {
		wantVerdict(t, "control: "+m2m.what+" with an ip6 accept", m2m.from, "connected", m2m.proto, m2m.dst, "--timeout", "3s")
	})
}

// controlRouted is the routed-path control on a scratch non-internal
// project-class bridge spp9998, whose members have a route: a member's
// connection to the routed neighbour fails with our tables; with F4 alone
// deleted it still fails (F2 drops the opening packet), with F2 alone deleted
// it still fails (F4 drops the reply), with both deleted it connects. The same
// member's datagram to the LLMNR group on the bridge's host side fails and is
// answered with I2 deleted. Under the drift hold throughout.
func controlRouted(t testing.TB) {
	t.Helper()
	driftHold(t)
	net8, gw := scratchBridge(t, "spp9998", false)
	m := member(t, "sp-test-f2-m", net8)
	nb := neighbour(t)
	dst := bound(t, listen(t, neighbourName, "tcp", netip.AddrPortFrom(nb, 0).String())).String()
	listen(t, "", "udp", netip.AddrPortFrom(gw, 5355).String(), "--join", llmnr4.String())
	wantVerdict(t, "control: the neighbour answers the node", "", "connected", "tcp", dst)

	wantVerdict(t, "member → routed neighbour (tables loaded)", m, "timeout", "tcp", dst)
	group := netip.AddrPortFrom(llmnr4, 5355).String()
	wantVerdict(t, "member → LLMNR group (tables loaded)", m, "timeout", "udp", group)
	withRuleDeleted(t, "inet supapace", "forward", "F4", func() {
		wantVerdict(t, "member → routed neighbour with only F4 deleted (F2 drops the opening packet)", m, "timeout", "tcp", dst)
	})
	withRuleDeleted(t, "inet supapace", "forward", "F2", func() {
		wantVerdict(t, "member → routed neighbour with only F2 deleted (F4 drops the reply)", m, "timeout", "tcp", dst)
		withRuleDeleted(t, "inet supapace", "forward", "F4", func() {
			wantVerdict(t, "control: member → routed neighbour with F2 and F4 deleted", m, "connected", "tcp", dst)
		})
	})
	withRuleDeleted(t, "inet supapace", "input", "I2", func() {
		wantVerdict(t, "control: member → LLMNR group with I2 deleted", m, "answered", "udp", group)
	})
}

// bypassUnknownBridges: two members of a non-internal network created without
// the bridge-name option, and two of docker0, reach neither the host, nor each
// other, nor the routed neighbour with our tables loaded — and nothing of the
// routed attempts arrives at the neighbour, so a one-way leak fails too; with
// both tables deleted all of it reaches, possible only because these networks
// have a host address and a route. Under the drift hold throughout.
func bypassUnknownBridges(t testing.TB) {
	t.Helper()
	driftHold(t)
	unnamed := scratchNet(t, "sp-test-unnamed", "--ipv6=false")
	nb := neighbour(t)
	tcpDst := bound(t, listen(t, neighbourName, "tcp", netip.AddrPortFrom(nb, 0).String()))
	udpDst := bound(t, listen(t, neighbourName, "udp", netip.AddrPortFrom(nb, 0).String()))
	rx := map[string]func() uint64{
		"tcp": rxCounter(t, neighbourName, "tcp", tcpDst.Port()),
		"udp": rxCounter(t, neighbourName, "udp", udpDst.Port()),
	}
	routed := map[string]string{"tcp": tcpDst.String(), "udp": udpDst.String()}
	type pair struct{ from, host, peer string }
	var pairs []pair
	for _, n := range []struct{ network, first, second string }{{unnamed, "sp-test-u1", "sp-test-u2"}, {"bridge", "sp-test-d1", "sp-test-d2"}} {
		a, b := member(t, n.first, n.network), member(t, n.second, n.network)
		br := bridgeOf(t, n.network)
		if strings.HasPrefix(br, "spp") || br == "spl0" || br == "spi0" {
			t.Fatalf("network %s has bridge %s, a name our rules allow", n.network, br)
		}
		host := bound(t, listen(t, "", "tcp", netip.AddrPortFrom(networkGateway(t, n.network), 0).String())).String()
		peer := bound(t, listen(t, b, "tcp", netip.AddrPortFrom(containerLinks(t, b)[br].Addr, 0).String())).String()
		wantVerdict(t, "control: the host canary of "+br+" answers the node", "", "connected", "tcp", host)
		pairs = append(pairs, pair{a, host, peer})
	}
	wantVerdict(t, "control: the neighbour answers the node over TCP", "", "connected", "tcp", routed["tcp"])
	wantVerdict(t, "control: the neighbour answers the node over UDP", "", "answered", "udp", routed["udp"])
	reached := map[string]string{"tcp": "connected", "udp": "answered"}
	for _, p := range pairs {
		wantVerdict(t, p.from+" → the host (tables loaded)", p.from, "timeout", "tcp", p.host)
		wantVerdict(t, p.from+" → the other member (tables loaded)", p.from, "timeout", "tcp", p.peer)
		for _, proto := range []string{"tcp", "udp"} {
			before := rx[proto]()
			wantVerdict(t, p.from+" → a routed address (tables loaded)", p.from, "timeout", proto, routed[proto])
			if got := rx[proto](); got != before {
				t.Errorf("%s → the routed neighbour over %s: %d packets arrived at the neighbour, want none", p.from, proto, got-before)
			}
		}
	}
	withTablesDeleted(t, func() {
		for _, p := range pairs {
			wantVerdict(t, "control: "+p.from+" → the host, tables deleted", p.from, "connected", "tcp", p.host)
			wantVerdict(t, "control: "+p.from+" → the other member, tables deleted", p.from, "connected", "tcp", p.peer)
			for _, proto := range []string{"tcp", "udp"} {
				before := rx[proto]()
				wantVerdict(t, "control: "+p.from+" → a routed address, tables deleted", p.from, reached[proto], proto, routed[proto])
				if rx[proto]() == before {
					t.Errorf("control: %s → the routed neighbour over %s reached, yet the neighbour's counter did not move", p.from, proto)
				}
			}
		}
	})
}

// ───────── the egress sweep ─────────

// target is one probe of the egress sweep. A link-local or multicast IPv6
// destination carries the zone of the node's interface it belongs to; the
// sweep translates it to the prober's own interface on that link.
type target struct {
	What, Proto string
	Dst         netip.AddrPort
}

// link is one network attachment of a container as the test asserts it.
type link struct {
	Network, Bridge string
	Prefix          netip.Prefix // the container's address and the network's prefix length
}

// assertTopology requires container to be attached to exactly the networks of
// want, each at its address there, and returns those attachments. An extra or
// missing network fails the test by name.
func assertTopology(t testing.TB, container string, want map[string]netip.Addr) []link {
	t.Helper()
	var nets map[string]struct {
		IPAddress   string
		IPPrefixLen int
	}
	if err := json.Unmarshal([]byte(docker(t, "inspect", "-f", "{{json .NetworkSettings.Networks}}", container)), &nets); err != nil {
		t.Fatalf("inspect %s: %v", container, err)
	}
	var out []link
	for name, n := range nets {
		w, ok := want[name]
		if !ok {
			t.Fatalf("%s is attached to network %s, which it must not be on (want only %v)", container, name, slices.Sorted(maps.Keys(want)))
		}
		ip, err := netip.ParseAddr(n.IPAddress)
		if err != nil || ip != w {
			t.Fatalf("%s is on %s at %q, want %v", container, name, n.IPAddress, w)
		}
		out = append(out, link{name, bridgeOf(t, name), netip.PrefixFrom(ip, n.IPPrefixLen)})
	}
	for name := range want {
		if _, ok := nets[name]; !ok {
			t.Fatalf("%s is not attached to network %s", container, name)
		}
	}
	slices.SortFunc(out, func(a, b link) int { return strings.Compare(a.Network, b.Network) })
	return out
}

// nsView is what a sweep's expectations are computed from: the asserted links,
// the prober's interface on each link's bridge, and which interfaces hold IPv6.
type nsView struct {
	Links  []link
	Ifname map[string]string // bridge → the prober's interface on it
	V6     map[string]bool   // interface → holds an IPv6 address
	AnyV6  bool              // any IPv6 address in the namespace, loopback included
}

// plan is the probe of tg from v: the destination as the prober addresses it,
// the verdict a dropped or unroutable packet gives, or why it cannot be sent
// ("no IPv6", "off link"). An IPv4 destination inside one of the links times
// out; any other IPv4 destination is unreachable (no default route). An IPv6
// link-local or group destination on a link's bridge times out when the
// prober's interface there holds IPv6; otherwise a unicast one is unreachable
// and a group one cannot be sent. Every other IPv6 destination is unreachable.
func (v nsView) plan(tg target) (dst netip.AddrPort, want, skip string) {
	dst, ip := tg.Dst, tg.Dst.Addr()
	if ip.Is4() {
		for _, l := range v.Links {
			if l.Prefix.Masked().Contains(ip) {
				return dst, "timeout", ""
			}
		}
		return dst, "unreachable ENETUNREACH", ""
	}
	if !v.AnyV6 {
		return dst, "", "no IPv6"
	}
	if z := ip.Zone(); z != "" {
		ifn, ok := v.Ifname[z]
		if !ok {
			return dst, "", "off link"
		}
		dst = netip.AddrPortFrom(ip.WithZone(ifn), dst.Port())
		switch {
		case v.V6[ifn]:
			return dst, "timeout", ""
		case ip.IsMulticast():
			return dst, "", "no IPv6"
		}
		return dst, "unreachable ENETUNREACH", ""
	}
	if ip.IsMulticast() {
		return dst, "", "off link"
	}
	return dst, "unreachable ENETUNREACH", ""
}

// view builds the namespace view of container from its asserted links: each
// link's address must be held by one of its interfaces, and no other
// non-loopback IPv4 address may exist there.
func view(t testing.TB, container string, links []link) nsView {
	t.Helper()
	v := nsView{Links: links, Ifname: map[string]string{}, V6: map[string]bool{}}
	for _, a := range nsAddrs(t, container) {
		ip := a.Addr
		switch {
		case ip.Is6():
			v.AnyV6 = true
			if a.Ifname != "lo" {
				v.V6[a.Ifname] = true
			}
		case !ip.IsLoopback():
			i := slices.IndexFunc(links, func(l link) bool { return l.Prefix.Addr() == ip })
			if i < 0 {
				t.Fatalf("%s holds %v on %s, outside its asserted networks", container, ip, a.Ifname)
			}
			v.Ifname[links[i].Bridge] = a.Ifname
		}
	}
	for _, l := range links {
		if _, ok := v.Ifname[l.Bridge]; !ok {
			t.Fatalf("%s: no interface holds its address %v on %s", container, l.Prefix.Addr(), l.Network)
		}
	}
	return v
}

// hostAddrs are the node's addresses a neighbour could be sent to: every
// non-loopback address, and of the IPv6 link-local ones only those of bridges
// (a bridge port's own address is not on any member's link). An address still
// in duplicate address detection is left out: nothing can bind it yet.
func hostAddrs(t testing.TB) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, a := range nsAddrs(t, "") {
		ip := a.Addr
		if ip.IsLoopback() || a.Tentative || (ip.Is6() && ip.IsLinkLocalUnicast() && a.Kind != "bridge") {
			continue
		}
		out = append(out, ip)
	}
	return out
}

// canaries starts the suite's own listeners in the node's namespace: TCP and
// UDP on every host address and on both wildcards, the LLMNR (UDP 5355,
// 224.0.0.252) and mDNS (UDP 5353, 224.0.0.251) groups, and the same two
// groups on the fe80:: address of each bridge in bridges (ff02::1:3, ff02::fb).
// Each unicast canary is first shown to answer in the node's own namespace.
// It returns the group targets; the unicast canaries are found by nsListeners.
func canaries(t testing.TB, bridges []string) []target {
	t.Helper()
	reached := map[string]string{"tcp": "connected", "udp": "answered"}
	for _, br := range bridges {
		bridgeLinkLocal(t, br) // present and usable before the per-address canaries
	}
	addrs := hostAddrs(t)
	var first4, first6 netip.Addr
	for _, a := range addrs {
		if a.Is4() && !first4.IsValid() {
			first4 = a
		}
		if a.Is6() && !first6.IsValid() {
			first6 = a
		}
		for _, proto := range []string{"tcp", "udp"} {
			ap := bound(t, listen(t, "", proto, netip.AddrPortFrom(a, 0).String()))
			wantVerdict(t, "control: canary answers in the node", "", reached[proto], proto, netip.AddrPortFrom(a, ap.Port()).String())
		}
	}
	for _, w := range []struct {
		any, at netip.Addr
	}{{netip.IPv4Unspecified(), first4}, {netip.IPv6Unspecified(), first6}} {
		for _, proto := range []string{"tcp", "udp"} {
			ap := bound(t, listen(t, "", proto, netip.AddrPortFrom(w.any, 0).String()))
			if w.at.IsValid() {
				wantVerdict(t, "control: wildcard canary answers in the node", "", reached[proto], proto, netip.AddrPortFrom(w.at, ap.Port()).String())
			}
		}
	}
	groups := []target{
		{"LLMNR group", "udp", netip.AddrPortFrom(llmnr4, 5355)},
		{"mDNS group", "udp", netip.AddrPortFrom(mdns4, 5353)},
	}
	listen(t, "", "udp", "0.0.0.0:5355", "--join", llmnr4.String())
	listen(t, "", "udp", "0.0.0.0:5353", "--join", mdns4.String())
	for _, br := range bridges {
		ll := bridgeLinkLocal(t, br)
		for _, g := range []struct {
			group string
			port  uint16
		}{{"ff02::1:3", 5355}, {"ff02::fb", 5353}} {
			listen(t, "", "udp", netip.AddrPortFrom(ll, g.port).String(), "--join", g.group)
			groups = append(groups, target{"group " + g.group + " on " + br, "udp",
				netip.AddrPortFrom(netip.MustParseAddr(g.group).WithZone(br), g.port)})
		}
	}
	return groups
}

// hostTargets expands the node's listeners into targets on the node's own
// addresses (see expandListeners).
func hostTargets(t testing.TB, listeners []Listener) []target {
	t.Helper()
	return expandListeners(listeners, hostAddrs(t))
}

// expandListeners: a wildcard socket on every host address of its family, a
// loopback socket not at all (no other namespace can address it), any other
// socket at its own address; sorted and without repeats.
func expandListeners(listeners []Listener, addrs []netip.Addr) []target {
	var out []target
	for _, l := range listeners {
		ip := l.Addr.Addr()
		switch {
		case ip.IsLoopback():
		case ip.IsUnspecified():
			for _, a := range addrs {
				if a.Is4() == ip.Is4() {
					out = append(out, target{"host listener " + l.Proto + " " + l.Addr.String(), l.Proto, netip.AddrPortFrom(a, l.Addr.Port())})
				}
			}
		default:
			out = append(out, target{"host listener", l.Proto, l.Addr})
		}
	}
	slices.SortFunc(out, func(a, b target) int {
		return strings.Compare(a.Proto+a.Dst.String(), b.Proto+b.Dst.String())
	})
	return slices.CompactFunc(out, func(a, b target) bool { return a.Proto == b.Proto && a.Dst == b.Dst })
}

// sweep probes every target from container's namespace at its uid and
// requires the verdict plan gives for the asserted links (the container must
// have no default route). A connection, an answer or a refusal fails the test.
func sweep(t testing.TB, container string, links []link, targets []target) {
	t.Helper()
	if hasDefaultRoute(t, container, "-4") {
		t.Fatalf("%s has an IPv4 default route", container)
	}
	v := view(t, container, links)
	if v.AnyV6 && hasDefaultRoute(t, container, "-6") {
		t.Fatalf("%s has an IPv6 default route", container)
	}
	probed, skipped := 0, map[string]int{}
	for _, tg := range targets {
		dst, want, skip := v.plan(tg)
		if skip != "" {
			skipped[skip]++
			continue
		}
		probed++
		wantVerdict(t, tg.What, container, want, tg.Proto, dst.String())
	}
	t.Logf("%s: %d probes; not sendable: %v", container, probed, skipped)
	if probed == 0 {
		t.Fatalf("%s: no target probed", container)
	}
}

// fixedTargets are the destinations every tenant namespace is probed for
// besides the node's listeners: the provider metadata endpoints, and one
// address in each private and shared address range (TCP 443 and UDP 53).
func fixedTargets() []target {
	out := []target{
		{"metadata endpoint", "tcp", netip.MustParseAddrPort("169.254.169.254:80")},
		{"metadata endpoint", "udp", netip.MustParseAddrPort("169.254.169.254:53")},
		{"IPv6 metadata endpoint", "tcp", netip.MustParseAddrPort("[fd00:ec2::254]:80")},
	}
	for _, a := range []string{"10.215.255.254", "172.16.0.1", "192.168.0.1", "100.64.0.1"} {
		ip := netip.MustParseAddr(a)
		out = append(out, target{"private range", "tcp", netip.AddrPortFrom(ip, 443)},
			target{"private range", "udp", netip.AddrPortFrom(ip, 53)})
	}
	return out
}

// TestImagectr_SweepPlan pins the sweep's expectations.
func TestImagectr_SweepPlan(t *testing.T) {
	v := nsView{
		Links:  []link{{"proj-x", "spp3", netip.MustParsePrefix("10.213.0.194/26")}, {"platform", "spl0", netip.MustParsePrefix("10.212.0.19/21")}},
		Ifname: map[string]string{"spp3": "eth0", "spl0": "eth1"},
		V6:     map[string]bool{"eth1": true},
		AnyV6:  true,
	}
	for _, c := range []struct {
		dst, want, skip, as string
	}{
		{"10.213.0.195:3000", "timeout", "", ""},
		{"10.212.0.2:8443", "timeout", "", ""},
		{"10.212.8.1:443", "unreachable ENETUNREACH", "", ""},
		{"224.0.0.252:5355", "unreachable ENETUNREACH", "", ""},
		{"[fe80::1%spp3]:22", "unreachable ENETUNREACH", "", "[fe80::1%eth0]:22"},
		{"[fe80::1%spl0]:22", "timeout", "", "[fe80::1%eth1]:22"},
		{"[ff02::fb%spp3]:5353", "", "no IPv6", ""},
		{"[ff02::fb%spl0]:5353", "timeout", "", "[ff02::fb%eth1]:5353"},
		{"[fe80::1%spi0]:22", "", "off link", ""},
		{"[fd00:ec2::254]:80", "unreachable ENETUNREACH", "", ""},
	} {
		dst, want, skip := v.plan(target{"", "tcp", netip.MustParseAddrPort(c.dst)})
		as := c.as
		if as == "" {
			as = c.dst
		}
		if want != c.want || skip != c.skip || (skip == "" && dst.String() != as) {
			t.Errorf("plan(%s) = %s %q %q; want %s %q %q", c.dst, dst, want, skip, as, c.want, c.skip)
		}
	}
	none := nsView{Links: v.Links, Ifname: v.Ifname}
	if _, _, skip := none.plan(target{"", "tcp", netip.MustParseAddrPort("[fd00:ec2::254]:80")}); skip != "no IPv6" {
		t.Errorf("a namespace without IPv6: skip %q", skip)
	}
	got := expandListeners([]Listener{
		{"tcp", netip.MustParseAddrPort("0.0.0.0:443")}, {"tcp", netip.MustParseAddrPort("127.0.0.1:9")},
		{"udp", netip.MustParseAddrPort("[::]:5353")}, {"tcp", netip.MustParseAddrPort("10.212.8.1:443")},
	}, []netip.Addr{netip.MustParseAddr("10.212.8.1"), netip.MustParseAddr("fe80::1%spl0")})
	var s []string
	for _, tg := range got {
		s = append(s, tg.Proto+" "+tg.Dst.String())
	}
	if want := []string{"tcp 10.212.8.1:443", "udp [fe80::1%spl0]:5353"}; !slices.Equal(s, want) {
		t.Errorf("expandListeners = %q, want %q", s, want)
	}
}

// ───────── the byte search ─────────

// keyForms is a secret file's bytes as they could appear elsewhere: the
// trimmed text; its hex and base64 forms when short; the bytes a hex text
// decodes to; each base64 body line of a PEM block and the block's DER.
func keyForms(b []byte) [][]byte {
	tb := bytes.TrimSpace(b)
	forms := [][]byte{tb}
	if len(tb) <= 64 {
		forms = append(forms, []byte(hex.EncodeToString(tb)), []byte(base64.StdEncoding.EncodeToString(tb)))
	}
	if raw, err := hex.DecodeString(string(tb)); err == nil && len(raw) >= 16 {
		forms = append(forms, raw)
	}
	if blk, _ := pem.Decode(tb); blk != nil {
		forms = append(forms, blk.Bytes)
	}
	for line := range bytes.Lines(tb) {
		line = bytes.TrimSpace(line)
		if len(line) >= 40 && !bytes.HasPrefix(line, []byte("-----")) {
			forms = append(forms, line)
		}
	}
	return forms
}

// TestImagectr_KeyForms: each form a key may take elsewhere is found.
func TestImagectr_KeyForms(t *testing.T) {
	der := bytes.Repeat([]byte{0x30, 0x82, 0x01, 0x0a, 0xde, 0xad}, 12)
	pemText := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	hexKey := bytes.Repeat([]byte("0123456789abcdef"), 4)
	raw, _ := hex.DecodeString(string(hexKey))
	for name, c := range map[string]struct{ key, hay []byte }{
		"PEM file, DER elsewhere":       {pemText, append([]byte("x"), der...)},
		"PEM file, one body line":       {pemText, bytes.Split(pemText, []byte("\n"))[1]},
		"hex key, its bytes elsewhere":  {append(hexKey, '\n'), append([]byte{1, 2}, raw...)},
		"short secret, base64 of it":    {[]byte("s3cret-pass\n"), []byte(base64.StdEncoding.EncodeToString([]byte("s3cret-pass")))},
		"short secret, hex of it":       {[]byte("s3cret-pass"), []byte(hex.EncodeToString([]byte("s3cret-pass")))},
		"short secret, verbatim, inner": {[]byte(" s3cret-pass "), []byte("a=s3cret-pass;")},
	} {
		if containsAny(c.hay, keyForms(c.key)) < 0 {
			t.Errorf("%s: not found", name)
		}
	}
	if containsAny([]byte("nothing here"), keyForms(pemText)) >= 0 {
		t.Error("a PEM key matched unrelated bytes")
	}
}

// searchTree reads every regular file below each root as the tree at base (a
// container's /proc/<pid>/root) sees it: the root is resolved through the
// tree's own links first, so a mount reached through a link is searched where
// it is mounted. look gets each file's path inside the tree and its bytes. It
// returns the files read per root and every error: a root that does not
// resolve or cannot be walked, and an unreadable file (one that vanished while
// the walk ran excepted).
func searchTree(base string, roots []string, look func(path string, data []byte)) (map[string]int, []error) {
	counts := map[string]int{}
	var errs []error
	for _, r := range roots {
		res, err := resolveIn(base, r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		top := filepath.Join(base, res)
		n := 0
		err = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p != top && errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			n++
			look(path.Join(res, strings.TrimPrefix(p, top)), data)
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s (%s): %v", r, res, err))
		}
		counts[r] = n
	}
	return counts, errs
}

// TestImagectr_SearchTreeFollowsRootLinks: a directory mount whose path is an
// absolute link inside the container is searched where the link points
// within the container's tree; a walk of the unresolved path finds nothing.
func TestImagectr_SearchTreeFollowsRootLinks(t *testing.T) {
	base := t.TempDir()
	for _, d := range []string{"etc/postgresql/postgresql.conf.d", "etc/postgresql-custom"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(base, "etc/postgresql/postgresql.conf.d/zz.conf"), []byte("x = 'NEEDLE'"), 0o644)
	os.Symlink("/etc/postgresql/postgresql.conf.d", filepath.Join(base, "etc/postgresql-custom/conf.d"))
	found := ""
	counts, errs := searchTree(base, []string{"/etc/postgresql-custom/conf.d"}, func(p string, data []byte) {
		if bytes.Contains(data, []byte("NEEDLE")) {
			found = p
		}
	})
	if len(errs) != 0 || counts["/etc/postgresql-custom/conf.d"] != 1 || found != "/etc/postgresql/postgresql.conf.d/zz.conf" {
		t.Fatalf("searchTree: counts %v, errors %v, found %q", counts, errs, found)
	}
	naive := 0
	filepath.WalkDir(filepath.Join(base, "/etc/postgresql-custom/conf.d"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			naive++
		}
		return nil
	})
	if naive != 0 {
		t.Fatalf("control: a walk of the unresolved path read %d files; the case no longer shows the difference", naive)
	}
	if _, errs := searchTree(base, []string{"/absent"}, func(string, []byte) {}); len(errs) == 0 {
		t.Error("a root that does not exist was not an error")
	}
}

// resolveIn resolves p inside the filesystem tree at root (a container's
// /proc/<pid>/root) the way the container sees it: every symbolic link on the
// way is followed, an absolute target from root. Mount points are listed by
// their resolved path ("/var/run/postgresql" under "/run/postgresql").
func resolveIn(root, p string) (string, error) {
	parts := strings.Split(strings.Trim(path.Clean("/"+p), "/"), "/")
	cur := "/"
	for hops := 0; len(parts) > 0; {
		next := path.Join(cur, parts[0])
		parts = parts[1:]
		target, err := os.Readlink(root + next)
		if err != nil {
			cur = next // not a link (or absent): taken as is
			continue
		}
		if hops++; hops > 40 {
			return "", fmt.Errorf("%s: too many links", p)
		}
		if !path.IsAbs(target) {
			target = path.Join(cur, target)
		}
		parts = append(strings.Split(strings.Trim(path.Clean(target), "/"), "/"), parts...)
		cur = "/"
	}
	return cur, nil
}

// TestImagectr_ResolveIn: relative and absolute links resolve inside the root.
func TestImagectr_ResolveIn(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"run/postgresql", "etc/postgresql/postgresql.conf.d", "etc/postgresql-custom"} {
		if err := os.MkdirAll(root+"/"+d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.Symlink("../run", root+"/var")
	os.Symlink("/etc/postgresql/postgresql.conf.d", root+"/etc/postgresql-custom/conf.d")
	os.Symlink("loop", root+"/loop")
	for in, want := range map[string]string{
		"/var/postgresql":               "/run/postgresql",
		"/etc/postgresql-custom/conf.d": "/etc/postgresql/postgresql.conf.d",
		"/etc/passwd":                   "/etc/passwd",
		"/":                             "/",
	} {
		if got, err := resolveIn(root, in); err != nil || got != want {
			t.Errorf("resolveIn(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := resolveIn(root, "/loop/x"); err == nil {
		t.Error("a link loop resolved")
	}
}

// ───────── container views shared by the posture tests ─────────

func imageOf(t testing.TB, container string) string {
	t.Helper()
	return strings.TrimSpace(docker(t, "inspect", "-f", "{{.Config.Image}}", container))
}

// networkMembers lists the names of the containers attached to network.
func networkMembers(t testing.TB, network string) []string {
	t.Helper()
	var cs map[string]struct{ Name string }
	if err := json.Unmarshal([]byte(docker(t, "network", "inspect", "-f", "{{json .Containers}}", network)), &cs); err != nil {
		t.Fatalf("network inspect %s: %v", network, err)
	}
	var out []string
	for _, c := range cs {
		out = append(out, c.Name)
	}
	slices.Sort(out)
	return out
}

func running(t testing.TB, container string) bool {
	t.Helper()
	r, err := run(cmdTimeout, nil, "docker", "inspect", "-f", "{{.State.Running}}", container)
	if err != nil {
		t.Fatal(err)
	}
	return r.code == 0 && strings.TrimSpace(r.stdout) == "true"
}

func hasCap(list []string, c string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.EqualFold(strings.TrimPrefix(strings.ToUpper(s), "CAP_"), c) })
}

// capViolations is every member of a bridge named spp*, spl0 or spi0 that is
// configured with a capability it must not have (privileged, no cap-drop ALL,
// or NET_RAW, NET_ADMIN or ALL added) or whose process holds bit 12 or 13 in
// its bounding set; one entry "<name>: configuration" or "<name>: bounding
// set" per finding, sorted. It also returns the members examined per bridge.
func capViolations(t testing.TB) ([]string, map[string][]string) {
	t.Helper()
	var out []string
	examined := map[string][]string{}
	for _, n := range strings.Fields(docker(t, "network", "ls", "-q")) {
		br := bridgeOf(t, n)
		if !strings.HasPrefix(br, "spp") && br != nodecfg.PlatformBridge && br != nodecfg.IngressBridge {
			continue
		}
		for _, m := range networkMembers(t, n) {
			examined[br] = append(examined[br], m)
			f := containerFlags(t, m)
			if f.Privileged || !hasCap(f.CapDrop, "ALL") || hasCap(f.CapAdd, "NET_RAW") || hasCap(f.CapAdd, "NET_ADMIN") || hasCap(f.CapAdd, "ALL") {
				out = append(out, m+": configuration")
			}
			if !running(t, m) {
				continue
			}
			pid, _ := containerPid(t, m)
			bnd, err := strconv.ParseUint(procStatus(t, pid)["CapBnd"], 16, 64)
			if err != nil {
				t.Fatalf("%s: CapBnd unreadable", m)
			}
			if bnd&(1<<capNetAdmin|1<<capNetRaw) != 0 {
				out = append(out, m+": bounding set")
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), examined
}

func containerMounts(t testing.TB, c string) map[string]mountJSON {
	t.Helper()
	var ms []mountJSON
	if err := json.Unmarshal([]byte(docker(t, "inspect", "-f", "{{json .Mounts}}", c)), &ms); err != nil {
		t.Fatalf("inspect %s: %v", c, err)
	}
	out := map[string]mountJSON{}
	for _, m := range ms {
		out[m.Destination] = m
	}
	return out
}

// mountRW is the set of read-write mount points of pid's mount namespace
// (the per-mount options of /proc/<pid>/mountinfo).
func mountRW(t testing.TB, pid int) []string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for line := range strings.Lines(string(b)) {
		if f := strings.Fields(line); len(f) > 5 && strings.HasPrefix(f[5]+",", "rw,") {
			out = append(out, f[4])
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// writableMounts: of c's mounts only rw (container paths) are read-write —
// in its configuration, and in its mount table, where every other read-write
// mount point must also be read-write in a scratch container of the same
// image and flags without the platform's mounts (Docker's own runtime mounts).
func writableMounts(t testing.TB, c string, rw []string) {
	t.Helper()
	for dst, m := range containerMounts(t, c) {
		if m.RW != slices.Contains(rw, dst) {
			t.Errorf("%s: mount %s read-write %v in its configuration", c, dst, m.RW)
		}
	}
	pid, _ := containerPid(t, c)
	f := containerFlags(t, c)
	f.Binds = nil
	scratch := imageContainer(t, "sp-test-rw-"+strings.SplitN(c, "-", 2)[0], imageOf(t, c), append([]string{"--network", "none"}, f.args()...)...)
	spid, _ := containerPid(t, scratch)
	want := mountRW(t, spid)
	for _, d := range rw {
		r, err := resolveIn(fmt.Sprintf("/proc/%d/root", pid), d)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, r)
	}
	slices.Sort(want)
	want = slices.Compact(want)
	if got := mountRW(t, pid); !slices.Equal(got, want) {
		extra := slices.DeleteFunc(slices.Clone(got), func(m string) bool { return slices.Contains(want, m) })
		missing := slices.DeleteFunc(slices.Clone(want), func(m string) bool { return slices.Contains(got, m) })
		t.Errorf("%s: read-write mount points: unexpected %v, missing %v", c, extra, missing)
	}
}

// searchContainer looks for the forbidden byte strings in everything of c a
// process there could read: every file below its bind mounts and tmpfs mounts
// (resolved through the container's links, each root visited at least once),
// the environment and command line of every process in its pid namespace, and
// its configured command, environment and labels. own must be found somewhere
// in the same places, or the search proves nothing.
func searchContainer(t testing.TB, c string, forbidden []needle, own needle) {
	t.Helper()
	pid, _ := containerPid(t, c)
	foundOwn := ""
	look := func(where string, data []byte) {
		for _, n := range forbidden {
			if containsAny(data, n.b) >= 0 {
				t.Errorf("%s: %s holds the bytes of %s", c, where, n.name)
			}
		}
		if foundOwn == "" && containsAny(data, own.b) >= 0 {
			foundOwn = where
		}
	}
	var roots []string
	for dst, m := range containerMounts(t, c) {
		if m.Type == "bind" {
			roots = append(roots, dst)
		}
	}
	roots = append(roots, slices.Collect(maps.Keys(containerFlags(t, c).Tmpfs))...)
	slices.Sort(roots)
	counts, errs := searchTree(fmt.Sprintf("/proc/%d/root", pid), roots, look)
	for _, err := range errs {
		t.Errorf("%s: byte search: %v", c, err)
	}
	for _, r := range roots {
		if counts[r] == 0 {
			t.Errorf("%s: byte search read no file below %s: the root was not searched", c, r)
		}
	}
	// Every process of the container.
	ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		t.Fatal(err)
	}
	procs, _ := os.ReadDir("/proc")
	n := 0
	for _, e := range procs {
		p, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if other, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", p)); other != ns {
			continue
		}
		for _, f := range []string{"environ", "cmdline"} {
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", p, f)); err == nil {
				n++
				look(fmt.Sprintf("the %s of process %d", f, p), b)
			}
		}
	}
	if n == 0 {
		t.Errorf("%s: no process environment or command line was read", c)
	}
	look("its configured command, environment and labels",
		[]byte(docker(t, "inspect", "-f", "{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{json .Config.Env}} {{json .Config.Labels}}", c)))
	if foundOwn == "" {
		t.Errorf("control: the search of %s found %s nowhere (roots %v)", c, own.name, counts)
	}
}

type mountJSON struct {
	Type, Source, Destination string
	RW                        bool
}

type needle struct {
	name string
	b    [][]byte
}

// oPath is O_PATH, the same on amd64 and arm64.
const oPath = 0x200000

// readDirAs lists dir as uid:gid with no supplementary groups. Root opens the
// directory (O_PATH) and hands the descriptor to the child, so only the
// directory's own permissions decide — not those of the root-only directories
// above it.
func readDirAs(uid, gid int, dir string) error {
	fd, err := syscall.Open(dir, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %v", dir, err)
	}
	f := os.NewFile(uintptr(fd), dir)
	defer f.Close()
	cmd := exec.Command("ls", "-A", "/proc/self/fd/3/")
	cmd.ExtraFiles = []*os.File{f}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.ToLower(brief(string(out))))
	}
	return nil
}

// TestImagectr_SearchTreeReportsUnreadable: a subtree the search cannot read
// is an error, never a silently smaller search, and a root whose files were
// all read counts them. (As root every directory is readable: skipped.)
func TestImagectr_SearchTreeReportsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	base := t.TempDir()
	for _, f := range []string{"r/a", "r/locked/b"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(base, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(base, "r/locked"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(base, "r/locked"), 0o755) })
	if _, errs := searchTree(base, []string{"/r"}, func(string, []byte) {}); len(errs) == 0 {
		t.Fatal("an unreadable subtree was not reported")
	}
	os.Chmod(filepath.Join(base, "r/locked"), 0o755)
	counts, errs := searchTree(base, []string{"/r"}, func(string, []byte) {})
	if len(errs) != 0 || counts["/r"] != 2 {
		t.Fatalf("readable tree: counts %v, errors %v", counts, errs)
	}
}
