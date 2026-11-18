package pgconf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/nodecfg"
)

// pinnedFive are the override-file lines the command line takes over.
var pinnedFive = []string{"archive_mode", "archive_command", "max_connections", "superuser_reserved_connections", "reserved_connections"}

var targetNames = []string{"recovery_target", "recovery_target_name", "recovery_target_xid", "recovery_target_time", "recovery_target_lsn"}

// flags turns a -c list into its name=value elements, checking the shape.
func flags(t *testing.T, args []string) []string {
	t.Helper()
	if len(args)%2 != 0 {
		t.Fatalf("odd list %q", args)
	}
	var out []string
	for i := 0; i < len(args); i += 2 {
		if args[i] != "-c" || !strings.Contains(args[i+1], "=") {
			t.Fatalf("element %d: %q %q", i, args[i], args[i+1])
		}
		out = append(out, args[i+1])
	}
	return out
}

func settingNames(kv []string) []string {
	var out []string
	for _, s := range kv {
		n, _, _ := strings.Cut(s, "=")
		out = append(out, n)
	}
	return out
}

// The existing override file is unchanged by this file's additions: compared
// with the committed bytes without the -update path.
func TestOverrides_Unchanged(t *testing.T) {
	got, err := Overrides(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden", OverrideFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Overrides changed:\n%s", got)
	}
}

func TestOverridesPinned_OmitsFive(t *testing.T) {
	for _, gucs := range []map[string]string{nil, {"max_connections": "200", "work_mem": "8MB"}} {
		full, err := Overrides(gucs, 512)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OverridesPinned(gucs, 512)
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, l := range lines(full) {
			n, _, _ := strings.Cut(l, " = ")
			if !slices.Contains(pinnedFive, n) {
				want = append(want, l)
			}
		}
		if string(got) != strings.Join(want, "\n") {
			t.Errorf("%v: got\n%s\nwant\n%s", gucs, got, strings.Join(want, "\n"))
		}
		for _, n := range pinnedFive {
			if bytes.Contains(got, []byte("\n"+n+" ")) || bytes.HasPrefix(got, []byte(n+" ")) {
				t.Errorf("%v: %s still in the file", gucs, n)
			}
		}
		if len(lines(full))-len(lines(got)) != 5 {
			t.Errorf("%v: %d lines dropped", gucs, len(lines(full))-len(lines(got)))
		}
	}
	got, err := OverridesPinned(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "pins-"+OverrideFile, got)
	// Same checks as Overrides.
	for _, c := range []struct {
		gucs  map[string]string
		memMB int
		want  error
	}{
		{map[string]string{"archive_command": "x"}, 512, ErrGUCNotAllowed},
		{map[string]string{"max_connections": "15"}, 512, ErrGUCValue},
		{map[string]string{"shared_buffers": "205MB"}, 512, ErrGUCValue},
		{nil, 383, ErrGUCValue},
	} {
		if got, err := OverridesPinned(c.gucs, c.memMB); !errors.Is(err, c.want) || got != nil {
			t.Errorf("%v %d: %q, %v", c.gucs, c.memMB, got, err)
		}
	}
}

func TestPins_OrderAndValues(t *testing.T) {
	want := func(mc string) []string {
		return []string{"-c", "archive_mode=on", "-c", "archive_command=" + ArchiveCommand,
			"-c", "restore_command=" + RestoreCommand, "-c", "max_connections=" + mc,
			"-c", "superuser_reserved_connections=3", "-c", "reserved_connections=2"}
	}
	for _, c := range []struct {
		gucs map[string]string
		mc   string
	}{
		{nil, "120"},
		{map[string]string{}, "120"},
		{map[string]string{"work_mem": "8MB"}, "120"},
		{map[string]string{"max_connections": "200"}, "200"},
		{map[string]string{"max_connections": "16", "work_mem": "8MB"}, "16"},
	} {
		got, err := Pins(c.gucs)
		if err != nil {
			t.Fatalf("%v: %v", c.gucs, err)
		}
		if !slices.Equal(got, want(c.mc)) {
			t.Errorf("%v:\ngot  %q\nwant %q", c.gucs, got, want(c.mc))
		}
	}
	if ArchiveCommand != "/opt/supapace/tools/supapace-arch push %p %f # pgbackrest" ||
		RestoreCommand != "/opt/supapace/tools/supapace-arch get %f %p" {
		t.Fatalf("commands: %q %q", ArchiveCommand, RestoreCommand)
	}
}

// Settings above 1 GB that the platform allows pass Pins: its check does
// not stand in a small container.
func TestPins_AcceptsLargeMemorySettings(t *testing.T) {
	for _, g := range []map[string]string{{"effective_cache_size": "2GB"}, {"shared_buffers": "1GB", "effective_cache_size": "64GB"}} {
		if _, err := Pins(g); err != nil {
			t.Errorf("%v: %v", g, err)
		}
	}
}

// Pins refuses what Overrides refuses. The memory-relative bounds depend on
// the container's memory, which Pins is not given: they are checked by
// OverridesPinned, which the same start renders.
func TestPins_RejectsWhatOverridesRejects(t *testing.T) {
	bad := []map[string]string{
		{"archive_command": "true"}, {"archive_mode": "off"}, {"restore_command": "x"},
		{"superuser_reserved_connections": "1"}, {"reserved_connections": "0"}, {"Max_connections": "100"},
		{"max_connections": "15"}, {"max_connections": "401"}, {"max_connections": "0100"}, {"max_connections": "1e3"},
		{"max_connections": ""}, {"max_connections": "100\n-c archive_mode=off"}, {"max_connections": "100 "},
		{"cron.max_running_jobs": "0"}, {"archive_timeout": "29"}, {"work_mem": "8 MB"},
		{"shared_buffers": "15MB"}, {"shared_buffers": "128"}, {"effective_cache_size": "64MB"},
		{"max_connections": "200", "archive_command": "x"},
	}
	for _, g := range bad {
		_, oerr := Overrides(g, 512)
		if oerr == nil {
			t.Fatalf("control: Overrides accepts %v", g)
		}
		got, err := Pins(g)
		if err == nil || got != nil {
			t.Errorf("%v: Pins accepted: %q", g, got)
			continue
		}
		if errors.Is(oerr, ErrGUCValue) != errors.Is(err, ErrGUCValue) || errors.Is(oerr, ErrGUCNotAllowed) != errors.Is(err, ErrGUCNotAllowed) {
			t.Errorf("%v: Pins %v, Overrides %v", g, err, oerr)
		}
	}
}

func rt(tm time.Time, lsn, tl string) RecoveryTarget {
	return RecoveryTarget{Time: tm, LSN: lsn, Timeline: tl}
}

var tenAM = time.Date(2026, 11, 18, 10, 0, 0, 120000000, time.FixedZone("x", 5*3600+1800))

func wantRecovery(target, chosen string) []string {
	out := []string{"recovery_target=", "recovery_target_name=", "recovery_target_xid="}
	switch {
	case strings.HasPrefix(chosen, "recovery_target_time="):
		out = append(out, "recovery_target_lsn=")
	case strings.HasPrefix(chosen, "recovery_target_lsn="):
		out = append(out, "recovery_target_time=")
	default:
		out = append(out, "recovery_target_time=", "recovery_target_lsn=")
	}
	out = append(out, "recovery_target_inclusive=on", "recovery_target_action=promote", "recovery_target_timeline="+target,
		"recovery_min_apply_delay=0", "recovery_end_command=", "archive_cleanup_command=")
	if chosen != "" {
		out = append(out, chosen)
	}
	return out
}

func recoveryCase(t *testing.T, in RecoveryTarget, tl, chosen string) {
	t.Helper()
	got, err := RecoveryPins(in)
	if err != nil {
		t.Fatal(err)
	}
	if kv := flags(t, got); !slices.Equal(kv, wantRecovery(tl, chosen)) {
		t.Fatalf("got  %q\nwant %q", kv, wantRecovery(tl, chosen))
	}
}

func TestRecoveryPins_Time(t *testing.T) {
	// Rendered in UTC with microseconds; trailing zeros of the fraction dropped.
	recoveryCase(t, rt(tenAM, "", "current"), "current", "recovery_target_time=2026-11-18 04:30:00.12+00")
	recoveryCase(t, rt(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "", "3"), "3", "recovery_target_time=2026-01-02 03:04:05+00")
	recoveryCase(t, rt(time.Date(2026, 1, 2, 3, 4, 5, 999999999, time.UTC), "", "current"), "current", "recovery_target_time=2026-01-02 03:04:05.999999+00")
}

func TestRecoveryPins_LSN(t *testing.T) {
	recoveryCase(t, rt(time.Time{}, "0/3000000", "current"), "current", "recovery_target_lsn=0/3000000")
	recoveryCase(t, rt(time.Time{}, "FFFFFFFF/ffffffff", "current"), "current", "recovery_target_lsn=FFFFFFFF/ffffffff")
}

func TestRecoveryPins_Latest(t *testing.T) {
	recoveryCase(t, rt(time.Time{}, "", "latest"), "latest", "")
}

func TestRecoveryPins_Timeline(t *testing.T) {
	for _, tl := range []string{"current", "1", "2", "42", "4294967295"} {
		recoveryCase(t, rt(tenAM, "", tl), tl, "recovery_target_time=2026-11-18 04:30:00.12+00")
		recoveryCase(t, rt(time.Time{}, "1/0", tl), tl, "recovery_target_lsn=1/0")
	}
}

func TestRecoveryPins_Refusals(t *testing.T) {
	for _, c := range []RecoveryTarget{
		rt(tenAM, "0/1", "current"),           // both targets
		rt(tenAM, "", "latest"),               // latest with a target
		rt(time.Time{}, "0/1", "latest"),      // latest with a target
		rt(time.Time{}, "", "current"),        // a zero time and no position: no target, so only latest
		rt(time.Time{}, "", "1"),              // the same
		rt(time.Time{}, "", ""),               //
		rt(tenAM, "", "0"),                    // timeline 0
		rt(tenAM, "", "00"),                   //
		rt(tenAM, "", "01"),                   // read as octal by the server
		rt(tenAM, "", "0x2"),                  // read as hex by the server
		rt(tenAM, "", "4294967296"),           // beyond 32 bits
		rt(tenAM, "", "99999999999999999999"), //
		rt(tenAM, "", "-1"),                   //
		rt(tenAM, "", "+1"),                   //
		rt(tenAM, "", " 1"),                   //
		rt(tenAM, "", "two"),                  // text
		rt(tenAM, "", "Current"),              //
		rt(tenAM, "", ""),                     //
		rt(tenAM, "", "1\n-c recovery_target=x"),
		rt(time.Time{}, "0", "current"),                                 // LSN not hex/hex
		rt(time.Time{}, "/0", "current"),                                //
		rt(time.Time{}, "0/", "current"),                                //
		rt(time.Time{}, "0/0/0", "current"),                             //
		rt(time.Time{}, "g/0", "current"),                               //
		rt(time.Time{}, "0/x1", "current"),                              //
		rt(time.Time{}, "0x1/0", "current"),                             //
		rt(time.Time{}, " 0/1", "current"),                              //
		rt(time.Time{}, "0/1 ", "current"),                              //
		rt(time.Time{}, "0/1\n", "current"),                             //
		rt(time.Time{}, "100000000/0", "current"),                       // more than 32 bits a half
		rt(time.Time{}, "0/100000000", "current"),                       //
		rt(time.Time{}, "0 /1", "current"),                              //
		rt(time.Time{}, "-1/1", "current"),                              //
		rt(time.Time{}, "0/0", "current"),                               // no position
		rt(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), "", "current"), // a year the rule refuses
		rt(time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("z", -13*3600)), "", "current"), // year 10000 in UTC
		rt(time.Time{}, "00000000/0", "current"),
	} {
		got, err := RecoveryPins(c)
		if !errors.Is(err, ErrGUCValue) || got != nil {
			t.Errorf("%+v: %q, %v", c, got, err)
		}
	}
}

func TestRecoveryPins_EmptiedTargetsFirst_ChosenTargetLast(t *testing.T) {
	for _, c := range []struct {
		target RecoveryTarget
		chosen string
	}{
		{rt(tenAM, "", "current"), "recovery_target_time"},
		{rt(time.Time{}, "0/3000000", "current"), "recovery_target_lsn"},
		{rt(time.Time{}, "", "latest"), ""},
	} {
		got, err := RecoveryPins(c.target)
		if err != nil {
			t.Fatal(err)
		}
		kv := flags(t, got)
		names := settingNames(kv)
		for _, n := range targetNames {
			if k := slices.Index(names, n); k < 0 || slices.Index(names[k+1:], n) >= 0 {
				t.Errorf("%+v: %s does not appear exactly once: %q", c.target, n, names)
			}
		}
		last := -1
		for i, n := range names {
			if !slices.Contains(targetNames, n) {
				continue
			}
			if n == c.chosen {
				if i != len(kv)-1 || strings.HasSuffix(kv[i], "=") {
					t.Errorf("%+v: chosen %s at %d of %d: %q", c.target, n, i, len(kv), kv[i])
				}
				continue
			}
			if !strings.HasSuffix(kv[i], "=") {
				t.Errorf("%+v: %q not emptied", c.target, kv[i])
			}
			last = i
		}
		if c.chosen == "" && last < 0 {
			t.Errorf("no targets")
		}
		if c.chosen != "" && last >= len(kv)-1 {
			t.Errorf("%+v: an emptied target after the chosen one", c.target)
		}
	}
}

func TestRecoveryExtensionPins(t *testing.T) {
	want := []string{"-c", "pgtle.enable_clientauth=off", "-c", "pgtle.enable_password_check=off", "-c", "cron.launch_active_jobs=off"}
	if got := RecoveryExtensionPins(); !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	// A fresh slice each call: a caller appending to it cannot change the next.
	a := RecoveryExtensionPins()
	a[1] = "x"
	if got := RecoveryExtensionPins(); !slices.Equal(got, want) {
		t.Fatalf("shared: %q", got)
	}
}

func TestPinnedNames(t *testing.T) {
	l1 := []string{"session_preload_libraries", "shared_preload_libraries"}
	if got := PinnedNames(1); !slices.Equal(got, l1) {
		t.Fatalf("layout 1: %q", got)
	}
	pins, err := Pins(nil)
	if err != nil {
		t.Fatal(err)
	}
	l2 := append(slices.Clone(l1), settingNames(flags(t, pins))...)
	if got := PinnedNames(2); !slices.Equal(got, l2) || len(got) != 8 {
		t.Fatalf("layout 2: %q, want %q", got, l2)
	}
	for _, l := range []int{0, 3, -1} {
		if got := PinnedNames(l); got != nil {
			t.Errorf("layout %d: %q", l, got)
		}
	}
	a := PinnedNames(2)
	a[0] = "x"
	if PinnedNames(2)[0] != l1[0] || PinnedNames(1)[0] != l1[0] {
		t.Fatal("shared slice")
	}
}

// ---- against the pinned cluster image ----

func pinnedImage(t *testing.T) string {
	t.Helper()
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("docker not reachable")
	}
	im, err := nodecfg.LockedImages()
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("docker", "image", "inspect", im.Postgres).Run(); err != nil {
		t.Skipf("image %s not present", im.Postgres)
	}
	return im.Postgres
}

func testName() string {
	b := make([]byte, 5)
	rand.Read(b)
	return "sp-test-pgconf-" + hex.EncodeToString(b)
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func volume(t *testing.T) string {
	t.Helper()
	v := testName()
	docker(t, "volume", "create", "--label", "supapace.test=1", v)
	t.Cleanup(func() { exec.Command("docker", "volume", "rm", "-f", v).Run() })
	return v
}

// sh runs a shell script in a throw-away container of the image, as root,
// with the given volume mounts.
func sh(t *testing.T, img, script string, mounts ...string) {
	t.Helper()
	args := []string{"run", "--rm", "--name", testName(), "--label", "supapace.test=1", "--network", "none"}
	for _, m := range mounts {
		args = append(args, "-v", m)
	}
	docker(t, append(args, "--entrypoint", "sh", img, "-c", script)...)
}

// until polls cond until it holds, the container has stopped, or the
// deadline passes; it returns whether cond held.
func until(t *testing.T, name string, d time.Duration, cond func() bool) bool {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if cond() {
			return true
		}
		if out, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output(); strings.TrimSpace(string(out)) != "true" {
			return cond()
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func logs(name string) string {
	out, _ := exec.Command("docker", "logs", name).CombinedOutput()
	return string(out)
}

// hostileAuto is what a database server can write into its own
// postgresql.auto.conf: none of it may reach a pinned setting.
const hostileAuto = "max_connections = 3\narchive_command = 'true'\nrestore_command = 'true'\nrecovery_min_apply_delay = '1h'\n" +
	"archive_mode = off\nsuperuser_reserved_connections = 0\nreserved_connections = 0\n"

// cluster holds an initialised data directory of the pinned image, with
// hostileAuto appended, and a tools volume whose archive tool answers every
// request "not in the archive".
type pinCluster struct {
	img, data, tools string
}

func newPinCluster(t *testing.T) pinCluster {
	img := pinnedImage(t)
	c := pinCluster{img: img, data: volume(t), tools: volume(t)}
	name := testName()
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	docker(t, "run", "-d", "--name", name, "--label", "supapace.test=1", "--network", "none", "--memory", "512m",
		"-e", "POSTGRES_PASSWORD="+testName(), "-v", c.data+":/var/lib/postgresql/data", img)
	if !until(t, name, 5*time.Minute, func() bool {
		return exec.Command("docker", "exec", name, "psql", "-XAtq", "-h", "/var/run/postgresql", "-U", "supabase_admin",
			"-d", "postgres", "-c", "select 1").Run() == nil && strings.Contains(logs(name), "init process complete")
	}) {
		t.Fatalf("cluster did not initialise:\n%s", logs(name))
	}
	docker(t, "stop", "-t", "60", name)
	sh(t, img, "printf '%s' \""+hostileAuto+"\" >> /d/postgresql.auto.conf && "+
		"printf '#!/bin/sh\\nexit 1\\n' > /t/supapace-arch && chmod 0555 /t/supapace-arch /t",
		c.data+":/d", c.tools+":/t")
	return c
}

// start runs postgres on a copy of the data directory with args after the
// image's command-line pins; recovery adds recovery.signal.
func (c pinCluster) start(t *testing.T, recovery bool, args []string) string {
	t.Helper()
	run := volume(t)
	script := "cp -a /s/. /d/"
	if recovery {
		script += " && touch /d/recovery.signal && chown postgres:postgres /d/recovery.signal"
	}
	sh(t, c.img, script, c.data+":/s:ro", run+":/d")
	cl, err := CommandLine(image(t, "postgresql.conf"))
	if err != nil {
		t.Fatal(err)
	}
	name := testName()
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", "-v", name).Run() })
	docker(t, append([]string{"run", "-d", "--name", name, "--label", "supapace.test=1", "--network", "none", "--memory", "512m",
		"-v", run + ":/var/lib/postgresql/data", "-v", c.tools + ":/opt/supapace/tools:ro",
		c.img, "postgres", "-D", "/etc/postgresql"}, append(cl, args...)...)...)
	return name
}

func TestPins_AcceptedByServer(t *testing.T) {
	c := newPinCluster(t)
	pins, err := Pins(nil)
	if err != nil {
		t.Fatal(err)
	}
	name := c.start(t, false, pins)
	var out string
	q := "select name || '|' || source || '|' || setting from pg_catalog.pg_settings where name = any(string_to_array('" +
		strings.Join(append(PinnedNames(2), "recovery_min_apply_delay"), ",") + "', ',')) order by name"
	if !until(t, name, 2*time.Minute, func() bool {
		b, err := exec.Command("docker", "exec", name, "psql", "-XAtq", "-h", "/var/run/postgresql", "-U", "supabase_admin",
			"-d", "postgres", "-c", q).Output()
		out = string(b)
		return err == nil
	}) {
		t.Fatalf("server did not start:\n%s", logs(name))
	}
	got := map[string][2]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.SplitN(l, "|", 3)
		if len(f) != 3 {
			t.Fatalf("row %q", l)
		}
		got[f[0]] = [2]string{f[1], f[2]}
	}
	want := map[string]string{"archive_mode": "on", "archive_command": ArchiveCommand, "restore_command": RestoreCommand,
		"max_connections": "120", "superuser_reserved_connections": "3", "reserved_connections": "2"}
	for _, n := range PinnedNames(2) {
		if got[n][0] != "command line" {
			t.Errorf("%s: source %q", n, got[n][0])
		}
		if v, ok := want[n]; ok && got[n][1] != v {
			t.Errorf("%s = %q, want %q", n, got[n][1], v)
		}
	}
	// Control on the same path: the hostile file was read — its unpinned
	// recovery delay is in effect from it.
	if g := got["recovery_min_apply_delay"]; g[0] != "configuration file" || g[1] != "3600000" {
		t.Errorf("control: recovery_min_apply_delay %q", g)
	}
}

// The server applies -c settings in order and refuses a start in which any
// recovery target setting follows a set one. The list starts for a time and a
// position target; moved first, the chosen target is refused.
func TestRecoveryPins_TimeAndPositionTargetsBothStart(t *testing.T) {
	c := newPinCluster(t)
	pins, err := Pins(nil)
	if err != nil {
		t.Fatal(err)
	}
	const refused = "multiple recovery targets specified"
	for _, tc := range []struct {
		target RecoveryTarget
		want   string
	}{
		{rt(time.Now().Add(time.Hour), "", "current"), "starting point-in-time recovery to 20"},
		{rt(time.Time{}, "1/0", "current"), `starting point-in-time recovery to WAL location (LSN) "1/0"`},
	} {
		rp, err := RecoveryPins(tc.target)
		if err != nil {
			t.Fatal(err)
		}
		args := slices.Concat(pins, RecoveryExtensionPins(), rp)
		name := c.start(t, true, args)
		if !until(t, name, 2*time.Minute, func() bool { l := logs(name); return strings.Contains(l, tc.want) || strings.Contains(l, refused) }) ||
			strings.Contains(logs(name), refused) || !strings.Contains(logs(name), tc.want) {
			t.Errorf("%+v: not started:\n%s", tc.target, logs(name))
		}
		// Control: the same settings with the chosen target first.
		first := slices.Concat(rp[len(rp)-2:], rp[:len(rp)-2])
		name = c.start(t, true, slices.Concat(pins, RecoveryExtensionPins(), first))
		if !until(t, name, 2*time.Minute, func() bool { return strings.Contains(logs(name), refused) }) {
			t.Errorf("%+v: control, chosen target first, not refused:\n%s", tc.target, logs(name))
		}
	}
}
