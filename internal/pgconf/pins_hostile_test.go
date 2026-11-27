package pgconf

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Amphoze/supapace/internal/testdocker"
)

// More hostile sources than the first server test: other spellings of the
// same names, an include chain, the recovery names, and the extension names.
const hostileMore = "Max_Connections = '3'\nARCHIVE_COMMAND = 'touch /tmp/hostile-a'\nrestore_command 'touch /tmp/hostile-r'\n" +
	"Reserved_Connections = 0\nSuperuser_Reserved_Connections=0\nARCHIVE_MODE='off'\n" +
	"recovery_target_name = 'h'\nrecovery_target_xid = '5'\nrecovery_target_timeline = 'current'\n" +
	"recovery_target_action = 'shutdown'\nrecovery_end_command = 'touch /tmp/hostile-e'\n" +
	"archive_cleanup_command = 'touch /tmp/hostile-c'\nrecovery_target_inclusive = off\n" +
	"pgtle.enable_clientauth = on\npgtle.enable_password_check = on\ncron.launch_active_jobs = on\n" +
	"include '/var/lib/postgresql/data/hostile.conf'\ninclude_if_exists '/var/lib/postgresql/data/hostile.conf'\n"

const hostileInclude = "max_connections = 5\narchive_command = 'false'\nrestore_command = 'false'\narchive_mode = off\n" +
	"reserved_connections = 0\nsuperuser_reserved_connections = 0\nrecovery_target_lsn = '0/1'\n"

// effective prints the value the server settles on for each name, with the
// given arguments, without starting it (postgres -C).
func (c pinCluster) effective(t *testing.T, args []string, names ...string) map[string]string {
	t.Helper()
	cl, err := CommandLine(image(t, "postgresql.conf"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, n := range names {
		a := slices.Concat([]string{"run", "--rm", "--name", testName(), "--label", "supapace.test=1", "--network", "none",
			"--user", "postgres", "-v", c.data + ":/var/lib/postgresql/data:ro", "--entrypoint", "postgres", c.img, "-D", "/etc/postgresql"},
			cl, args, []string{"-C", n})
		b, err := exec.Command("docker", slices.Concat(a[:1], testdocker.Labels(t), a[1:])...).CombinedOutput()
		if err != nil {
			t.Fatalf("-C %s: %v\n%s", n, err, b)
		}
		out[n] = strings.TrimSpace(string(b))
	}
	return out
}

func TestPins_HostileFilesAndIncludesDoNotMovePins(t *testing.T) {
	c := newPinCluster(t)
	sh(t, c.img, "printf '%s' \""+hostileMore+"\" >> /d/postgresql.auto.conf && printf '%s' \""+hostileInclude+"\" > /d/hostile.conf",
		c.data+":/d")
	pins, err := Pins(map[string]string{"max_connections": "200"})
	if err != nil {
		t.Fatal(err)
	}
	rp, err := RecoveryPins(RecoveryTarget{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Timeline: "current"})
	if err != nil {
		t.Fatal(err)
	}
	args := slices.Concat(pins, RecoveryExtensionPins(), rp)
	names := append(PinnedNames(2)[2:], "recovery_target", "recovery_target_name", "recovery_target_xid", "recovery_target_lsn",
		"recovery_target_time", "recovery_target_timeline", "recovery_target_action", "recovery_target_inclusive",
		"recovery_end_command", "archive_cleanup_command", "recovery_min_apply_delay",
		"pgtle.enable_clientauth", "pgtle.enable_password_check", "cron.launch_active_jobs")
	got := c.effective(t, args, names...)
	want := map[string]string{
		"archive_mode": "on", "archive_command": ArchiveCommand, "restore_command": RestoreCommand, "max_connections": "200",
		"superuser_reserved_connections": "3", "reserved_connections": "2",
		"recovery_target": "", "recovery_target_name": "", "recovery_target_xid": "", "recovery_target_lsn": "",
		"recovery_target_time": "2026-01-02 03:04:05+00", "recovery_target_timeline": "current", "recovery_target_action": "promote",
		"recovery_target_inclusive": "on", "recovery_end_command": "", "archive_cleanup_command": "", "recovery_min_apply_delay": "0",
		"pgtle.enable_clientauth": "off", "pgtle.enable_password_check": "off", "cron.launch_active_jobs": "off",
	}
	for n, w := range want {
		if got[n] != w {
			t.Errorf("%s = %q, want %q", n, got[n], w)
		}
	}
	// Control: the hostile files alone set several recovery targets; the
	// server refuses them, so the pins are what makes this start possible.
	cl, _ := CommandLine(image(t, "postgresql.conf"))
	b, err := exec.Command("docker", slices.Concat([]string{"run", "--rm", "--name", testName()}, testdocker.Labels(t), []string{"--label", "supapace.test=1",
		"--network", "none", "--user", "postgres", "-v", c.data + ":/var/lib/postgresql/data:ro", "--entrypoint", "postgres", c.img,
		"-D", "/etc/postgresql"}, cl, []string{"-C", "max_connections"})...).CombinedOutput()
	if err == nil || !strings.Contains(string(b), "multiple recovery targets specified") {
		t.Errorf("control: %v\n%s", err, b)
	}
}

func TestPins_RunningServerRefusesLaterChanges(t *testing.T) {
	c := newPinCluster(t)
	pins, err := Pins(nil)
	if err != nil {
		t.Fatal(err)
	}
	name := c.start(t, false, pins)
	psql := func(sql string) (string, error) {
		b, err := exec.Command("docker", "exec", name, "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql",
			"-U", "supabase_admin", "-d", "postgres", "-c", sql).CombinedOutput()
		return strings.TrimSpace(string(b)), err
	}
	if !until(t, name, 2*time.Minute, func() bool { _, err := psql("select 1"); return err == nil }) {
		t.Fatalf("not started:\n%s", logs(name))
	}
	// Each of these is refused or has no effect on the pinned value.
	for _, s := range []string{
		"alter system set \"Max_Connections\" = 3", "alter system set archive_command = 'touch /tmp/x'",
		"alter system set restore_command = 'x'", "alter system set archive_mode = off",
		"alter system set reserved_connections = 0", "alter system set superuser_reserved_connections = 0",
		"alter database postgres set max_connections = 3", "alter database postgres set archive_command = 'x'",
		"alter database postgres set archive_mode = off", "alter role postgres set restore_command = 'x'",
		"alter role supabase_admin in database postgres set reserved_connections = 0",
	} {
		psql(s) // the outcome may be an error or a stored line; the check is below
	}
	loaded, err := psql("select pg_conf_load_time()")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := psql("select pg_reload_conf()"); err != nil {
		t.Fatal(err)
	}
	// The reload is done when the server records a new load time.
	if !until(t, name, time.Minute, func() bool { l, err := psql("select pg_conf_load_time()"); return err == nil && l != loaded }) {
		t.Fatalf("configuration not reloaded:\n%s", logs(name))
	}
	for _, n := range PinnedNames(2) {
		out, err := psql("select source || '|' || setting || '|' || pending_restart from pg_settings where name = '" + n + "'")
		if err != nil || !strings.HasPrefix(out, "command line|") || strings.HasSuffix(out, "|t") {
			t.Errorf("%s: %q %v", n, out, err)
		}
	}
	// A new session with the per-database and per-role rows sees the same.
	if out, _ := psql("show archive_command"); out != ArchiveCommand {
		t.Errorf("archive_command %q", out)
	}
}

// Values at the edges of what the server reads: each must be accepted by the
// server exactly as rendered.
func TestRecoveryPins_EdgeTargetsReadBackBytewise(t *testing.T) {
	c := newPinCluster(t)
	for _, rt := range []RecoveryTarget{
		{Timeline: "4294967295", LSN: "FFFFFFFF/FFFFFFFF"},
		{Timeline: "1", LSN: "0000000A/0000000b"},
		{Timeline: "current", Time: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Microsecond)},
		{Timeline: "current", Time: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("z", 13*3600))},
		{Timeline: "current", Time: time.Unix(0, 0)},
	} {
		rp, err := RecoveryPins(rt)
		if err != nil {
			t.Errorf("%+v: %v", rt, err)
			continue
		}
		n := "recovery_target_lsn"
		want := rt.LSN
		if rt.LSN == "" {
			n, want = "recovery_target_time", rp[len(rp)-1][len("recovery_target_time="):]
		}
		got := c.effective(t, rp, n, "recovery_target_timeline")
		if got[n] != want || got["recovery_target_timeline"] != rt.Timeline {
			t.Errorf("%+v: read back %q", rt, got)
		}
	}
}

// The package may name the time type but must not read a clock or a zone
// database: the only selector of package time in a non-test file is Time.
func TestImports_TimeIsTheTypeOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := s.X.(*ast.Ident); ok && id.String() == "time" && s.Sel.String() != "Time" {
					t.Errorf("%s: time.%s", f, s.Sel)
				}
			}
			return true
		})
	}
}

// A time the server cannot read (year before 1) makes the
// recovery start fail after the data directory was already replaced, so it is
// refused where it is rendered.
func TestRecoveryPins_RefusesTimesTheServerCannotRead(t *testing.T) {
	for _, tm := range []time.Time{
		time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(-1, 6, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Nanosecond), time.Date(294277, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if got, err := RecoveryPins(rt(tm, "", "current")); err == nil {
			t.Errorf("%v accepted: %q", tm, got[len(got)-1])
		}
	}
}

// The message quotes what the operator typed; raw bytes
// would reach a log line and the output of the command line tool.
func TestRecoveryPins_ErrorDoesNotEchoRawInput(t *testing.T) {
	long := strings.Repeat("9", 10000)
	for _, c := range []RecoveryTarget{
		rt(time.Time{}, "0/1\nFATAL: forged \x1b[31m", "current"), rt(tenAM, "", "1\r\n\x00"), rt(tenAM, "", long), rt(time.Time{}, long, "current"),
	} {
		_, err := RecoveryPins(c)
		if err == nil {
			t.Fatalf("%+v accepted", c)
		}
		if m := err.Error(); strings.ContainsAny(m, "\n\r\x00\x1b") || len(m) > 300 {
			t.Errorf("message echoes raw input (%d bytes): %.120q", len(m), m)
		}
	}
}
