package main

import (
	"bytes"
	"maps"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/pgsock"
)

// splitPGOptions splits the variable the way libpq does: on white space that
// is not preceded by a backslash; a backslash takes the next byte literally.
func splitPGOptions(s string) []string {
	var out []string
	var cur strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			in = true
		case c == ' ' || c == '\t' || c == '\n':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}

func TestPGOptions_RoundTripIsTheNonSuperuserList(t *testing.T) {
	want := pgsock.StartupParams(false)
	s := pgOptions(want)
	for _, frag := range []string{`-c DateStyle=ISO,\ MDY`, `-c local_preload_libraries= `, `-c default_transaction_isolation=read\ committed`} {
		if !strings.Contains(s+" ", frag) {
			t.Errorf("PGOPTIONS lacks %q: %s", frag, s)
		}
	}
	words := splitPGOptions(s)
	got := map[string]string{}
	for i := 0; i < len(words); i += 2 {
		if words[i] != "-c" || i+1 == len(words) {
			t.Fatalf("not a -c name=value list at %d: %q", i, words)
		}
		k, v, ok := strings.Cut(words[i+1], "=")
		if !ok {
			t.Fatalf("no '=' in %q", words[i+1])
		}
		got[k] = v
	}
	if !maps.Equal(got, want) {
		t.Fatalf("round trip:\n got %v\nwant %v", got, want)
	}
	if _, ok := got["event_triggers"]; ok {
		t.Fatal("the non-superuser list carries event_triggers")
	}
	// A backslash in a value is escaped too (control: the plain value above).
	if g := splitPGOptions(pgOptions(map[string]string{"a": `x\ y`})); len(g) != 2 || g[1] != `a=x\ y` {
		t.Fatalf("backslash value: %q", g)
	}
}

func TestPins_ExtensionPinsThenRecoveryPinsTargetLast(t *testing.T) {
	var out, errb bytes.Buffer
	if c := run([]string{"pins", "-time", "2026-11-19 10:00:00.123456+00", "-timeline", "current"}, &out, &errb); c != 0 {
		t.Fatalf("exit %d: %s", c, errb.String())
	}
	l := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if strings.Join(l[:6], " ") != "-c pgtle.enable_clientauth=off -c pgtle.enable_password_check=off -c cron.launch_active_jobs=off" {
		t.Fatalf("extension pins first: %q", l[:6])
	}
	if last := l[len(l)-1]; last != "recovery_target_time=2026-11-19 10:00:00.123456+00" {
		t.Fatalf("last line %q", last)
	}
	// End of the archive: no target set at all.
	out.Reset()
	if c := run([]string{"pins", "-timeline", "latest"}, &out, &errb); c != 0 {
		t.Fatalf("exit %d: %s", c, errb.String())
	}
	if !strings.HasSuffix(out.String(), "archive_cleanup_command=\n") {
		t.Fatalf("end-of-archive pins: %s", out.String())
	}
	// Refusals come from pgconf: both targets; a target without its timeline rule.
	for _, a := range [][]string{
		{"pins", "-time", "2026-11-19T10:00:00Z", "-lsn", "0/5000000", "-timeline", "current"},
		{"pins", "-lsn", "0/0", "-timeline", "current"},
		{"pins", "-timeline", "current"},
	} {
		out.Reset()
		if c := run(a, &out, &errb); c != 1 || out.Len() != 0 {
			t.Errorf("%q: exit %d, output %q", a, c, out.String())
		}
	}
}

func TestParseTime(t *testing.T) {
	for _, s := range []string{"2026-11-19 10:00:00.123456+00", "2026-11-19T10:00:00.123456Z", "2026-11-19 12:00:00+02"} {
		tm, err := parseTime(s)
		if err != nil || tm.UTC().Format("15:04:05") != "10:00:00" {
			t.Errorf("%q: %v %v", s, tm, err)
		}
	}
	for _, s := range []string{"", "yesterday", "2026-11-19 10:00:00"} {
		if _, err := parseTime(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestTrustParams(t *testing.T) {
	m, err := trustParams(true, []string{"log_statement=none", "pgaudit.role="}, []string{"application_name"})
	if err != nil {
		t.Fatal(err)
	}
	if m["event_triggers"] != "off" || m["log_statement"] != "none" {
		t.Fatalf("superuser base with additions: %v", m)
	}
	if v, ok := m["pgaudit.role"]; !ok || v != "" {
		t.Fatal("an empty value is a parameter too")
	}
	if _, ok := m["application_name"]; ok {
		t.Fatal("-unset left the parameter")
	}
	m, _ = trustParams(false, nil, nil)
	if !maps.Equal(m, pgsock.StartupParams(false)) {
		t.Fatal("plain base is not the non-superuser list")
	}
	if _, err := trustParams(false, []string{"noequals"}, nil); err == nil {
		t.Fatal("-set without '=' accepted")
	}
}

func TestSecrets_LabValuesPerGeneration(t *testing.T) {
	a, b, c := secrets("abcdefghij0123456789", 0), secrets("abcdefghij0123456789", 0), secrets("abcdefghij0123456789", 1)
	if a.SupabaseAdminPassword != b.SupabaseAdminPassword || a.PostgresPassword == c.PostgresPassword {
		t.Fatal("passwords must repeat within a generation and change across")
	}
	for _, p := range []string{a.SupabaseAdminPassword, a.PostgresPassword, a.AuthenticatorPassword, c.AuthenticatorPassword} {
		if !strings.HasPrefix(p, "lab") {
			t.Errorf("not a lab value: %q", p)
		}
	}
	if len(a.ScramSalts) != 3 {
		t.Fatalf("salts: %d", len(a.ScramSalts))
	}
}

func TestRun_UsageExits2(t *testing.T) {
	for _, a := range [][]string{nil, {"nope"}, {"sql", "x"}, {"render", "r", "1"}, {"trust", "-bogus"}} {
		var o, e bytes.Buffer
		if c := run(a, &o, &e); c != 2 {
			t.Errorf("%q: exit %d", a, c)
		}
	}
}
