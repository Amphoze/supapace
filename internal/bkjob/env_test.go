package bkjob

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/Amphoze/supapace/internal/pgsock"
)

var allKinds = []string{"push", "stanza-create", "backup", "check", "restore", "serve", "seed", "replicate", "fetch", "probe"}

// The pgBackRest options every job sets, with their pinned values.
var common = map[string]string{
	"PGBACKREST_STANZA":            "ref-1",
	"PGBACKREST_REPO1_PATH":        "/repo",
	"PGBACKREST_REPO1_CIPHER_TYPE": "aes-256-cbc",
	"PGBACKREST_LOCK_PATH":         "/tmp/lock",
	"PGBACKREST_LOG_PATH":          "/tmp/log",
	"PGBACKREST_SPOOL_PATH":        "/tmp/spool",
	"PGBACKREST_LOG_LEVEL_FILE":    "off",
	"PGBACKREST_LOG_LEVEL_CONSOLE": "warn",
	"PGBACKREST_COMPRESS_TYPE":     "zst",
	"PGBACKREST_PROCESS_MAX":       "1",
	"PGBACKREST_START_FAST":        "y",
	"PGBACKREST_REPO1_BUNDLE":      "n",
	"PGBACKREST_REPO1_BLOCK":       "n",
	"PGBACKREST_RESUME":            "n",
	"PGBACKREST_REPO1_HARDLINK":    "n",
	"PGBACKREST_ARCHIVE_COPY":      "n",
	"PGBACKREST_NEUTRAL_UMASK":     "y",
	"PGBACKREST_CONFIG":            "/dev/null",
}

// Every kind gets exactly the pinned names, and the database ones by kind.
func TestEnv_EveryPinnedOption(t *testing.T) {
	for _, kind := range allKinds {
		want := maps.Clone(common)
		switch kind {
		case "stanza-create", "backup", "check":
			want["PGBACKREST_PG1_SOCKET_PATH"] = "/var/run/postgresql"
			want["PGBACKREST_PG1_USER"] = "supapace_backup"
			want["PGOPTIONS"] = Env("ref-1", kind, false)["PGOPTIONS"]
			fallthrough
		case "restore", "serve":
			want["PGBACKREST_PG1_PATH"] = "/var/lib/postgresql/data"
		}
		if got := Env("ref-1", kind, false); !maps.Equal(got, want) {
			t.Errorf("Env(%s):\n got %v\nwant %v", kind, got, want)
		}
		if Env("ref-1", kind, false)["PGBACKREST_CONFIG"] != "/dev/null" {
			t.Errorf("Env(%s) lets a configuration file supply options", kind)
		}
	}
}

// archive-push takes an absolute path and no data directory.
func TestEnv_PushHasNoPG1Path(t *testing.T) {
	for _, cp := range []bool{false, true} {
		for k := range Env("cp-1", "push", cp) {
			if strings.HasPrefix(k, "PGBACKREST_PG1_") || k == "PGOPTIONS" {
				t.Errorf("push (control plane %v) sets %s", cp, k)
			}
		}
	}
	if Env("ref-1", "backup", false)["PGBACKREST_PG1_PATH"] == "" {
		t.Error("control: backup has no data directory")
	}
}

func TestEnv_ControlPlaneUser(t *testing.T) {
	for _, kind := range []string{"stanza-create", "backup", "check"} {
		if u := Env("cp-1", kind, true)["PGBACKREST_PG1_USER"]; u != "supapaced" {
			t.Errorf("control plane %s logs in as %q", kind, u)
		}
		if u := Env("ref-1", kind, false)["PGBACKREST_PG1_USER"]; u != "supapace_backup" {
			t.Errorf("project %s logs in as %q", kind, u)
		}
	}
}

// Env never holds the passphrase; Environ adds it for the six kinds that use
// the stanza's encryption and for no other, whatever is handed to it.
func TestEnv_PassphraseNameOnlyForTheSixWorkerKinds(t *testing.T) {
	six := []string{"push", "stanza-create", "backup", "check", "restore", "serve"}
	for _, kind := range allKinds {
		if _, ok := Env("ref-1", kind, false)[PassName]; ok {
			t.Errorf("Env(%s) holds the passphrase's name", kind)
		}
		e := Environ("ref-1", kind, false, "the-pass")
		v, ok := e[PassName]
		if slices.Contains(six, kind) != ok || ok && v != "the-pass" {
			t.Errorf("Environ(%s): passphrase present %v (%q)", kind, ok, v)
		}
		delete(e, PassName)
		if !maps.Equal(e, Env("ref-1", kind, false)) {
			t.Errorf("Environ(%s) differs from Env beyond the passphrase", kind)
		}
	}
	if _, ok := Environ("ref-1", "push", false, "")[PassName]; ok {
		t.Error("an empty passphrase is set")
	}
}

// splitOptions splits PGOPTIONS the way the server does (pg_split_opts):
// on unescaped white space, a backslash taking the next byte literally.
func splitOptions(s string) []string {
	var out []string
	var cur strings.Builder
	in := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			in = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
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

// parseOptions reads "-c name=value" pairs back; an empty value is "-c name=".
func parseOptions(t *testing.T, s string) map[string]string {
	t.Helper()
	w := splitOptions(s)
	if len(w)%2 != 0 {
		t.Fatalf("PGOPTIONS %q splits into %q", s, w)
	}
	m := map[string]string{}
	for i := 0; i < len(w); i += 2 {
		k, v, ok := strings.Cut(w[i+1], "=")
		if w[i] != "-c" || !ok {
			t.Fatalf("PGOPTIONS %q: pair %q %q", s, w[i], w[i+1])
		}
		m[k] = v
	}
	return m
}

func TestEnv_PGOPTIONSRoundTrip(t *testing.T) {
	in := map[string]string{"DateStyle": "ISO, MDY", "a": `back\slash`, "b": "", "c": `\ x  y\\`, "d": "plain"}
	s := pgOptions(in)
	if !strings.Contains(s, `-c DateStyle=ISO,\ MDY`) || !strings.Contains(s, "-c b=") {
		t.Errorf("PGOPTIONS %q", s)
	}
	if got := parseOptions(t, s); !maps.Equal(got, in) {
		t.Errorf("round trip:\n got %q\nwant %q", got, in)
	}
}

func TestEnv_PGOPTIONSIsTheNonSuperuserList(t *testing.T) {
	for _, cp := range []bool{false, true} {
		got := parseOptions(t, Env("ref-1", "backup", cp)["PGOPTIONS"])
		if !maps.Equal(got, pgsock.StartupParams(false)) {
			t.Errorf("PGOPTIONS (control plane %v) = %v, want the non-superuser list", cp, got)
		}
		for _, k := range []string{"event_triggers", "session_preload_libraries"} {
			if _, ok := got[k]; ok {
				t.Errorf("PGOPTIONS sets %s", k)
			}
		}
	}
	if _, ok := pgsock.StartupParams(true)["event_triggers"]; !ok {
		t.Error("control: the superuser list has no event_triggers; the check proves nothing")
	}
}
