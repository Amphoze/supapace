package pgconf

import (
	"bytes"
	"errors"
	"flag"
	"go/parser"
	"go/token"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func image(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "image", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func lines(b []byte) []string { return strings.Split(string(b), "\n") }

func TestOverrides_Golden(t *testing.T) {
	got, err := Overrides(nil, 512)
	if err != nil {
		t.Fatal(err)
	}
	if OverrideFile != "zz-supapace.conf" {
		t.Fatalf("OverrideFile = %q", OverrideFile)
	}
	golden(t, OverrideFile, got)
	// Same bytes for an empty, non-nil map.
	got2, err := Overrides(map[string]string{}, 512)
	if err != nil || !bytes.Equal(got, got2) {
		t.Fatalf("empty map: %v", err)
	}
}

// Postgres reads an include directory in byte order of the names and a later
// file wins: the override file must come after every file of the image.
func TestSortsLast(t *testing.T) {
	ents, err := os.ReadDir(filepath.Join("testdata", "image", "conf.d"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		t.Fatal("no fixture files")
	}
	if err := SortsLast(names); err != nil {
		t.Fatal(err)
	}
	if err := SortsLast(nil); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"zzz.conf", "~x.conf", OverrideFile, "\xff.conf"} {
		err := SortsLast(append(slices.Clone(names), bad, "zzzz.conf"))
		if err == nil || !strings.Contains(err.Error(), strconv.Quote(bad)) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	for _, ok := range []string{"zz-supapace.con", "zz-a.conf", "z.conf", "ZZ.conf", "99.conf",
		"zzz.bak", ".zzz.conf", "zz-supapace.conf.bak", "zz-supapace.conf.d", "zzsub"} { // not read by the server
		if err := SortsLast([]string{ok}); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func TestOverrides_AllowListedMerge(t *testing.T) {
	def, _ := Overrides(nil, 512)
	got, err := Overrides(map[string]string{"max_connections": "200"}, 512)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Replace(def, []byte("max_connections = 120\n"), []byte("max_connections = 200\n"), 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("got\n%s", got)
	}
	// Every allow-listed name merges in place; order and line count unchanged.
	all := map[string]string{
		"max_connections": "100", "shared_buffers": "192MB", "work_mem": "8MB",
		"maintenance_work_mem": "128MB", "effective_cache_size": "400MB",
		"archive_timeout": "600", "cron.max_running_jobs": "4",
	}
	got, err = Overrides(all, 512)
	if err != nil {
		t.Fatal(err)
	}
	gl, dl := lines(got), lines(def)
	if len(gl) != len(dl) {
		t.Fatalf("line count %d, want %d", len(gl), len(dl))
	}
	for i := range dl {
		name, _, _ := strings.Cut(dl[i], " = ")
		if v, ok := all[name]; ok {
			if gl[i] != name+" = "+v {
				t.Errorf("line %d = %q", i, gl[i])
			}
		} else if gl[i] != dl[i] {
			t.Errorf("line %d changed: %q", i, gl[i])
		}
	}
}

func TestOverrides_RejectsUnlistedGUC(t *testing.T) {
	for _, name := range []string{
		"shared_preload_libraries", "archive_command", "disk_quota_mb",
		"", "Max_Connections", "MAX_CONNECTIONS", "max_connections ", " max_connections",
		"max_connections=1", "max_connections\n", "include", "include_dir", "hba_file",
		"listen_addresses", "password_encryption", "cron.max_running_jobs\x00",
	} {
		_, err := Overrides(map[string]string{name: "1"}, 512)
		if !errors.Is(err, ErrGUCNotAllowed) {
			t.Errorf("%q: err = %v", name, err)
		}
	}
	// With several bad names the first in byte order is reported, every time.
	for range 50 {
		_, err := Overrides(map[string]string{"b": "1", "a": "1", "c": "1", "max_connections": "x y"}, 512)
		if err == nil || !strings.Contains(err.Error(), `"a"`) {
			t.Fatalf("err = %v", err)
		}
	}
	// Two names differing only in case: the canonical one alone would pass.
	_, err := Overrides(map[string]string{"max_connections": "100", "MAX_CONNECTIONS": "100"}, 512)
	if !errors.Is(err, ErrGUCNotAllowed) {
		t.Errorf("case duplicate: err = %v", err)
	}
}

func TestOverrides_RejectsBadValue(t *testing.T) {
	bad := []string{
		"", "8MB\n", "8MB\ninclude = '/x'", "'\ninclude = '/x", "'8MB'", "\"8MB\"", "8 MB", " 8MB", "8MB ",
		"8MB;", "8MB#", "8MB\\", "8MB\x00", "8MB\r", "8MB\t", "-8MB", "+8MB", "8MB,9MB", "8=MB",
		"８MB", "٨MB", strings.Repeat("9", 200), "8MB" + strings.Repeat("A", 100),
	}
	for _, name := range []string{"work_mem", "maintenance_work_mem", "archive_timeout", "max_connections",
		"shared_buffers", "effective_cache_size", "cron.max_running_jobs"} {
		for _, v := range bad {
			got, err := Overrides(map[string]string{name: v}, 512)
			if !errors.Is(err, ErrGUCValue) {
				t.Errorf("%s=%q: err = %v", name, v, err)
			}
			if got != nil {
				t.Errorf("%s=%q: output on error", name, v)
			}
		}
	}
}

func TestOverrides_RangeChecks(t *testing.T) {
	bad := []map[string]string{
		{"max_connections": "5"},
		{"max_connections": "15"},
		{"max_connections": "401"},
		{"max_connections": "1000"},
		{"max_connections": "99999999999999999999999"},
		{"max_connections": "1e3"},
		{"shared_buffers": "100GB"},
		{"shared_buffers": "15MB"},
		{"shared_buffers": "16383kB"},
		{"shared_buffers": "205MB"}, // 40 % of 512 MB is 204.8 MB
		{"shared_buffers": "128"},   // a unit is required
		{"shared_buffers": "128mb"}, // units are case-sensitive
		{"shared_buffers": "1.5GB"}, // integers only
		{"shared_buffers": "128TB"},
		{"shared_buffers": "128B"},
		{"shared_buffers": "99999999999999999999GB"},
		{"effective_cache_size": "64MB"}, // below the default shared_buffers
		{"effective_cache_size": "513MB"},
		{"effective_cache_size": "1GB"},
		{"shared_buffers": "200MB", "effective_cache_size": "199MB"},
		{"shared_buffers": "200MB", "effective_cache_size": "204799kB"},
		{"cron.max_running_jobs": "abc"},
		{"cron.max_running_jobs": "0"},
		{"cron.max_running_jobs": "33"},
		{"cron.max_running_jobs": "2.5"},
		{"archive_timeout": "0"},
		{"archive_timeout": "29"},
		{"archive_timeout": "29s"},
		{"archive_timeout": "3601"},
		{"archive_timeout": "3601s"},
		{"archive_timeout": "61min"},
		{"archive_timeout": "1d"},
		{"archive_timeout": "1h"},
		{"archive_timeout": "300ms"},
		{"archive_timeout": "5MIN"},
		{"archive_timeout": "5m"},
		{"archive_timeout": "0min"},
		{"archive_timeout": "999999999"},
		{"archive_timeout": "1.5min"},
		{"archive_timeout": "min"},
	}
	for _, g := range bad {
		if _, err := Overrides(g, 512); !errors.Is(err, ErrGUCValue) {
			t.Errorf("%v: err = %v", g, err)
		}
	}
	good := []map[string]string{
		nil,
		{"max_connections": "16"},
		{"max_connections": "400"},
		{"shared_buffers": "16MB"},
		{"shared_buffers": "16384kB"},
		{"shared_buffers": "209715kB"}, // ⌊0.4 × 512 × 1024⌋ kB
		{"shared_buffers": "200MB", "effective_cache_size": "200MB"},
		{"effective_cache_size": "128MB"},
		{"effective_cache_size": "512MB"},
		{"effective_cache_size": "524288kB"},
		{"shared_buffers": "1GB", "effective_cache_size": "4GB"}, // with memMB 4096 below
		{"cron.max_running_jobs": "1"},
		{"cron.max_running_jobs": "32"},
		{"archive_timeout": "30"},
		{"archive_timeout": "30s"},
		{"archive_timeout": "3600"},
		{"archive_timeout": "3600s"},
		{"archive_timeout": "1min"},
		{"archive_timeout": "60min"},
	}
	for _, g := range good {
		mem := 512
		if g["effective_cache_size"] == "4GB" {
			mem = 4096
		}
		if _, err := Overrides(g, mem); err != nil {
			t.Errorf("%v: %v", g, err)
		}
	}
	// The defaults are checked against the container's memory too.
	for _, mem := range []int{0, -1, 319, 383} {
		_, err := Overrides(nil, mem)
		if !errors.Is(err, ErrGUCValue) || !strings.Contains(err.Error(), "384") {
			t.Errorf("memMB %d: err = %v", mem, err)
		}
	}
	if _, err := Overrides(nil, 384); err != nil {
		t.Errorf("memMB 384: %v", err)
	}
	// A smaller container is fine once the overrides fit it.
	if _, err := Overrides(map[string]string{"effective_cache_size": "200MB"}, 320); err != nil {
		t.Errorf("memMB 320 with a smaller effective_cache_size: %v", err)
	}
}

func TestCommandLine_FromImageFixture(t *testing.T) {
	got, err := CommandLine(image(t, "postgresql.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-c", "hba_file=/etc/postgresql/pg_hba.conf", "-c", "ident_file=/etc/postgresql/pg_ident.conf",
		"-c", "shared_preload_libraries=pg_stat_statements, pgaudit, plpgsql, plpgsql_check, pg_cron, pg_net, pgsodium, auto_explain, pg_tle, plan_filter, supabase_vault",
		"-c", "session_preload_libraries=supautils", "-c", "local_preload_libraries="}
	if !slices.Equal(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestCommandLine_Parsing(t *testing.T) {
	get := func(conf string) []string {
		t.Helper()
		got, err := CommandLine([]byte(conf))
		if err != nil {
			t.Fatalf("%q: %v", conf, err)
		}
		return got
	}
	// Last occurrence wins, names are case-insensitive, '=' is optional, '' is a quote.
	got := get("shared_preload_libraries = 'a'\n# shared_preload_libraries = 'x'\n" +
		"SHARED_PRELOAD_LIBRARIES 'b, c''d' # note\nlocal_preload_libraries=e\n")
	if got[5] != "shared_preload_libraries=b, c'd" || got[9] != "local_preload_libraries=e" || got[7] != "session_preload_libraries=" {
		t.Fatalf("%q", got)
	}
	for _, conf := range []string{
		"", "# shared_preload_libraries = 'a'\n", "session_preload_libraries = 'a'\n",
		"shared_preload_libraries = 'a\n", "shared_preload_libraries = 'a\\'b'\n",
	} {
		if _, err := CommandLine([]byte(conf)); !errors.Is(err, ErrTemplate) {
			t.Errorf("%q: err = %v", conf, err)
		}
	}
}

func mustHBA(t *testing.T, p string) []byte {
	t.Helper()
	b, err := HBA(netip.MustParsePrefix(p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPostgREST(t *testing.T, addr, pw string) []byte {
	t.Helper()
	b, err := PostgREST(PostgRESTConfig{ClusterAddr: netip.MustParseAddr(addr), AuthenticatorPassword: pw})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHBA_Golden(t *testing.T) {
	got := mustHBA(t, "10.213.3.64/26")
	golden(t, "pg_hba.conf", got)
	// The slice line is spaced as the other address lines' template: four spaces after the prefix.
	if !bytes.Contains(got, []byte("\nhost    all  all              10.213.3.64/26    scram-sha-256\n")) {
		t.Fatalf("slice line: %q", got)
	}
	if n := len(lines(got)); n != 11 || !bytes.HasSuffix(got, []byte("\n")) {
		t.Fatalf("%d lines", n)
	}
	// A prefix with host bits set is rendered as its network.
	if !bytes.Equal(mustHBA(t, "10.213.3.66/26"), got) {
		t.Fatal("host bits not masked")
	}
	for _, p := range []netip.Prefix{{}, netip.MustParsePrefix("10.213.3.64/25"), netip.MustParsePrefix("10.213.3.64/27"),
		netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("0.0.0.0/26"), netip.MustParsePrefix("2001:db8::/64"),
		netip.MustParsePrefix("2001:db8::/26"), netip.MustParsePrefix("::ffff:10.213.3.64/122")} {
		if b, err := HBA(p); err == nil || b != nil {
			t.Errorf("%v: accepted", p)
		}
	}
	if string(Ident()) != "supapace  postgres  supapace_backup\n" {
		t.Fatalf("ident %q", Ident())
	}
}

var network = []string{"pg_net", "http", "dblink", "postgres_fdw", "wrappers"}

// listOf returns the comma-separated names on the line "<key> = '…'" of b.
func listOf(t *testing.T, b []byte, key string) []string {
	t.Helper()
	for _, l := range lines(b) {
		if v, ok := strings.CutPrefix(l, key+" = '"); ok {
			return strings.Split(strings.TrimSuffix(v, "'"), ", ")
		}
	}
	t.Fatalf("no %s line", key)
	return nil
}

// diffLines returns the indexes of the lines that differ; the line counts must match.
func diffLines(t *testing.T, a, b []byte) []int {
	t.Helper()
	al, bl := lines(a), lines(b)
	if len(al) != len(bl) {
		t.Fatalf("line count %d, want %d", len(al), len(bl))
	}
	var d []int
	for i := range al {
		if al[i] != bl[i] {
			d = append(d, i)
		}
	}
	return d
}

func TestSupautils_RemovesNetworkExtensions(t *testing.T) {
	img := image(t, "supautils.conf")
	got, err := Supautils(img, false)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "supautils.conf", got)
	before, after := listOf(t, img, "supautils.privileged_extensions"), listOf(t, got, "supautils.privileged_extensions")
	for _, n := range before {
		if slices.Contains(network, n) == slices.Contains(after, n) {
			t.Errorf("%s: present=%v", n, slices.Contains(after, n))
		}
	}
	if len(after) != len(before)-len(network) {
		t.Errorf("%d names left of %d", len(after), len(before))
	}
	d := diffLines(t, img, got)
	if len(d) != 2 || !strings.HasPrefix(lines(got)[d[0]], "supautils.privileged_extensions = ") ||
		!strings.HasPrefix(lines(got)[d[1]], "supautils.reserved_roles = ") {
		t.Fatalf("changed lines %v", d)
	}
}

func TestSupautils_OutboundKeepsThem(t *testing.T) {
	img := image(t, "supautils.conf")
	got, err := Supautils(img, true)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "supautils-outbound.conf", got)
	d := diffLines(t, img, got)
	if len(d) != 1 || !strings.HasPrefix(lines(got)[d[0]], "supautils.reserved_roles = ") {
		t.Fatalf("changed lines %v", d)
	}
}

func TestSupautils_ReservedRolesAddsBackup(t *testing.T) {
	img := image(t, "supautils.conf")
	for _, outbound := range []bool{false, true} {
		got, err := Supautils(img, outbound)
		if err != nil {
			t.Fatal(err)
		}
		before, after := listOf(t, img, "supautils.reserved_roles"), listOf(t, got, "supautils.reserved_roles")
		if !slices.Equal(append(before, "supapace_backup"), after) {
			t.Errorf("outbound=%v: %q", outbound, after)
		}
	}
}

func TestSupautils_FailsIfLineMissing(t *testing.T) {
	img := image(t, "supautils.conf")
	drop := func(prefix string) []byte {
		var out []string
		for _, l := range lines(img) {
			if !strings.HasPrefix(l, prefix) {
				out = append(out, l)
			}
		}
		return []byte(strings.Join(out, "\n"))
	}
	dup := func(prefix string) []byte {
		for _, l := range lines(img) {
			if strings.HasPrefix(l, prefix) {
				return append(append([]byte{}, img...), l+"\n"...)
			}
		}
		t.Fatal(prefix)
		return nil
	}
	for name, in := range map[string][]byte{
		"no privileged_extensions":  drop("supautils.privileged_extensions = "),
		"no reserved_roles":         drop("supautils.reserved_roles = "),
		"two privileged_extensions": dup("supautils.privileged_extensions = "),
		"two reserved_roles":        dup("supautils.reserved_roles = "),
		"unquoted": bytes.Replace(img, []byte("supautils.reserved_roles = '"),
			[]byte("supautils.reserved_roles = "), 1),
		"empty":                          nil,
		"reserved_roles again, tab":      append(slices.Clone(img), "supautils.reserved_roles\t= 'x'\n"...),
		"reserved_roles again, no space": append(slices.Clone(img), "supautils.reserved_roles='x'\n"...),
		"reserved_roles again, indented": append(slices.Clone(img), "  supautils.reserved_roles = 'x'\n"...),
		"reserved_roles again, case":     append(slices.Clone(img), "SUPAUTILS.Reserved_Roles = 'x'\n"...),
		"extensions again, case":         append(slices.Clone(img), "Supautils.Privileged_Extensions = 'x'\n"...),
		"extensions again, no =":         append(slices.Clone(img), "supautils.privileged_extensions 'x'\n"...),
	} {
		for _, outbound := range []bool{false, true} {
			if _, err := Supautils(in, outbound); !errors.Is(err, ErrTemplate) {
				t.Errorf("%s outbound=%v: err = %v", name, outbound, err)
			}
		}
	}
}

func TestPasswd_RewritesOnlyPostgres(t *testing.T) {
	img := image(t, "passwd")
	got, err := Passwd(img, 700613, 700614)
	if err != nil {
		t.Fatal(err)
	}
	d := diffLines(t, img, got)
	if len(d) != 1 || lines(got)[d[0]] != "postgres:x:700613:700614::/var/lib/postgresql:/bin/bash" {
		t.Fatalf("changed lines %v: %q", d, got)
	}
	for _, in := range [][]byte{nil, []byte("root:x:0:0:root:/root:/bin/sh\n"),
		append(append([]byte{}, img...), "postgres:x:1:1:dup:/:/bin/sh\n"...), []byte("postgres:x:100\n")} {
		if _, err := Passwd(in, 700613, 700613); !errors.Is(err, ErrTemplate) {
			t.Errorf("%q: err = %v", in, err)
		}
	}
	for _, id := range [][2]int{{0, 1}, {1, 0}, {-1, 1}, {1 << 31, 1}} {
		if _, err := Passwd(img, id[0], id[1]); !errors.Is(err, ErrTemplate) {
			t.Errorf("%v: err = %v", id, err)
		}
	}
}

func TestGroup_RewritesOnlyPostgres(t *testing.T) {
	img := image(t, "group")
	got, err := Group(img, 700614)
	if err != nil {
		t.Fatal(err)
	}
	d := diffLines(t, img, got)
	if len(d) != 1 || lines(got)[d[0]] != "postgres:x:700614:postgres" {
		t.Fatalf("changed lines %v: %q", d, got)
	}
	for _, in := range [][]byte{nil, []byte("root:x:0:root\n"),
		append(append([]byte{}, img...), "postgres:x:1:\n"...), []byte("postgres:x\n")} {
		if _, err := Group(in, 700613); !errors.Is(err, ErrTemplate) {
			t.Errorf("%q: err = %v", in, err)
		}
	}
	if _, err := Group(img, 0); !errors.Is(err, ErrTemplate) {
		t.Errorf("gid 0: err = %v", err)
	}
}

const testPassword = "synthetic-test-password-0000"

func TestPostgREST_Golden(t *testing.T) {
	got := mustPostgREST(t, "10.213.3.66", testPassword)
	golden(t, "postgrest.conf", got)
	keys := map[string]string{}
	for _, l := range lines(got) {
		if l == "" {
			continue
		}
		k, v, ok := strings.Cut(l, " = ")
		if !ok {
			t.Fatalf("line %q", l)
		}
		if _, dup := keys[k]; dup {
			t.Fatalf("duplicate %s", k)
		}
		keys[k] = v
	}
	want := map[string]string{
		"db-uri":               `"postgres://authenticator:` + testPassword + `@10.213.3.66:5432/postgres?require_auth=scram-sha-256"`,
		"db-schemas":           `"public, graphql_public"`,
		"db-anon-role":         `"anon"`,
		"db-pool":              "10",
		"db-extra-search-path": `"public, extensions"`,
		"jwt-secret":           `"@/etc/postgrest/jwks.json"`,
		"db-config":            "false",
		"server-host":          `"*4"`,
		"server-port":          "3000",
	}
	if len(keys) != len(want) {
		t.Errorf("keys %v", keys)
	}
	for k, v := range want {
		if keys[k] != v {
			t.Errorf("%s = %s, want %s", k, keys[k], v)
		}
	}
	for _, k := range []string{"admin-server-port", "GHCRTS"} {
		if bytes.Contains(got, []byte(k)) {
			t.Errorf("%s present", k)
		}
	}
	// Every byte outside [A-Za-z0-9._~-] of the password is percent-encoded.
	l := lines(mustPostgREST(t, "10.213.3.66", "a\"b\\c\nd@e/f$g%h:i?j#k'l é~._-Z9"))[0]
	if l != `db-uri = "postgres://authenticator:a%22b%5Cc%0Ad%40e%2Ff%24g%25h%3Ai%3Fj%23k%27l%20%C3%A9~._-Z9@10.213.3.66:5432/postgres?require_auth=scram-sha-256"` {
		t.Errorf("escaped: %s", l)
	}
	// Refused: an address that is not IPv4, a NUL, more than 256 bytes.
	for _, c := range []PostgRESTConfig{
		{AuthenticatorPassword: testPassword},
		{ClusterAddr: netip.MustParseAddr("2001:db8::2"), AuthenticatorPassword: testPassword},
		{ClusterAddr: netip.MustParseAddr("::ffff:10.213.3.66"), AuthenticatorPassword: testPassword},
		{ClusterAddr: netip.MustParseAddr("10.213.3.66"), AuthenticatorPassword: "a\x00b"},
		{ClusterAddr: netip.MustParseAddr("10.213.3.66"), AuthenticatorPassword: strings.Repeat("a", 257)},
	} {
		if b, err := PostgREST(c); err == nil || b != nil {
			t.Errorf("%v %d bytes: accepted", c.ClusterAddr, len(c.AuthenticatorPassword))
		}
	}
	if _, err := PostgREST(PostgRESTConfig{ClusterAddr: netip.MustParseAddr("10.213.3.66"), AuthenticatorPassword: strings.Repeat("a", 256)}); err != nil {
		t.Errorf("256 bytes: %v", err)
	}
}

func TestPostgREST_SecretOnlyInFile(t *testing.T) {
	got := mustPostgREST(t, "10.213.3.66", testPassword)
	if n := bytes.Count(got, []byte(testPassword)); n != 1 {
		t.Fatalf("password appears %d times", n)
	}
	for _, l := range lines(got) {
		if strings.Contains(l, testPassword) && !strings.HasPrefix(l, "db-uri = ") {
			t.Fatalf("password outside db-uri: %q", l)
		}
	}
	// No other render takes or emits it.
	others := [][]byte{mustHBA(t, "10.213.3.64/26"), Ident()}
	if b, err := Overrides(nil, 512); err == nil {
		others = append(others, b)
	}
	for _, b := range others {
		if bytes.Contains(b, []byte(testPassword)) {
			t.Fatal("password in another render")
		}
	}
}

// The package renders bytes only: nothing outside this list may be imported by
// its non-test files (no filesystem, network or process access).
func TestImports_PureOnly(t *testing.T) {
	allowed := []string{"bytes", "errors", "fmt", "maps", "net/netip", "slices", "strconv", "strings", "time"}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		n++
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if !slices.Contains(allowed, p) {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
	if n == 0 {
		t.Fatal("no source files")
	}
}

// Postgres reads a leading 0 as octal and 0x as hex: "0100" is 64 to the server,
// "0128MB" is refused by it. A value the range check reads differently from the
// server must not pass.
func TestOverrides_RejectsLeadingZeros(t *testing.T) {
	for _, g := range []map[string]string{
		{"max_connections": "0100"}, {"max_connections": "017"},
		{"shared_buffers": "0128MB"}, {"effective_cache_size": "0400MB"},
		{"cron.max_running_jobs": "010"}, {"work_mem": "04MB"}, {"work_mem": "0x10"},
		{"maintenance_work_mem": "064MB"}, {"archive_timeout": "0300"}, {"archive_timeout": "0x12C"},
		{"max_connections": "0x64"}, {"max_connections": "00"}, {"shared_buffers": "0x10MB"},
		{"shared_buffers": "020000kB"}, {"effective_cache_size": "0x180MB"}, {"cron.max_running_jobs": "0x2"},
		{"cron.max_running_jobs": "02"}, {"archive_timeout": "060s"}, {"archive_timeout": "05min"},
		{"archive_timeout": "0X12C"},
	} {
		if _, err := Overrides(g, 512); !errors.Is(err, ErrGUCValue) {
			t.Errorf("%v: err = %v", g, err)
		}
	}
}

func TestOverrides_Deterministic(t *testing.T) {
	all := map[string]string{
		"max_connections": "100", "shared_buffers": "192MB", "work_mem": "8MB",
		"maintenance_work_mem": "128MB", "effective_cache_size": "400MB",
		"archive_timeout": "600", "cron.max_running_jobs": "4",
	}
	first, err := Overrides(all, 512)
	if err != nil {
		t.Fatal(err)
	}
	for range 1000 {
		if got, _ := Overrides(all, 512); !bytes.Equal(got, first) {
			t.Fatalf("output differs between runs:\n%s", got)
		}
	}
}

func TestOverrides_EveryByteOutsideGrammarRefused(t *testing.T) {
	for c := range 256 {
		b := byte(c)
		if b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '.' {
			continue
		}
		v := "4" + string([]byte{b}) + "MB"
		if _, err := Overrides(map[string]string{"work_mem": v}, 512); !errors.Is(err, ErrGUCValue) {
			t.Errorf("byte %#x: err = %v", b, err)
		}
	}
	if _, err := Overrides(map[string]string{"work_mem": strings.Repeat("9", 64)}, 512); err != nil {
		t.Errorf("64 bytes: %v", err)
	}
	if _, err := Overrides(map[string]string{"work_mem": strings.Repeat("9", 65)}, 512); !errors.Is(err, ErrGUCValue) {
		t.Errorf("65 bytes: err = %v", err)
	}
}

func TestOverrides_MemoryBounds(t *testing.T) {
	// The defaults need 384 MB: effective_cache_size = 384MB must fit.
	for mem, ok := range map[int]bool{383: false, 384: true, 1 << 30: true, 1<<30 + 1: false,
		math.MaxInt: false, math.MinInt: false} {
		_, err := Overrides(nil, mem)
		if ok != (err == nil) || err != nil && !errors.Is(err, ErrGUCValue) {
			t.Errorf("memMB %d: err = %v", mem, err)
		}
	}
	// shared_buffers alone is checked against the default effective_cache_size.
	if _, err := Overrides(map[string]string{"shared_buffers": "400MB"}, 1024); !errors.Is(err, ErrGUCValue) {
		t.Errorf("shared_buffers above the default effective_cache_size: err = %v", err)
	}
	// Large figures do not wrap.
	for _, v := range []string{"999999999GB", "999999999999999GB", "9223372036854775807kB"} {
		if _, err := Overrides(map[string]string{"shared_buffers": v, "effective_cache_size": v}, 1<<30); !errors.Is(err, ErrGUCValue) {
			t.Errorf("%s: err = %v", v, err)
		}
	}
}

func TestCommandLine_BareValueComment(t *testing.T) {
	got, err := CommandLine([]byte("shared_preload_libraries = a\t# note\nsession_preload_libraries = 'x#y' # note\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got[5] != "shared_preload_libraries=a" || got[7] != "session_preload_libraries=x#y" {
		t.Fatalf("%q", got)
	}
}

func TestSupautils_RefusesOddListLines(t *testing.T) {
	img := image(t, "supautils.conf")
	const key = "supautils.reserved_roles = '"
	for name, in := range map[string][]byte{
		"no closing quote": bytes.Replace(img, []byte("supabase_privileged_role'\nsupautils.hint_roles"), []byte("supabase_privileged_role\nsupautils.hint_roles"), 1),
		"doubled quote":    bytes.Replace(img, []byte(key+"supabase_admin"), []byte(key+"supa''base_admin"), 1),
		"hash inside":      bytes.Replace(img, []byte(key+"supabase_admin"), []byte(key+"supabase_admin#x"), 1),
		"backslash inside": bytes.Replace(img, []byte(key+"supabase_admin"), []byte(key+`supabase\_admin`), 1),
		"CRLF":             bytes.ReplaceAll(img, []byte("\n"), []byte("\r\n")),
	} {
		if bytes.Equal(in, img) {
			t.Fatalf("%s: fixture unchanged", name)
		}
		if _, err := Supautils(in, false); !errors.Is(err, ErrTemplate) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// The image's full list of extensions a non-superuser may create. A new image
// that changes it fails here, so that whether a new entry can reach the network
// is decided before the list is rendered.
func TestSupautils_PrivilegedExtensionsSnapshot(t *testing.T) {
	want := strings.Split("address_standardizer, address_standardizer_data_us, autoinc, bloom, btree_gin, "+
		"btree_gist, citext, cube, dblink, dict_int, dict_xsyn, earthdistance, fuzzystrmatch, hstore, http, "+
		"hypopg, index_advisor, insert_username, intarray, isn, ltree, moddatetime, orioledb, pg_buffercache, "+
		"pg_cron, pg_graphql, pg_hashids, pg_jsonschema, pg_net, pg_prewarm, pg_repack, pg_stat_monitor, "+
		"pg_stat_statements, pg_tle, pg_trgm, pg_walinspect, pgaudit, pgcrypto, pgjwt, pgroonga, "+
		"pgroonga_database, pgrouting, pgrowlocks, pgsodium, pgstattuple, pgtap, plcoffee, pljava, plls, "+
		"plpgsql_check, postgis, postgis_raster, postgis_sfcgal, postgis_tiger_geocoder, postgis_topology, "+
		"postgres_fdw, refint, rum, seg, sslinfo, supabase_vault, supautils, tablefunc, tcn, tsm_system_rows, "+
		"tsm_system_time, unaccent, uuid-ossp, vector, wrappers", ", ")
	got := listOf(t, image(t, "supautils.conf"), "supautils.privileged_extensions")
	if !slices.Equal(got, want) {
		t.Fatalf("image list changed:\n got  %q\n want %q", got, want)
	}
	// A commented-out line with the same name is not a second setting.
	img := append(image(t, "supautils.conf"), "# supautils.reserved_roles = 'x'\n"...)
	if _, err := Supautils(img, false); err != nil {
		t.Fatal(err)
	}
}

// The constant names extensions the pinned image actually lists.
func TestSupautils_NetworkExtensionsInImage(t *testing.T) {
	list := listOf(t, image(t, "supautils.conf"), "supautils.privileged_extensions")
	for _, n := range networkExtensions {
		if !slices.Contains(list, n) {
			t.Errorf("%s not in the image's privileged_extensions", n)
		}
	}
}

func TestPasswd_FieldCountAndBytesKept(t *testing.T) {
	if _, err := Passwd([]byte("postgres:x:100:101:g:/bin/bash\n"), 7, 7); !errors.Is(err, ErrTemplate) {
		t.Errorf("6 fields: err = %v", err)
	}
	if _, err := Group([]byte("postgres:x:101:a:b\n"), 7); !errors.Is(err, ErrTemplate) {
		t.Errorf("5 fields: err = %v", err)
	}
	for in, want := range map[string]string{
		"root:x:0:0:g:/:/bin/sh\r\npostgres:x:1:2:g:/h:/bin/sh\r\n": "root:x:0:0:g:/:/bin/sh\r\npostgres:x:7:8:g:/h:/bin/sh\r\n",
		"postgres:x:1:2:g:/h:/bin/sh":                               "postgres:x:7:8:g:/h:/bin/sh",
		"postgresql:x:1:2:g:/h:/bin/sh\npostgres:x:1:2:g:/h:/s\n":   "postgresql:x:1:2:g:/h:/bin/sh\npostgres:x:7:8:g:/h:/s\n",
	} {
		got, err := Passwd([]byte(in), 7, 8)
		if err != nil || string(got) != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
}

// db-uri parses back to exactly the password, and holds no byte that
// PostgREST's configuration syntax treats specially ('$' starts an
// interpolation; '"' and '\' would end or escape the quoted value).
func TestPostgREST_DbURIRoundTrip(t *testing.T) {
	var all []byte
	for c := 1; c < 256; c++ {
		all = append(all, byte(c))
	}
	for _, pw := range []string{testPassword, "ab$cd", "$(HOME)", ":/?#[]@!$&'()*+,;=%", string(all)} {
		for _, addr := range []string{"10.213.3.66", "10.213.255.130"} {
			l := lines(mustPostgREST(t, addr, pw))[0]
			raw, ok := strings.CutPrefix(l, `db-uri = "`)
			raw, ok2 := strings.CutSuffix(raw, `"`)
			if !ok || !ok2 || strings.ContainsAny(raw, "$\"\\\n") {
				t.Errorf("%q at %s: line %q", pw, addr, l)
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Errorf("%q: %v", pw, err)
				continue
			}
			got, _ := u.User.Password()
			if got != pw || u.User.Username() != "authenticator" || u.Hostname() != addr || u.Port() != "5432" ||
				u.Path != "/postgres" || u.RawQuery != "require_auth=scram-sha-256" {
				t.Errorf("%q at %s: parsed %#v", pw, addr, u)
			}
		}
	}
}
