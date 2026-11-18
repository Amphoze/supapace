// Package pgconf renders the configuration of a project's database cluster and
// of its PostgREST: the platform's override file, pg_hba.conf, pg_ident.conf,
// the extension template, the passwd and group files, the command-line pins and
// postgrest.conf. Every function is pure: bytes in, bytes out.
//
// Product defaults are the lines of the override file; an operator may change
// only the allow-listed ones. Pinned settings — hba_file, ident_file and the
// three preload lists — are passed on the postmaster's command line, which wins
// over every configuration file, so no file a project's database server can
// influence moves them.
package pgconf

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

var (
	ErrGUCNotAllowed = errors.New("pgconf: setting not allowed")
	ErrGUCValue      = errors.New("pgconf: bad setting value")
	ErrTemplate      = errors.New("pgconf: image file not as expected")
)

// GUCAllowList holds the settings an operator may override.
var GUCAllowList = []string{
	"max_connections", "shared_buffers", "work_mem", "maintenance_work_mem",
	"effective_cache_size", "archive_timeout", "cron.max_running_jobs",
}

// defaults is the override file, in order. Values are rendered verbatim.
var defaults = [][2]string{
	{"listen_addresses", "'*'"},
	{"max_connections", "120"},
	{"superuser_reserved_connections", "3"},
	{"reserved_connections", "2"},
	{"shared_buffers", "128MB"},
	{"effective_cache_size", "384MB"},
	{"work_mem", "4MB"},
	{"maintenance_work_mem", "64MB"},
	{"autovacuum_work_mem", "32MB"},
	{"autovacuum_max_workers", "2"},
	{"max_wal_size", "1GB"},
	{"max_slot_wal_keep_size", "2GB"},
	{"wal_level", "logical"},
	{"archive_mode", "on"},
	{"archive_command", "'true # pgbackrest'"},
	{"archive_timeout", "300"},
	{"max_replication_slots", "8"},
	{"max_wal_senders", "10"},
	{"password_encryption", "'scram-sha-256'"},
	{"cron.max_running_jobs", "2"},
	{"random_page_cost", "1.1"},
	{"huge_pages", "off"},
	{"max_parallel_workers_per_gather", "0"},
	{"max_prepared_transactions", "0"},
	{"temp_file_limit", "1GB"},
}

// OverrideFile is the name the output of Overrides is written under in the
// image's include directory. Postgres reads that directory in byte order of the
// names and a later file wins, so this name must sort after every file of the
// image (see SortsLast).
const OverrideFile = "zz-supapace.conf"

// SortsLast returns an error naming the first of names (the regular files of the
// image's include directory) that the server would read at or after
// OverrideFile. The server reads only names that end in ".conf" and do not start
// with a dot, in byte order; other names are skipped here as they are there.
func SortsLast(names []string) error {
	for _, n := range names {
		if !strings.HasSuffix(n, ".conf") || strings.HasPrefix(n, ".") {
			continue
		}
		if n >= OverrideFile {
			return fmt.Errorf("%w: include directory entry %q does not sort before %s", ErrTemplate, n, OverrideFile)
		}
	}
	return nil
}

const (
	maxValueLen = 64
	// minDefaultMemMB is the smallest container memory the defaults fit:
	// effective_cache_size = 384MB must not exceed it.
	minDefaultMemMB = 384
)

// Overrides renders the override file (OverrideFile): the defaults with the
// allow-listed overrides merged in place. memMB is the cluster container's
// memory limit.
//
// Every value must be 1–64 bytes of [A-Za-z0-9.] and must not start with 0
// followed by a digit or letter (Postgres reads those as octal or hex). The
// merged result is then range-checked: max_connections an integer 16–400 (each
// connection is a process; the container allows 512); shared_buffers and
// effective_cache_size an integer with unit kB, MB or GB (case as Postgres
// spells them, no fraction, no bare number), 16 MB ≤ shared_buffers ≤ 40 % of
// memMB and shared_buffers ≤ effective_cache_size ≤ memMB;
// cron.max_running_jobs an integer 1–32; archive_timeout an integer with no
// unit (seconds), unit s or unit min, 30 s to 3600 s. work_mem and
// maintenance_work_mem are left to Postgres's own check. With several bad
// names the first in byte order is reported.
func Overrides(gucs map[string]string, memMB int) ([]byte, error) {
	for _, name := range slices.Sorted(maps.Keys(gucs)) {
		v := gucs[name]
		if !slices.Contains(GUCAllowList, name) {
			return nil, fmt.Errorf("%w: %q", ErrGUCNotAllowed, name)
		}
		if !plainValue(v) {
			return nil, fmt.Errorf("%w: %s = %q", ErrGUCValue, name, v)
		}
	}
	merged := make(map[string]string, len(defaults))
	for _, d := range defaults {
		merged[d[0]] = d[1]
	}
	for name, v := range gucs {
		merged[name] = v
	}
	if err := checkRanges(merged, memMB); err != nil {
		return nil, err
	}
	var b strings.Builder
	for _, d := range defaults {
		b.WriteString(d[0] + " = " + merged[d[0]] + "\n")
	}
	return []byte(b.String()), nil
}

func plainValue(v string) bool {
	if v == "" || len(v) > maxValueLen {
		return false
	}
	alnum := func(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	if v[0] == '0' && len(v) > 1 && alnum(v[1]) {
		return false
	}
	for _, c := range []byte(v) {
		if !alnum(c) && c != '.' {
			return false
		}
	}
	return true
}

func checkRanges(m map[string]string, memMB int) error {
	bad := func(name, why string) error {
		return fmt.Errorf("%w: %s = %q: %s", ErrGUCValue, name, m[name], why)
	}
	hint := ""
	if memMB < minDefaultMemMB {
		hint = fmt.Sprintf(" (the defaults need a container of at least %dMB)", minDefaultMemMB)
	}
	if memMB <= 0 || memMB > 1<<30 {
		return fmt.Errorf("%w: container memory %d MB%s", ErrGUCValue, memMB, hint)
	}
	memKB := int64(memMB) * 1024
	if n, ok := integer(m["max_connections"]); !ok || n < 16 || n > 400 {
		return bad("max_connections", "want an integer 16–400")
	}
	if n, ok := integer(m["cron.max_running_jobs"]); !ok || n < 1 || n > 32 {
		return bad("cron.max_running_jobs", "want an integer 1–32")
	}
	if n, ok := seconds(m["archive_timeout"]); !ok || n < 30 || n > 3600 {
		return bad("archive_timeout", "want 30s to 3600s, unit none, s or min")
	}
	sb, ok := kilobytes(m["shared_buffers"])
	if !ok || sb < 16*1024 || sb*100 > memKB*40 {
		return bad("shared_buffers", fmt.Sprintf("want kB/MB/GB, 16MB to 40%% of %dMB%s", memMB, hint))
	}
	if ecs, ok := kilobytes(m["effective_cache_size"]); !ok || ecs < sb || ecs > memKB {
		return bad("effective_cache_size", fmt.Sprintf("want kB/MB/GB, shared_buffers to %dMB%s", memMB, hint))
	}
	return nil
}

// seconds parses an integer with no unit or unit s (seconds) or min.
func seconds(s string) (int64, bool) {
	if num, ok := strings.CutSuffix(s, "min"); ok {
		n, ok := integer(num)
		return n * 60, ok
	}
	n, ok := integer(strings.TrimSuffix(s, "s"))
	return n, ok
}

// integer parses ASCII decimal digits only (no sign), at most 9 of them.
func integer(s string) (int64, bool) {
	if s == "" || len(s) > 9 || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// kilobytes parses an integer with unit kB, MB or GB into kB.
func kilobytes(s string) (int64, bool) {
	for unit, mult := range map[string]int64{"kB": 1, "MB": 1 << 10, "GB": 1 << 20} {
		if num, ok := strings.CutSuffix(s, unit); ok {
			n, ok := integer(num)
			return n * mult, ok // ≤ 999999999 × 2^20: no overflow
		}
	}
	return 0, false
}

const (
	hbaFile   = "/etc/postgresql/pg_hba.conf"
	identFile = "/etc/postgresql/pg_ident.conf"
)

// CommandLine returns the -c flags that pin hba_file, ident_file and the three
// preload lists, each flag and each name=value its own element. The preload
// values are those of the image's postgresql.conf (empty when absent; a missing
// shared_preload_libraries is ErrTemplate). The caller prepends
// "postgres -D /etc/postgresql".
func CommandLine(imageConf []byte) ([]string, error) {
	preload := []string{"shared_preload_libraries", "session_preload_libraries", "local_preload_libraries"}
	vals := map[string]string{}
	for i, line := range strings.Split(string(imageConf), "\n") {
		name, v, ok, err := confLine(line)
		if err != nil {
			return nil, fmt.Errorf("%w: postgresql.conf line %d: %v", ErrTemplate, i+1, err)
		}
		if name = strings.ToLower(name); ok && slices.Contains(preload, name) {
			vals[name] = v
		}
	}
	if _, ok := vals["shared_preload_libraries"]; !ok {
		return nil, fmt.Errorf("%w: postgresql.conf sets no shared_preload_libraries", ErrTemplate)
	}
	out := []string{"-c", "hba_file=" + hbaFile, "-c", "ident_file=" + identFile}
	for _, p := range preload {
		out = append(out, "-c", p+"="+vals[p])
	}
	return out, nil
}

// confLine parses one line of postgresql.conf syntax: `name [=] value [# …]`,
// value either bare or single-quoted (a doubled quote stands for one). A backslash in a
// quoted value is refused rather than interpreted.
func confLine(line string) (name, value string, ok bool, err error) {
	name, s := settingName(line)
	if name == "" {
		if s == "" || s[0] == '#' {
			return "", "", false, nil
		}
		return "", "", false, errors.New("no setting name")
	}
	s = strings.TrimLeft(strings.TrimPrefix(s, "="), " \t")
	if !strings.HasPrefix(s, "'") {
		value, _, _ = strings.Cut(s, "#")
		return name, strings.TrimRight(value, " \t\r"), true, nil
	}
	var b strings.Builder
	for j := 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			return "", "", false, errors.New("backslash in quoted value")
		case '\'':
			if j+1 < len(s) && s[j+1] == '\'' {
				b.WriteByte('\'')
				j++
				continue
			}
			return name, b.String(), true, nil
		default:
			b.WriteByte(s[j])
		}
	}
	return "", "", false, errors.New("unterminated quoted value")
}

// settingName splits a configuration line into its leading setting name and
// the rest, blanks trimmed. A blank or comment line has no name.
func settingName(line string) (name, rest string) {
	s := strings.TrimLeft(line, " \t\r")
	i := strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '.')
	})
	if i < 0 {
		i = len(s)
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}
