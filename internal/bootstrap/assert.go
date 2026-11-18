package bootstrap

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Amphoze/supapace/internal/nodecfg"
	"github.com/Amphoze/supapace/internal/pgconf"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/jackc/pgx/v5"
)

// The names a finding can carry; the set is frozen.
const (
	checkPresence            = "presence"
	checkSuperuser           = "superuser"
	checkAttributes          = "attributes"
	checkMembershipsReserved = "memberships-reserved"
	checkMembershipsDanger   = "memberships-dangerous"
	checkRoleSettings        = "role-settings"
	checkSchemaACL           = "schema-acl"
	checkEventTriggers       = "event-triggers"
	checkAuthFunctions       = "auth-functions"
	checkConfiguration       = "configuration"
	checkSourceFile          = "source-file"
	checkHBA                 = "hba"
	checkServicePasswords    = "service-passwords"
)

var checkNames = []string{checkPresence, checkSuperuser, checkAttributes, checkMembershipsReserved,
	checkMembershipsDanger, checkRoleSettings, checkSchemaACL, checkEventTriggers, checkAuthFunctions,
	checkConfiguration, checkSourceFile, checkHBA, checkServicePasswords}

// allowedSourceFiles are the files a setting may come from: the image's main
// file and its includes, the image's include-directory files and the
// platform's override file. Nothing from postgresql.auto.conf.
var allowedSourceFiles = []string{
	"/etc/postgresql/postgresql.conf",
	"/etc/postgresql/logging.conf",
	"/etc/postgresql-custom/wal-g.conf",
	"/etc/postgresql-custom/read-replica.conf",
	"/etc/postgresql-custom/supautils.conf",
	"/etc/postgresql-custom/conf.d/auto_explain.conf",
	"/etc/postgresql-custom/conf.d/custom_overrides.conf",
	"/etc/postgresql-custom/conf.d/generated_optimizations.conf",
	"/etc/postgresql-custom/conf.d/pg_cron.conf",
	"/etc/postgresql-custom/conf.d/pg_net.conf",
	"/etc/postgresql-custom/conf.d/zz-supapace.conf",
}

// commandLinePins are the settings that read source "command line" in a
// platform session. hba_file and ident_file, also passed on the command line,
// read source "override"; local_preload_libraries, passed there too, reads
// "client" because the platform session sets it in its startup packet.
var commandLinePins = []string{"session_preload_libraries", "shared_preload_libraries"}

// platformRoles are the roles bootstrap creates, with their attributes.
var platformRoles = []Role{
	{Name: "supabase_realtime_admin", ConnLimit: -1},
	{Name: "supapace_backup", Login: true, ConnLimit: -1},
}

var (
	presenceRoles = []string{"anon", "authenticated", "service_role", "authenticator", "dashboard_user",
		"supabase_admin", "supabase_read_only_user", "supabase_storage_admin"}
	presenceSchemas = []string{"auth", "extensions", "realtime", "storage"}
	aclSchemas      = []string{"auth", "realtime", "storage"}
	// reservedMembers: every membership these hold is compared with the baseline.
	reservedMembers = []string{"supabase_admin", "supabase_auth_admin", "supabase_storage_admin",
		"supabase_read_only_user", "supabase_replication_admin", "supabase_etl_admin", "supabase_privileged_role",
		"supabase_realtime_admin", "dashboard_user", "pgbouncer", "supapace_backup"}
	// grantedMembership is the membership bootstrap adds.
	grantedMembership = Membership{Member: "supapace_backup", Role: "pg_read_all_settings"}
	// dangerousRoles: every membership in these must be one of the baseline's.
	dangerousRoles = []string{"supabase_admin", "supabase_auth_admin", "supabase_storage_admin",
		"supabase_read_only_user", "supabase_realtime_admin", "supabase_replication_admin", "supabase_etl_admin",
		"dashboard_user", "pgbouncer", "authenticator", "pg_read_server_files", "pg_write_server_files",
		"pg_execute_server_program", "supapace_backup"}
	// settingsRoles: their role settings are compared with the baseline.
	settingsRoles = []string{"supabase_admin", "supabase_auth_admin", "supabase_storage_admin",
		"supabase_read_only_user", "supabase_replication_admin", "supabase_etl_admin", "dashboard_user",
		"pgbouncer", "supabase_privileged_role", "supabase_realtime_admin", "supapace_backup"}
	// servicePasswordRoles have no password after bootstrap.
	servicePasswordRoles = []string{"pgbouncer", "supabase_auth_admin", "supabase_storage_admin",
		"supabase_replication_admin", "supabase_etl_admin", "supabase_read_only_user"}
	authFunctions = []string{"email", "jwt", "role", "uid"}
)

const (
	maxRows     = 256 // rows examined per query; the queries' LIMIT is one more
	maxSettings = 1024
	maxFindings = 32 // findings per check; further ones are summarised
	maxDetail   = 256
)

// report collects findings.
type report struct {
	out []nodecfg.CheckResult
	n   map[string]int
}

func (r *report) add(name, format string, a ...any) {
	r.n[name]++
	switch {
	case r.n[name] == maxFindings+1:
		r.out = append(r.out, nodecfg.CheckResult{Name: name, Detail: "further findings omitted"})
	case r.n[name] <= maxFindings:
		r.out = append(r.out, nodecfg.CheckResult{Name: name, Detail: pgsock.Sanitize(fmt.Sprintf(format, a...), maxDetail)})
	}
}

// q quotes a value read from the server for a finding.
func q(s string) string { return strconv.Quote(pgsock.Sanitize(s, 64)) }

func deref[T any](p *T) (v T) {
	if p != nil {
		v = *p
	}
	return v
}

// Assert compares the cluster behind c with want and with renderedConf (the
// bytes of the platform's override file). It returns one finding (OK false)
// per difference, nothing when there is none; the error is reserved for a
// failed session or query. It reads with plain SQL only.
func Assert(ctx context.Context, c *pgx.Conn, want Baseline, renderedConf []byte) ([]nodecfg.CheckResult, error) {
	r := &report{n: map[string]int{}}
	for _, step := range []struct {
		name string
		fn   func(context.Context, *pgx.Conn, Baseline, *report) error
	}{
		{"roles", assertRoles}, {checkSuperuser, assertSuperusers}, {"memberships", assertMemberships},
		{checkRoleSettings, assertRoleSettings}, {checkServicePasswords, assertServicePasswords},
		{"schemas", assertSchemas}, {checkEventTriggers, assertEventTriggers},
		{checkAuthFunctions, assertAuthFunctions},
		{checkConfiguration, func(ctx context.Context, c *pgx.Conn, want Baseline, r *report) error {
			return assertConfiguration(ctx, c, want, renderedConf, r)
		}},
		{checkSourceFile, assertSourceFiles},
	} {
		if err := step.fn(ctx, c, want, r); err != nil {
			return nil, fmt.Errorf("bootstrap: assert %s: %w", step.name, err)
		}
	}
	return r.out, nil
}

// assertRoles: presence of the named roles; the seven attributes of every
// baseline role but postgres, and of the platform's roles.
func assertRoles(ctx context.Context, c *pgx.Conn, want Baseline, r *report) error {
	expect := slices.Clone(platformRoles)
	for _, b := range want.Roles {
		if b.Name != "postgres" {
			expect = append(expect, b)
		}
	}
	names := slices.Clone(presenceRoles)
	for _, e := range expect {
		names = append(names, e.Name)
	}
	got := map[string]Role{}
	err := querySQL(ctx, c, sqlRoles, []any{names}, func(rows pgx.Rows) error {
		var g Role
		if err := rows.Scan(&g.Name, &g.Super, &g.CreateRole, &g.CreateDB, &g.Replication, &g.BypassRLS,
			&g.Login, &g.ConnLimit); err != nil {
			return err
		}
		got[g.Name] = g
		return nil
	})
	if err != nil {
		return err
	}
	for _, n := range presenceRoles {
		if _, ok := got[n]; !ok {
			r.add(checkPresence, "role %s is absent", n)
		}
	}
	for _, e := range expect {
		g, ok := got[e.Name]
		if !ok {
			r.add(checkAttributes, "role %s is absent", e.Name)
		} else if g != e {
			r.add(checkAttributes, "role %s: attributes %s, expected %s", e.Name, attrs(g), attrs(e))
		}
	}
	return nil
}

func attrs(r Role) string {
	return fmt.Sprintf("super=%t createrole=%t createdb=%t replication=%t bypassrls=%t login=%t connlimit=%d",
		r.Super, r.CreateRole, r.CreateDB, r.Replication, r.BypassRLS, r.Login, r.ConnLimit)
}

// assertSuperusers: the set of superusers equals the baseline's.
func assertSuperusers(ctx context.Context, c *pgx.Conn, want Baseline, r *report) error {
	var expect, got []string
	for _, b := range want.Roles {
		if b.Super {
			expect = append(expect, b.Name)
		}
	}
	err := querySQL(ctx, c, sqlSuperusers, nil, func(rows pgx.Rows) error {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		got = append(got, n)
		return nil
	})
	if err != nil {
		return err
	}
	if len(got) > maxRows {
		r.add(checkSuperuser, "more than %d roles have the superuser attribute", maxRows)
		got = got[:maxRows]
	}
	for _, n := range got {
		if !slices.Contains(expect, n) {
			r.add(checkSuperuser, "role %s has the superuser attribute; the baseline does not list it", q(n))
		}
	}
	for _, n := range expect {
		if !slices.Contains(got, n) {
			r.add(checkSuperuser, "role %s lacks the superuser attribute of the baseline", n)
		}
	}
	return nil
}

// pairs returns a row scanner appending (member, role) rows to dst.
func pairs(dst *[]Membership) func(pgx.Rows) error {
	return func(rows pgx.Rows) error {
		var m Membership
		if err := rows.Scan(&m.Member, &m.Role); err != nil {
			return err
		}
		*dst = append(*dst, m)
		return nil
	}
}

// assertMemberships: the distinct memberships held by the reserved platform
// roles equal the baseline's plus the one bootstrap grants; every membership
// in a dangerous role is one of the baseline's.
func assertMemberships(ctx context.Context, c *pgx.Conn, want Baseline, r *report) error {
	expect := []Membership{grantedMembership}
	for _, m := range want.Memberships {
		if slices.Contains(reservedMembers, m.Member) {
			expect = append(expect, m)
		}
	}
	cmp := func(a, b Membership) int { return strings.Compare(a.Member+"\x00"+a.Role, b.Member+"\x00"+b.Role) }
	slices.SortFunc(expect, cmp)
	var got []Membership
	if err := querySQL(ctx, c, sqlMembersFrom, []any{reservedMembers}, pairs(&got)); err != nil {
		return err
	}
	if len(got) > maxRows {
		r.add(checkMembershipsReserved, "more than %d memberships held by platform roles", maxRows)
		got = got[:maxRows]
	}
	slices.SortFunc(got, cmp)
	if !slices.Equal(got, expect) {
		diff := false
		for _, g := range got {
			if !slices.Contains(expect, g) {
				diff = true
				r.add(checkMembershipsReserved, "%s is a member of %s; the baseline does not list it", g.Member, q(g.Role))
			}
		}
		for _, e := range expect {
			if !slices.Contains(got, e) {
				diff = true
				r.add(checkMembershipsReserved, "%s is not a member of %s as in the baseline", e.Member, e.Role)
			}
		}
		if !diff {
			r.add(checkMembershipsReserved, "a membership is listed more than once")
		}
	}
	got = nil
	if err := querySQL(ctx, c, sqlMembersOf, []any{dangerousRoles}, pairs(&got)); err != nil {
		return err
	}
	if len(got) > maxRows {
		r.add(checkMembershipsDanger, "more than %d memberships in platform roles", maxRows)
		got = got[:maxRows]
	}
	for _, g := range got {
		if !slices.Contains(want.Memberships, g) {
			r.add(checkMembershipsDanger, "%s is a member of %s; the platform did not grant it", q(g.Member), g.Role)
		}
	}
	return nil
}

// assertRoleSettings: the settings of the platform's roles equal the
// baseline's, and none has settings for a single database.
func assertRoleSettings(ctx context.Context, c *pgx.Conn, want Baseline, r *report) error {
	expect := map[string][]string{}
	for _, s := range want.RoleSettings {
		if slices.Contains(settingsRoles, s.Role) {
			expect[s.Role] = s.Settings
		}
	}
	seen := map[string]bool{}
	n := 0
	err := querySQL(ctx, c, sqlRoleSettings, []any{settingsRoles}, func(rows pgx.Rows) error {
		var role string
		var all bool
		var cfg []string
		if err := rows.Scan(&role, &all, &cfg); err != nil {
			return err
		}
		if n++; n > maxRows {
			return nil
		}
		switch {
		case !all:
			r.add(checkRoleSettings, "role %s has settings for one database", role)
		case !slices.Equal(slices.Sorted(slices.Values(cfg)), slices.Sorted(slices.Values(expect[role]))):
			r.add(checkRoleSettings, "settings of role %s differ from the baseline", role)
			seen[role] = true
		default:
			seen[role] = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	if n > maxRows {
		r.add(checkRoleSettings, "more than %d setting rows for platform roles", maxRows)
	}
	for _, role := range settingsRoles {
		if _, ok := expect[role]; ok && !seen[role] {
			r.add(checkRoleSettings, "role %s lacks the settings of the baseline", role)
		}
	}
	return nil
}

// assertServicePasswords: the service roles have no password.
func assertServicePasswords(ctx context.Context, c *pgx.Conn, _ Baseline, r *report) error {
	return querySQL(ctx, c, sqlServicePasswords, []any{servicePasswordRoles}, func(rows pgx.Rows) error {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		r.add(checkServicePasswords, "role %s has a password", n)
		return nil
	})
}

// assertSchemas: the four schemas exist; auth, storage and realtime have the
// baseline's owner and every baseline access entry, and no further entry
// granted by the baseline owner or a platform role.
func assertSchemas(ctx context.Context, c *pgx.Conn, want Baseline, r *report) error {
	got := map[string]Schema{}
	err := querySQL(ctx, c, sqlSchemas, []any{presenceSchemas}, func(rows pgx.Rows) error {
		var s Schema
		if err := rows.Scan(&s.Name, &s.Owner, &s.ACL); err != nil {
			return err
		}
		got[s.Name] = s
		return nil
	})
	if err != nil {
		return err
	}
	for _, n := range presenceSchemas {
		if _, ok := got[n]; !ok {
			r.add(checkPresence, "schema %s is absent", n)
		}
	}
	for _, b := range want.Schemas {
		if !slices.Contains(aclSchemas, b.Name) {
			continue
		}
		g, ok := got[b.Name]
		if !ok {
			r.add(checkSchemaACL, "schema %s is absent", b.Name)
			continue
		}
		if g.Owner != b.Owner {
			r.add(checkSchemaACL, "schema %s is owned by %s, not %s", b.Name, q(g.Owner), b.Owner)
		}
		for _, e := range b.ACL {
			if !slices.Contains(g.ACL, e) {
				r.add(checkSchemaACL, "schema %s: baseline access entry %s is missing or changed", b.Name, e)
			}
		}
		// Entries granted by others (a role holding a grant option) are
		// ordinary use; the baseline owner and the platform's roles grant
		// nothing after the baseline.
		for _, e := range g.ACL {
			if gr := aclGrantor(e); !slices.Contains(b.ACL, e) && (gr == b.Owner || slices.Contains(reservedMembers, gr)) {
				r.add(checkSchemaACL, "schema %s: access entry %s granted by %s is not in the baseline", b.Name, q(e), gr)
			}
		}
	}
	return nil
}

// aclGrantor returns the grantor of an access entry "grantee=privileges/grantor"
// as the server writes it, or "" when e is not in that form. A name is read
// from the front: in double quotes (a quote inside doubled) when it has a
// character other than a letter, digit or underscore, so a quoted name may
// itself contain "/", "=" or a platform role's name.
func aclGrantor(e string) string {
	_, rest := aclName(e)
	priv, gr, ok := strings.Cut(rest, "/")
	if !ok || !strings.HasPrefix(priv, "=") {
		return ""
	}
	name, tail := aclName(gr)
	if tail != "" {
		return ""
	}
	return name
}

// aclName reads the role name at the start of s, written as in an access
// entry, and returns it unquoted with the rest of s. An unterminated quoted
// name gives "" and "".
func aclName(s string) (name, rest string) {
	if !strings.HasPrefix(s, `"`) {
		i := strings.IndexAny(s, `=/"`)
		if i < 0 {
			return s, ""
		}
		return s[:i], s[i:]
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] != '"':
			b.WriteByte(s[i])
		case i+1 < len(s) && s[i+1] == '"':
			b.WriteByte('"')
			i++
		default:
			return b.String(), s[i+1:]
		}
	}
	return "", ""
}

// assertEventTriggers: the event triggers owned by a superuser are the
// baseline's (name, event, function).
func assertEventTriggers(ctx context.Context, c *pgx.Conn, want Baseline, r *report) error {
	var expect, got []string
	for _, e := range want.EventTriggers {
		expect = append(expect, e.Name+" "+e.Event+" "+e.Function)
	}
	err := querySQL(ctx, c, sqlEventTriggers, nil, func(rows pgx.Rows) error {
		var name, event, schema, fn string
		if err := rows.Scan(&name, &event, &schema, &fn); err != nil {
			return err
		}
		got = append(got, name+" "+event+" "+schema+"."+fn)
		return nil
	})
	if err != nil {
		return err
	}
	if len(got) > maxRows {
		r.add(checkEventTriggers, "more than %d event triggers owned by a superuser", maxRows)
		got = got[:maxRows]
	}
	for _, g := range got {
		if !slices.Contains(expect, g) {
			r.add(checkEventTriggers, "event trigger %s owned by a superuser is not in the baseline", q(g))
		}
	}
	for _, e := range expect {
		if !slices.Contains(got, e) {
			r.add(checkEventTriggers, "event trigger %s of the baseline is absent", e)
		}
	}
	return nil
}

// assertAuthFunctions: auth.uid, role, email and jwt exist, are owned by
// supabase_auth_admin, have the platform's body, are not security definer and
// may be executed by authenticated.
func assertAuthFunctions(ctx context.Context, c *pgx.Conn, _ Baseline, r *report) error {
	// The bodies are compared on the server and never read back, so an
	// oversized one costs nothing.
	bodies := make([]string, len(authFunctions))
	for i, n := range authFunctions {
		bodies[i] = authBodies[n]
	}
	seen := map[string]bool{}
	err := querySQL(ctx, c, sqlAuthFunctions, []any{authFunctions, bodies}, func(rows pgx.Rows) error {
		var name, owner string
		var sameBody *bool
		var secdef bool
		var exec *bool
		if err := rows.Scan(&name, &owner, &sameBody, &secdef, &exec); err != nil {
			return err
		}
		seen[name] = true
		if owner != "supabase_auth_admin" {
			r.add(checkAuthFunctions, "auth.%s is owned by %s", name, q(owner))
		}
		if !deref(sameBody) {
			r.add(checkAuthFunctions, "auth.%s has another body", name)
		}
		if secdef {
			r.add(checkAuthFunctions, "auth.%s is security definer", name)
		}
		if !deref(exec) {
			r.add(checkAuthFunctions, "authenticated may not execute auth.%s", name)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, n := range authFunctions {
		if !seen[n] {
			r.add(checkAuthFunctions, "auth.%s is absent", n)
		}
	}
	return nil
}

// assertConfiguration: every setting of the rendered override file is in
// force from that file, at its line. Values are not compared as text (the
// server reports them in base units); file and line identify them.
func assertConfiguration(ctx context.Context, c *pgx.Conn, want Baseline, rendered []byte, r *report) error {
	file := want.Files.IncludeDir + "/" + pgconf.OverrideFile
	lines := map[string]int{}
	var names []string
	for i, l := range strings.Split(string(rendered), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		name, _, ok := strings.Cut(l, " = ")
		if !ok || !nameRE.MatchString(strings.ReplaceAll(name, ".", "_")) || lines[name] != 0 {
			r.add(checkConfiguration, "line %d of the rendered file is not a setting", i+1)
			continue
		}
		lines[name] = i + 1
		names = append(names, name)
	}
	seen := map[string]bool{}
	err := querySQL(ctx, c, sqlSettingSources, []any{names}, func(rows pgx.Rows) error {
		var name, source string
		var src *string
		var line *int32
		if err := rows.Scan(&name, &source, &src, &line); err != nil {
			return err
		}
		seen[name] = true
		if source == "database" || source == "user" {
			return nil // a per-database or per-role value: ordinary use where the setting allows it
		}
		if deref(src) != file || int(deref(line)) != lines[name] {
			r.add(checkConfiguration, "%s is in force from %s line %d, not line %d of %s",
				name, q(deref(src)), deref(line), lines[name], pgconf.OverrideFile)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, n := range names {
		if !seen[n] {
			r.add(checkConfiguration, "%s is not a setting of the cluster", n)
		}
	}
	return nil
}

// assertSourceFiles: every setting from a configuration file comes from an
// allowed file; exactly the preload lists come from the command line;
// hba_file and ident_file are the pinned paths, set on the command line.
func assertSourceFiles(ctx context.Context, c *pgx.Conn, want Baseline, r *report) error {
	n := 0
	reported := map[string]bool{}
	err := querySQL(ctx, c, sqlConfigFileSettings, nil, func(rows pgx.Rows) error {
		var name string
		var src *string
		if err := rows.Scan(&name, &src); err != nil {
			return err
		}
		if n++; n <= maxSettings && !slices.Contains(allowedSourceFiles, deref(src)) {
			reported[name+"\x00"+deref(src)] = true
			r.add(checkSourceFile, "%s is in force from %s, not a platform or image file", q(name), q(deref(src)))
		}
		return nil
	})
	if err != nil {
		return err
	}
	if n > maxSettings {
		r.add(checkSourceFile, "more than %d settings from configuration files", maxSettings)
	}
	// Every line of every configuration file, also one for a setting this
	// session overrides at startup.
	n = 0
	err = querySQL(ctx, c, sqlFileSettings, nil, func(rows pgx.Rows) error {
		var name, src string
		if err := rows.Scan(&name, &src); err != nil {
			return err
		}
		if n++; n <= maxSettings && !slices.Contains(allowedSourceFiles, src) && !reported[name+"\x00"+src] {
			reported[name+"\x00"+src] = true
			r.add(checkSourceFile, "%s is set in %s, not a platform or image file", q(name), q(src))
		}
		return nil
	})
	if err != nil {
		return err
	}
	if n > maxSettings {
		r.add(checkSourceFile, "more than %d lines in configuration files", maxSettings)
	}
	var cl []string
	err = querySQL(ctx, c, sqlCommandLineSettings, nil, func(rows pgx.Rows) error {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		cl = append(cl, name)
		return nil
	})
	if err != nil {
		return err
	}
	if len(cl) > maxRows {
		r.add(checkSourceFile, "more than %d settings from the command line", maxRows)
		cl = cl[:maxRows]
	}
	for _, name := range cl {
		if !slices.Contains(commandLinePins, name) {
			r.add(checkSourceFile, "%s is set on the command line", q(name))
		}
	}
	for _, name := range commandLinePins {
		if !slices.Contains(cl, name) {
			r.add(checkSourceFile, "%s is not set on the command line", name)
		}
	}
	pinned := map[string]string{"hba_file": want.Files.HBAFile, "ident_file": want.Files.IdentFile}
	seen := map[string]bool{}
	err = querySQL(ctx, c, sqlPinnedFiles, nil, func(rows pgx.Rows) error {
		var name, setting, source string
		if err := rows.Scan(&name, &setting, &source); err != nil {
			return err
		}
		seen[name] = true
		if setting != pinned[name] || source != "override" {
			r.add(checkSourceFile, "%s is %s from %s, not %s from the command line", name, q(setting), q(source), pinned[name])
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range []string{"hba_file", "ident_file"} {
		if !seen[name] {
			r.add(checkSourceFile, "%s is not a setting of the cluster", name)
		}
	}
	return nil
}

// AssertHBA compares the rules in force (pg_hba_file_rules) with rendered,
// the platform's pg_hba.conf: the same rules at the same lines, none with an
// error. Findings and error as for Assert.
func AssertHBA(ctx context.Context, c *pgx.Conn, rendered []byte) ([]nodecfg.CheckResult, error) {
	r := &report{n: map[string]int{}}
	expect := map[int]string{}
	for i, l := range strings.Split(string(rendered), "\n") {
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
			expect[i+1] = renderedRule(f)
		}
	}
	got := map[int]string{}
	n := 0
	err := querySQL(ctx, c, sqlHBARules, nil, func(rows pgx.Rows) error {
		var line int32
		var typ, addr, mask, method, ruleErr *string
		var db, user, opts []string
		if err := rows.Scan(&line, &typ, &db, &user, &addr, &mask, &method, &opts, &ruleErr); err != nil {
			return err
		}
		if n++; n > maxRows {
			return nil
		}
		if ruleErr != nil {
			r.add(checkHBA, "line %d: %s", line, q(*ruleErr))
		}
		got[int(line)] = rule(deref(typ), strings.Join(db, ","), strings.Join(user, ","), deref(addr), deref(mask),
			deref(method), strings.Join(opts, ","))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: assert hba: %w", err)
	}
	if n > maxRows {
		r.add(checkHBA, "more than %d rules in force", maxRows)
	}
	for _, line := range slices.Sorted(maps.Keys(got)) {
		if want, ok := expect[line]; !ok {
			r.add(checkHBA, "line %d is not a rendered rule: %s", line, got[line])
		} else if got[line] != want {
			r.add(checkHBA, "line %d in force: %s; rendered: %s", line, got[line], want)
		}
	}
	for _, line := range slices.Sorted(maps.Keys(expect)) {
		if _, ok := got[line]; !ok {
			r.add(checkHBA, "rendered line %d is not in force: %s", line, expect[line])
		}
	}
	return r.out, nil
}

// rule is the comparable form of one pg_hba rule; an empty field is "-".
func rule(fields ...string) string {
	for i, f := range fields {
		if f == "" {
			fields[i] = "-"
		}
		fields[i] = pgsock.Sanitize(fields[i], 64)
	}
	return strings.Join(fields, " ")
}

// renderedRule turns a rendered line (type, database, user, [address,]
// method, options…) into the form of rule.
func renderedRule(f []string) string {
	typ, rest := f[0], f[1:]
	db, user, addr, mask := "", "", "", ""
	if len(rest) >= 2 {
		db, user, rest = rest[0], rest[1], rest[2:]
	}
	if typ != "local" && len(rest) > 0 {
		addr, rest = rest[0], rest[1:]
		if p, err := netip.ParsePrefix(addr); err == nil {
			addr = p.Addr().String()
			bits := 32
			if p.Addr().Is6() {
				bits = 128
			}
			mask = net.IP(net.CIDRMask(p.Bits(), bits)).String()
		}
	}
	method := ""
	if len(rest) > 0 {
		method, rest = rest[0], rest[1:]
	}
	return rule(typ, db, user, addr, mask, method, strings.Join(rest, ","))
}
