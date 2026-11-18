package bootstrap

// Every statement the package sends is one of these constants; values travel
// as parameters. The one exception is a password verifier, which ALTER ROLE
// cannot take as a parameter: it is appended to a sqlPassword… prefix only
// after verifierStatement has checked it.

// First boot.
const (
	sqlPasswordSupabaseAdmin = "alter role supabase_admin password '"
	sqlPasswordPostgres      = "alter role postgres password '"
	sqlPasswordAuthenticator = "alter role authenticator password '"

	sqlRoleExists = "select exists (select from pg_catalog.pg_roles where rolname = $1)"

	sqlCreateRealtimeAdmin = "create role supabase_realtime_admin nologin noinherit"
	sqlCreateBackup        = "create role supapace_backup login nosuperuser noinherit nocreatedb nocreaterole noreplication"
	sqlGrantBackupSettings = "grant pg_read_all_settings to supapace_backup"
	sqlGrantBackupFuncs    = "grant execute on function pg_catalog.pg_backup_start(text, boolean), " +
		"pg_catalog.pg_backup_stop(boolean), pg_catalog.pg_switch_wal(), " +
		"pg_catalog.pg_create_restore_point(text) to supapace_backup"

	sqlSetRoleAuthAdmin = "set role supabase_auth_admin"
	sqlResetRole        = "reset role"
)

// The auth helper functions. Their bodies run under the caller's search_path,
// so every function, type and operator in them is written pg_catalog-qualified,
// and no construct that looks an operator up by name (nullif, IN, a simple
// CASE) is used: an empty setting is turned into NULL with a searched CASE on
// operator(pg_catalog.=). coalesce looks up no operator. None is security
// definer and none has a SET clause, so they stay inlinable. Each reads the
// per-claim setting first, then the JSON claims.
const (
	bodyUID = `
  select coalesce(
    case when pg_catalog.current_setting('request.jwt.claim.sub', true) operator(pg_catalog.=) '' then null
         else pg_catalog.current_setting('request.jwt.claim.sub', true) end,
    (case when pg_catalog.current_setting('request.jwt.claims', true) operator(pg_catalog.=) '' then null
          else pg_catalog.current_setting('request.jwt.claims', true) end)::pg_catalog.jsonb
      operator(pg_catalog.->>) 'sub')::pg_catalog.uuid `
	bodyRole = `
  select coalesce(
    case when pg_catalog.current_setting('request.jwt.claim.role', true) operator(pg_catalog.=) '' then null
         else pg_catalog.current_setting('request.jwt.claim.role', true) end,
    (case when pg_catalog.current_setting('request.jwt.claims', true) operator(pg_catalog.=) '' then null
          else pg_catalog.current_setting('request.jwt.claims', true) end)::pg_catalog.jsonb
      operator(pg_catalog.->>) 'role')::pg_catalog.text `
	bodyEmail = `
  select coalesce(
    case when pg_catalog.current_setting('request.jwt.claim.email', true) operator(pg_catalog.=) '' then null
         else pg_catalog.current_setting('request.jwt.claim.email', true) end,
    (case when pg_catalog.current_setting('request.jwt.claims', true) operator(pg_catalog.=) '' then null
          else pg_catalog.current_setting('request.jwt.claims', true) end)::pg_catalog.jsonb
      operator(pg_catalog.->>) 'email')::pg_catalog.text `
	bodyJWT = `
  select coalesce(
    case when pg_catalog.current_setting('request.jwt.claim', true) operator(pg_catalog.=) '' then null
         else pg_catalog.current_setting('request.jwt.claim', true) end,
    case when pg_catalog.current_setting('request.jwt.claims', true) operator(pg_catalog.=) '' then null
         else pg_catalog.current_setting('request.jwt.claims', true) end)::pg_catalog.jsonb `

	sqlCreateUID   = "create or replace function auth.uid() returns pg_catalog.uuid language sql stable as $$" + bodyUID + "$$"
	sqlCreateRole  = "create or replace function auth.role() returns pg_catalog.text language sql stable as $$" + bodyRole + "$$"
	sqlCreateEmail = "create or replace function auth.email() returns pg_catalog.text language sql stable as $$" + bodyEmail + "$$"
	sqlCreateJWT   = "create or replace function auth.jwt() returns pg_catalog.jsonb language sql stable as $$" + bodyJWT + "$$"
)

// authBodies maps each auth function to the body the platform defines.
var authBodies = map[string]string{"uid": bodyUID, "role": bodyRole, "email": bodyEmail, "jwt": bodyJWT}

// The assertion: plain, schema-qualified reads, each bounded by a LIMIT one
// above what is examined (maxRows), so a cluster holding more rows than that
// is reported, not read in full.
const (
	sqlRoles = `select rolname::text, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls,
	  rolcanlogin, rolconnlimit from pg_catalog.pg_roles where rolname::text = any($1::text[]) order by 1 limit 257`
	sqlSuperusers  = "select rolname::text from pg_catalog.pg_roles where rolsuper order by 1 limit 257"
	sqlMembersFrom = `select distinct m.rolname::text, r.rolname::text from pg_catalog.pg_auth_members a
	  join pg_catalog.pg_roles m on m.oid = a.member join pg_catalog.pg_roles r on r.oid = a.roleid
	  where m.rolname::text = any($1::text[]) order by 1, 2 limit 257`
	sqlMembersOf = `select distinct m.rolname::text, r.rolname::text from pg_catalog.pg_auth_members a
	  join pg_catalog.pg_roles m on m.oid = a.member join pg_catalog.pg_roles r on r.oid = a.roleid
	  where r.rolname::text = any($1::text[]) order by 1, 2 limit 257`
	sqlRoleSettings = `select r.rolname::text, s.setdatabase = 0, s.setconfig from pg_catalog.pg_db_role_setting s
	  join pg_catalog.pg_roles r on r.oid = s.setrole where r.rolname::text = any($1::text[]) order by 1, 2 limit 257`
	sqlServicePasswords = `select rolname::text from pg_catalog.pg_authid
	  where rolname::text = any($1::text[]) and rolpassword is not null order by 1 limit 257`
	sqlSchemas = `select nspname::text, pg_catalog.pg_get_userbyid(nspowner)::text, nspacl::text[]
	  from pg_catalog.pg_namespace where nspname::text = any($1::text[]) order by 1 limit 257`
	sqlEventTriggers = `select e.evtname::text, e.evtevent::text, n.nspname::text, p.proname::text
	  from pg_catalog.pg_event_trigger e join pg_catalog.pg_roles r on r.oid = e.evtowner
	  join pg_catalog.pg_proc p on p.oid = e.evtfoid join pg_catalog.pg_namespace n on n.oid = p.pronamespace
	  where r.rolsuper and not exists (select from pg_catalog.pg_depend d
	    where d.classid = 'pg_catalog.pg_event_trigger'::pg_catalog.regclass and d.objid = e.oid and d.deptype = 'e')
	  order by 1 limit 257`
	sqlAuthFunctions = `select p.proname::text, pg_catalog.pg_get_userbyid(p.proowner)::text,
	  p.prosrc operator(pg_catalog.=) ($2::text[])[pg_catalog.array_position($1::text[], p.proname::text)], p.prosecdef,
	  pg_catalog.has_function_privilege((select oid from pg_catalog.pg_roles where rolname = 'authenticated'), p.oid, 'EXECUTE')
	  from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
	  where n.nspname = 'auth' and p.pronargs = 0 and p.proname::text = any($1::text[]) order by 1 limit 257`
	sqlSettingSources = `select name::text, source::text, sourcefile::text, sourceline from pg_catalog.pg_settings
	  where name::text = any($1::text[]) order by 1 limit 257`
	sqlConfigFileSettings = `select name::text, sourcefile::text from pg_catalog.pg_settings
	  where source = 'configuration file' order by 1 limit 1025`
	// pg_file_settings re-reads the files: it lists every line, including
	// those the platform session overrides at startup.
	sqlFileSettings = `select coalesce(name, '')::text, coalesce(sourcefile, '')::text from pg_catalog.pg_file_settings
	  order by 2, 1 limit 1025`
	sqlCommandLineSettings = "select name::text from pg_catalog.pg_settings where source = 'command line' order by 1 limit 257"
	sqlPinnedFiles         = `select name::text, setting::text, source::text from pg_catalog.pg_settings
	  where name in ('hba_file', 'ident_file') order by 1`
	sqlHBARules = `select line_number, type::text, database::text[], user_name::text[], address::text, netmask::text,
	  auth_method::text, options::text[], error::text from pg_catalog.pg_hba_file_rules order by line_number limit 257`
)
