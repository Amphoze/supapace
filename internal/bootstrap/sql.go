package bootstrap

// Every statement the package sends is one of these constants; values travel
// as parameters. The one exception is a password verifier, which ALTER ROLE
// cannot take as a parameter: it is appended to a sqlPassword… prefix only
// after verifierStatement has checked it.

// First boot and re-key. A password statement also restores the login right,
// an unlimited connection limit and no expiry: on a fresh cluster the three
// roles already hold these in effect (an unset expiry reads infinity afterwards).
const (
	sqlPasswordSupabaseAdmin = "alter role supabase_admin with login connection limit -1 valid until 'infinity' password '"
	sqlPasswordPostgres      = "alter role postgres with login connection limit -1 valid until 'infinity' password '"
	sqlPasswordAuthenticator = "alter role authenticator with login connection limit -1 valid until 'infinity' password '"

	sqlRoleExists = "select exists (select from pg_catalog.pg_roles where rolname = $1)"

	sqlCreateRealtimeAdmin = "create role supabase_realtime_admin nologin noinherit"
	sqlCreateBackup        = "create role supapace_backup login nosuperuser noinherit nocreatedb nocreaterole noreplication"
	sqlGrantBackupSettings = "grant pg_read_all_settings to supapace_backup with inherit true"
	sqlGrantBackupFuncs    = "grant execute on function pg_catalog.pg_backup_start(text, boolean), " +
		"pg_catalog.pg_backup_stop(boolean), pg_catalog.pg_switch_wal(), " +
		"pg_catalog.pg_create_restore_point(text) to supapace_backup"

	// The image's settings, read before the first statement of Run.
	sqlPreload       = "select pg_catalog.current_setting('shared_preload_libraries'), pg_catalog.current_setting('session_preload_libraries')"
	sqlImageSettings = "select name::text from pg_catalog.pg_settings limit 1025"

	sqlSetRoleAuthAdmin = "set role supabase_auth_admin"
	sqlResetRole        = "reset role"
)

// The re-key's caller, after the re-key: the timeline, then the reset of the
// platform login role's statement statistics. The recovery read runs in a
// session of its own.
const (
	sqlInRecovery          = "select pg_catalog.pg_is_in_recovery()"
	sqlTimeline            = "select pg_catalog.substr(pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()), 1, 8)"
	sqlResetStatementStats = "select extensions.pg_stat_statements_reset('supabase_admin'::pg_catalog.regrole)"
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
	sqlMembersFrom = `select m.rolname::text, r.rolname::text, pg_catalog.bool_or(a.inherit_option) from pg_catalog.pg_auth_members a
	  join pg_catalog.pg_roles m on m.oid = a.member join pg_catalog.pg_roles r on r.oid = a.roleid
	  where m.rolname::text = any($1::text[]) group by 1, 2 order by 1, 2 limit 257`
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

// The pooler's manager role and its lookup helper. The manager's password
// statement sets every attribute of the role each time it is sent. The
// helper returns the SCRAM verifier of a login role for the pooler's lookup:
// never of a superuser, of one of the excluded names, of a pg_ role or of an
// expired role; the manager's own row is returned (the pooler reads it when a
// project is registered). It is security definer with an empty search_path,
// and every name in its body is qualified.
const (
	sqlPasswordPooler = "alter role supapace_pooler with login noinherit nosuperuser nocreatedb nocreaterole " +
		"noreplication nobypassrls connection limit -1 valid until 'infinity' password '"

	sqlCreatePooler       = "create role supapace_pooler"
	sqlPoolerSchema       = "create schema if not exists supapace_pooler authorization supabase_admin"
	sqlPoolerSchemaOwner  = "alter schema supapace_pooler owner to supabase_admin"
	sqlPoolerSchemaRevoke = "revoke all on schema supapace_pooler from public"
	sqlPoolerSchemaGrant  = "grant usage on schema supapace_pooler to supapace_pooler"
	sqlPoolerHelperOwner  = "alter function supapace_pooler.get_auth(text) owner to supabase_admin"
	sqlPoolerHelperRevoke = "revoke all on function supapace_pooler.get_auth(text) from public"
	sqlPoolerHelperGrant  = "grant execute on function supapace_pooler.get_auth(text) to supapace_pooler"
	sqlCreatePoolerHelper = "create or replace function supapace_pooler.get_auth(p_usename text) returns table (username text, password text)\n" +
		"  language sql stable security definer set search_path = '' as $f$" + bodyPoolerHelper + "$f$"
	bodyPoolerHelper = `
  select a.rolname::pg_catalog.text, a.rolpassword::pg_catalog.text from pg_catalog.pg_authid a
  where a.rolname = p_usename and a.rolcanlogin and not a.rolsuper
    and (a.rolvaliduntil is null or a.rolvaliduntil > pg_catalog.now())
    and a.rolpassword like 'SCRAM-SHA-256$%'
    and a.rolname not in ('supabase_admin','supabase_auth_admin','supabase_storage_admin',
      'supabase_realtime_admin','supabase_replication_admin','supabase_etl_admin','supabase_privileged_role',
      'dashboard_user','pgbouncer','authenticator','supapace_backup','anon','authenticated','service_role')
    and a.rolname !~ '^pg_' `
	// poolerHelperConfig is the helper's only SET clause as the catalog holds it.
	poolerHelperConfig = `search_path=""`
	// poolerHelperGrantees are the roles that may execute the helper.
	poolerHelperGrantees = "supabase_admin,supapace_pooler"

	// poolerSchemaACL is the helper schema's access list as defined.
	poolerSchemaACL = "{supabase_admin=UC/supabase_admin,supapace_pooler=U/supabase_admin}"

	// The read-back: the manager's seven compared attributes (super, createrole,
	// createdb, replication, bypassrls, login, an unlimited connection limit),
	// whether no membership names it (as member, granted role or grantor), the
	// helper schema's access list; and the helper's owner, body ($1), security
	// definer, SET clause ($2) and the roles that may execute it.
	sqlPoolerRole = `select r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls, r.rolcanlogin,
	  r.rolconnlimit operator(pg_catalog.=) -1,
	  not exists (select from pg_catalog.pg_auth_members m where m.roleid operator(pg_catalog.=) r.oid
	    or m.member operator(pg_catalog.=) r.oid or m.grantor operator(pg_catalog.=) r.oid),
	  (select n.nspacl::pg_catalog.text from pg_catalog.pg_namespace n where n.nspname operator(pg_catalog.=) 'supapace_pooler')
	  from pg_catalog.pg_roles r where r.rolname operator(pg_catalog.=) 'supapace_pooler' limit 2`
	sqlPoolerHelper = `select pg_catalog.pg_get_userbyid(p.proowner)::text, p.prosrc operator(pg_catalog.=) $1::text, p.prosecdef,
	  coalesce(p.proconfig operator(pg_catalog.=) array[$2::text], false),
	  pg_catalog.array_to_string(array(select distinct coalesce(r.rolname::text, 'public')
	    from pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) e
	    left join pg_catalog.pg_roles r on r.oid operator(pg_catalog.=) e.grantee
	    where e.privilege_type operator(pg_catalog.=) 'EXECUTE' order by 1), ',')
	  from pg_catalog.pg_proc p
	  where p.oid operator(pg_catalog.=) pg_catalog.to_regprocedure('supapace_pooler.get_auth(pg_catalog.text)')::pg_catalog.oid limit 2`
)

// The backup canary: a platform-owned schema and table of one row. The schema
// is taken over by supabase_admin each time, whoever made it; a table of that
// name another role made is dropped with everything on it and made again.
const (
	sqlCanarySchema       = "create schema if not exists supapace authorization supabase_admin"
	sqlCanarySchemaOwner  = "alter schema supapace owner to supabase_admin"
	sqlCanarySchemaRevoke = "revoke all on schema supapace from public"
	// The relation holding the canary's name: its kind, and whether
	// supabase_admin owns it.
	sqlCanaryRelation = `select coalesce(c.relkind::pg_catalog.text, ''),
	  coalesce(c.relowner operator(pg_catalog.=) 'supabase_admin'::pg_catalog.regrole::pg_catalog.oid, false), n.nspacl::pg_catalog.text
	  from pg_catalog.pg_namespace n left join pg_catalog.pg_class c
	    on c.oid operator(pg_catalog.=) pg_catalog.to_regclass('supapace._backup_canary')::pg_catalog.oid
	  where n.nspname operator(pg_catalog.=) 'supapace' limit 2`
	// canarySchemaACL is the canary schema's access list as defined.
	canarySchemaACL     = "{supabase_admin=UC/supabase_admin}"
	sqlCanaryDrop       = "drop table supapace._backup_canary cascade"
	sqlCanaryTable      = "create table if not exists supapace._backup_canary (id smallint primary key check (id = 1), written_at timestamptz not null)"
	sqlCanaryTableOwner = "alter table supapace._backup_canary owner to supabase_admin"
	sqlCanaryWrite      = "insert into supapace._backup_canary (id, written_at) values (1, pg_catalog.now()) " +
		"on conflict (id) do update set written_at = excluded.written_at"
)

// The re-key of one login, the read-only signal and restore points.
const (
	sqlPasswordReadOnly = "alter role supabase_read_only_user with login connection limit -1 valid until 'infinity' password '"

	sqlTerminateRole = "select pg_catalog.pg_terminate_backend(pid) from pg_catalog.pg_stat_activity " +
		"where usename = $1 and pid <> pg_catalog.pg_backend_pid()"
	sqlUnlinkReadOnlyLargeObjects = "select pg_catalog.lo_unlink(m.oid) from pg_catalog.pg_largeobject_metadata m where m.lomowner = " +
		"(select oid from pg_catalog.pg_roles where rolname = 'supabase_read_only_user') limit 10000"

	sqlReadOnlySignalOn  = "alter database postgres set default_transaction_read_only = on"
	sqlReadOnlySignalOff = "alter database postgres reset default_transaction_read_only"

	sqlRestorePoint = "select pg_catalog.pg_create_restore_point($1)::text"
)
