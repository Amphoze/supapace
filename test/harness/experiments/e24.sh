# shellcheck shell=sh disable=SC2154,SC2034 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables
# e24.sh — the re-key after a restore, end to end, with restored settings and
# restored content that must not delay, stop or observe it, written before the
# backup with the platform's own superuser session: role settings on the
# platform's login role (statement logging, debug output, audit, statement
# statistics, preloaded libraries, a search path, session bounds, a planner
# cost limit), database and system-file settings, event triggers (a login
# trigger among them), a password check, a scheduled job, a replaced built-in
# function, shadowing functions, an expired VALID UNTIL on two platform roles,
# and last the platform's three passwords changed. The backup is restored to
# the end of the archive and started by the agent's recovery start; then
# agent.Rekey gives the roles the next generation's passwords; then the
# agent's normal start.
#
# This tests the re-key as built (internal/agent recovery.go, internal/pgsock's
# startup list, internal/bootstrap's re-key): the recovery start's extension
# pins, the platform session's startup parameters, the password statements
# first, with the role attributes reset. The build has no other order or list,
# so none is asked. Each vector is shown live in the
# restored cluster by a control session that is not the platform's (no startup
# list, no password: the recovery start's own access files): the cost limit
# refuses its statements, its statements are logged and counted, the login
# trigger holds it.
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e24.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E24
R=e24rk000000000000001 U=700824
# What of a re-key session a log line or a captured statement may not show.
LEAK='SCRAM-SHA-256|alter role|pg_read_all_settings|pg_is_in_recovery|pg_walfile_name|supapace_backup|create role|pg_stat_statements_reset'

stage "project $R and its restored content"
ag_project "$R" "$U" 1 2048 1024
ajob "$R" stanza-create || die "stanza-create: $JSUM"
q() { asql "$R" "$1" >/dev/null || die "statement: $(echo "$1" | head -c 80)"; }
q 'create table public.marker (n int primary key)'
q 'insert into public.marker values (1)'
q 'create table public.x_log (t timestamptz default pg_catalog.clock_timestamp(), who text, ev text, q text)'
q 'create table public.x_spy (t timestamptz default pg_catalog.clock_timestamp(), pid int, who text, st text, q text)'
q 'grant all on public.x_log, public.x_spy to public'
q 'create role x_root superuser login'
q 'create role tenant_r login'
q "$(
	cat <<'EOF'
create function public.x_login() returns event_trigger language plpgsql as $f$
begin
  if session_user = 'supabase_admin' then
    insert into public.x_log(who, ev, q) values (session_user, 'login', current_query());
    perform pg_sleep(20);
    raise exception 'restored login trigger refuses %', session_user;
  end if;
end $f$
EOF
)"
q 'create event trigger x_login on login execute function public.x_login()'
q "create function public.x_ddl() returns event_trigger language plpgsql as \$f\$ begin insert into public.x_log(who, ev, q) values (session_user, tg_event || ' ' || tg_tag, current_query()); end \$f\$"
q 'create event trigger x_ddl_s on ddl_command_start execute function public.x_ddl()'
q 'create event trigger x_ddl_e on ddl_command_end execute function public.x_ddl()'
q 'create event trigger x_drop on sql_drop execute function public.x_ddl()'
q 'create extension if not exists pg_cron'
q "select cron.schedule_in_database('x_spy', '1 seconds', \$c\$insert into public.x_spy(pid, who, st, q) select pid, usename::text, state, query from pg_catalog.pg_stat_activity where usename = 'supabase_admin' and pid <> pg_catalog.pg_backend_pid()\$c\$, 'postgres', 'x_root')"
q 'create extension if not exists pg_tle'
q "$(
	cat <<'EOF'
create function public.x_pass(username text, shadow_pass text, password_types pgtle.password_types, validuntil_time timestamptz, validuntil_null boolean)
returns void language plpgsql as $f$
begin
  insert into public.x_log(who, ev, q) values (username, 'passcheck', shadow_pass);
  perform pg_catalog.set_config('log_statement', 'all', false);
  perform pg_catalog.set_config('log_min_duration_statement', '0', false);
end $f$
EOF
)"
q "select pgtle.register_feature('public.x_pass', 'passcheck')"
q 'create role x_auditor'
q 'grant select on pg_catalog.pg_authid to x_auditor'
q 'grant select on pg_catalog.pg_roles to x_auditor'
q "create function public.pg_is_in_recovery() returns boolean language sql as 'select false'"
q "create function pg_catalog.pg_walfile_name(text) returns text language sql as 'select ''FFFFFFFF'''"
q "$(
	cat <<'EOF'
create function public.x_flip() returns boolean language plpgsql as $f$
begin
  begin
    perform pg_catalog.set_config('log_statement', 'all', false);
    perform pg_catalog.set_config('log_min_duration_statement', '0', false);
  exception when others then null;
  end;
  begin perform pg_catalog.pg_is_wal_replay_paused(); return true; exception when others then return false; end;
end $f$
EOF
)"
q "create or replace function pg_catalog.pg_is_in_recovery() returns boolean language sql as 'select public.x_flip()'"
q 'insert into public.marker values (2)'
for kv in log_statement=all log_min_duration_statement=0 log_min_duration_sample=0 log_statement_sample_rate=1 \
	log_duration=on log_transaction_sample_rate=1 debug_print_parse=on debug_print_rewritten=on debug_print_plan=on \
	log_min_error_statement=debug5 log_min_messages=debug5 pgaudit.log=all pgaudit.role=x_auditor auto_explain.log_min_duration=0 \
	session_preload_libraries=auto_explain pg_stat_statements.track_utility=on pg_stat_statements.track=all track_activities=on \
	search_path=public,pg_catalog statement_timeout=1ms default_transaction_read_only=on plan_filter.statement_cost_limit=0.001; do
	q "alter role supabase_admin set ${kv%%=*} = '${kv#*=}'"
done
for kv in log_statement=all log_min_duration_statement=0 session_preload_libraries=auto_explain \
	auto_explain.log_min_duration=0 pgaudit.log=all debug_print_parse=on log_transaction_sample_rate=1; do
	q "alter database postgres set ${kv%%=*} = '${kv#*=}'"
done
for kv in log_statement=all log_min_duration_statement=0 debug_print_parse=on log_min_error_statement=debug1 \
	log_min_messages=debug1 log_transaction_sample_rate=1 pgaudit.log=all session_preload_libraries=auto_explain \
	auto_explain.log_min_duration=0 shared_preload_libraries=auto_explain track_activities=on pgtle.enable_password_check=on; do
	q "alter system set ${kv%%=*} = '${kv#*=}'"
done
q 'select pg_catalog.pg_reload_conf()'
# Last, in one session (after it the platform's login is refused): the expiry and the passwords.
q "alter role authenticator valid until '2000-01-01'; alter role supabase_admin valid until '2000-01-01'; alter role supabase_admin password 'changed-in-the-restored-content-1'; alter role postgres password 'changed-in-the-restored-content-2'; alter role authenticator password 'changed-in-the-restored-content-3'"
s=0
asql "$R" 'select 1' >/dev/null 2>&1 || s=$?
control "the platform's password no longer logs in to the source" "$([ "$s" != 0 ] && echo 1 || echo 0)" "exit $s"
ajob "$R" backup || die "backup: $JSUM"
SET=$(echo "$JSUM" | sed -n 's/^label \([^ ]*\) .*/\1/p')
jsay "$R" backup
ag stop "$R"
ajob "$R" push || die "push: $JSUM"

stage "restore to the end of the archive; the agent's recovery start"
restore_set "$R" "$SET" || die "restore"
arecover "$R" -timeline latest || die "the recovery start did not promote"
n=$(atsql "$R" "select count(*) from pg_catalog.pg_db_role_setting, pg_catalog.unnest(setconfig) where setrole = 'supabase_admin'::pg_catalog.regrole")
control "the restored role settings are there" "$([ "$n" -ge 22 ] && echo 1 || echo 0)" "$n settings on the platform's login role"
vu=$(atsql "$R" "select pg_catalog.string_agg(rolname || '=' || coalesce(rolvaliduntil::text, '-'), ' ' order by rolname) from pg_catalog.pg_roles where rolname in ('authenticator', 'supabase_admin')")
control "the restored VALID UNTIL is there" "$(echo "$vu" | grep -c 2000-01-01 | sed 's/^2$/1/')" "$vu"

stage "controls: a session that is not the platform's sees every vector"
t0=$(date +%s)
# Its packet undoes the restored bound, cost limit and read-only default, so that none cuts the trigger short.
b=$(ag sql -bare -set statement_timeout=0 -set plan_filter.statement_cost_limit=0 -set default_transaction_read_only=off "$R" 'select 1' 2>&1) || :
t1=$(($(date +%s) - t0))
control "the restored login trigger holds such a session and refuses it" \
	"$([ "$t1" -ge 15 ] && echo "$b" | grep -q 'login trigger refuses' && echo 1 || echo 0)" "$t1 s: $(echo "$b" | tail -1 | sed 's/.*): //' | cut -c1-120)"

stage "the re-key"
start=$(atsql "$R" 'select pg_catalog.clock_timestamp()::text')
LOG1=$(docker logs "pg-$R" 2>&1 | wc -l)
t0=$(date +%s)
rk=$(ag rekey "$R" 2>&1) || die "re-key: $rk"
say "  $rk ($(($(date +%s) - t0)) s)"
sleep 3
lines=$(docker logs "pg-$R" 2>&1 | tail -n +"$((LOG1 + 1))" | grep -E "$LEAK" | grep -vE 'x_spy|cron' || :)
check "the server log holds none of the re-key's statements or verifiers" "$(printf '%s\n' "$lines" | grep -c . || :) lines" test -z "$lines"
x=$(atsql "$R" "select count(*) from public.x_log where t >= '$start'::timestamptz")
check "the restored capture tables hold nothing of it (statement triggers, the password check)" "x_log $x rows since the re-key" test "$x" = 0
p=$(atsql "$R" "select count(*) from extensions.pg_stat_statements where query ~* '$LEAK'")
check "the statement statistics hold none of its statements" "$p rows" test "$p" = 0
y=$(atsql "$R" "select count(*) from public.x_spy where t >= '$start'::timestamptz")
res RECORDED "the scheduled job's copy of the activity view" "$y rows since the re-key (the recovery start runs no scheduler)"

stage "controls: the restored settings act on a session without the platform's list"
# Only event_triggers=off and statement_timeout=0 in its packet: the login trigger lets it in and the
# restored 1 ms bound does not cut its statements short.
ET="-set event_triggers=off -set statement_timeout=0"
# shellcheck disable=SC2086 # one option and its value
b=$(ag sql -bare $ET "$R" "select count(*) from public.marker" 2>&1) || :
control "the restored cost limit refuses its statements" "$(echo "$b" | grep -q 'plan cost limit exceeded' && echo 1 || echo 0)" "$(echo "$b" | tail -1 | cut -c1-100)"
LOG2=$(docker logs "pg-$R" 2>&1 | wc -l)
# shellcheck disable=SC2086 # options and their values
ag sql -bare $ET -set plan_filter.statement_cost_limit=0 "$R" "select 1 as e24_control_statement" >/dev/null 2>&1 || :
sleep 1
lc=$(docker logs "pg-$R" 2>&1 | tail -n +"$((LOG2 + 1))" | grep -c e24_control_statement || :)
control "its statement is logged by the restored settings" "$([ "$lc" -ge 1 ] && echo 1 || echo 0)" "$lc lines"
sc=$(atsql "$R" "select count(*) from extensions.pg_stat_statements where query ~ 'e24_control_statement'")
control "and counted in the statement statistics" "$([ "$sc" -ge 1 ] && echo 1 || echo 0)" "$sc rows"

stage "the normal start, the next generation's passwords"
ag stop "$R"
ag start "$R" || die "the normal start after the re-key"
m=$(asql "$R" "select pg_catalog.string_agg(n::text, ',' order by n) from public.marker")
check "the agent's SCRAM login with the new generation works; the restored rows are there" "markers $m" test "$m" = 1,2
s=0
ag sql -gen 1 "$R" 'select 1' >/dev/null 2>&1 || s=$?
check "the previous generation's password is refused" "exit $s" test "$s" = 1
vu=$(asql "$R" "select pg_catalog.string_agg(rolname || '=' || coalesce(rolvaliduntil::text, '-'), ' ' order by rolname) from pg_catalog.pg_roles where rolname in ('authenticator', 'supabase_admin')")
check "the re-key reset VALID UNTIL on both roles" "$vu" test "$vu" = "authenticator=infinity supabase_admin=infinity"
ajob "$R" check -tl 1,2 || :
check "the backup role's check succeeds under the restored database settings" "$(echo "$JSUM" | cut -c1-80)" sh -c "echo \"\$1\" | grep -q '^ok;'" sh "$JSUM"
asql "$R" "alter role tenant_r password 'tenant-own-password'" >/dev/null 2>&1 || :
pc=$(asql "$R" "select count(*) from public.x_log where ev = 'passcheck'")
control "in the normal start the restored password check is live (a tenant role's password reaches it)" "$([ "$pc" -ge 1 ] && echo 1 || echo 0)" "$pc rows"

verdict E24 "as built (recovery-start pins, the platform session's startup list, the password statements first with the role attributes reset) the re-key completes against every restored vector, nothing of it reaches the server log, the statement statistics or the restored capture tables, the next generation's SCRAM login works and the previous is refused"
