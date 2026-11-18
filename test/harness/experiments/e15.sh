#!/bin/sh
# shellcheck disable=SC2154 # R_<id> and N_<id> are set by try() through eval
# e15.sh - login event triggers on the pinned supabase/postgres image (Postgres 17)
# against platform sessions. Can the non-superuser role postgres create an ON login
# event trigger under supautils? Does it fire for supabase_admin? Does the startup
# parameter event_triggers=off (sent as its own startup-packet key, as a driver's
# runtime parameters are) keep a superuser session silent, and is search_path
# from the startup packet already in force when a trigger body runs? Also the
# libpq-style form options='-c event_triggers=off'.
#
# Sessions are opened by a small raw protocol-3 client (bash /dev/tcp inside the
# cluster container, trust on 127.0.0.1 under the image's own pg_hba), so every
# parameter travels in the startup packet itself. The trigger logs current_user,
# search_path, event_triggers and application_name into a table.
#
# Run on the bare test node: docker exec -i <node> sh -s < e15.sh
set -eu

IMG=supabase/postgres@sha256:b3bfedb107413abb3b8cb0d0874b0414a1dceb3d55bc0c778de6ad22d1f7dc86
REF=e15exp00000000000000
PUID=700615
PROJ=/var/lib/supapace/projects/$REF
REND=/var/lib/supapace/platform/projects/$REF
PG=pg-$REF

say() { echo "e15: $*"; }
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

cleanup() {
	docker rm -f "$PG" >/dev/null 2>&1 || :
	rm -rf "$PROJ" "$REND"
}
# A step that fails under set -e still ends with a VERDICT line.
STEP=start
step() { STEP=$*; }
on_exit() {
	rc=$?
	cleanup
	[ "$rc" = 0 ] || [ -n "${DONE:-}" ] || echo "VERDICT E15: unknown — step '$STEP' failed (exit $rc)"
}
trap on_exit EXIT
# A killed run still ends with its VERDICT line and cleans up.
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
cleanup

docker image inspect "$IMG" >/dev/null || { say "image $IMG not loaded"; exit 2; }
mountpoint -q /var/lib/supapace/projects || { say "projects mount absent"; exit 2; }

step "render and start"
mkdir -p "$PROJ/data" "$PROJ/sock" "$REND/image"
chown "$PUID:$PUID" "$PROJ" "$PROJ/data" "$PROJ/sock"
chmod 0700 "$PROJ" "$PROJ/data" "$PROJ/sock"
chmod 0755 /var/lib/supapace/platform /var/lib/supapace/platform/projects "$REND"
cid=$(docker create --network none "$IMG")
docker cp -q "$cid:/etc/passwd" "$REND/image/"
docker cp -q "$cid:/etc/group" "$REND/image/"
docker cp -q "$cid:/etc/postgresql-custom/supautils.conf" "$REND/image/"
docker rm "$cid" >/dev/null
sed "s/^postgres:x:[0-9]*:[0-9]*:/postgres:x:$PUID:$PUID:/" "$REND/image/passwd" >"$REND/passwd"
sed "s/^postgres:x:[0-9]*:/postgres:x:$PUID:/" "$REND/image/group" >"$REND/group"
# supautils.conf: the image's file, and a variant listing supapace_backup as a reserved role.
cp "$REND/image/supautils.conf" "$REND/supautils.conf"
sed "s/^\(supautils.reserved_roles = '.*\)'\$/\1, supapace_backup'/" "$REND/image/supautils.conf" >"$REND/supautils-reserved.conf"
rnd 32 >"$REND/pgsodium_root.key"
chown "$PUID:$PUID" "$REND/pgsodium_root.key"
chmod 0400 "$REND/pgsodium_root.key"
chmod 0444 "$REND/passwd" "$REND/group" "$REND/supautils.conf" "$REND/supautils-reserved.conf"

start() { # supautils file
	docker run -d --name "$PG" --hostname "$PG" --network none --user "$PUID:$PUID" \
		--cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
		--memory 512m --memory-swap 512m --cpus 1 --pids-limit 512 --shm-size 64m --ulimit core=0 \
		-e POSTGRES_PASSWORD="$(rnd 32)" \
		-v "$PROJ/data:/var/lib/postgresql/data" -v "$PROJ/sock:/var/run/postgresql" \
		-v "$REND/passwd:/etc/passwd:ro" -v "$REND/group:/etc/group:ro" \
		-v "$REND/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro" \
		-v "$1:/etc/postgresql-custom/supautils.conf:ro" \
		--label supapace.role=cluster --label supapace.ref=$REF --label supapace.test=1 "$IMG" >/dev/null
	i=0
	until docker logs "$PG" 2>&1 | grep -qE 'init process complete|Skipping initialization' &&
		docker exec "$PG" pg_isready -q -h /var/run/postgresql; do
		[ "$(docker inspect -f '{{.State.Running}}' "$PG")" = true ] || { docker logs --tail 30 "$PG"; exit 1; }
		i=$((i + 1))
		[ "$i" -lt 600 ] || { say "not ready"; exit 1; }
		sleep 0.5
	done
}
start "$REND/supautils.conf"

# The startup-packet parameters a platform session sends, one name=value per line;
# superuser sessions add event_triggers=off. This is the single definition: the raw
# sessions get them as startup keys, the psql bookkeeping sessions as PGOPTIONS.
LIST='search_path=pg_catalog,pg_temp
role=none
default_transaction_read_only=off
statement_timeout=0
lock_timeout=0
idle_in_transaction_session_timeout=0
idle_session_timeout=0
transaction_timeout=0
local_preload_libraries=
exit_on_error=off
default_transaction_isolation=read committed
default_transaction_deferrable=off
standard_conforming_strings=on
backslash_quote=safe_encoding
synchronous_commit=on
client_encoding=UTF8
DateStyle=ISO, MDY
TimeZone=UTC
IntervalStyle=postgres
bytea_output=hex
extra_float_digits=1
quote_all_identifiers=off
transform_null_equals=off
row_security=on
check_function_bodies=on
default_tablespace=
temp_tablespaces=
client_min_messages=notice'
NLIST=$(printf '%s\n' "$LIST" | grep -c .)
OPTS=$(printf '%s\n' "$LIST" | sed 's/ /\\ /g;s/^/-c /' | tr '\n' ' ')
# Bookkeeping sessions carry the list, so settings under test never reach them; they
# are not counted (their application_name is bookkeeping).
asql() { docker exec -e PGOPTIONS="$OPTS -c event_triggers=off" -e PGAPPNAME=bookkeeping "$PG" \
	psql -X -At -v ON_ERROR_STOP=1 -h /var/run/postgresql -U supabase_admin -d postgres -c "$1"; }
tsql() { docker exec -e PGOPTIONS="$OPTS" -e PGAPPNAME=bookkeeping "$PG" psql -X -At -h /var/run/postgresql -U postgres -d postgres -c "$1" 2>&1 |
	grep -E '^(ERROR|DETAIL|[A-Z]+( [A-Z]+)*$)' | tr '\n' ' ' | sed 's/ *$//'; }

# Raw client: user, application_name, then key value pairs for the startup packet; the
# query (env E15Q) returns one text value between ROW: and :END.
# Prints "ok <value>" or "error <SQLSTATE> <message>", plus "(warning: …)" if the server warned.
# shellcheck disable=SC2016 # bash code, expanded inside the container
RAW='
# A server that refuses the login may close before the query is written: keep reading.
trap "" PIPE
u=$1 app=$2; shift 2
i32() { printf "$(printf "\\%03o\\%03o\\%03o\\%03o" $(($1>>24&255)) $(($1>>16&255)) $(($1>>8&255)) $(($1&255)))"; }
set -- user "$u" database postgres application_name "$app" "$@"
n=9
for a; do n=$((n + ${#a} + 1)); done
q=$E15Q
exec 3<>/dev/tcp/127.0.0.1/5432
{ i32 $n; i32 196608; printf "%s\0" "$@"; printf "\0"
  printf Q; i32 $((4 + ${#q} + 1)); printf "%s\0" "$q"; printf X; i32 4; } >&3 2>/dev/null
out=$(timeout 5 cat <&3 | tr -c " -~" ".")
row=$(printf "%s" "$out" | grep -o "ROW:[ -~]*:END" | head -1)
err=$(printf "%s" "$out" | grep -o "S\(ERROR\|FATAL\)\.V[A-Z]*\.C[0-9A-Z]\{5\}\.M[^.]*" | head -1 | sed "s/^S[A-Z]*\.V[A-Z]*\.//")
wrn=$(printf "%s" "$out" | grep -o "SWARNING\.V[A-Z]*\.C[0-9A-Z]\{5\}\.M[^.]*" | head -1 | sed "s/^.*\.M//")
if [ -n "$row" ]; then echo "ok ${row#ROW:}"; else echo "error ${err:-no reply}"; fi | sed "s/:END\$//"
[ -z "$wrn" ] || echo "(warning: $wrn)"
'
Q1="select 'ROW:u='||current_user||';sp='||current_setting('search_path')||';et='||current_setting('event_triggers')||':END'"
Q=
conn() { docker exec -e "E15Q=${Q:-$Q1}" "$PG" bash -c "$RAW" raw "$@" | sed 's/^error C\([0-9A-Z]*\)\.M/error \1 /' | tr '\n' ' ' | sed 's/ *$//'; }
fired() { asql "select count(*) from public.e15_log where app = '$1'"; }
logged() { asql "select coalesce(string_agg(trg||': u='||usr||' sp='||sp||' et='||et, ' | '),'-') from public.e15_log where app = '$1'"; }
# One session: id, user, startup parameters. Prints the session result and the trigger rows.
try() {
	id=$1 u=$2
	shift 2
	r=$(conn "$u" "$id" "$@")
	n=$(fired "$id")
	say "$id  user=$u params=[$*] -> $r; trigger rows: $n ($(logged "$id"))"
	eval "R_$id=\$r N_$id=\$n"
}

step "part 1: tenant login trigger"
# --- the tenant creates a login trigger ---
asql "create table public.e15_log(at timestamptz default clock_timestamp(), trg text, usr text, sess text, sp text, et text, app text); grant insert on public.e15_log to public" >/dev/null
r=$(tsql "create function public.e15_on_login() returns event_trigger language plpgsql as \$\$ begin
  insert into public.e15_log(trg, usr, sess, sp, et, app) values (tg_tag || '/' || (select pg_get_userbyid(evtowner) from pg_event_trigger where evtname = 'e15_tenant_login'),
    current_user, session_user, current_setting('search_path'), current_setting('event_triggers'), current_setting('application_name'));
  if current_setting('application_name') like 'boom%' then raise exception 'e15 tenant login trigger refuses this session'; end if;
end \$\$")
say "tenant: create function -> $r"
r=$(tsql "create event trigger e15_tenant_login on login execute function public.e15_on_login()")
say "tenant: create event trigger ... on login -> $r"
CREATED=0
[ "$r" = "CREATE EVENT TRIGGER" ] && CREATED=1
say "event triggers now: $(asql "select string_agg(e.evtname||' event='||e.evtevent||' owner='||pg_get_userbyid(e.evtowner)||' owner_super='||r.rolsuper||' enabled='||e.evtenabled::text||' fn_owner='||pg_get_userbyid(p.proowner), '; ') from pg_event_trigger e join pg_roles r on r.oid=e.evtowner join pg_proc p on p.oid=e.evtfoid where e.evtevent='login'")"
say "dathasloginevt: $(asql "select dathasloginevt from pg_database where datname='postgres'")"
if [ "$CREATED" = 0 ]; then
	r=$(asql "create event trigger e15_tenant_login on login execute function public.e15_on_login()" 2>&1 || :)
	say "control: supabase_admin creates the same trigger -> $r"
fi

# --- sessions against the tenant's trigger ---
try t1 postgres
try t2 postgres search_path pg_catalog,pg_temp
try t3 postgres event_triggers off
try a1 supabase_admin
try a2 supabase_admin event_triggers off search_path pg_catalog,pg_temp
try a3 supabase_admin options "-c event_triggers=off -c search_path=pg_catalog,pg_temp"
try boom1 supabase_admin
try boom2 supabase_admin event_triggers off search_path pg_catalog,pg_temp
try boom3 supabase_admin options "-c event_triggers=off"
try r1 authenticator
try r2 supabase_storage_admin
try boomr authenticator
# The platform's own non-superuser login role, created as the bootstrap creates it;
# it is not in supautils.reserved_roles and may not set event_triggers.
asql "create role supapace_backup login nosuperuser noinherit nocreatedb nocreaterole noreplication" >/dev/null
try p1 supapace_backup
try p2 supapace_backup event_triggers off
try boomp supapace_backup

step "part 1: superuser control trigger"
# --- control: a superuser-owned login trigger, which fires for supabase_admin unless suppressed ---
asql "create function public.e15_admin_login() returns event_trigger language plpgsql as \$\$ begin
  insert into public.e15_log(trg, usr, sess, sp, et, app) values ('admin', current_user, session_user,
    current_setting('search_path'), current_setting('event_triggers'), current_setting('application_name'));
end \$\$; create event trigger e15_admin_login on login execute function public.e15_admin_login()" >/dev/null
say "control trigger e15_admin_login created by supabase_admin"
try c1 supabase_admin
try c2 supabase_admin event_triggers off
try c3 supabase_admin options "-c event_triggers=off"
try c4 supabase_admin search_path pg_catalog,pg_temp
asql "drop event trigger e15_admin_login" >/dev/null

step "part 1: reserved_roles variant"
# --- supapace_backup listed in supautils.reserved_roles ---
docker rm -f "$PG" >/dev/null
start "$REND/supautils-reserved.conf"
say "supautils.reserved_roles now: $(asql 'show supautils.reserved_roles')"
try p3 supapace_backup
try boomp2 supapace_backup

# --- evaluation ---
admin_rows() { asql "select count(*) from public.e15_log where app = '$1' and trg = 'admin'"; }
tenant_rows() { asql "select count(*) from public.e15_log where app = '$1' and trg <> 'admin'"; }
startup_silent=0 options_silent=0 sp_first=0 control=0
[ "$(admin_rows c1)" -ge 1 ] && control=1
[ "$N_c2" = 0 ] && [ "$N_a2" = 0 ] && [ "$N_boom2" = 0 ] && case $R_c2$R_a2$R_boom2 in ok*ok*ok*) startup_silent=1 ;; esac
[ "$N_c3" = 0 ] && [ "$N_a3" = 0 ] && [ "$N_boom3" = 0 ] && case $R_c3$R_a3$R_boom3 in ok*ok*ok*) options_silent=1 ;; esac
if [ "$CREATED" = 1 ]; then
	t2sp=$(asql "select sp from public.e15_log where app = 't2' limit 1")
	c4sp=$(asql "select sp from public.e15_log where app = 'c4' and trg = 'admin' limit 1")
	[ "$t2sp" = "pg_catalog,pg_temp" ] && [ "$c4sp" = "pg_catalog,pg_temp" ] && sp_first=1
	say "tenant trigger fired for the tenant: $(tenant_rows t1); for supabase_admin without the parameter: $(tenant_rows a1) (session: $R_a1)"
	say "tenant trigger raising for supabase_admin: without the parameter -> $R_boom1; with event_triggers=off -> $R_boom2"
	say "tenant trigger for reserved non-superuser logins: authenticator $(tenant_rows r1) (session: $R_r1), supabase_storage_admin $(tenant_rows r2), raising for authenticator -> $R_boomr"
	say "tenant trigger for supapace_backup: $(tenant_rows p1) row(s) (session: $R_p1); sending event_triggers=off -> $R_p2; raising -> $R_boomp"
	say "with supapace_backup in supautils.reserved_roles: $(tenant_rows p3) row(s) (session: $R_p3); raising -> $R_boomp2"
	say "search_path in the trigger body: tenant with startup search_path -> $t2sp; superuser control -> $c4sp"
fi
say "control trigger fired for supabase_admin without the parameter: $(admin_rows c1)"
say "event_triggers=off as a startup key: silent=$startup_silent; as options -c: silent=$options_silent; tenant sending it: $R_t3"
say "part 1 result: tenant-can-create=$CREATED control=$control startup-key=$startup_silent options=$options_silent search_path-first=$sp_first"
P1=fallback
if [ "$control" = 1 ] && [ "$startup_silent" = 1 ] && { [ "$sp_first" = 1 ] || [ "$CREATED" = 0 ]; }; then
	P1=confirmed
elif [ "$control" != 1 ]; then
	P1=unknown
fi

# ===== part 2: session defaults the tenant sets at database level =====
# The tenant owns database postgres, so ALTER DATABASE postgres SET reaches every
# role's sessions. For each entry of LIST the tenant sets a hostile value; it is
# observed in sessions of e15_svc (a non-superuser login role standing for a platform
# service role) and supabase_admin without the list (control), then with it.
step "part 2 setup"
# Part 1's login trigger would also fire here; drop it so each effect below has one cause.
tsql "drop event trigger e15_tenant_login" >/dev/null
asql "create role e15_svc login nosuperuser noinherit nocreatedb nocreaterole noreplication" >/dev/null
asql "create table public.e15_shadow(at timestamptz default clock_timestamp(), usr text); grant insert on public.e15_shadow to public;
 create sequence public.e15_seq; grant usage on sequence public.e15_seq to public" >/dev/null
say "database postgres owner: $(asql "select pg_get_userbyid(datdba) from pg_database where datname = 'postgres'")"
# A tenant schema whose now() shadows the built-in for an unqualified call and records the caller.
say "tenant: create schema e15t -> $(tsql 'create schema e15t')"
tsql 'grant usage on schema e15t to public' >/dev/null
say "tenant: create function e15t.now() -> $(tsql "create function e15t.now() returns timestamptz language plpgsql as \$\$ begin
  insert into public.e15_shadow(usr) values (current_user); return pg_catalog.now(); end \$\$")"
sess() { # user, expression, startup parameters...
	u=$1 Q="select 'ROW:'||($2)||':END'"
	shift 2
	conn "$u" e15p2 "$@"
	Q=
}
# sess_list user expression [super]: a session with every entry of LIST as a startup key.
sess_list() {
	lu=$1 le=$2 lsup=${3:-}
	set --
	while IFS= read -r kv; do set -- "$@" "${kv%%=*}" "${kv#*=}"; done <<EOF
$LIST
EOF
	[ -z "$lsup" ] || set -- "$@" event_triggers off
	sess "$lu" "$le" "$@"
}
shadowed() { asql "select count(*) from public.e15_shadow where usr = '$1'"; }
role_own() { # does supabase_admin carry its own role-level value for this setting?
	asql "select count(*) from pg_db_role_setting s join pg_roles r on r.oid = s.setrole, unnest(s.setconfig) c
	  where r.rolname = 'supabase_admin' and s.setdatabase = 0 and lower(split_part(c, '=', 1)) = lower('$1')"
}

# --- every entry is accepted from a non-superuser, and in force as sent ---
step "part 2: list accepted"
NORM='' REFUSED=''
while IFS= read -r kv; do
	k=${kv%%=*} v=${kv#*=}
	r=$(sess e15_svc "current_setting('$k')" "$k" "$v")
	got=$(echo "$r" | sed 's/^ok *//')
	case $r in
	ok*) [ "$got" = "$v" ] || NORM="$NORM $k='$got'" ;;
	*) REFUSED="$REFUSED $k" ;;
	esac
	say "startup key $k='$v' from e15_svc -> $r"
done <<EOF
$LIST
EOF
say "startup key event_triggers=off from e15_svc -> $(sess e15_svc "current_setting('event_triggers')" event_triggers off)"
say "startup key plpgsql.extra_errors=none from e15_svc (not in the list) -> $(sess e15_svc "current_setting('plpgsql.extra_errors')" plpgsql.extra_errors none)"
say "whole list from e15_svc -> $(sess_list e15_svc "'accepted'")"
say "whole list + event_triggers=off from supabase_admin -> $(sess_list supabase_admin "'accepted'" super)"
say "refused from a non-superuser:${REFUSED:- none}; in force differently from the value sent:${NORM:- none}"

# --- each entry: hostile database-level value, control without the list, then with it ---
# Pattern SHADOW: affected when the session ran the tenant's e15t.now().
step "part 2: entries"
P2=1 NPASS=0
# shellcheck disable=SC2254 # the patterns are globs on purpose
hit() { # result, pattern, shadow count
	if [ "$2" = SHADOW ]; then [ "$3" -gt 0 ]; else case $1 in $2) return 0 ;; esac; return 1; fi
}
while IFS='|' read -r g v pr pat; do
	step "part 2: entry $g"
	t=$(tsql "alter database postgres set $g = $v")
	asql "delete from public.e15_shadow" >/dev/null
	s0=$(sess e15_svc "$pr")
	n0=$(shadowed e15_svc)
	apr=$pr
	[ "$pat" = SHADOW ] && apr="current_setting('search_path')"
	a0=$(sess supabase_admin "$apr")
	asql "delete from public.e15_shadow" >/dev/null
	s1=$(sess_list e15_svc "$pr")
	n1=$(shadowed e15_svc)
	a1=$(sess_list supabase_admin "$apr" super)
	tsql "alter database postgres reset $g" >/dev/null
	apat=$pat
	[ "$pat" = SHADOW ] && apat="*e15t*"
	hs=no ha=no
	hit "$s0" "$pat" "$n0" && hs=yes
	if hit "$a0" "$apat" 0; then ha=yes; elif [ "$(role_own "$g")" != 0 ]; then ha="no (its own role setting wins)"; fi
	o=yes
	{ hit "$s1" "$pat" "$n1" || hit "$a1" "$apat" 0; } && o=no
	case $s1$a1 in ok*ok*) ;; *) o=no ;; esac
	say "$g = $v  tenant: $t"
	say "   without the list: e15_svc $s0$([ "$pat" = SHADOW ] && echo " [e15t.now() ran: $n0]") | supabase_admin $a0"
	say "   with the list:    e15_svc $s1$([ "$pat" = SHADOW ] && echo " [e15t.now() ran: $n1]") | supabase_admin $a1"
	say "   => takes hold: e15_svc $hs, supabase_admin $ha; neutralised by the list: $o"
	if [ "$t" = "ALTER DATABASE" ] && [ "$o" = yes ] && { [ "$hs" = yes ] || [ "$ha" = yes ]; }; then
		NPASS=$((NPASS + 1))
	else
		P2=0
	fi
done <<'EOF'
search_path|e15t, pg_catalog|now()::text|SHADOW
role|'postgres'|current_user::text|ok postgres*
default_transaction_read_only|on|nextval('public.e15_seq')::text|error 25006*
statement_timeout|'1ms'|(select pg_sleep(0.05))::text|error 57014*
lock_timeout|'1ms'|current_setting('lock_timeout')|ok 1ms*
idle_in_transaction_session_timeout|'1s'|current_setting('idle_in_transaction_session_timeout')|ok 1s*
idle_session_timeout|'1s'|current_setting('idle_session_timeout')|ok 1s*
transaction_timeout|'1ms'|(select pg_sleep(0.05))::text|error 25P04*
local_preload_libraries|'e15none'|current_setting('local_preload_libraries')|error 58P01*
exit_on_error|on|current_setting('exit_on_error')|ok on*
default_transaction_isolation|'serializable'|current_setting('transaction_isolation')|ok serializable*
default_transaction_deferrable|on|current_setting('transaction_deferrable')|ok on*
standard_conforming_strings|off|current_setting('standard_conforming_strings')|ok off*
backslash_quote|on|current_setting('backslash_quote')|ok on*
synchronous_commit|off|current_setting('synchronous_commit')|ok off*
client_encoding|'LATIN1'|current_setting('client_encoding')|ok LATIN1*
DateStyle|'SQL, DMY'|current_setting('DateStyle')|ok SQL, DMY*
TimeZone|'Etc/GMT+5'|current_setting('TimeZone')|ok Etc/GMT+5*
IntervalStyle|'iso_8601'|current_setting('IntervalStyle')|ok iso_8601*
bytea_output|'escape'|current_setting('bytea_output')|ok escape*
extra_float_digits|-15|current_setting('extra_float_digits')|ok -15*
quote_all_identifiers|on|'pg_class'::regclass::text|ok "pg_class"*
transform_null_equals|on|((null = null) is true)::text|ok true*
row_security|off|current_setting('row_security')|ok off*
check_function_bodies|off|current_setting('check_function_bodies')|ok off*
default_tablespace|'pg_default'|current_setting('default_tablespace')|ok pg_default*
temp_tablespaces|'e15none'|current_setting('temp_tablespaces')|ok e15none*
client_min_messages|'error'|current_setting('client_min_messages')|ok error*
EOF
say "entries neutralised with a working control: $NPASS/$NLIST"
[ "$NPASS" = "$NLIST" ] || P2=0

# --- role-in-database level: the tenant may not set it for other roles; set by the
# superuser here to compare its precedence with the list ---
step "part 2: role in database"
say "tenant: alter role e15_svc in database postgres set statement_timeout -> $(tsql "alter role e15_svc in database postgres set statement_timeout = '1ms'")"
say "tenant: alter role supabase_admin in database postgres set statement_timeout -> $(tsql "alter role supabase_admin in database postgres set statement_timeout = '1ms'")"
for r in e15_svc supabase_admin; do
	asql "alter role $r in database postgres set default_transaction_read_only = on; alter role $r in database postgres set statement_timeout = '1ms'" >/dev/null
done
RIP="nextval('public.e15_seq')::text"
say "role-in-database read only + 1ms timeout: e15_svc without the list $(sess e15_svc "$RIP"); with it $(sess_list e15_svc "$RIP || (select pg_sleep(0.05))::text")"
say "role-in-database read only + 1ms timeout: supabase_admin without the list $(sess supabase_admin "$RIP"); with it $(sess_list supabase_admin "$RIP || (select pg_sleep(0.05))::text" super)"
case $(sess_list e15_svc "$RIP")$(sess_list supabase_admin "$RIP" super) in ok*ok*) ;; *) P2=0 ;; esac
asql "alter role e15_svc in database postgres reset all; alter role supabase_admin in database postgres reset all" >/dev/null

# --- refused at database level for the tenant ---
for kv in "session_preload_libraries = 'auto_explain'" "log_statement = 'all'" "session_replication_role = replica" "event_triggers = off"; do
	say "tenant: alter database postgres set $kv -> $(tsql "alter database postgres set $kv")"
done

# --- sweep: every user-context setting the tenant can set at database level ---
# Each gets a non-default value (bool flipped, next enum value, integer +1, a real
# moved far enough to show in the six digits pg_settings prints, a valid string where
# known, else 'e15x'); then a session opened with the list is compared with one
# opened before. Names still different are printed. Not in that list by construction:
# application_name (a startup key of its own) and transaction_read_only (the
# list's default_transaction_read_only decides it at every transaction start).
step "part 2: sweep"
VALS="(select string_agg(name || '=' || setting, ';' order by name) from pg_settings where context = 'user')"
base_s=$(sess_list e15_svc "$VALS")
base_a=$(sess_list supabase_admin "$VALS" super)
asql "select format('alter database postgres set %s = %L;', name, v) from (
  select name, case
    when vartype = 'bool' then case when setting = 'on' then 'off' else 'on' end
    when vartype = 'enum' then (select e from unnest(enumvals) e where e <> setting order by e limit 1)
    when vartype = 'integer' then case when setting::numeric < max_val::numeric then (setting::numeric + 1)::text else (setting::numeric - 1)::text end
    when vartype = 'real' then case when setting::numeric * 2 + 1 <= max_val::numeric then (setting::numeric * 2 + 1)::text
      when setting::numeric - 1 >= min_val::numeric then (setting::numeric - 1)::text
      when setting <> max_val then max_val else min_val end
    else coalesce((select m.v from (values ('DateStyle', 'SQL, DMY'), ('TimeZone', 'Etc/GMT+5'), ('client_encoding', 'LATIN1'),
      ('lc_monetary', 'C'), ('lc_numeric', 'C'), ('lc_time', 'C'), ('default_text_search_config', 'pg_catalog.simple'),
      ('timezone_abbreviations', 'Australia'), ('search_path', 'e15t'), ('plpgsql.extra_errors', 'all'),
      ('plpgsql.extra_warnings', 'all'), ('default_tablespace', 'pg_default'),
      ('default_table_access_method', 'heap')) m(n, v) where m.n = name), 'e15x') end v
  from pg_settings where context = 'user') x
  where v is not null and v <> (select setting from pg_settings p where p.name = x.name) order by name" >"$REND/sweep.sql"
NSW=$(grep -c . "$REND/sweep.sql")
docker exec -i -e PGOPTIONS="$OPTS" -e PGAPPNAME=bookkeeping "$PG" psql -X -q -h /var/run/postgresql -U postgres -d postgres \
	<"$REND/sweep.sql" >/dev/null 2>&1 || :
SET=$(asql "select count(*) from pg_db_role_setting s, unnest(s.setconfig) where s.setrole = 0 and s.setdatabase = (select oid from pg_database where datname = 'postgres')")
after_s=$(sess_list e15_svc "$VALS")
after_a=$(sess_list supabase_admin "$VALS" super)
# The tenant can set transaction_read_only here but can never reset it again, so its
# own reset fails once; the superuser session below clears what is left.
r=$(tsql "alter database postgres reset all")
say "tenant: alter database postgres reset all -> $r"
case $r in
*"cannot be reset"*)
	n=$(echo "$r" | sed -n 's/.*parameter "\([^"]*\)" cannot be reset.*/\1/p')
	say "tenant: alter database postgres reset $n -> $(tsql "alter database postgres reset $n")"
	say "tenant: alter database postgres set $n to default -> $(tsql "alter database postgres set $n to default")"
	say "tenant: alter database postgres reset all, again -> $(tsql "alter database postgres reset all")"
	;;
esac
names_diff() { # before, after: names whose value differs
	printf '%s\n' "${1#ok }" | tr ';' '\n' >"$REND/b"
	printf '%s\n' "${2#ok }" | tr ';' '\n' >"$REND/a"
	grep -vxFf "$REND/b" "$REND/a" | cut -d= -f1 | tr '\n' ' ' | sed 's/ *$//'
}
SWEEP=1
case $base_s$after_s$base_a$after_a in ok*ok*ok*ok*) ;; *) SWEEP=0 ;; esac
say "sweep: user-context settings with a probe value: $NSW; accepted by the tenant's ALTER DATABASE: $SET"
if [ "$SWEEP" = 1 ]; then
	RES_S=$(names_diff "$base_s" "$after_s")
	RES_A=$(names_diff "$base_a" "$after_a")
	NRES=$(echo "$RES_S" | wc -w)
	say "residual (differs from the default in an e15_svc session with the list): $NRES: $RES_S"
	[ "$RES_A" = "$RES_S" ] || say "residual for supabase_admin with the list differs: $RES_A"
else
	NRES=unknown
	say "sweep sessions failed: base $base_s | after $after_s | admin $base_a | $after_a"
fi

step "part 2 reset"
tsql "alter database postgres reset all" >/dev/null
asql "alter role e15_svc in database postgres reset all" >/dev/null
left=$(asql "select count(*) from pg_db_role_setting where setdatabase = (select oid from pg_database where datname = 'postgres')")
say "database-level settings left after the tenant's reset: $left"
if [ "$left" != 0 ]; then
	say "   left: $(asql "select string_agg(coalesce(setrole::regrole::text, 'all') || ' ' || array_to_string(setconfig, ','), '; ') from pg_db_role_setting where setdatabase = (select oid from pg_database where datname = 'postgres')")"
	asql "alter database postgres reset all" >/dev/null
	say "   after supabase_admin's reset all: $(asql "select count(*) from pg_db_role_setting where setdatabase = (select oid from pg_database where datname = 'postgres')")"
fi
[ -z "$REFUSED" ] || P2=0
say "part 2 result: entries=$NPASS/$NLIST list-accepted=$([ -z "$REFUSED" ] && echo yes || echo "no:$REFUSED") sweep=$SWEEP residual=$NRES"

DONE=1
if [ "$P1" = unknown ] || [ "$SWEEP" = 0 ]; then
	echo "VERDICT E15: unknown — $([ "$P1" = unknown ] && echo "the superuser-owned control trigger did not fire" || echo "the sweep sessions failed")."
	exit 1
elif [ "$P1" = confirmed ] && [ "$P2" = 1 ]; then
	echo "VERDICT E15: confirmed — event_triggers=off silences login triggers for supabase_admin and a startup search_path precedes trigger bodies; each of the $NLIST session-list entries takes hold from the database level without the list and not with it, all accepted from a non-superuser; residual database-level settings not in the session list: $NRES"
else
	echo "VERDICT E15: fallback — login triggers: $P1; session-list entries neutralised: $NPASS/$NLIST, refused from a non-superuser:${REFUSED:- none}; residual database-level settings not in the session list: $NRES"
fi
