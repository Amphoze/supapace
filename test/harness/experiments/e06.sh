#!/bin/sh
# e06.sh - two-phase first boot of the pinned supabase/postgres image at an
# arbitrary uid under the cluster container's hardening flags.
#
# Phase A: --network none, POSTGRES_PASSWORD, the image's own pg_hba, our conf.d
# (archive_mode=on with a placeholder archive_command) and supautils template
# mounted read-only; a bootstrap session over the socket. Phase B: the same data
# directory on an internal project network, our pg_hba and pg_ident. Then phase A
# again over a wiped data directory. Also prints the image baseline (roles,
# memberships, role settings, schemas, event triggers, files, auto.conf, size)
# of the fresh, un-bootstrapped cluster between BASELINE-BEGIN / BASELINE-END.
#
# Run on the bare test node: docker exec -i <node> sh -s < e06.sh
set -eu

IMG=supabase/postgres@sha256:b3bfedb107413abb3b8cb0d0874b0414a1dceb3d55bc0c778de6ad22d1f7dc86
REF=e06exp00000000000000
PUID=700601
IDX=6                      # slice index: 10.213.0.0/16 + 64*6 = 10.213.1.128/26
SLICE=10.213.1.128/26
PGIP=10.213.1.130
PROJ=/var/lib/supapace/projects/$REF
REND=/var/lib/supapace/platform/projects/$REF
PG=pg-$REF
NET=proj-$REF

say() { echo "e06: $*"; }
now() { cut -d' ' -f1 /proc/uptime; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b-a}'; }
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

cleanup() {
	docker rm -f "$PG" "$PG-wipe" "$PG-nopw" >/dev/null 2>&1 || :
	docker network rm "$NET" >/dev/null 2>&1 || :
	rm -rf "$PROJ" "$REND"
}
# A step that fails under set -e still ends with a VERDICT line.
STEP=start
step() { STEP=$*; }
on_exit() {
	rc=$?
	cleanup
	[ "$rc" = 0 ] || [ -n "${DONE:-}" ] || echo "VERDICT E06: unknown — step '$STEP' failed (exit $rc)"
}
trap on_exit EXIT
# A killed run still ends with its VERDICT line and cleans up.
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
cleanup

docker image inspect "$IMG" >/dev/null || { say "image $IMG not loaded"; exit 2; }
mountpoint -q /var/lib/supapace/projects || { say "projects mount absent"; exit 2; }

step "render"
# --- render: image files extracted once, postgres renamed to the project uid ---
mkdir -p "$PROJ/data" "$PROJ/sock" "$REND/conf.d" "$REND/tools" "$REND/image"
chmod 0755 /var/lib/supapace/platform /var/lib/supapace/platform/projects "$REND" "$REND/conf.d" "$REND/tools"
chown "$PUID:$PUID" "$PROJ/data" "$PROJ/sock"
chmod 0700 "$PROJ/data" "$PROJ/sock" "$PROJ"
chown "$PUID:$PUID" "$PROJ"
cid=$(docker create --network none "$IMG")
docker cp -q "$cid:/etc/passwd" "$REND/image/passwd"
docker cp -q "$cid:/etc/group" "$REND/image/group"
docker cp -q "$cid:/etc/postgresql-custom/supautils.conf" "$REND/image/supautils.conf"
docker cp -q "$cid:/etc/postgresql/postgresql.conf" "$REND/image/postgresql.conf"
docker cp -q "$cid:/etc/postgresql/postgresql.conf.d" "$REND/image/conf.d"
docker rm "$cid" >/dev/null

INCLUDE_DIR=$(sed -n "s/^include_dir *= *'\([^']*\)'.*/\1/p" "$REND/image/postgresql.conf")
say "image include_dir (postgresql.conf): $INCLUDE_DIR"
[ -n "$INCLUDE_DIR" ] || { say "no include_dir in the image's postgresql.conf"; exit 2; }

sed "s/^postgres:x:[0-9]*:[0-9]*:/postgres:x:$PUID:$PUID:/" "$REND/image/passwd" >"$REND/passwd"
sed "s/^postgres:x:[0-9]*:/postgres:x:$PUID:/" "$REND/image/group" >"$REND/group"
cp "$REND/image/conf.d/"*.conf "$REND/conf.d/"
cat >"$REND/conf.d/90-supapace.conf" <<'EOF'
listen_addresses = '*'
max_connections = 120
superuser_reserved_connections = 3
reserved_connections = 2
shared_buffers = 128MB
effective_cache_size = 384MB
work_mem = 4MB
maintenance_work_mem = 64MB
autovacuum_work_mem = 32MB
autovacuum_max_workers = 2
max_wal_size = 1GB
max_slot_wal_keep_size = 2GB
wal_level = logical
archive_mode = on
archive_command = 'true # pgbackrest'
archive_timeout = 300
max_replication_slots = 8
max_wal_senders = 10
password_encryption = 'scram-sha-256'
cron.max_running_jobs = 2
random_page_cost = 1.1
huge_pages = off
max_parallel_workers_per_gather = 0
max_prepared_transactions = 0
temp_file_limit = 1GB
EOF
# supautils template: the five network-capable extensions removed from the list.
sed -E "/^supautils.privileged_extensions = /{s/(['[:space:]])(pg_net|http|dblink|postgres_fdw|wrappers), /\\1/g;s/, wrappers'\$/'/}" \
	"$REND/image/supautils.conf" >"$REND/supautils.conf"
cat >"$REND/pg_hba.conf" <<EOF
local   all  supabase_admin                 scram-sha-256
local   all  supapace_backup                peer map=supapace
local   all  all                            reject
host    all  supabase_admin   all           reject
host    all  supapace_backup  all           reject
host    all  all              127.0.0.1/32  scram-sha-256
host    all  all              ::1/128       scram-sha-256
host    all  all              $SLICE    scram-sha-256
host    all  all              0.0.0.0/0     reject
host    all  all              ::/0          reject
EOF
echo 'supapace  postgres  supapace_backup' >"$REND/pg_ident.conf"
rnd 32 >"$REND/pgsodium_root.key"
chown "$PUID:$PUID" "$REND/pgsodium_root.key"
chmod 0400 "$REND/pgsodium_root.key"
chmod 0444 "$REND/passwd" "$REND/group" "$REND/supautils.conf" "$REND/pg_hba.conf" "$REND/pg_ident.conf" "$REND/conf.d/"*
renderhash() { (cd "$REND" && sha256sum passwd group supautils.conf pg_hba.conf pg_ident.conf pgsodium_root.key conf.d/*); }
H0=$(renderhash)

# --- the cluster container (phase A or B), hardening flags as the platform runs them ---
run_cluster() { # phase [extra docker args...]
	phase=$1
	shift
	set -- --user "$PUID:$PUID" --cap-drop ALL --security-opt no-new-privileges \
		--read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
		--memory 512m --memory-swap 512m --cpus 1 --pids-limit 512 --shm-size 64m --ulimit core=0 \
		-v "$PROJ/data:/var/lib/postgresql/data" -v "$PROJ/sock:/var/run/postgresql" \
		-v "$REND/passwd:/etc/passwd:ro" -v "$REND/group:/etc/group:ro" \
		-v "$REND/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro" \
		-v "$REND/conf.d:$INCLUDE_DIR:ro" \
		-v "$REND/supautils.conf:/etc/postgresql-custom/supautils.conf:ro" \
		-v "$REND/tools:/opt/supapace/tools:ro" \
		--label supapace.role=cluster --label supapace.ref=$REF --label supapace.phase="$phase" \
		--label supapace.test=1 "$@"
	if [ "$phase" = A ]; then
		docker run -d --name "$PG" --hostname "$PG" --network none -e POSTGRES_PASSWORD="$(rnd 32)" "$@" "$IMG" >/dev/null
	else
		docker run -d --name "$PG" --hostname "$PG" --network "$NET" --ip "$PGIP" \
			--sysctl net.ipv6.conf.all.disable_ipv6=1 \
			-v "$REND/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro" \
			-v "$REND/pg_ident.conf:/etc/postgresql/pg_ident.conf:ro" "$@" "$IMG" >/dev/null
	fi
}
wait_ready() { # marker
	i=0
	while :; do
		if [ "$(docker inspect -f '{{.State.Running}}' "$PG")" != true ]; then
			say "container stopped:"
			docker logs --tail 30 "$PG" 2>&1 | sed 's/^/  | /'
			return 1
		fi
		if docker logs "$PG" 2>&1 | grep -q "$1" &&
			docker exec "$PG" pg_isready -q -h /var/run/postgresql; then
			return 0
		fi
		i=$((i + 1))
		[ "$i" -lt 600 ] || { say "not ready after 300 s"; return 1; }
		sleep 0.5
	done
}
OPTS='-c event_triggers=off -c search_path=pg_catalog,pg_temp'
# Commands of this script must not read stdin (the script itself arrives there):
# asql takes -c, asqli a here-document.
asql() { docker exec -e PGOPTIONS="$OPTS" -e PGAPPNAME=supapace-agent -e PGPASSWORD="${APW:-}" "$PG" \
	psql -X -At -v ON_ERROR_STOP=1 -h /var/run/postgresql -U supabase_admin -d postgres "$@"; }
asqli() { docker exec -i -e PGOPTIONS="$OPTS" -e PGAPPNAME=supapace-agent -e PGPASSWORD="${APW:-}" "$PG" \
	psql -X -At -v ON_ERROR_STOP=1 -h /var/run/postgresql -U supabase_admin -d postgres; }

step "passwd negative control"
# --- negative + control: the uid needs a passwd entry (no nss_wrapper in the image) ---
docker run -d --name "$PG-nopw" --user "$PUID:$PUID" --network none --cap-drop ALL \
	--security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
	-e POSTGRES_PASSWORD=x -v "$PROJ/data:/var/lib/postgresql/data" -v "$PROJ/sock:/var/run/postgresql" \
	--label supapace.test=1 "$IMG" >/dev/null
docker wait "$PG-nopw" >/dev/null
say "without the passwd mount: $(docker logs "$PG-nopw" 2>&1 | grep -m1 'initdb:' || echo '(no initdb error)')"
docker rm -f "$PG-nopw" >/dev/null
[ -z "$(find "$PROJ/data" -mindepth 1)" ] || { say "data directory not empty after the failed start"; exit 1; }

step "phase A"
# --- phase A ---
t=$(now)
run_cluster A
wait_ready 'PostgreSQL init process complete'
TA=$(since "$t")
say "phase A ready in ${TA}s (initdb + image migrations + start)"
docker logs "$PG" 2>&1 | grep -iE 'permission denied|read-only|operation not permitted|error' | sort | uniq -c | sed 's/^/  log | /' | head -20 || :

say "hardening: $(docker inspect -f 'user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} capdrop={{.HostConfig.CapDrop}} capadd={{.HostConfig.CapAdd}} secopt={{.HostConfig.SecurityOpt}} tmpfs={{.HostConfig.Tmpfs}} shm={{.HostConfig.ShmSize}} mem={{.HostConfig.Memory}} swap={{.HostConfig.MemorySwap}} cpus={{.HostConfig.NanoCpus}} pids={{.HostConfig.PidsLimit}} ulimits={{.HostConfig.Ulimits}} net={{.HostConfig.NetworkMode}}' "$PG")"
say "root filesystem write: $(docker exec "$PG" touch /etc/e06 2>&1 || :)"
say "include_dir $INCLUDE_DIR -> $(docker exec "$PG" readlink "$INCLUDE_DIR"); mounted at: $(docker exec "$PG" awk '$5 ~ /conf\.d$/ {print $5, $6}' /proc/1/mountinfo); via include_dir: $(docker exec "$PG" ls "$INCLUDE_DIR/" | tr '\n' ' ')"
say "caps: $(docker exec "$PG" grep -E 'CapEff|CapBnd' /proc/1/status | tr '\t\n' ' ')"
say "pg: $(asql -c 'select version()' | cut -d' ' -f1-2)"
CONF_SRC=$(asql -c "select sourcefile from pg_settings where name='archive_mode'")
say "archive_mode source: $CONF_SRC"

# The fresh, un-bootstrapped cluster: baseline in the image-baseline schema.
FRESH_KB=$(du -sk "$PROJ/data" | cut -f1)
FRESH_INODES=$(find "$PROJ/data" | wc -l)
PGV=$(asql -c "select current_setting('server_version')" | cut -d' ' -f1)
HBA=$(asql -c "select current_setting('hba_file')")
IDENT=$(asql -c "select current_setting('ident_file')")
SUPA=$(asql -c "select sourcefile from pg_settings where name='supautils.privileged_extensions'")
CRON=$(asql -c "select sourcefile from pg_settings where name='cron.database_name'")
KEYF=$(docker exec "$PG" sed -n 's/^KEY_FILE=//p' /usr/lib/postgresql/bin/pgsodium_getkey.sh)
GETKEY=$(asql -c "select setting from pg_settings where name='pgsodium.getkey_script'")
say "include_dir as applied: ${CRON%/*} (from cron.database_name sourcefile $CRON)"
say "pgsodium.getkey_script=$GETKEY, its KEY_FILE=$KEYF"
say "postgresql.auto.conf: $(docker exec "$PG" grep -vc '^#' /var/lib/postgresql/data/postgresql.auto.conf || :) non-comment line(s)"
say "fresh data directory: ${FRESH_KB} KiB, ${FRESH_INODES} inodes (running, before bootstrap)"
echo BASELINE-BEGIN
asqli <<EOF
select json_build_object(
 'image', 'supabase/postgres:17.6.1.166',
 'digest', '${IMG#*@}',
 'pg_version', '$PGV',
 'roles', (select json_agg(json_build_object('name',rolname,'super',rolsuper,'createrole',rolcreaterole,
     'createdb',rolcreatedb,'replication',rolreplication,'bypassrls',rolbypassrls,'login',rolcanlogin,
     'connlimit',rolconnlimit) order by rolname) from pg_roles where rolname !~ '^pg_'),
 'memberships', (select json_agg(json_build_object('member',m,'role',r) order by m, r) from
     (select distinct mr.rolname m, rr.rolname r from pg_auth_members a
        join pg_roles mr on mr.oid=a.member join pg_roles rr on rr.oid=a.roleid
       where mr.rolname !~ '^pg_' or rr.rolname !~ '^pg_') p),
 'role_settings', (select json_agg(json_build_object('role',r.rolname,'settings',s.setconfig) order by r.rolname)
     from pg_db_role_setting s join pg_roles r on r.oid=s.setrole where s.setdatabase=0),
 'schemas', (select json_agg(json_build_object('name',nspname,'owner',pg_get_userbyid(nspowner),
     'acl',coalesce(nspacl::text[],'{}')) order by nspname) from pg_namespace
     where nspname in ('auth','storage','realtime','extensions')),
 'event_triggers', (select coalesce(json_agg(json_build_object('name',e.evtname,'event',e.evtevent,
     'owner',pg_get_userbyid(e.evtowner),'function',n.nspname||'.'||p.proname) order by e.evtname),'[]'::json)
     from pg_event_trigger e join pg_proc p on p.oid=e.evtfoid join pg_namespace n on n.oid=p.pronamespace),
 'files', json_build_object('include_dir','$INCLUDE_DIR','hba_file','$HBA','ident_file','$IDENT',
     'supautils_conf','$SUPA','pgsodium_key','$KEYF'),
 'auto_conf', (select coalesce(json_agg(name order by name),'[]'::json) from pg_settings
     where sourcefile like '%/postgresql.auto.conf'),
 'fresh_cluster_mb', ($FRESH_KB + 1023) / 1024)
EOF
echo BASELINE-END
say "role settings outside database 0: $(asql -c 'select count(*) from pg_db_role_setting where setdatabase<>0')"

step "bootstrap"
# --- bootstrap session (phase A, trust over the socket, startup options as the agent sends them) ---
APW=$(rnd 24) PPW=$(rnd 24) AUPW=$(rnd 24)
t=$(now)
asqli <<EOF
alter role supabase_admin password '$APW';
alter role postgres password '$PPW';
alter role authenticator password '$AUPW';
alter role pgbouncer password null;
alter role supabase_auth_admin password null;
alter role supabase_storage_admin password null;
alter role supabase_replication_admin password null;
alter role supabase_etl_admin password null;
alter role supabase_read_only_user password null;
do \$\$ begin
  if not exists (select from pg_roles where rolname='supabase_realtime_admin') then
    create role supabase_realtime_admin nologin noinherit; end if;
  if not exists (select from pg_roles where rolname='supapace_backup') then
    create role supapace_backup login nosuperuser noinherit nocreatedb nocreaterole noreplication; end if;
end \$\$;
grant pg_read_all_settings to supapace_backup;
grant execute on function pg_catalog.pg_backup_start(text, boolean), pg_catalog.pg_backup_stop(boolean),
  pg_catalog.pg_switch_wal(), pg_catalog.pg_create_restore_point(text) to supapace_backup;
set role supabase_auth_admin;
create or replace function auth.uid() returns pg_catalog.uuid language sql stable as \$f\$
  select coalesce(nullif(pg_catalog.current_setting('request.jwt.claim.sub', true), ''),
                  (nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::pg_catalog.jsonb
                     operator(pg_catalog.->>) 'sub'))::pg_catalog.uuid \$f\$;
create or replace function auth.role() returns pg_catalog.text language sql stable as \$f\$
  select coalesce(nullif(pg_catalog.current_setting('request.jwt.claim.role', true), ''),
                  (nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::pg_catalog.jsonb
                     operator(pg_catalog.->>) 'role'))::pg_catalog.text \$f\$;
create or replace function auth.email() returns pg_catalog.text language sql stable as \$f\$
  select coalesce(nullif(pg_catalog.current_setting('request.jwt.claim.email', true), ''),
                  (nullif(pg_catalog.current_setting('request.jwt.claims', true), '')::pg_catalog.jsonb
                     operator(pg_catalog.->>) 'email'))::pg_catalog.text \$f\$;
create or replace function auth.jwt() returns pg_catalog.jsonb language sql stable as \$f\$
  select coalesce(nullif(pg_catalog.current_setting('request.jwt.claim', true), ''),
                  nullif(pg_catalog.current_setting('request.jwt.claims', true), ''))::pg_catalog.jsonb \$f\$;
reset role;
create table public.e06_marker(id int);
EOF
say "bootstrap steps 1-5 ok in $(since "$t")s"
say "auth functions: $(asql -c "select string_agg(proname||'/'||pg_get_userbyid(proowner)||'/'||prosecdef, ' ' order by proname) from pg_proc where pronamespace='auth'::regnamespace and proname in ('uid','role','email','jwt')")"

# Configuration rule: every setting of 90-supapace.conf comes from that file at its line.
check_conf() {
	bad=0 n=0
	ln=0
	while IFS= read -r line; do
		ln=$((ln + 1))
		name=${line%% *}
		got=$(asql -c "select coalesce(sourcefile,'-')||':'||coalesce(sourceline::text,'-') from pg_settings where name='$name'")
		n=$((n + 1))
		case "$got" in
		*/90-supapace.conf:"$ln") ;;
		*) bad=$((bad + 1)); say "  $name: expected line $ln of 90-supapace.conf, got $got" ;;
		esac
	done <"$REND/conf.d/90-supapace.conf"
	say "$1: $((n - bad))/$n settings applied from 90-supapace.conf at their line"
	auto=$(asql -c "select count(*) from pg_settings where sourcefile like '%/postgresql.auto.conf'")
	say "$1: settings from postgresql.auto.conf: $auto"
	[ "$bad" = 0 ] && [ "$auto" = 0 ]
}
check_archive() {
	before=$(asql -c 'select archived_count from pg_stat_archiver')
	asql -c 'create table if not exists public.e06_wal(x int); insert into public.e06_wal select generate_series(1,1000)' >/dev/null
	asql -c 'select pg_switch_wal()' >/dev/null
	i=0
	while [ "$(asql -c 'select archived_count from pg_stat_archiver')" = "$before" ] && [ "$i" -lt 40 ]; do
		sleep 0.5
		i=$((i + 1))
	done
	res=$(asql -c "select archived_count||' archived, failed_count='||failed_count||', last='||coalesce(last_archived_wal,'-') from pg_stat_archiver")
	say "$1: archive_mode=$(asql -c 'show archive_mode') archive_command=$(asql -c 'show archive_command'); $res"
	asql -c 'select failed_count = 0 and archived_count > 0 from pg_stat_archiver' | grep -qx t
}
okA=1
check_conf "phase A" || okA=0
check_archive "phase A" || okA=0
SYSID_A=$(asql -c 'select system_identifier from pg_control_system()')

t=$(now)
docker stop "$PG" >/dev/null
say "phase A stop: $(since "$t")s; exit $(docker inspect -f '{{.State.ExitCode}}' "$PG")"
docker rm "$PG" >/dev/null
say "data directory after bootstrap and clean stop: $(du -sk "$PROJ/data" | cut -f1) KiB, $(find "$PROJ/data" | wc -l) inodes"
H1=$(renderhash)
if [ "$H0" = "$H1" ]; then say "rendered files unchanged by phase A"; else say "rendered files CHANGED by phase A"; okA=0; fi

step "phase B"
# --- phase B ---
docker network create --internal --ipv6=false --subnet "$SLICE" \
	-o com.docker.network.bridge.name=spp$IDX \
	-o com.docker.network.bridge.gateway_mode_ipv4=isolated "$NET" >/dev/null
t=$(now)
run_cluster B
wait_ready 'Skipping initialization'
TB=$(since "$t")
say "phase B ready in ${TB}s"
okB=1
docker logs "$PG" 2>&1 | grep -q 'init process complete' && { say "phase B re-initialised!"; okB=0; }
say "phase B entrypoint: $(docker logs "$PG" 2>&1 | grep -m1 -o 'Database directory appears to contain a database; Skipping initialization')"
SYSID_B=$(asql -c 'select system_identifier from pg_control_system()')
[ "$SYSID_A" = "$SYSID_B" ] && say "same cluster (system_identifier $SYSID_B), marker table: $(asql -c "select to_regclass('public.e06_marker') is not null")" || okB=0
say "addresses: $(docker exec "$PG" sh -c 'ip -o addr 2>/dev/null | awk "{print \$2, \$4}" | tr "\n" " "' || echo '-')"
say "hba_file=$(asql -c 'show hba_file') ident_file=$(asql -c 'show ident_file')"
asql -c "select line_number||' '||type||' '||array_to_string(database,',')||' '||array_to_string(user_name,',')||' '||coalesce(address,'')||' '||coalesce(netmask,'')||' '||auth_method||coalesce(' '||array_to_string(options,','),'')||coalesce(' ERROR '||error,'') from pg_hba_file_rules order by rule_number" | sed 's/^/  hba | /'
errs=$(asql -c 'select count(*) from pg_hba_file_rules where error is not null')
nrules=$(asql -c 'select count(*) from pg_hba_file_rules')
say "pg_hba_file_rules: $nrules rules, $errs with error"
[ "$errs" = 0 ] && [ "$nrules" = 10 ] || okB=0
say "pg_ident_file_mappings: $(asql -c "select string_agg(map_name||' '||sys_name||' '||pg_username||coalesce(' ERROR '||error,''), '; ') from pg_ident_file_mappings")"
check_conf "phase B" || okB=0
check_archive "phase B" || okB=0
# pg_hba in force: negative + control for each refused path.
tsql() { docker exec -e PGPASSWORD="$2" "$PG" psql -X -At -h "$1" -U "$3" -d postgres -c 'select current_user' 2>&1 | tail -1; }
r1=$(tsql /var/run/postgresql "$PPW" postgres)
r2=$(tsql 127.0.0.1 "$PPW" postgres)
r3=$(tsql 127.0.0.1 "$APW" supabase_admin)
r4=$(tsql /var/run/postgresql "$APW" supabase_admin)
r5=$(tsql /var/run/postgresql wrong supabase_admin)
say "postgres over the socket: $r1"
say "postgres over 127.0.0.1 with its password (control): $r2"
say "supabase_admin over 127.0.0.1: $r3"
say "supabase_admin over the socket with its password (control): $r4"
say "supabase_admin over the socket, wrong password: $r5"
echo "$r1" | grep -q 'rejects connection' && [ "$r2" = postgres ] &&
	echo "$r3" | grep -q 'rejects connection' && [ "$r4" = supabase_admin ] &&
	echo "$r5" | grep -q 'password authentication failed' || okB=0
t=$(now)
docker stop "$PG" >/dev/null
say "phase B stop: $(since "$t")s"
docker rm "$PG" >/dev/null
H2=$(renderhash)
if [ "$H0" = "$H2" ]; then say "rendered files unchanged by phase B"; else say "rendered files CHANGED by phase B"; okB=0; fi

step "wipe and phase A re-run"
# --- wipe at the project uid (task container), then phase A again ---
t=$(now)
docker run --rm --name "$PG-wipe" --user "$PUID:$PUID" --network none --cap-drop ALL \
	--security-opt no-new-privileges --read-only --memory 512m --pids-limit 512 --ulimit core=0 \
	-v "$PROJ/data:/w/data" -v "$PROJ/sock:/w/sock" --entrypoint find "$IMG" \
	/w/data /w/sock -mindepth 1 -delete
say "wipe at uid $PUID: $(since "$t")s; data entries left: $(find "$PROJ/data" -mindepth 1 | wc -l), sock entries left: $(find "$PROJ/sock" -mindepth 1 | wc -l)"
t=$(now)
okR=1
APW=
run_cluster A
wait_ready 'PostgreSQL init process complete' || okR=0
TR=$(since "$t")
say "phase A re-run ready in ${TR}s"
SYSID_R=$(asql -c 'select system_identifier from pg_control_system()')
say "re-run system_identifier $SYSID_R (first run $SYSID_A); marker table: $(asql -c "select to_regclass('public.e06_marker') is not null")"
[ "$SYSID_R" != "$SYSID_A" ] || okR=0
check_conf "phase A re-run" || okR=0
docker stop "$PG" >/dev/null
docker rm "$PG" >/dev/null

say "timings: phase A ${TA}s, phase B ${TB}s, phase A over wiped dir ${TR}s"
say "result: phaseA=$okA phaseB=$okB rerun=$okR"
DONE=1
if [ "$okA$okB$okR" = 111 ]; then
	echo "VERDICT E06: confirmed — two-phase boot works fully hardened at uid $PUID with conf.d mounted at the image's include_dir $INCLUDE_DIR; no re-init, mounted files untouched, archiver clean."
else
	echo "VERDICT E06: fallback — the two-phase boot did not behave as designed (phaseA=$okA phaseB=$okB rerun=$okR); see the lines above."
fi
