#!/bin/sh
# e13.sh - configuration pre-validation for a restart of the pinned
# supabase/postgres image: while the real cluster runs (second boot, project
# network, own pg_hba), a task container with the same image, uid and hardening,
# --rm --network none, the data directory mounted read-only and a candidate
# conf.d at the image's include_dir runs `postgres -D /etc/postgresql -C
# max_connections`. A good candidate prints its value and exits 0; a bad value
# exits non-zero; the running cluster is not disturbed.
#
# Run on the bare test node: docker exec -i <node> sh -s < e13.sh
set -eu

IMG=supabase/postgres@sha256:b3bfedb107413abb3b8cb0d0874b0414a1dceb3d55bc0c778de6ad22d1f7dc86
REF=e13exp00000000000000
PUID=700613
IDX=13                     # slice 10.213.0.0/16 + 64*13
SLICE=10.213.3.64/26
PGIP=10.213.3.66
PROJ=/var/lib/supapace/projects/$REF
REND=/var/lib/supapace/platform/projects/$REF
PG=pg-$REF
NET=proj-$REF

say() { echo "e13: $*"; }
now() { cut -d' ' -f1 /proc/uptime; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b-a}'; }
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

cleanup() {
	docker rm -f "$PG" "$PG-check" >/dev/null 2>&1 || :
	docker network rm "$NET" >/dev/null 2>&1 || :
	rm -rf "$PROJ" "$REND"
}
# A step that fails under set -e still ends with a VERDICT line.
STEP=start
step() { STEP=$*; }
on_exit() {
	rc=$?
	cleanup
	[ "$rc" = 0 ] || [ -n "${DONE:-}" ] || echo "VERDICT E13: unknown — step '$STEP' failed (exit $rc)"
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
# --- render (image files, postgres renamed to the project uid) ---
mkdir -p "$PROJ/data" "$PROJ/sock" "$REND/conf.d" "$REND/image" "$REND/candidate"
chown "$PUID:$PUID" "$PROJ" "$PROJ/data" "$PROJ/sock"
chmod 0700 "$PROJ" "$PROJ/data" "$PROJ/sock"
chmod 0755 /var/lib/supapace/platform /var/lib/supapace/platform/projects "$REND" "$REND/conf.d" "$REND/candidate"
cid=$(docker create --network none "$IMG")
for f in /etc/passwd /etc/group /etc/postgresql-custom/supautils.conf /etc/postgresql/postgresql.conf; do
	docker cp -q "$cid:$f" "$REND/image/"
done
docker cp -q "$cid:/etc/postgresql/postgresql.conf.d" "$REND/image/conf.d"
docker rm "$cid" >/dev/null
INCLUDE_DIR=$(sed -n "s/^include_dir *= *'\([^']*\)'.*/\1/p" "$REND/image/postgresql.conf")
sed "s/^postgres:x:[0-9]*:[0-9]*:/postgres:x:$PUID:$PUID:/" "$REND/image/passwd" >"$REND/passwd"
sed "s/^postgres:x:[0-9]*:/postgres:x:$PUID:/" "$REND/image/group" >"$REND/group"
cp "$REND/image/supautils.conf" "$REND/supautils.conf"
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
cat >"$REND/pg_hba.conf" <<EOF
local   all  supabase_admin                 scram-sha-256
local   all  supapace_backup                peer map=supapace
local   all  all                            reject
host    all  supabase_admin   all           reject
host    all  supapace_backup  all           reject
host    all  all              127.0.0.1/32  scram-sha-256
host    all  all              ::1/128       scram-sha-256
host    all  all              $SLICE     scram-sha-256
host    all  all              0.0.0.0/0     reject
host    all  all              ::/0          reject
EOF
echo 'supapace  postgres  supapace_backup' >"$REND/pg_ident.conf"
rnd 32 >"$REND/pgsodium_root.key"
chown "$PUID:$PUID" "$REND/pgsodium_root.key"
chmod 0400 "$REND/pgsodium_root.key"
chmod 0444 "$REND/passwd" "$REND/group" "$REND/supautils.conf" "$REND/pg_hba.conf" "$REND/pg_ident.conf" "$REND/conf.d/"*

HARD="--user $PUID:$PUID --cap-drop ALL --security-opt no-new-privileges --read-only
 --tmpfs /tmp:rw,noexec,nosuid,size=64m --memory 512m --memory-swap 512m --cpus 1 --pids-limit 512
 --shm-size 64m --ulimit core=0 --label supapace.test=1"
# Mounts shared by the cluster and the check container; $1 = conf.d source, $2 = data mount mode.
mounts() {
	echo "-v $PROJ/data:/var/lib/postgresql/data:$2 -v $REND/passwd:/etc/passwd:ro -v $REND/group:/etc/group:ro
 -v $REND/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro -v $1:$INCLUDE_DIR:ro
 -v $REND/supautils.conf:/etc/postgresql-custom/supautils.conf:ro"
}
wait_ready() {
	i=0
	until docker logs "$PG" 2>&1 | grep -q "$1" && docker exec "$PG" pg_isready -q -h /var/run/postgresql; do
		[ "$(docker inspect -f '{{.State.Running}}' "$PG")" = true ] || { docker logs --tail 30 "$PG"; exit 1; }
		i=$((i + 1))
		[ "$i" -lt 600 ] || { say "not ready"; exit 1; }
		sleep 0.5
	done
}
APW=$(rnd 24)
asql() { docker exec -e PGPASSWORD="$APW" "$PG" psql -X -At -v ON_ERROR_STOP=1 -h /var/run/postgresql -U supabase_admin -d postgres -c "$1"; }

step "cluster boot"
# --- first boot (phase A), then the cluster as it runs normally (phase B) ---
# shellcheck disable=SC2046,SC2086
docker run -d --name "$PG" --network none -e POSTGRES_PASSWORD="$(rnd 32)" $HARD \
	$(mounts "$REND/conf.d" rw) -v "$PROJ/sock:/var/run/postgresql" "$IMG" >/dev/null
wait_ready 'PostgreSQL init process complete'
asql "alter role supabase_admin password '$APW'" >/dev/null
docker stop "$PG" >/dev/null
docker rm "$PG" >/dev/null
docker network create --internal --ipv6=false --subnet "$SLICE" -o com.docker.network.bridge.name=spp$IDX \
	-o com.docker.network.bridge.gateway_mode_ipv4=isolated "$NET" >/dev/null
# shellcheck disable=SC2046,SC2086
docker run -d --name "$PG" --hostname "$PG" --network "$NET" --ip "$PGIP" --sysctl net.ipv6.conf.all.disable_ipv6=1 \
	$HARD $(mounts "$REND/conf.d" rw) -v "$PROJ/sock:/var/run/postgresql" \
	-v "$REND/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro" -v "$REND/pg_ident.conf:/etc/postgresql/pg_ident.conf:ro" \
	--label supapace.role=cluster --label supapace.phase=B "$IMG" >/dev/null
wait_ready 'Skipping initialization'
state() {
	echo "pid=$(docker inspect -f '{{.State.Pid}}' "$PG") started=$(asql 'select pg_postmaster_start_time()') max_connections=$(asql 'show max_connections') pidfile=$(head -1 "$PROJ/data/postmaster.pid") backends=$(asql 'select count(*) from pg_stat_activity')"
}
S0=$(state)
L0=$(docker logs "$PG" 2>&1 | wc -l)
say "running cluster: $S0"
asql 'create table if not exists public.e13(x int)' >/dev/null
# A session held open across every check: it must survive them.
docker exec -d -e PGPASSWORD="$APW" "$PG" psql -X -h /var/run/postgresql -U supabase_admin -d postgres \
	-c "select pg_sleep(30)" -c "insert into public.e13 values (1)"

step "checks"
# --- the check container ---
candidate() { # name, then lines appended to a copy of the rendered conf.d's 90-supapace.conf
	n=$1
	shift
	rm -rf "$REND/candidate/$n"
	mkdir -p "$REND/candidate/$n"
	cp "$REND/conf.d/"*.conf "$REND/candidate/$n/"
	chmod 0644 "$REND/candidate/$n/90-supapace.conf"
	for l; do
		key=${l%% =*}
		sed -i "/^$key = /d" "$REND/candidate/$n/90-supapace.conf"
		echo "$l" >>"$REND/candidate/$n/90-supapace.conf"
	done
	chmod 0755 "$REND/candidate/$n"
	chmod 0444 "$REND/candidate/$n/"*
}
check() { # candidate name; sets OUT, RC
	t=$(now)
	RC=0
	# shellcheck disable=SC2046,SC2086
	OUT=$(docker run --rm --name "$PG-check" --network none $HARD $(mounts "$REND/candidate/$1" ro) \
		--entrypoint postgres "$IMG" -D /etc/postgresql -C max_connections 2>&1) || RC=$?
	say "check $1: exit $RC in $(since "$t")s: $(echo "$OUT" | tr '\n' ' ')"
}
candidate good "max_connections = 200"
candidate bad_value "max_connections = abc"
candidate out_of_range "max_connections = 999999999"
candidate bad_unit "shared_buffers = 128XB"
candidate bad_syntax "work_mem = 4MB 5MB"
candidate unknown_core "max_connectionz = 10"
candidate ext_guc "cron.max_running_jobs = abc"
okc=1
check good
[ "$RC" = 0 ] && [ "$OUT" = 200 ] || okc=0
for n in bad_value out_of_range bad_unit bad_syntax unknown_core; do
	check "$n"
	[ "$RC" != 0 ] || okc=0
done
check ext_guc
EXT_RC=$RC
say "data directory mount of the check container is read-only: $(docker run --rm --network none --user "$PUID:$PUID" --cap-drop ALL --security-opt no-new-privileges --read-only -v "$PROJ/data:/d:ro" --entrypoint touch "$IMG" /d/e13 2>&1 || :)"

step "cluster after the checks"
# --- the running cluster afterwards ---
sleep 1
S1=$(state)
say "running cluster after: $S1"
okr=1
s0=$(echo "$S0" | sed 's/ backends=.*//')
s1=$(echo "$S1" | sed 's/ backends=.*//')
[ "$s0" = "$s1" ] || { say "cluster state changed"; okr=0; }
NEWLOG=$(docker logs "$PG" 2>&1 | tail -n +"$((L0 + 1))")
say "cluster log lines during the checks: $(echo "$NEWLOG" | grep -c . || :)"
echo "$NEWLOG" | grep -iE 'fatal|panic|lock file|shutdown|terminat' | sed 's/^/  log | /' || :
echo "$NEWLOG" | grep -qiE 'fatal|panic|lock file|shutdown' && okr=0
say "held session still open: $(asql "select count(*) from pg_stat_activity where query like 'select pg_sleep(30)%'")"
[ "$(asql "select count(*) from pg_stat_activity where query like 'select pg_sleep(30)%'")" = 1 ] || okr=0
say "new connections: $(asql 'select 1')"

step "start with the extension setting"
# Settings of preloaded libraries are placeholders when -C runs; what does a real
# start make of the bad extension value the check let through?
docker rm -f "$PG" >/dev/null
# shellcheck disable=SC2046,SC2086
docker run -d --name "$PG" --hostname "$PG" --network "$NET" --ip "$PGIP" --sysctl net.ipv6.conf.all.disable_ipv6=1 \
	$HARD $(mounts "$REND/candidate/ext_guc" rw) -v "$PROJ/sock:/var/run/postgresql" \
	-v "$REND/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro" -v "$REND/pg_ident.conf:/etc/postgresql/pg_ident.conf:ro" "$IMG" >/dev/null
wait_ready 'Skipping initialization'
say "start with cron.max_running_jobs = abc: running, $(docker logs "$PG" 2>&1 | grep -m1 'max_running_jobs' | sed 's/^.*UTC \[[0-9]*\] //'); in force: $(asql 'show cron.max_running_jobs') (source $(asql "select coalesce(sourcefile,'default') from pg_settings where name='cron.max_running_jobs'"))"

say "result: checks=$okc cluster-undisturbed=$okr; extension setting with a bad value: exit $EXT_RC"
DONE=1
if [ "$okc$okr" = 11 ]; then
	echo "VERDICT E13: confirmed — postgres -C in a hardened read-only task container prints the candidate's max_connections, exits non-zero for each bad core setting, and leaves the running cluster untouched."
elif [ "$okr" = 1 ]; then
	echo "VERDICT E13: fallback — the check container does not separate good from bad candidates (checks=$okc)."
else
	echo "VERDICT E13: fallback — the check container disturbed the running cluster."
fi
