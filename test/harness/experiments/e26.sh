# shellcheck shell=sh disable=SC2154,SC2034 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables
# e26.sh — the control-plane database is a stanza too. The platform's own
# code end to end: internal/agent's control-plane database (EnsureControlPlaneDB:
# uid 70, peer over its socket only, archiving with the platform's archive
# command, quotas on uid 70; PrepareControlPlaneRestore, the recovery start
# EnsureControlPlaneRecovery, FinishControlPlaneRestore), the store's own
# schema (internal/store Open and Migrate), and the daemon's jobs of subject
# cp (stanza-create, backup, check, push, replicate to the control plane's
# bucket, fetch of the stanza's two trees with the read-only credential, seed,
# restore, serve) by agent.RunJob.
#
#   - archived at uid 70, the jobs at 70:70 as the store's own role by peer
#     work (the control: a job container at uid 71 is refused by peer);
#   - replication into the control plane's bucket; the projects' credential
#     cannot read that bucket, the read-only one cannot write; the platform's
#     probe of the control plane's bucket;
#   - the mechanism's seconds from a WAL switch to the segment in the store;
#   - uid 70's two quotas are charged;
#   - everything wiped as on a replaced node: fetch, seed, restore, the
#     recovery start in its own container to the end of the archive, read
#     back by root: the schema identical, the rows up to the last replicated
#     segment present, the one written after it absent; back to the normal
#     database, Migrate a no-op, check on the new timeline, its history
#     replicated;
#   - a recovery start's postmaster killed is not restarted by Docker (it has
#     no restart policy; the control: the normal database's is restarted).
#
# Not asked: a restart of the node's Docker daemon (this harness has no hold
# for it); a stanza name used twice under one prefix (the fetch takes only the
# stanza's own trees).
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e26.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E26
CPD=/var/lib/supapace/cp
CPP=$P/cp
qused() { xfs_quota -x -c 'report -u -b -n -N' "$1" | awk -v u="#$2" '$1 == u { print $2; f = 1 } END { if (!f) print 0 }'; }
csql() { ag cp sql "$1"; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", a - b }'; }
dump() { # schema version, tables, an MD5 over the store's columns, the lab markers
	csql "select (select pg_catalog.string_agg(table_name::text, ' ' order by table_name) from information_schema.tables where table_schema = 'public'), (select pg_catalog.md5(pg_catalog.string_agg(table_name || '.' || column_name || ':' || data_type, ',' order by table_name, column_name)) from information_schema.columns where table_schema = 'public'), (select pg_catalog.string_agg(m, ',' order by m) from lab.marker)"
}
cpwait() { # until the store answers (120 s)
	_w=0
	until csql 'select 1' >/dev/null 2>&1; do
		_w=$((_w + 1))
		[ "$_w" -le 120 ] || die "the control-plane database does not answer"
		sleep 1
	done
}

stage "the control-plane database, archived, at uid 70"
ag cp ensure || die "EnsureControlPlaneDB"
cpwait
ag cp migrate || die "store.Migrate"
csql 'create schema lab' >/dev/null
csql 'create table lab.marker (m text primary key)' >/dev/null
csql "insert into lab.marker values ('m1')" >/dev/null
say "  $(docker inspect -f 'user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} net={{.HostConfig.NetworkMode}} restart={{.HostConfig.RestartPolicy.Name}}' sp-cp-db)"
say "  $(csql "select pg_catalog.string_agg(name || '=' || setting, ' ' order by name) from pg_catalog.pg_settings where name in ('archive_mode', 'archive_timeout', 'data_checksums', 'server_version')")"
before=$(dump)
say "  store: $before"
for k in stanza-create backup check; do
	ajob cp "$k" || die "$k: $JSUM"
	jsay cp "$k"
	[ "$k" != backup ] || SET=$(echo "$JSUM" | sed -n 's/^label \([^ ]*\) .*/\1/p')
done
check "stanza-create, a full backup and check as the store's role by peer at 70:70" "set $SET" test -n "$SET"
# shellcheck disable=SC2086 # an option list
refusal71=$(docker run --rm --name "$N-peer71" --label supapace.test=1 --user 71:71 $JOB_FLAGS --network none \
	-v "$CPD/sock:/var/run/postgresql" -e PGBACKREST_STANZA=cp-1 -e PGBACKREST_PG1_PATH=/var/lib/postgresql/data \
	-e PGBACKREST_PG1_USER=supapaced -e PGBACKREST_REPO1_PATH=/tmp/r -e PGBACKREST_LOCK_PATH=/tmp -e PGBACKREST_LOG_PATH=/tmp \
	-e PGBACKREST_LOG_LEVEL_FILE=off -e PGBACKREST_CONFIG=/dev/null --entrypoint pgbackrest "$WK_IMAGE" check 2>&1 | grep -o 'Peer authentication failed[^"]*' | head -1) || :
control "a job container at uid 71 is refused by peer" "$([ -n "$refusal71" ] && echo 1 || echo 0)" "${refusal71:-no refusal}"
w70=$(docker run --rm --name "$N-w70" --label supapace.test=1 --entrypoint sh "$WK_IMAGE" -c 'grep ":70:" /etc/passwd; ls /usr/bin/postgres 2>&1 | head -1' | tr '\n' ' ')
res RECORDED "the worker image: uid 70 and server binaries" "$w70"

stage "replication into the control plane's bucket"
ajob cp replicate -prefix "$PFX" || die "replicate: $JSUM"
jsay cp replicate
check "the copy job uploads the stanza, no notice" "$(echo "$JSUM" | cut -d' ' -f1-2)" sh -c "echo \"\$1\" | grep -q '^uploaded [1-9]' && echo \"\$1\" | grep -qF 'notices []'" sh "$JSUM"
ro=$(s3 cp-read versions "$PFX/cp/" | grep -c ' latest$' || :)
check "the read-only credential lists them" "$ro objects" test "$ro" -gt 100
d1=$(BUCKET=sp-cp s3 projects-write versions "$PFX/cp/" 2>&1 | tail -1) || :
check "the projects' credential cannot read the control plane's bucket" "$d1" test "$d1" = denied
d2=$(printf x | s3 cp-read put "$PFX/cp/probe" 2>&1) || :
check "the read-only credential cannot write" "$d2" test "$d2" = denied
rows=$(ag job cp probe -prefix "$PFX") || die "probe: $rows"
bad=$(printf '%s\n' "$rows" | grep '^row ' | grep -vE '^row (write-cannot-delete|region-checked) ' | grep ' false' | cut -d' ' -f2 | tr '\n' ' ')
check "the platform's probe of the control plane's bucket: every row the stand-in can pass is ok" "${bad:-all ok}; $(printf '%s\n' "$rows" | grep -c '^row ') rows" test -z "$bad"

stage "seconds from a switch to the segment in the store"
i=1
while [ "$i" -le 3 ]; do
	csql "insert into lab.marker values ('m3-$i')" >/dev/null
	t0=$(cut -d' ' -f1 /proc/uptime)
	seg=$(csql 'select pg_catalog.pg_walfile_name(pg_catalog.pg_switch_wal())')
	_w=0
	until [ -e "$CPP/spool/$seg" ]; do
		_w=$((_w + 1))
		[ "$_w" -le 1200 ] || die "segment $seg not spooled"
		sleep 0.05
	done
	t1=$(cut -d' ' -f1 /proc/uptime)
	ajob cp push || die "push: $JSUM"
	t2=$(cut -d' ' -f1 /proc/uptime)
	ajob cp replicate -prefix "$PFX" || die "replicate: $JSUM"
	t3=$(cut -d' ' -f1 /proc/uptime)
	n=$(s3 cp-read versions "$PFX/cp/archive/cp-1/" | grep -c "/$seg-" || :)
	say "  $seg: in the spool $(sub "$t1" "$t0") s, pushed $(sub "$t2" "$t0") s, in the store $(sub "$t3" "$t0") s ($n listed)"
	i=$((i + 1))
done
res RECORDED "switch to store, the mechanism only (the scheduler's wait is not in it)" "last $(sub "$t3" "$t0") s"

stage "uid 70's quotas"
p70=$(qused "$P" 70) r70=$(qused "$REPO" 70)
check "the data and spool on the projects filesystem, the repository on the repository filesystem, both charged to uid 70" \
	"projects $p70 KiB, repository $r70 KiB" test "$p70" -gt 10000 -a "$r70" -gt 1000

stage "a replaced node: wipe, fetch, seed, restore, the recovery start"
csql "insert into lab.marker values ('m5')" >/dev/null
csql 'select pg_catalog.pg_switch_wal()' >/dev/null
sleep 2
ajob cp push || die "push: $JSUM"
ajob cp replicate -prefix "$PFX" || die "replicate: $JSUM"
csql "insert into lab.marker values ('m6')" >/dev/null
say "  m5 archived, pushed and replicated; m6 written after the last copy"
docker stop -t 30 sp-cp-db >/dev/null
docker rm sp-cp-db >/dev/null
find "$CPP/data" "$CPP/spool" "$CPP/rspool" "$REPO/cp/repo" -mindepth 1 -delete 2>/dev/null || :
ag cp prepare || die "PrepareControlPlaneRestore"
s=0
ag cp ensure >/dev/null 2>&1 || s=$?
control "while the restore is marked the normal database is refused" "$([ "$s" != 0 ] && ! docker inspect sp-cp-db >/dev/null 2>&1 && echo 1 || echo 0)" "exit $s"
ajob cp fetch -prefix "$PFX" || die "fetch: $JSUM"
jsay cp fetch
NSET=$(echo "$JSUM" | sed -n 's/.* newest_set \([^ ]*\) .*/\1/p')
ajob cp seed || die "seed: $JSUM"
jsay cp seed
ajob cp restore -set "$NSET" || die "restore: $JSUM"
serve_bg cp
RLINE=$(ag cp recover -timeline latest 2>&1) || :
say "  the recovery start: $RLINE"
check "the recovery start promotes" "$RLINE" sh -c "echo \"\$1\" | grep -q '^promoted after'" sh "$RLINE"
after=$(dump)
say "  store read back: $after"
check "the schema is identical" "$(echo "$after" | cut -d'|' -f2)" test "$(echo "$after" | cut -d'|' -f1,2)" = "$(echo "$before" | cut -d'|' -f1,2)"
check "the rows up to the last replicated segment are there, the later one is not" "$(echo "$after" | cut -d'|' -f3)" \
	test "$(echo "$after" | cut -d'|' -f3)" = "m1,m3-1,m3-2,m3-3,m5"
serve_end

stage "a recovery start killed is not restarted"
pm=$(docker inspect -f '{{.State.Pid}}' sp-cp-recovery)
kill -9 "$pm"
sleep 5
st=$(docker inspect -f 'running={{.State.Running}} restarts={{.RestartCount}}' sp-cp-recovery 2>/dev/null || echo absent)
check "its postmaster killed, the recovery start stays down; no normal database appears" "$st; sp-cp-db $(docker inspect sp-cp-db >/dev/null 2>&1 && echo present || echo absent)" \
	sh -c "echo '$st' | grep -q 'running=false restarts=0' && ! docker inspect sp-cp-db >/dev/null 2>&1" sh
ag cp finish || die "FinishControlPlaneRestore"
ag cp ensure || die "EnsureControlPlaneDB after the restore"
cpwait
ag cp migrate || die "Migrate after the restore"
check "Migrate is a no-op: the schema unchanged" "" test "$(dump | cut -d'|' -f1,2)" = "$(echo "$before" | cut -d'|' -f1,2)"
pm=$(docker inspect -f '{{.State.Pid}}' sp-cp-db)
kill -9 "$pm"
i=0
until [ "$(docker inspect -f '{{.RestartCount}}' sp-cp-db)" -ge 1 ] || [ "$i" -ge 30 ]; do
	i=$((i + 1))
	sleep 1
done
control "the normal database's postmaster killed, Docker restarts it" "$([ "$(docker inspect -f '{{.RestartCount}}' sp-cp-db)" -ge 1 ] && echo 1 || echo 0)" "restarts $(docker inspect -f '{{.RestartCount}}' sp-cp-db)"
cpwait
tl=$(csql "select pg_catalog.substr(pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()), 1, 8)")
ajob cp check || :
check "check on the new timeline" "timeline $tl; $(echo "$JSUM" | cut -c1-60)" sh -c "[ '$tl' = 00000002 ] && echo \"\$1\" | grep -q '^ok;'" sh "$JSUM"
ajob cp replicate -prefix "$PFX" || :
h=$(s3 cp-read head "$PFX/cp/archive/cp-1/17-1/00000002.history" | cut -d' ' -f1)
check "the new timeline's history is in the store" "$h" test "$h" = object

verdict E26 "the control-plane database archives at uid 70 like a project, its jobs work as the store's role by peer (another uid is refused), it replicates into its own bucket with credentials scoped as designed, both quotas of uid 70 are charged, and after a full wipe the fetch, seed, restore and its own recovery start bring the store back with an identical schema and every replicated row; a killed recovery start is not restarted"
