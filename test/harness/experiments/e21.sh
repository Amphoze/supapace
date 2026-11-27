# shellcheck shell=sh disable=SC2154,SC2010 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables (fixed spool names)
# e21.sh — quotas on the backup path. Three questions:
#
#   1. The user quota on a project's uid at the repository filesystem: is it
#      enforced, and what do the platform's jobs do at it? Repository quota
#      64 MiB, a full backup, then 16 MiB of incompressible WAL, one switch and
#      one push job per step until a push is refused. Then a backup at the full
#      quota; the quota raised, a backup that meets it part-way; raised again,
#      push and backup with no repair by hand, and what is left behind.
#   2. A fetch job writes the project's fetch/ at the replicator's uid: which
#      uid's quota on the repository filesystem is charged, and does the
#      replicator's own quota (agent.SetReplicatorQuota) stop a fetch?
#   3. A cluster stopped at its disk quota where the copy into the spool fails
#      first (WAL still fits into recycled segments of pg_wal/): a restore that
#      skips the quota runbook against one that follows it (raise the quota,
#      start, let the archiver catch up, stop cleanly, push, then restore).
#      Reported: the counts are the finding.
#
# Everything runs through the platform's code: the agent's layout-2 project and
# quotas, the daemon's job programs launched by agent.RunJob, the archive
# binary in the cluster, the agent's recovery start. pgBackRest's own info
# command (no platform job runs it) reads the set list.
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e21.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E21
qused() { xfs_quota -x -c 'report -u -b -n -N' "$1" | awk -v u="#$2" '$1 == u { print $2; f = 1 } END { if (!f) print 0 }'; }
spooled() {
	_w=0
	until [ -e "$P/$1/spool/$2" ]; do
		_w=$((_w + 1))
		[ "$_w" -le 300 ] || return 1
		sleep 0.2
	done
}
sets_listed() { worker "$1" push pgbackrest info --output=json 2>/dev/null | grep -o '"label":"[0-9F-]*"' | wc -l; }
leftovers() {
	_rp=$REPO/$1/repo
	_t=$(find "$_rp" -name '*.pgbackrest.tmp' | wc -l)
	_p=0
	for _d in "$_rp/backup/$1-1"/2*; do [ -d "$_d" ] && [ ! -e "$_d/backup.manifest" ] && _p=$((_p + 1)); done
	echo "$_t temporaries, $_p set directories without a manifest"
}

stage "1. the repository quota (64 MiB)"
R=e21rq000000000000001 U=700821
ag_project "$R" "$U" 1 4096 64
asql "$R" 'create table public.t (n int, b bytea)' >/dev/null
ajob "$R" stanza-create || die "stanza-create: $JSUM"
ajob "$R" backup || die "backup: $JSUM"
jsay "$R" backup
step=0 refused='' pushed_seg=''
while [ "$step" -lt 12 ]; do
	step=$((step + 1))
	asql "$R" "insert into public.t select $step, pg_catalog.string_agg(pg_catalog.decode(pg_catalog.md5(pg_catalog.random()::text || g), 'hex'), ''::bytea) from pg_catalog.generate_series(1, 1048576) g group by g % 16" >/dev/null
	seg=$(asql "$R" 'select pg_catalog.pg_walfile_name(pg_catalog.pg_switch_wal())')
	spooled "$R" "$seg" || die "segment $seg not spooled"
	if ajob "$R" push; then
		say "  step $step: $(echo "$JSUM" | cut -d' ' -f1-4); repository use $(qused "$REPO" "$U") KiB"
		pushed_seg=$seg
	else
		say "  step $step: $JSUM; repository use $(qused "$REPO" "$U") KiB"
		refused=$step
		break
	fi
done
check "a push is refused at the quota, with the platform's code repository_quota" "step ${refused:-none}: $(echo "$JSUM" | cut -c1-160)" \
	sh -c "[ -n '$refused' ] && echo \"\$1\" | grep -q '^fail repository_quota '" sh "$JSUM"
check "the refused segment stays in the spool" "$(ls "$P/$R/spool" | grep -E '^[0-9A-F]{24}$' | tr '\n' ' ')" test -e "$P/$R/spool/$seg"
say "  left: $(leftovers "$R")"
control "segments before it were pushed" "$([ -n "$pushed_seg" ] && echo 1 || echo 0)" "last pushed ${pushed_seg:-none}"

stage "1b. a backup at the full quota"
ajob "$R" backup || :
jsay "$R" backup
check "the backup fails: its WAL cannot be pushed (archive_timeout), it is not a write error" "$(echo "$JSUM" | cut -c1-160)" \
	sh -c "echo \"\$1\" | grep -q '^fail archive_timeout '" sh "$JSUM"
n=$(sets_listed "$R")
check "the repository still lists one set" "$n" test "$n" = 1

stage "1c. the quota raised; a backup that meets the quota part-way"
ag quota "$R" 4096 1024
ajob "$R" push || die "push after the raise: $JSUM"
say "  push after the raise: $(echo "$JSUM" | cut -d' ' -f1-4); left: $(leftovers "$R")"
mb=$(($(qused "$REPO" "$U") / 1024 + 24))
ag quota "$R" 4096 "$mb"
ajob "$R" backup || :
jsay "$R" backup
check "a backup whose own files meet the quota fails (pgbackrest)" "quota $mb MiB: $(echo "$JSUM" | cut -c1-200)" \
	sh -c "echo \"\$1\" | grep -q '^fail pgbackrest '" sh "$JSUM"
n=$(sets_listed "$R")
check "the failed set is not listed" "$n listed; left: $(leftovers "$R")" test "$n" = 1

stage "1d. the quota raised again: push, backup, check, nothing done by hand"
ag quota "$R" 4096 1024
ajob "$R" push || die "push: $JSUM"
ajob "$R" backup || :
jsay "$R" backup
check "the backup succeeds" "$(echo "$JSUM" | cut -c1-80)" sh -c "echo \"\$1\" | grep -q '^label '" sh "$JSUM"
ajob "$R" check || :
check "check succeeds" "$(echo "$JSUM" | cut -c1-80)" sh -c "echo \"\$1\" | grep -q '^ok;'" sh "$JSUM"
n=$(sets_listed "$R") m=$(find "$REPO/$R/repo/backup/$R-1" -mindepth 2 -maxdepth 2 -name backup.manifest | wc -l) left=$(leftovers "$R")
check "sets listed = set directories with a manifest = 2; nothing left behind" "listed $n, with a manifest $m; $left" \
	test "$n" = 2 -a "$m" = 2 -a "$left" = "0 temporaries, 0 set directories without a manifest"

stage "2. fetch/ is charged to the replicator's uid"
# A small project of its own: the stand-in keeps every object it is given for a day.
R2=e21fc000000000000002 U2=700822
ag_project "$R2" "$U2" 2 2048 1024
ajob "$R2" stanza-create || die "stanza-create: $JSUM"
ajob "$R2" backup || die "backup: $JSUM"
ajob "$R2" replicate -prefix "$PFX" || die "replication: $JSUM"
jsay "$R2" replicate
before_u=$(qused "$REPO" "$U2") before_r=$(qused "$REPO" "$REPL")
ajob "$R2" fetch -prefix "$PFX" || die "fetch: $JSUM"
jsay "$R2" fetch
fb=$(du -sk "$REPO/$R2/fetch" | cut -f1)
after_u=$(qused "$REPO" "$U2") after_r=$(qused "$REPO" "$REPL")
own=$(find "$REPO/$R2/fetch" -mindepth 1 ! \( -user "$REPL" -group "$U2" \) | wc -l)
say "  fetch/: $fb KiB; quota use KiB: project $before_u -> $after_u, replicator $before_r -> $after_r"
check "every entry of fetch/ is the replicator's, in the project's group" "$own other" test "$own" = 0
check "the replicator's quota is charged, the project's is not" "replicator +$((after_r - before_r)) KiB, project +$((after_u - before_u)) KiB" \
	test "$((after_r - before_r))" -ge "$((fb * 9 / 10))" -a "$((after_u - before_u))" -lt 1024
ag rmfetch "$R2" # as the daemon does before every fetch: fetch/ must be empty
ag rquota 1
ajob "$R2" fetch -prefix "$PFX" || :
jsay "$R2" fetch
check "at a replicator quota of 1 MiB the fetch fails with code quota" "$(echo "$JSUM" | cut -c1-120)" \
	sh -c "echo \"\$1\" | grep -q '^fail quota '" sh "$JSUM"
ag rquota 0

stage "3. a cluster stopped at its disk quota, the spool copy failing first"
R3=e21dq000000000000003 U3=700823
ag_project "$R3" "$U3" 3 4096 2048
st3() { asql "$R3" "select archived_count || '/' || failed_count || ' last=' || coalesce(last_archived_wal, '-') from pg_catalog.pg_stat_archiver" 2>/dev/null; }
asql "$R3" 'create table public.m (k int primary key, seg text)' >/dev/null
asql "$R3" "insert into public.m values (0, pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()))" >/dev/null
ajob "$R3" stanza-create || die "stanza-create: $JSUM"
ajob "$R3" backup || die "backup: $JSUM"
SET3=$(echo "$JSUM" | sed -n 's/^label \([^ ]*\) .*/\1/p')
# Recycled segments: WAL-only writes with the spool pushed, a checkpoint per step.
i=0
while [ "$i" -lt 8 ]; do
	asql "$R3" "select pg_catalog.pg_logical_emit_message(false, 'x', pg_catalog.repeat('x', 1048576)) from pg_catalog.generate_series(1, 16)" >/dev/null
	asql "$R3" 'select pg_catalog.pg_switch_wal()' >/dev/null
	asql "$R3" 'checkpoint' >/dev/null
	sleep 0.5
	ajob "$R3" push || :
	i=$((i + 1))
done
asql "$R3" 'checkpoint' >/dev/null
sleep 1
ajob "$R3" push || :
say "  pg_wal before the quota: $(ls "$P/$R3/data/pg_wal" | grep -cE '^[0-9A-F]{24}$') segments; archiver $(st3)"
# The pushes stop; the disk quota is set 8 MiB above use: a 16 MiB copy into the spool cannot fit.
q=$(($(qused "$P" "$U3") / 1024 + 8))
ag quota "$R3" "$q" 2048
k=1 committed=0
while [ "$k" -le 20 ]; do
	r=$(asql "$R3" "insert into public.m values ($k, pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn())) returning seg" 2>&1) || {
		say "  marker $k: $(echo "$r" | cut -c1-160)"
		break
	}
	committed=$k
	w=$(asql "$R3" "select count(*) from (select pg_catalog.pg_logical_emit_message(false, 'x', pg_catalog.repeat('x', 1048576)) from pg_catalog.generate_series(1, 16)) s" 2>&1) || {
		say "  marker $k committed in $r; then: $(echo "$w" | cut -c1-120)"
		break
	}
	asql "$R3" 'select pg_catalog.pg_switch_wal()' >/dev/null 2>&1 || :
	sleep 1
	say "  marker $k committed in $r; archiver $(st3)"
	k=$((k + 1))
done
i=0
while running "pg-$R3" && [ "$i" -lt 60 ]; do
	i=$((i + 1))
	sleep 1
done
res RECORDED "the cluster at its quota" "$(running "pg-$R3" && echo "still running after a crash restart" || echo "stopped") ($(docker logs "pg-$R3" 2>&1 | grep -c PANIC) PANIC lines)"
say "  cluster stopped: $(docker logs "pg-$R3" 2>&1 | grep -cE 'PANIC|FATAL') PANIC/FATAL lines; $(docker logs "pg-$R3" 2>&1 | grep -c 'archive command failed') failed archive commands"
say "  spool: $(ls "$P/$R3/spool" | grep -cE '^[0-9A-F]{24}$') segments; markers committed: 0..$committed"
control "the copy into the spool failed before the stop" \
	"$(docker logs "pg-$R3" 2>&1 | grep -q 'archive command failed' && echo 1 || echo 0)" "archive command failures in the log"
ag stop "$R3"
SNAP=$KIT/snap
mkdir -p "$SNAP"
cp -a "$P/$R3" "$SNAP/proj" && cp -a "$REPO/$R3" "$SNAP/repo" && cp -a "$RD/$R3" "$SNAP/render"
markers() { atsql "$R3" "select pg_catalog.string_agg(k::text, ',' order by k) from public.m"; }
# restore_count: the newest set restored to the end of the archive; $RESTORED the markers it holds.
restore_count() {
	RESTORED=failed
	restore_set "$R3" "$SET3" || return 0
	arecover "$R3" -timeline latest || return 0
	RESTORED=$(markers)
}

stage "3a. without the runbook: push the spool, wipe, restore to the end of the archive"
ag quota "$R3" 4096 2048
ajob "$R3" push || :
restore_count
unsafe=$RESTORED
say "  restored markers: $unsafe"

stage "3b. with the runbook: raise, start, archiver caught up, clean stop, push, restore"
ag stop "$R3"
rm -rf "${P:?}/$R3" "${REPO:?}/$R3" "${RD:?}/$R3"
cp -a "$SNAP/proj" "$P/$R3" && cp -a "$SNAP/repo" "$REPO/$R3" && cp -a "$SNAP/render" "$RD/$R3"
ag quota "$R3" 4096 2048
ag start "$R3" || die "start after the raise"
i=0
until [ "$(ls "$P/$R3/data/pg_wal/archive_status" | grep -c '\.ready$')" = 0 ] || [ "$i" -ge 120 ]; do
	i=$((i + 1))
	sleep 1
done
say "  after the start: archiver $(st3); markers in the running cluster: $(asql "$R3" "select pg_catalog.string_agg(k::text, ',' order by k) from public.m")"
ag stop "$R3"
ajob "$R3" push || die "push after the clean stop: $JSUM"
say "  push after the clean stop: $(echo "$JSUM" | cut -d' ' -f1-2)"
restore_count
safe=$RESTORED
say "  restored markers: $safe"
all=$(seq -s, 0 "$committed")
check "with the runbook every committed marker is restored" "[$safe] of 0..$committed" test "$safe" = "$all"
res RECORDED "without the runbook" "[$unsafe] of 0..$committed restored"
# A restore that failed outright is no loss of rows: the control needs a
# restored, shorter run of the committed markers, 0..k-1.
short=0
case $unsafe in
failed | "" | "$all") ;;
*) case "$all," in "$unsafe,"*) short=1 ;; esac ;;
esac
control "the runbook made a difference this run: without it a shorter run of the committed markers is restored" "$short" "[$unsafe] against [$safe]"

verdict E21 "the repository quota is enforced: a push is refused (repository_quota) and its segment stays spooled, a backup at the quota fails (archive_timeout) and no failed set is listed, and after the raise push, backup and check succeed with nothing left behind; fetch/ is charged to the replicator's uid and its own quota stops a fetch (quota); a restore after a disk-quota stop keeps every committed row with the runbook [$safe] and without it restores only the markers before the loss [$unsafe]"
