# shellcheck shell=sh disable=SC2154,SC2034,SC2010,SC2012 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables (fixed spool names)
# e28.sh — the archive binary's `.partial` rule under the real server. The
# server renames the old timeline's last segment to <segment>.partial and hands
# it to the archive command when archive recovery ends inside a segment that has
# no archive status. The archive binary as built accepts exactly
# <24 hex>.partial and discards it (exit 0, nothing written). Two checks, with
# the platform's archive binary, the agent's recovery start and re-key, and the
# daemon's job programs:
#
#   restore-leaves-no-partial: a restore to a time inside a segment. Right
#     after the promotion that segment has its .done status (it came from the
#     archive), no .partial is in pg_wal/ or among the statuses (the server
#     queued none, so the archive command was never handed one), nothing failed
#     to archive, and the spool holds none;
#   self-promoted-archiving-continues (also the positive control of the
#     listing above): a cluster that promotes itself (the project's uid inside
#     its container) does hand over its .partial — it is in pg_wal/ with its
#     .done status — the archiver's failure count stays 0, nothing .partial
#     reaches the spool, archiving goes on on the new timeline, and the next
#     push sets the new timeline's names aside.
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e28.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E28
mark() { asql "$1" "insert into public.marker (n) values ($2)" >/dev/null; }
switch() { asql "$1" 'select pg_catalog.pg_switch_wal()' >/dev/null; }
seg() { asql "$1" 'select pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn())'; }
fresh() {
	ag_project "$1" "$2" "$3" 2048 1024
	asql "$1" 'create table public.marker (n int primary key)' >/dev/null
	ajob "$1" stanza-create || die "stanza-create $1: $JSUM"
	ajob "$1" backup || die "backup $1: $JSUM"
	SET=$(echo "$JSUM" | sed -n 's/^label \([^ ]*\) .*/\1/p')
}
partials() { # REF: every .partial name in pg_wal/ and among its statuses, the spool's too
	{
		ls "$P/$1/data/pg_wal" "$P/$1/data/pg_wal/archive_status" 2>/dev/null
		ls "$P/$1/spool" 2>/dev/null | sed 's/^/spool:/'
	} | grep '\.partial' | tr '\n' ' '
}

stage "restore-leaves-no-partial"
A=e28rp000000000000001
fresh "$A" 700881 1
mark "$A" 1
switch "$A"
mark "$A" 2
T1=$(asql "$A" "select pg_catalog.to_char(pg_catalog.clock_timestamp() at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') || '+00'")
TSEG=$(seg "$A")
mark "$A" 3
mark "$A" 4
check "the target and the two rows after it lie in one segment" "$TSEG" test "$(seg "$A")" = "$TSEG"
switch "$A"
ag stop "$A"
ajob "$A" push || die "push: $JSUM"
restore_set "$A" "$SET" || die "restore"
arecover "$A" -time "$T1" -timeline current || die "the recovery start: $RLINE"
pw=$(partials "$A")
st=$(ls "$P/$A/data/pg_wal/archive_status" | tr '\n' ' ')
say "  pg_wal: $(ls "$P/$A/data/pg_wal" | grep -v archive_status | tr '\n' ' ')"
say "  statuses: $st"
m=$(atsql "$A" "select pg_catalog.string_agg(n::text, ',' order by n) from public.marker")
control "the restore stopped at the target inside the segment" "$([ "$m" = 1,2 ] && echo 1 || echo 0)" "markers $m"
check "the segment of the target carries its .done status (restored from the archive)" "$TSEG" test -e "$P/$A/data/pg_wal/archive_status/$TSEG.done"
check "no .partial in pg_wal/, among the statuses or in the spool" "${pw:-none}" test -z "$pw"
ar=$(atsql "$A" "select failed_count || ' failed, last ' || coalesce(last_archived_wal, '-') from pg_catalog.pg_stat_archiver")
check "nothing failed to archive" "$ar" sh -c "echo '$ar' | grep -q '^0 failed'" sh
tl=$(ag rekey "$A" | sed -n 's/^rekey timeline \([0-9]*\) .*/\1/p')
ag stop "$A"
ag start "$A"
mark "$A" 5
switch "$A"
sleep 2
pw=$(partials "$A")
ar=$(asql "$A" "select failed_count || ' failed, last ' || coalesce(last_archived_wal, '-') from pg_catalog.pg_stat_archiver")
check "after the re-key (timeline $tl) and the normal start: still none, nothing failed" "${pw:-none}; $ar" \
	sh -c "[ -z '$pw' ] && echo '$ar' | grep -q '^0 failed'" sh

stage "self-promoted-archiving-continues"
H=e28sp000000000000002 UH=700882
fresh "$H" "$UH" 2
mark "$H" 1
switch "$H"
mark "$H" 2
sleep 1
docker exec -u "$UH" "pg-$H" sh -c 'touch /var/lib/postgresql/data/recovery.signal'
docker exec -d -u "$UH" "pg-$H" sh -c 'while :; do for r in /opt/supapace/rspool/req/*; do [ -f "$r" ] || continue; n=${r##*/}; : >/opt/supapace/rspool/out/$n.none; rm -f "$r"; done; sleep 0.1; done'
cp=$(docker exec -u "$UH" "pg-$H" sh -c 'for p in /proc/[0-9]*; do tr "\0" " " <$p/cmdline 2>/dev/null | grep -q "checkpointer *$" && echo ${p#/proc/}; done' | head -1)
docker exec -u "$UH" "pg-$H" sh -c "kill -9 $cp"
i=0
until [ "$(asql "$H" "select pg_catalog.substr(pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn()), 1, 8)" 2>/dev/null)" = 00000002 ] || [ "$i" -ge 60 ]; do
	i=$((i + 1))
	sleep 1
done
sleep 2
pw=$(partials "$H")
say "  after $i s: $(docker logs "pg-$H" 2>&1 | grep -E 'selected new timeline|archive recovery complete' | cut -c1-100 | tr '\n' ' ')"
say "  .partial names: ${pw:-none}"
check "the server handed its .partial over and recorded it archived (.done)" "${pw:-none}" \
	sh -c "echo '$pw' | grep -qE '[0-9A-F]{24}\.partial\.done' && ! echo '$pw' | grep -q 'spool:'" sh
mark "$H" 3
switch "$H"
mark "$H" 4
switch "$H"
sleep 3
ar=$(asql "$H" "select archived_count || ' archived, ' || failed_count || ' failed, last ' || coalesce(last_archived_wal, '-') from pg_catalog.pg_stat_archiver")
check "the archiver's failure count stays 0 and archiving goes on on timeline 2" "$ar" \
	sh -c "echo '$ar' | grep -q ' 0 failed, last 00000002[0-9A-F]\{16\}$'" sh
ajob "$H" push -tl 1 || die "push: $JSUM"
jsay "$H" push
check "the next push sets the new timeline's names aside" "$(echo "$JSUM" | sed 's/.*quarantined //' | cut -c1-160)" \
	sh -c "echo \"\$1\" | grep -q '00000002.history:timeline' && echo \"\$1\" | grep -qE '00000002[0-9A-F]{16}:timeline'" sh "$JSUM"

verdict E28 "after the platform's restore to a time inside a segment the server hands the archive command no .partial (the segment came from the archive with .done); a cluster that promotes itself hands one over, the archive binary discards it, the failure count stays 0, archiving continues on the new timeline, and the next push sets that timeline's names aside"
