# shellcheck shell=sh disable=SC2154,SC2034,SC2010 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables (fixed spool names)
# e27.sh — two facts of the archive path, on the platform's control-plane
# database (internal/agent: archive_mode on, the platform's archive command,
# archive_timeout 300 s, restart unless-stopped) with the daemon's push job:
#
#   1. idle WAL: after one write, what does an otherwise idle database archive
#      over the next 25 minutes at archive_timeout 300 s, and what does the
#      push of it cost in the repository? Five intervals: the
#      write's two segments, then three quiet ones.
#   2. the server killed between its copy into the spool and its own
#      bookkeeping (the segment in the spool, still .ready): after the restart
#      the server archives it again; identical bytes are accepted and archiving
#      goes on; the push takes each segment once (also after the push had taken
#      it before the restart); different bytes at that name are refused and
#      hold every later segment back until the original bytes are back.
#
# No hook is added to the archive command: the state "copied, not yet
# recorded" is made from outside — the spool made unwritable to uid 70 for a
# moment (the archive command fails, the segment stays .ready), its bytes put
# into the spool by root as the archive binary writes them (uid 70, 0600), then
# the postmaster killed.
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e27.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E27
CPP=$P/cp SP=$P/cp/spool
csql() { ag cp sql "$1"; }
cpwait() {
	_w=0
	until csql 'select 1' >/dev/null 2>&1; do
		_w=$((_w + 1))
		[ "$_w" -le 120 ] || die "the control-plane database does not answer"
		sleep 1
	done
}
arch() { csql "select archived_count || '/' || failed_count || ' last=' || coalesce(last_archived_wal, '-') || ' failed=' || coalesce(last_failed_wal, '-') from pg_catalog.pg_stat_archiver"; }
rsize() { find "$REPO/cp/repo/archive" -type f -name '*.zst' -exec cat {} + 2>/dev/null | wc -c; }
spoolsegs() { ls "$SP" | grep -E '^[0-9A-F]{24}$' | tr '\n' ' '; }

stage "the control-plane database, its stanza, a full backup"
ag cp ensure || die "EnsureControlPlaneDB"
cpwait
ag cp migrate || die "Migrate"
csql 'create schema lab' >/dev/null
csql 'create table lab.marker (m text primary key)' >/dev/null
ajob cp stanza-create || die "stanza-create: $JSUM"
ajob cp backup || die "backup: $JSUM"
csql 'checkpoint' >/dev/null
sleep 2
ajob cp push || die "push: $JSUM"
say "  $(csql "select 'archive_timeout=' || pg_catalog.current_setting('archive_timeout') || ' checkpoint_timeout=' || pg_catalog.current_setting('checkpoint_timeout')")"

stage "1. one write, then 25 minutes idle"
ajob cp push || die "push: $JSUM"
r0=$(rsize) S0=$(spoolsegs)
csql "insert into lab.marker values ('one-write')" >/dev/null
w0=$(csql 'select pg_catalog.pg_current_wal_lsn()')
say "  t=0 $w0 archiver $(arch); spool [$S0]"
i=1
while [ "$i" -le 5 ]; do
	sleep 300
	eval "S$i=\"\$(spoolsegs)\""
	say "  t=$((i * 300)) s $(csql 'select pg_catalog.pg_current_wal_lsn()') archiver $(arch); spool [$(eval "echo \$S$i")]"
	i=$((i + 1))
done
n5=$(($(echo "$S5" | wc -w) - $(echo "$S0" | wc -w)))
check "the write costs two segments: one switched by the timeout, one for the checkpoint after it" "$n5 segments: $S5" test "$n5" = 2
check "then nothing for three intervals" "t=900 [$S3] t=1500 [$S5]" test "$S3" = "$S5" -a "$S4" = "$S5"
ajob cp push || die "push: $JSUM"
r1=$(rsize)
res RECORDED "the push of the idle period" "$(echo "$JSUM" | cut -d' ' -f1-2); the repository's archive +$((r1 - r0)) bytes for $((n5 * 16)) MiB of WAL"

stage "2. killed between the copy into the spool and the bookkeeping"
# hold SEG: the next segment switched while the spool refuses uid 70, so it stays .ready.
hold() {
	chmod 0500 "$SP"
	csql "insert into lab.marker values ('r$1')" >/dev/null
	HSEG=$(csql 'select pg_catalog.pg_walfile_name(pg_catalog.pg_switch_wal())')
	_w=0
	until [ "$(csql "select failed_count from pg_catalog.pg_stat_archiver")" -gt "${F0:-0}" ] || [ "$_w" -ge 30 ]; do
		_w=$((_w + 1))
		sleep 1
	done
	# Past the archiver's three quick tries: its next one comes a minute later.
	sleep 4
	install -o 70 -g 70 -m 0600 "$CPP/data/pg_wal/$HSEG" "$SP/$HSEG"
	# The state asked: copied into the spool, not yet recorded. A retry of the archiver
	# before the kill would make the step below vacuous.
	check "held: $HSEG in the spool, its status still .ready" "$(ls "$CPP/data/pg_wal/archive_status" | grep "^$HSEG" | tr '\n' ' ')" \
		test -e "$CPP/data/pg_wal/archive_status/$HSEG.ready" -a -e "$SP/$HSEG"
}
restart() { # the postmaster killed, the spool writable again; Docker restarts the database
	kill -9 "$(docker inspect -f '{{.State.Pid}}' sp-cp-db)"
	chmod 0700 "$SP"
	sleep 2
	cpwait
}
F0=$(csql "select failed_count from pg_catalog.pg_stat_archiver")
hold A
sum0=$(sha256sum <"$SP/$HSEG" | cut -c1-16)
st=$(ls "$CPP/data/pg_wal/archive_status" | grep "^$HSEG")
say "  $HSEG copied into the spool, its status $st"
restart
i=0
until [ -e "$CPP/data/pg_wal/archive_status/$HSEG.done" ] || [ "$i" -ge 60 ]; do
	i=$((i + 1))
	sleep 1
done
sum1=$(sha256sum <"$SP/$HSEG" | cut -c1-16)
check "after the restart the server archives it again: identical bytes accepted, the spool copy unchanged" \
	"status $(ls "$CPP/data/pg_wal/archive_status" | grep "^$HSEG" | tr '\n' ' '); $sum0 -> $sum1" \
	test -e "$CPP/data/pg_wal/archive_status/$HSEG.done" -a "$sum0" = "$sum1"
csql "insert into lab.marker values ('rA2')" >/dev/null
nseg=$(csql 'select pg_catalog.pg_walfile_name(pg_catalog.pg_switch_wal())')
sleep 3
check "the next segment is archived" "$nseg; archiver $(arch)" test -e "$SP/$nseg"
ajob cp push || die "push: $JSUM"
check "the push takes each once" "$(echo "$JSUM" | cut -d' ' -f1-4)" sh -c "echo \"\$1\" | grep -q '^pushed 2 remaining 0'" sh "$JSUM"

stage "2b. the push took the segment before the restart"
F0=$(csql "select failed_count from pg_catalog.pg_stat_archiver")
hold B
chmod 0700 "$SP"
ajob cp push || die "push: $JSUM"
say "  the push took $HSEG from the spool: $(echo "$JSUM" | cut -d' ' -f1-2)"
restart
i=0
until [ -e "$CPP/data/pg_wal/archive_status/$HSEG.done" ] || [ "$i" -ge 60 ]; do
	i=$((i + 1))
	sleep 1
done
check "archived again into the emptied spool" "status $(ls "$CPP/data/pg_wal/archive_status" | grep "^$HSEG" | tr '\n' ' ')" test -e "$SP/$HSEG"
ajob cp push || :
check "pushed again: the repository already holds it with the same bytes, the push succeeds" "$(echo "$JSUM" | cut -c1-80)" \
	sh -c "echo \"\$1\" | grep -q '^pushed 1 remaining 0'" sh "$JSUM"

stage "2c. other bytes at the name in the spool"
F0=$(csql "select failed_count from pg_catalog.pg_stat_archiver")
hold C
cp "$SP/$HSEG" "$KIT/orig"
printf 'OTHER-BYTES' | dd of="$SP/$HSEG" bs=1 seek=1000000 conv=notrunc 2>/dev/null
restart
sleep 8
a=$(arch)
check "refused: the server's archiving stops at that segment" "$a" sh -c "echo '$a' | grep -q 'failed=$HSEG' && [ ! -e '$CPP/data/pg_wal/archive_status/$HSEG.done' ]" sh
csql "insert into lab.marker values ('rC2')" >/dev/null
later=$(csql 'select pg_catalog.pg_walfile_name(pg_catalog.pg_switch_wal())')
sleep 5
check "a later segment is held back behind it" "$later in the spool: $([ -e "$SP/$later" ] && echo yes || echo no); $(arch)" test ! -e "$SP/$later"
install -o 70 -g 70 -m 0600 "$KIT/orig" "$SP/$HSEG.x" && mv "$SP/$HSEG.x" "$SP/$HSEG"
i=0
until [ -e "$SP/$later" ] || [ "$i" -ge 150 ]; do
	i=$((i + 1))
	sleep 1
done
control "the original bytes back: archiving goes on (the server's back-off)" "$([ -e "$SP/$later" ] && echo 1 || echo 0)" "after $i s; $(arch)"
ajob cp push || die "push: $JSUM"

verdict E27 "one write to an idle database costs two segments within two timeout intervals and nothing after them; a segment archived again after a crash between the copy and the bookkeeping is accepted when its bytes are identical (also after the push took it) and refused, holding every later segment back, when they differ"
