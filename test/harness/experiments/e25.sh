# shellcheck shell=sh disable=SC2154,SC2034,SC2010,SC2012 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables (fixed spool names)
# e25.sh — what is left of the recovery path, five parts, each with the
# platform's code: the agent's recovery start (pgconf.RecoveryPins: every
# unused target emptied first, the chosen one last), the daemon's job programs
# (push with its timeline filter, restore, serve, check, backup, replicate,
# fetch, seed) and the agent's re-key, which reads the timeline.
#
#   a. a time target beyond the end of the archive: no promotion (the server
#      stops with "recovery ended before configured recovery target"); the
#      control on the same path, a target inside the archive, promotes;
#   b. a repository seeded from the chosen set's start segment while its info
#      files list an older set: restore, check, a full backup succeed, and
#      pgBackRest's verify, info and expire accept it (no platform job runs
#      those three; they read the same repository);
#   c. replay through a segment altered in the spool after it was archived
#      there: to the end of the archive it promotes at the altered record (the
#      later rows missing, silently); a time target past it does not promote;
#   d. a stop between the promotion and the re-key, local and off-site: the
#      next push admits the pending timeline, its history reaches the
#      repository (and the store, and the next fetch), the next attempt
#      promotes the next number and the re-key reads it; the control: a fetch
#      that leaves the abandoned history out promotes the same number again and
#      the next copy finds the store's history differs (offsite-differs);
#   e. a cluster that promotes itself (the project's uid inside its container):
#      the push quarantines the new timeline's names, the owner's restore takes
#      the pending timeline unobstructed, check, backup and archiving go on.
#
# Not asked: another order of the recovery pins — the build has one (a unit
# test of internal/pgconf pins it).
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e25.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E25
mark() { asql "$1" "insert into public.marker (n) values ($2)" >/dev/null; }
switch() { asql "$1" 'select pg_catalog.pg_switch_wal()' >/dev/null; }
# markers REF: the marker rows, in a recovery start (trust) or a normal start (SCRAM).
markers() {
	_q="select pg_catalog.string_agg(n::text, ',' order by n) from public.marker"
	atsql "$1" "$_q" 2>/dev/null || asql "$1" "$_q"
}
utc() { asql "$1" "select pg_catalog.to_char((pg_catalog.clock_timestamp() $2) at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') || '+00'"; }
# fresh REF UID SLICE: a project, its stanza, a marker table, a full backup ($SET its label).
fresh() {
	ag_project "$1" "$2" "$3" 2048 1024
	asql "$1" 'create table public.marker (n int primary key)' >/dev/null
	ajob "$1" stanza-create || die "stanza-create $1: $JSUM"
	ajob "$1" backup || die "backup $1: $JSUM"
	SET=$(echo "$JSUM" | sed -n 's/^label \([^ ]*\) .*/\1/p')
	START=$(echo "$JSUM" | sed -n 's/.* start \([0-9A-F]*\) .*/\1/p')
}
# attempt REF [RECOVER OPTIONS]: wipe, restore $SET, the recovery start; its status.
attempt() {
	_r=$1
	shift
	restore_set "$_r" "$SET" || return 1
	arecover "$_r" "$@"
}
rekey_tl() { ag rekey "$1" | sed -n 's/^rekey timeline \([0-9]*\) .*/\1/p'; }
hist() { find "$REPO/$1/repo/archive" -name '*.history' 2>/dev/null | sed 's|.*/||' | sort | tr '\n' ' '; }

stage "a. a time target beyond the end of the archive"
B=e25a0000000000000001
fresh "$B" 700851 1
mark "$B" 1
mark "$B" 2
sleep 1
TIN=$(utc "$B" "")
sleep 1
mark "$B" 3
switch "$B"
TOUT=$(utc "$B" "+ interval '1 hour'")
ag stop "$B"
ajob "$B" push || die "push: $JSUM"
s=0
attempt "$B" -time "$TOUT" -timeline current -wait 120 || s=$?
f=$(docker logs "pg-$B" 2>&1 | grep -c 'recovery ended before configured recovery target was reached' || :)
check "beyond the end: no promotion, the server stops at the end of the archive" "$RLINE; $f such lines" \
	sh -c "[ $s != 0 ] && [ $f -ge 1 ] && echo \"\$1\" | grep -q '^exited after'" sh "$RLINE"
attempt "$B" -time "$TIN" -timeline current || die "inside: $RLINE"
m=$(markers "$B")
control "the same path with a target inside the archive promotes, to the target" "$([ "$m" = 1,2 ] && echo 1 || echo 0)" "markers $m"
ag stop "$B"

stage "b. a repository seeded from the chosen set's start while its info files list an older set"
C=e25b0000000000000002
fresh "$C" 700852 2
F1=$SET
mark "$C" 1
asql "$C" "create table public.bulk as select g, pg_catalog.repeat('x', 500) v from pg_catalog.generate_series(1, 60000) g" >/dev/null
switch "$C"
mark "$C" 2
switch "$C"
ajob "$C" backup || die "second backup: $JSUM"
SET=$(echo "$JSUM" | sed -n 's/^label \([^ ]*\) .*/\1/p') START=$(echo "$JSUM" | sed -n 's/.* start \([0-9A-F]*\) .*/\1/p')
mark "$C" 3
switch "$C"
ag stop "$C"
ajob "$C" push || die "push: $JSUM"
ajob "$C" replicate -prefix "$PFX" || die "replicate: $JSUM"
say "  sets $F1 (older) and $SET (chosen, from $START); repository: $(find "$REPO/$C/repo/archive" -name '*.zst' | wc -l) archived segments"
ag rmfetch "$C"
ajob "$C" fetch -prefix "$PFX" -from "$START" || die "fetch: $JSUM"
jsay "$C" fetch
ajob "$C" seed || die "seed: $JSUM"
jsay "$C" seed
first=$(find "$REPO/$C/repo/archive" -name '*.zst' | sed 's|.*/||' | sort | head -1 | cut -c1-24)
control "the seeded repository's archive begins at the chosen set's start" "$([ "$first" = "$START" ] && echo 1 || echo 0)" "first $first"
attempt "$C" -timeline latest || die "restore of the seeded repository: $RLINE"
tl=$(rekey_tl "$C")
ag stop "$C"
ag start "$C"
ok=0
for k in check backup; do
	if ajob "$C" "$k" -tl 1,2; then ok=$((ok + 1)); fi
	jsay "$C" "$k"
done
for c in verify info "expire --repo1-retention-full=2" verify; do
	# shellcheck disable=SC2086 # a command and its options
	if out=$(LLC=info worker "$C" push pgbackrest $c 2>&1); then ok=$((ok + 1)); fi
	say "  pgbackrest $c: $(printf '%s\n' "$out" | grep -E 'completed|status|ERROR|expire full' | tail -2 | tr '\n' ' ' | cut -c1-200)"
done
check "restore (timeline $tl), check, a full backup, verify, info, expire and verify again all succeed" "$ok of 6" test "$ok" = 6 -a "$(markers "$C")" = 1,2,3
ag stop "$C"

stage "c. replay through a segment altered in the spool"
D=e25c0000000000000003
fresh "$D" 700853 3
mark "$D" 1
asql "$D" 'create table public.bulk (g int, v text)' >/dev/null
for i in 2 3 4 5; do
	asql "$D" "insert into public.bulk select g, pg_catalog.repeat('y', 900) from pg_catalog.generate_series(1, 20000) g" >/dev/null
	mark "$D" "$i"
	eval "SEG$i=\$(asql \"\$D\" 'select pg_catalog.pg_walfile_name(pg_catalog.pg_current_wal_lsn())')"
done
sleep 1
TEND=$(utc "$D" "")
switch "$D"
ag stop "$D"
CSEG=$(ls "$P/$D/spool" | grep -E '^[0-9A-F]{24}$' | sort | awk -v s="$SEG3" '($1 "") > (s "") { print; exit }')
[ -n "$CSEG" ] || die "no spooled segment after $SEG3: $(ls "$P/$D/spool" | tr '\n' ' ')"
printf 'ALTERED-IN-THE-SPOOL' | dd of="$P/$D/spool/$CSEG" bs=1 seek=8000000 conv=notrunc 2>/dev/null
say "  markers 3 and 4 in $SEG3 and $SEG4; 20 bytes altered at offset 8000000 of $CSEG"
ajob "$D" push || die "push: $JSUM"
attempt "$D" -timeline latest || die "end of the archive: $RLINE"
m=$(markers "$D")
say "  $(docker logs "pg-$D" 2>&1 | grep -E 'incorrect resource manager|invalid record|redo done' | head -2 | cut -c1-160 | tr '\n' ' ')"
check "to the end of the archive it promotes at the altered record; the later rows are missing" "markers $m" test "$m" = 1,2,3
ag stop "$D"
s=0
attempt "$D" -time "$TEND" -timeline current -wait 120 || s=$?
check "a time target past the altered record does not promote" "$RLINE" sh -c "[ $s != 0 ] && echo \"\$1\" | grep -q '^exited after'" sh "$RLINE"
ag stop "$D"

stage "d. a stop between promotion and the re-key, local"
E=e25d0000000000000004
fresh "$E" 700854 4
mark "$E" 1
switch "$E"
ag stop "$E"
ajob "$E" push -tl 1 || die "push: $JSUM"
attempt "$E" -timeline latest || die "attempt 1: $RLINE"
docker kill "pg-$E" >/dev/null
say "  stopped between promotion and the re-key; spool: $(ls "$P/$E/spool" | tr '\n' ' ')"
ajob "$E" push -tl 1,2 || die "re-entry push: $JSUM"
say "  re-entry push (admitted 1 and the pending 2): $(echo "$JSUM" | cut -d' ' -f1-2); repository histories: $(hist "$E")"
attempt "$E" -timeline latest || die "attempt 2: $RLINE"
tl=$(rekey_tl "$E")
check "the next attempt promotes timeline 3 (2 is held by the abandoned history), and the re-key reads it" "timeline $tl" test "$tl" = 3
ag stop "$E"
ag start "$E"
mark "$E" 2
switch "$E"
ok=0
for k in check backup; do
	if ajob "$E" "$k" -tl 1,2,3; then ok=$((ok + 1)); fi
done
ctl=$(asql "$E" 'select timeline_id from pg_catalog.pg_control_checkpoint()')
check "check and a full backup on timeline 3" "$ok of 2; the server's timeline $ctl; histories $(hist "$E")" test "$ok" = 2 -a "$ctl" = 3
ag stop "$E"

stage "d. the same, off-site: push, copy, fetch and seed at each entry"
F=e25e0000000000000005
fresh "$F" 700855 5
mark "$F" 1
switch "$F"
ag stop "$F"
offsite_entry() { # REF TIMELINES: push, copy, fetch (the admitted timelines), seed
	ajob "$1" push -tl "$2" || die "push: $JSUM"
	ajob "$1" replicate -prefix "$PFX" -tl "$2" || die "replicate: $JSUM"
	ag rmfetch "$1"
	ajob "$1" fetch -prefix "$PFX" -tl "$2" || die "fetch: $JSUM"
	ajob "$1" seed || die "seed: $JSUM"
	say "  entry admitting $2: seeded histories: $(hist "$1")"
}
offsite_entry "$F" 1
attempt "$F" -timeline latest || die "attempt 1: $RLINE"
docker kill "pg-$F" >/dev/null
offsite_entry "$F" 1,2
attempt "$F" -timeline latest || die "attempt 2: $RLINE"
tl=$(rekey_tl "$F")
check "off-site: the next attempt promotes timeline 3, read by the re-key" "timeline $tl" test "$tl" = 3
ag stop "$F"
ag start "$F"
mark "$F" 2
switch "$F"
ajob "$F" backup -tl 1,2,3 || die "backup: $JSUM"
ag stop "$F"
ajob "$F" push -tl 1,2,3 || die "push: $JSUM"
ajob "$F" replicate -prefix "$PFX" -tl 1,2,3 || :
jsay "$F" replicate
check "the copy after it finds nothing that differs" "$(echo "$JSUM" | sed 's/.*notices //')" sh -c "echo \"\$1\" | grep -qF 'notices []'" sh "$JSUM"

stage "d. control: the re-entry's fetch leaves the abandoned history out"
G=e25f0000000000000006
fresh "$G" 700856 6
mark "$G" 1
switch "$G"
ag stop "$G"
offsite_entry "$G" 1
attempt "$G" -timeline latest || die "attempt 1: $RLINE"
docker kill "pg-$G" >/dev/null
ajob "$G" push -tl 1,2 || die "push: $JSUM"
ajob "$G" replicate -prefix "$PFX" -tl 1,2 || die "replicate: $JSUM"
ag rmfetch "$G"
ajob "$G" fetch -prefix "$PFX" -tl 1 || die "fetch: $JSUM"
ajob "$G" seed || die "seed: $JSUM"
attempt "$G" -timeline latest || die "attempt 2: $RLINE"
tl=$(rekey_tl "$G")
ag stop "$G"
ag start "$G"
mark "$G" 2
switch "$G"
ag stop "$G"
ajob "$G" push -tl 1,2 || :
ajob "$G" replicate -prefix "$PFX" -tl 1,2 || :
jsay "$G" replicate
control "without the abandoned history the number 2 is promoted again and the next copy finds the store's history differs" \
	"$([ "$tl" = 2 ] && echo "$JSUM" | grep -q 'offsite-differs' && echo 1 || echo 0)" "timeline $tl; $(echo "$JSUM" | sed 's/.*notices //')"

stage "e. a cluster that promotes itself, then the owner's restore"
H=e25g0000000000000007 UH=700857
fresh "$H" "$UH" 7
mark "$H" 1
switch "$H"
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
say "  after $i s: $(docker logs "pg-$H" 2>&1 | grep -E 'selected new timeline|archive recovery complete' | cut -c1-100 | tr '\n' ' ')"
mark "$H" 2
switch "$H"
sleep 2
ag stop "$H"
ajob "$H" push -tl 1 || die "push: $JSUM"
jsay "$H" push
check "the push sets the self-promoted timeline's names aside (timeline), pushes none of them" "$(echo "$JSUM" | sed 's/.*quarantined //' | cut -c1-200)" \
	sh -c "echo \"\$1\" | grep -q '00000002.history:timeline' && [ -d '$REPO/$H/repo/archive/$H-1/17-1' ] && ! ls '$REPO/$H/repo/archive/$H-1/17-1/' | grep -q '^00000002'" sh "$JSUM"
attempt "$H" -timeline latest || die "the owner's restore: $RLINE"
tl=$(rekey_tl "$H")
check "the owner's restore takes the pending timeline 2 unobstructed" "timeline $tl; markers $(markers "$H")" test "$tl" = 2
ag stop "$H"
ag start "$H"
ok=0
for k in check backup; do
	if ajob "$H" "$k" -tl 1,2; then ok=$((ok + 1)); fi
done
mark "$H" 3
switch "$H"
sleep 2
a=$(asql "$H" "select archived_count || ' archived, ' || failed_count || ' failed' from pg_catalog.pg_stat_archiver")
check "check, a full backup and archiving go on" "$ok of 2; $a" sh -c "[ $ok = 2 ] && echo '$a' | grep -q ' 0 failed$'" sh

verdict E25 "a time target beyond the archive does not promote; a repository seeded from the chosen set passes check, backup, verify, info and expire; replay through an altered segment promotes there (silently short) or not at all for a later target; a stop between promotion and the re-key leaves a history that makes the next attempt take the next timeline, locally and off-site (without it the number is reused and the copy flags it); a self-promoted timeline is set aside and the owner's restore is unobstructed"
