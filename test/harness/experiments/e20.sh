# shellcheck shell=sh disable=SC2154,SC2010 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables (fixed spool and repository names)
# e20.sh — the repository filesystem: does the replicator's identity (uid
# 65530, the project's gid as its only supplementary group) read every
# directory and regular file the platform's jobs write into a project's repo/?
#
# A layout-2 project as the agent creates it; the platform's job programs
# (stanza-create, check, a full backup, twenty pushes) write its repository. Then:
#   - the listing of repo/: every directory 0750, every regular file 0640, all
#     of the project's uid and gid, pgBackRest's one `latest` link beside them;
#   - the platform's replication job (agent.RunJob: 65530:65530 with the
#     project's group, repo/ read-only, on the backup network, to the
#     object-store stand-in) uploads every regular file, with no notice;
#   - the same read at 65530 without the group is refused at the top directory,
#     and with the group it reads every file with the owner's bytes (the
#     control: the read is the group's, not "other");
#   - entries the project's own uid can make in its repository: a file made
#     0600, a link with a segment's name, a FIFO with a segment's name — the
#     replication job uploads none of them, ends without blocking and names
#     them in its notice; the file made 0640 again is uploaded by the next copy.
#
# Not asked here: other umask settings of the worker — the job
# environment pins PGBACKREST_NEUTRAL_UMASK=y (internal/bkjob) and the launch
# takes no umask, so the product has no such variant; the ACL fallback, which
# was not built.
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e20.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E20
R=e20rf000000000000001 U=700820
stage "project $R and its repository"
ag_project "$R" "$U" 1 2048 1024
asql "$R" 'create table public.mark (n int primary key, t text)' >/dev/null
for k in stanza-create check backup; do
	ajob "$R" "$k" || { jsay "$R" "$k"; die "$k failed"; }
	jsay "$R" "$k"
done
# spooled REF NAME: waits (60 s) until the archive command has put NAME in the spool.
spooled() {
	_w=0
	until [ -e "$P/$1/spool/$2" ]; do
		_w=$((_w + 1))
		[ "$_w" -le 300 ] || return 1
		sleep 0.2
	done
}
i=1
while [ "$i" -le 20 ]; do
	asql "$R" "insert into public.mark values ($i, pg_catalog.md5(pg_catalog.random()::text))" >/dev/null
	seg=$(asql "$R" 'select pg_catalog.pg_walfile_name(pg_catalog.pg_switch_wal())')
	spooled "$R" "$seg" || die "segment $seg not spooled"
	ajob "$R" push || { jsay "$R" push; die "push $i failed"; }
	i=$((i + 1))
done
say "  20 pushes, last $seg"

stage "what the jobs wrote into repo/"
RP=$REPO/$R/repo
list=$(find "$RP" -mindepth 1 -exec stat -c '%F %a %u %g' {} + | sort | uniq -c)
printf '%s\n' "$list" | sed 's/^/  /'
files=$(find "$RP" -type f | wc -l)
other=$(find "$RP" -mindepth 1 \( -type d ! -perm 0750 \) -o \( -type f ! -perm 0640 \) -o \( ! -type d ! -type f ! -name latest \) -o ! -user "$U" -o ! -group "$U" | wc -l)
links=$(find "$RP" -type l | sed "s|^$RP/||")
check "every directory 0750, every file 0640, all at the project's ids; one link, latest" "$files files; other entries $other; links: $links" \
	test "$other" = 0 -a "$files" -gt 100 -a "$(printf '%s\n' "$links" | sed 's|.*/||')" = latest

stage "the platform's replication job reads repo/ at 65530 with the project's group"
ajob "$R" replicate -prefix "$PFX" || die "replication: $JOUT"
jsay "$R" replicate
up=$(printf '%s\n' "$JSUM" | sed -n 's/^uploaded \([0-9]*\) adopted \([0-9]*\) info \([0-9]*\) .*/\1 \2 \3/p')
# shellcheck disable=SC2086 # three numbers
set -- $up
check "every regular file of repo/ uploaded (data files and the four info files), no notice" \
	"uploaded $1 + info $3 of $files files; notices: $(printf '%s\n' "$JSUM" | sed 's/.*notices //')" \
	test "$(($1 + $3))" = "$files" -a "$2" = 0 -a -n "$(printf '%s\n' "$JSUM" | grep -F 'notices []')"
onl=$(s3 projects-read versions "$PFX/$R/" | grep -c ' latest$' || :)
check "the stand-in lists one current object per file, read with the read-only credential" "$onl objects" test "$onl" = "$files"

stage "the read is the group's: 65530 without and with the project's group"
# reader GROUPADD: sha256 of every regular file below /repo, read at 65530 (no network, the job's hardening).
reader() {
	# shellcheck disable=SC2086 # option lists
	docker run --rm --name "$N-reader-$R" --label supapace.test=1 --user "$REPL:$REPL" $1 $JOB_FLAGS --network none \
		-v "$RP:/repo:ro" "$WK_IMAGE" sh -c 'cd /repo && find . -type f | sort | while IFS= read -r f; do sha256sum "$f"; done' 2>&1
}
own=$(cd "$RP" && find . -type f | sort | while IFS= read -r f; do sha256sum "$f"; done)
with=$(reader "--group-add $U") || :
without=$(reader "") || :
control "65530 with the project's group reads every file with the owner's bytes" \
	"$([ "$with" = "$own" ] && echo 1 || echo 0)" "$(printf '%s\n' "$with" | grep -c .) of $files files equal"
check "65530 without the group reads nothing: the top directory refuses it" "$(printf '%s\n' "$without" | head -1)" \
	sh -c "printf '%s\n' \"\$1\" | grep -q 'Permission denied' && ! printf '%s\n' \"\$1\" | grep -qE '^[0-9a-f]{64} '" sh "$without"

stage "entries the project's uid makes in its own repository"
A=archive/$R-1/17-1/0000000100000000
# A new segment, archived and pushed, then made unreadable to the group by its owner.
asql "$R" "insert into public.mark values (21, 'x')" >/dev/null
nseg=$(asql "$R" 'select pg_catalog.pg_walfile_name(pg_catalog.pg_switch_wal())')
spooled "$R" "$nseg" || die "segment $nseg not spooled"
ajob "$R" push || die "push: $JSUM"
newf=$(cd "$RP/$A" && ls | grep "^$nseg-")
# The link points at a readable segment of the project (0640, its ids): only
# not following links keeps it out of the copy.
oldf=$(cd "$RP/$A" && ls | grep -v "^$nseg-" | head -1)
[ -f "$RP/$A/$oldf" ] || die "no other segment in $A"
owner() {
	# shellcheck disable=SC2086 # option list
	docker run --rm --name "$N-owner-$R" --label supapace.test=1 --user "$U:$U" $JOB_FLAGS --network none -v "$RP:/repo" \
		"$WK_IMAGE" sh -c "$1"
}
owner "chmod 0600 /repo/$A/$newf && ln -s $oldf /repo/$A/0000000100000000000000F1-0123456789abcdef0123456789abcdef01234567.zst && mkfifo /repo/$A/0000000100000000000000F2-0123456789abcdef0123456789abcdef01234567.zst" ||
	die "the owner's entries"
t0=$(date +%s)
ajob "$R" replicate -prefix "$PFX" || :
jsay "$R" replicate
t1=$(($(date +%s) - t0))
check "the copy ends (no read blocks on the FIFO) and uploads nothing new" "$t1 s; $(printf '%s\n' "$JSUM" | cut -d' ' -f1-2)" \
	sh -c "printf '%s\n' \"\$1\" | grep -q '^uploaded 0 ' && [ $t1 -lt 120 ]" sh "$JSUM"
check "it names the entries it could not take in a notice" "$(printf '%s\n' "$JSUM" | sed 's/.*notices //')" \
	sh -c "printf '%s\n' \"\$1\" | grep -qE 'notices \[.*unlisted-entry:2' && printf '%s\n' \"\$1\" | grep -qE 'notices \[.*unreadable-entry:[1-9]'" sh "$JSUM"
got=$(s3 projects-read head "$PFX/$R/$A/$newf" 2>&1 | head -1)
check "the 0600 segment is not in the store" "$got" test "$got" = not-found
owner "chmod 0640 /repo/$A/$newf && rm /repo/$A/0000000100000000000000F1-0123456789abcdef0123456789abcdef01234567.zst /repo/$A/0000000100000000000000F2-0123456789abcdef0123456789abcdef01234567.zst"
ajob "$R" replicate -prefix "$PFX" || die "replication after the repair: $JSUM"
jsay "$R" replicate
got=$(s3 projects-read head "$PFX/$R/$A/$newf" 2>&1 | cut -d' ' -f1)
control "made 0640 again, the segment is uploaded by the next copy" "$([ "$got" = object ] && echo 1 || echo 0)" "$got"

verdict E20 "the replicator's identity with the project's group reads every directory (0750) and regular file (0640) the platform's jobs write into repo/; without the group it reads nothing; an entry the project's uid makes unreadable, a link or a FIFO stalls only that entry, named in a notice"
