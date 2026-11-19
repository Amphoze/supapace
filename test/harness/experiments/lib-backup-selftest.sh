# shellcheck shell=sh disable=SC2154,SC2010 # run after lib-backup.sh, which sets the lab's variables (fixed spool names)
# lib-backup-selftest.sh — the kit's own test: one project end to end on a bare
# node. Stanza, full backup, three pushes (the third with an entry of a timeline
# that is not admitted), a copy to the object-store stand-in and back, a
# time-target restore from the repository, the re-key and the networked start
# after it. Prints "SELFTEST ok" when every line passes.
#
#   test/harness/experiments/bk/lab.sh <node> test/harness/experiments/lib-backup-selftest.sh

lab_up
R=bkselftest0000000001 U=700571
step "project $R"
mk "$R" "$U" 1
sql "$R" 'create table public.marker (n int primary key, t timestamptz not null default pg_catalog.clock_timestamp())'
check "networked start with the archive pins" "$(sql "$R" 'show archive_command')" \
	test "$(sql "$R" 'show archive_command')" = "/opt/supapace/tools/supapace-arch push %p %f # pgbackrest"

step "stanza and full backup"
check "stanza-create" "" job "$R" stanza-create
check "full backup" "" job "$R" backup --type=full
sets=$(worker "$R" db pgbackrest info | grep -c 'full backup: ' || :)
check "one full set in the repository" "$sets set(s)" test "$sets" = 1

# spool_segment REF: waits (60 s) until the archive command has put a segment in the spool.
spool_segment() {
	_w=0
	until ls "$P/$1/spool" | grep -qE '^[0-9A-F]{24}$'; do
		_w=$((_w + 1))
		[ "$_w" -le 60 ] || return 1
		sleep 1
	done
}
step "three pushes"
for k in 1 2 3; do
	sql "$R" "insert into public.marker (n) values ($k)"
	[ "$k" != 2 ] || T=$(sql "$R" 'select pg_catalog.clock_timestamp()')
	sql "$R" 'select pg_catalog.pg_switch_wal()' >/dev/null
	spool_segment "$R" || die "no segment reached the spool after marker $k"
	if [ "$k" = 3 ]; then
		# An entry of timeline 2, which is not admitted: the filter's negative.
		printf 'x' >"$P/$R/spool/000000020000000000000009"
		chown "$U:$U" "$P/$R/spool/000000020000000000000009"
	fi
	out=$(pushall "$R") || :
	n=$(printf '%s\n' "$out" | sed -n 's/^push: pushed \([0-9]*\) quarantined \([0-9]*\)$/\1 \2/p')
	left=$(ls "$P/$R/spool" | grep -cv '^quarantine$' || :)
	check "push $k: segments pushed, the spool empty" "pushed/quarantined ${n:-none}, $left left" \
		test "${n%% *}" -ge 1 -a "$left" = 0
done
control "push 3 pushed honest segments" "$([ "${n%% *}" -ge 1 ] && echo 1 || echo 0)" "pushed ${n%% *}"
check "an entry of a timeline not admitted is quarantined, not pushed" "quarantined ${n#* }" \
	test "${n#* }" = 1 -a -e "$P/$R/spool/quarantine/000000020000000000000009"
before=$(sql "$R" "select pg_catalog.string_agg(n::text, ',' order by n) from public.marker")
control "markers 1 to 3 in the source" "$([ "$before" = 1,2,3 ] && echo 1 || echo 0)" "$before"

step "copy to the stand-in and back"
if [ -e "$S3D/endpoint" ]; then
	# A fresh prefix per run: the stand-in keeps what earlier runs on this node wrote.
	PFX=lab/$R-$LAB_T0/
	files=$(find "$REPO/$R/repo" -type f | wc -l)
	out=$(copy_out "$R" "$PFX" | tail -1) || :
	check "copy_out uploads every regular file of the repository" "$out; $files files" \
		test "$out" = "copy: uploaded $files existing 0 failed 0"
	infos=$(find "$REPO/$R/repo" -type f \( -name '*.info' -o -name '*.info.copy' \) | wc -l)
	out=$(copy_out "$R" "$PFX" | tail -1) || :
	check "a second copy_out writes only the info files again" "$out" \
		test "$out" = "copy: uploaded $infos existing $((files - infos)) failed 0"
	key=$(cd "$REPO/$R/repo" && find . -type f -name archive.info | sed 's|^\./||')
	got=$(s3 projects-read head "$PFX$key" || :)
	check "s3 reads an uploaded object with the read-only role" "$got" test "${got%% *}" = object
	# Two names a repository never holds: one with a space, one with a dot part.
	for k in "${PFX}backup/a b" "${PFX}archive/.hidden"; do printf x | s3 projects-write put "$k" >/dev/null; done
	out=$(copy_back "$R" "$PFX" | tail -1) || :
	check "copy_back fetches every current object of the repository, refuses the two other names" "$out" \
		test "$out" = "copy: fetched $files refused 2 failed 0"
	check "nothing of a refused name is in fetch/" "" test ! -e "$REPO/$R/fetch/backup/a" -a ! -e "$REPO/$R/fetch/backup/a b" -a ! -e "$REPO/$R/fetch/archive/.hidden"
	bad=$(find "$REPO/$R/fetch" \( -type f ! -perm 0640 \) -o \( -type d ! -perm 2750 \) -o ! -group "$U" | wc -l)
	check "fetch/ files 0640, directories 2750, all of the project's group" "$bad other" test "$bad" = 0
	sums() { (cd "$1" && find . -type f -exec sha256sum {} + | sort -k2); }
	check "the fetched tree equals the repository" "$(sums "$REPO/$R/fetch" | wc -l) files" \
		test "$(sums "$REPO/$R/fetch")" = "$(sums "$REPO/$R/repo")"
	# A name with a space in the repository is one object, not two words (the control: infos and files above).
	sp="$REPO/$R/repo/zz a b"
	printf x >"$sp" && chmod 0640 "$sp" && chown "$U:$U" "$sp"
	out=$(copy_out "$R" "$PFX" | tail -1) || :
	rm -f "$sp"
	check "copy_out uploads a file whose name holds a space as one object" "$out" \
		test "$out" = "copy: uploaded $((infos + 1)) existing $((files - infos)) failed 0"
else
	res UNRUN "copy to the stand-in and back" "no stand-in beside this node (SP_OFFSITE=0)"
fi

step "time-target restore from the repository (to $T)"
stopc "$R"
wipe "$R"
check "restore" "" restore_files "$R"
check "recovery start promoted" "" recover "$R" -time "$T" -timeline current
after=$(tsql "$R" "select pg_catalog.string_agg(n::text, ',' order by n) from public.marker")
check "markers up to the target only" "$after (before: $before)" test "$after" = 1,2
out=$(rekey "$R" 1) || :
check "re-key on the new timeline" "$out" test "${out% reset *}" = "rekey ok timeline 2"
stopc "$R"
cluster "$R" B
wait_sql "$R"
check "networked start after the restore, the new password" "" test "$(sql "$R" 'select count(*) from public.marker')" = 2
s=0
"$BK" sql "$R" "$U" "$(pid_of "$R")" 0 'select 1' >/dev/null 2>&1 || s=$?
check "the password before the re-key is refused" "exit $s" test "$s" = 1

step "labels"
# Every container the lab created, also those already removed, from Docker's own record.
ev=$(docker events --since "$LAB_T0" --until "$(date +%s)" --filter type=container --filter event=create \
	--format '{{.Actor.Attributes.name}} {{index .Actor.Attributes "supapace.test"}}')
control "the event record lists the lab's containers" "$([ "$(printf '%s\n' "$ev" | grep -c .)" -ge 10 ] && echo 1 || echo 0)" "$(printf '%s\n' "$ev" | grep -c .) created"
unc=$(printf '%s\n' "$ev" | grep -v ' 1$' || :)
check "every container created since lab_up carried supapace.test=1" "${unc:-none without it}" test -z "$unc"
unl=$(docker ps -a --format '{{.Names}} {{.Label "supapace.test"}}' | grep -v ' 1$' || :)
unn=$(docker network ls --format '{{.Name}} {{.Label "supapace.test"}}' | grep -Ev '^(bridge|host|none) |  *1$' || :)
check "every container and network of the lab carries supapace.test=1" "${unl:-}${unn:-none unlabelled}" test -z "$unl$unn"

finish SELFTEST && say "SELFTEST ok"
