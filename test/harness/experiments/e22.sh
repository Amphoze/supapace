# shellcheck shell=sh disable=SC2154 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables
# e22.sh — the object store's conditional create and versions, on the
# stand-in, through the platform's own client (internal/s3x, by sp-probe s3
# and by `supapaced exp mpu`) and the platform's operator check (the probe
# job, `supapaced replicate probe`, by agent.RunJob on the backup network):
#
#   - a single PUT with If-None-Match: * creates an absent key and returns its
#     version; on an existing key it is refused (412) and adds no version (the
#     control: the same PUT without the condition adds one); the first version
#     reads back by its id; a key whose newest version is a delete marker counts
#     as absent (recorded);
#   - ten such PUTs of one absent key at once, three rounds: exactly one wins;
#   - multipart: five uploads of one absent key completed at once with the
#     condition: exactly one wins, the four refused ones are aborted; on the now
#     existing key all five are refused;
#   - a version id written under the default compliance lock is not removed by
#     the write credential nor by the stand-in's admin keys (the control: a
#     delete without a version places a marker);
#   - the listing names each key's versions newest first, the current one first;
#   - the probe job's rows read as expected on the stand-in:
#     versioning, the lock, conditional create (single and multipart), both
#     wrong digests refused, abort, read-only and cross-bucket refusals, the
#     lifecycle rules ok; write-cannot-delete and region-checked not ok (the
#     stand-in's write identity may delete, and it accepts any region).
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e22.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E22
K=$PFX/e22
W=projects-write
body() { head -c "$1" /dev/urandom; }
nver() { s3 projects-read versions "$1" | grep -c "^version \"$1\" " || :; }
vid() { sed -n 's/^version \([^ ]*\)$/\1/p'; }

stage "single PUT with the conditional create"
v1=$(body 1000 | tee "$KIT/s1" | s3 "$W" put "$K/s1" --if-absent | vid)
check "an absent key is created and its version returned" "version ${v1:-none}" test -n "$v1"
got=$(body 1000 | s3 "$W" put "$K/s1" --if-absent 2>&1) || :
n=$(nver "$K/s1")
cur=$(s3 projects-read head "$K/s1" | cut -d' ' -f3)
check "on an existing key it is refused (412) and adds no version" "$got; versions $n; current $cur" \
	test "$got" = exists -a "$n" = 1 -a "$cur" = "$v1"
v2=$(body 1000 | s3 "$W" put "$K/s1" | vid)
control "the same PUT without the condition adds a version" "$([ -n "$v2" ] && [ "$(nver "$K/s1")" = 2 ] && echo 1 || echo 0)" "versions $(nver "$K/s1")"
s=$(s3 projects-read get "$K/s1" --version "$v1" --out "$KIT/s1.get" | cut -d' ' -f3)
check "the first version reads back by its id with its bytes" "sha256 ${s%"${s#????????????}"}…" test "$s" = "$(sha256sum <"$KIT/s1" | cut -d' ' -f1)"
body 10 | s3 "$W" put "$K/s5" >/dev/null
m=$(s3 "$W" rm "$K/s5")
got=$(body 10 | s3 "$W" put "$K/s5" --if-absent 2>&1 | cut -d' ' -f1) || :
res RECORDED "a key whose newest version is a delete marker counts as absent for the condition" "$m; then put --if-absent: $got"

stage "ten conditional PUTs of one absent key at once, three rounds"
ok=0
for r in 1 2 3; do
	i=1
	while [ "$i" -le 10 ]; do
		(body 300000 | s3 "$W" put "$K/race$r" --if-absent >"$KIT/race$r.$i" 2>&1 || :) &
		i=$((i + 1))
	done
	wait
	won=$(grep -l '^version ' "$KIT/race$r".* | wc -l) lost=$(grep -lx exists "$KIT/race$r".* | wc -l) n=$(nver "$K/race$r")
	say "  round $r: created $won, refused $lost, versions $n"
	[ "$won/$lost/$n" = 1/9/1 ] && ok=$((ok + 1))
done
check "exactly one of ten wins, each round" "$ok of 3 rounds" test "$ok" = 3

stage "multipart: five uploads of one key completed at once with the condition"
first=$(ag mpu "$W" "$K/m1" 5)
say "  absent key: $first"
again=$(ag mpu "$W" "$K/m1" 5)
say "  existing key: $again"
check "exactly one completion wins on an absent key; the refused uploads are aborted" "$first" test "$first" = "completed 1 refused 4 other 0 versions 1"
check "every completion is refused on an existing key, no version added" "$again" test "$again" = "completed 0 refused 5 other 0 versions 1"

stage "a locked version"
d1=$(s3 "$W" rm "$K/s1" --version "$v1" 2>&1) || :
d2=$(s3 admin rm "$K/s1" --version "$v1" 2>&1) || :
check "the write credential cannot remove a version under the compliance lock, nor can the admin keys" "$d1; $d2" test "$d1" = denied -a "$d2" = denied
check "the version is still there" "$(s3 projects-read head "$K/s1" --version "$v1" | cut -d' ' -f1)" \
	test "$(s3 projects-read head "$K/s1" --version "$v1" | cut -d' ' -f1)" = object
mk=$(s3 "$W" rm "$K/s1" | cut -d' ' -f1,3)
control "a delete without a version places a marker" "$([ "$mk" = "removed marker=true" ] && echo 1 || echo 0)" "$mk"

stage "the listing's order"
i=1
while [ "$i" -le 5 ]; do
	body 10 | s3 "$W" put "$K/l/a" >/dev/null
	i=$((i + 1))
done
body 10 | s3 "$W" put "$K/l/b" >/dev/null
lst=$(s3 projects-read versions "$K/l/")
printf '%s\n' "$lst" | sed 's/^/  /'
cur=$(s3 projects-read head "$K/l/a" | cut -d' ' -f3)
check "per key newest first: the first entry of l/a is its current version, the others noncurrent" "current $cur" \
	test "$(printf '%s\n' "$lst" | grep -F "\"$K/l/a\"" | head -1 | cut -d' ' -f3,4)" = "$cur latest" \
	-a "$(printf '%s\n' "$lst" | grep -F "\"$K/l/a\"" | grep -c noncurrent)" = 4
dup=$(printf '%s\n' "$lst" | cut -d' ' -f3 | sort | uniq -d | wc -l)
check "no version listed twice" "$dup" test "$dup" = 0

stage "the platform's operator check (probe job) on the projects' bucket"
rows=$(ag job projects probe -prefix "$PFX") || die "the probe job: $rows"
printf '%s\n' "$rows" | grep '^row ' | cut -c1-200 | sed 's/^/  /'
rowis() { printf '%s\n' "$rows" | grep -q "^row $1 $2\( \|$\)"; }
bad=''
for r in versioning default-lock-compliance conditional-create conditional-create-multipart checksum-enforced \
	write-can-abort-multipart read-only-cannot-write projects-credential-cannot-reach-control-plane-bucket \
	lifecycle-noncurrent-rule-present lifecycle-abort-incomplete-rule-present; do
	rowis "$r" true || bad="$bad $r"
done
check "every row the stand-in can pass is ok" "${bad:-all ok}" test -z "$bad"
nd=$(printf '%s\n' "$rows" | grep -cE '^row (write-cannot-delete|region-checked) false' || :)
check "write-cannot-delete and region-checked are not ok on the stand-in" \
	"$(printf '%s\n' "$rows" | grep -E '^row (write-cannot-delete|region-checked) ' | cut -d' ' -f2,3 | tr '\n' ' ')" test "$nd" = 2

verdict E22 "on the stand-in a conditional create, single or at multipart completion, makes an absent key once and refuses an existing one (412) without a version, exactly one of concurrent writers wins, a locked version is kept, and the platform's probe reads every row as expected (write-cannot-delete and region-checked not ok on the stand-in)"
