# E4: XFS user and project quotas on the node's loop-backed filesystem.
#   1. a user quota stops its uid with EDQUOT wherever that uid writes, also in
#      files it has moved to another project id;
#   2. a file's owner can change the file's project id, and so escape its own
#      project limit or spend another project's (control: a non-owner cannot);
#   3. the user inode limit stops file creation with EDQUOT.
# Every limit has a control (the same write under the limit, or by a uid
# without a limit, succeeds).
#
# Run inside the bare node:
#   docker exec -i <node> sh -s < e04.sh
set -eu

P=/var/lib/supapace/projects
A=700401 B=700402 C=700403
DA=$P/e04-a DB=$P/e04-b DS=$P/e04-shared

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
q() { xfs_quota -x -c "$*" "$P"; }
clear_limits() {
	for u in $A $B $C; do q "limit -u bsoft=0 bhard=0 isoft=0 ihard=0 $u" 2>/dev/null || :; done
	for u in $A $B; do q "limit -p bsoft=0 bhard=0 isoft=0 ihard=0 $u" 2>/dev/null || :; done
}
cleanup() {
	rm -rf "$DA" "$DB" "$DS"
	clear_limits
}
trap 'trap "" INT TERM HUP; cleanup' EXIT # a signal during cleanup must not cut it short
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
cleanup

mountpoint -q "$P" || { echo "ERROR: $P is not mounted" >&2; exit 1; }
say "mount: $(grep " $P " /proc/mounts)"
say "kernel $(uname -r), $(xfs_quota -V)"
q "state -u" | grep -E 'Accounting|Enforcement' | sed 's/^ */user    /'
q "state -p" | grep -E 'Accounting|Enforcement' | sed 's/^ */project /'

# musl's text for EDQUOT; ENOSPC reads "No space left on device".
EDQUOT="Quota exceeded"
fail=0
check() { # check LABEL WANT GOT
	case $3 in
	*"$2"*) say "ok    $1: $3" ;;
	*) say "FAIL  $1: want '$2', got '$3'"; fail=1 ;;
	esac
}
check_eq() { # check_eq LABEL WANT GOT: exact match
	if [ "$2" = "$3" ]; then say "ok    $1: $3"; else
		say "FAIL  $1: want '$2', got '$3'"
		fail=1
	fi
}
# as UID DIR CMD...: runs CMD at UID:UID with no supplementary groups in DIR.
# /var/lib/supapace is root 0700, so the tenant could not walk to DIR (as a
# container reaches it through its mount); the working directory is entered as
# root first and CMD uses names relative to it.
as() { (_u=$1 && cd "$2" && shift 2 && setpriv --reuid "$_u" --regid "$_u" --clear-groups "$@"); }
# fill UID DIR NAME MIB: appends MIB MiB to DIR/NAME; prints its size or the error.
# shellcheck disable=SC2016 # expanded by the inner shell
fill() { as "$1" "$2" sh -c 'dd if=/dev/zero of="$1" bs=1M count="$2" conv=notrunc,fsync oflag=append 2>&1 >/dev/null | grep -v -e records -e copied | tr "\\n" " " || :; [ -s "$1" ] && echo "size $(($(stat -c %s "$1") / 1048576)) MiB"' - "$3" "$4"; }
projid() { xfs_io -c stat "$1" | awk '/fsxattr.projid/ { print $3 }'; }
usage_p() { q "quota -p -N -b $1" | awk '{ print $2 }'; }

mkdir -p "$DA" "$DB" "$DS"
chown "$A:$A" "$DA"
chown "$B:$B" "$DB"
chmod 0700 "$DA" "$DB"
chmod 1777 "$DS"
# Project id and inherit flag on each project directory, as the platform sets them.
xfs_io -c "chproj $A" -c "chattr +P" "$DA"
xfs_io -c "chproj $B" -c "chattr +P" "$DB"
check_eq "project ids of e04-a e04-b e04-shared" "$A $B 0" "$(projid "$DA") $(projid "$DB") $(projid "$DS")"

step "1. the user quota (16 MiB on uid $A) holds wherever the uid writes"
q "limit -u bhard=16m $A"
as $A "$DA" sh -c ": > f2 && xfs_io -c 'chproj 0' f2"
check_eq "own file f2 re-tagged to project id 0 by its owner" 0 "$(projid "$DA/f2")"
check "8 MiB in its own directory (control, under the limit)" "size 8 MiB" "$(fill $A "$DA" f1 8)"
check "32 MiB more in its own directory" "$EDQUOT" "$(fill $A "$DA" f1 32)"
rm -f "$DA/f1"
check "32 MiB in a shared directory of another project id" "$EDQUOT" "$(fill $A "$DS" f1 32)"
rm -f "$DS/f1"
check "32 MiB in the re-tagged file" "$EDQUOT" "$(fill $A "$DA" f2 32)"
check "32 MiB by uid $C, which has no limit (control)" "size 32 MiB" "$(fill $C "$DS" c1 32)"
rm -f "$DA"/f* "$DS"/*
q "limit -u bhard=0 $A"

step "2. the owner of a file sets its project id"
q "limit -p bhard=16m $A"
q "limit -p bhard=16m $B"
check "32 MiB into a file of project $A (control: the project limit enforces)" "No space left on device" "$(fill $A "$DA" p1 32)"
rm -f "$DA/p1"
as $A "$DA" sh -c ": > esc && xfs_io -c 'chproj 0' esc"
check_eq "escape: owner re-tags its file to project 0" 0 "$(projid "$DA/esc")"
check "escape: 32 MiB into it, past project $A's 16 MiB" "size 32 MiB" "$(fill $A "$DA" esc 32)"
rm -f "$DA/esc"
as $A "$DA" sh -c ": > borrow && xfs_io -c 'chproj $B' borrow"
check_eq "borrow: owner re-tags its file to project $B" "$B" "$(projid "$DA/borrow")"
check "borrow: 15 MiB into it by uid $A" "size 15 MiB" "$(fill $A "$DA" borrow 15)"
say "project $B usage now $(usage_p $B) KiB (uid $B has written nothing)"
check "borrow: uid $B now cannot write 8 MiB in its own directory" "No space left on device" "$(fill $B "$DB" b1 8)"
as $A "$DS" sh -c ": > nonowner"
check "control: uid $B cannot re-tag a file uid $A owns" "Operation not permitted" "$(as $B "$DS" xfs_io -r -c "chproj $B" nonowner 2>&1 || :)"
rm -f "$DA"/* "$DB"/* "$DS"/*
q "limit -p bhard=0 $A"
q "limit -p bhard=0 $B"

step "3. the user inode limit (1000 on uid $A) enforces"
q "limit -u ihard=1000 $A"
q "limit -u ihard=0 $C"
# touch_n UID DIR N: creates up to N empty files in DIR at UID.
# shellcheck disable=SC2016 # expanded by the inner shell
touch_n() { as "$1" "$2" sh -c 'i=0; while [ $i -lt "$1" ]; do m=$(touch "n$i" 2>&1) || { echo "stopped at $i: $m"; exit 0; }; i=$((i + 1)); done; echo "created $i"' - "$3"; }
mkdir "$DS/a" "$DS/c"
chown $A:$A "$DS/a"
chown $C:$C "$DS/c"
check "1100 empty files by uid $A" "$EDQUOT" "$(touch_n $A "$DS/a" 1100)"
check "1100 empty files by uid $C, no limit (control)" "created 1100" "$(touch_n $C "$DS/c" 1100)"
q "quota -u -N -i $A" | awk '{ print "inodes used by uid '"$A"': " $2 " (hard limit " $4 ")" }'

step "result"
if [ "$fail" = 0 ]; then
	say "VERDICT E4: confirmed — the user quota (blocks and inodes) stops the uid with EDQUOT wherever it writes and whatever project id its files carry, while a file's owner can re-tag it to escape or spend any project limit, so only the user quota can enforce."
else
	say "VERDICT E4: unknown — a check above failed (FAIL lines)."
fi
