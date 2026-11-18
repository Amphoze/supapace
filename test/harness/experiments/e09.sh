# E9: a pgx SCRAM login over a cluster socket reached as
# /proc/self/fd/N/.s.PGSQL.5432, where N is a directory descriptor opened with
# O_PATH|O_DIRECTORY|O_NOFOLLOW; the same dial after the directory's path was
# renamed (control: the absolute path then fails), a wrong password (control:
# authentication is really checked) and a link in place of the directory; then
# a dial through /proc/self/fd/M, M being an O_PATH|O_NOFOLLOW descriptor of the
# checked socket inode, which a link swapped in after the check cannot redirect
# (control: the name-based dial is redirected to a decoy listener).
#
# Needs bin/e09 (CGO_ENABLED=0 go build -o bin/ ./test/harness/experiments/e09).
# Run inside the bare node:
#   cat lib-rest.sh e09.sh | docker exec -i <node> sh -s
set -eu
if [ -z "${LIB_REST:-}" ]; then
	# shellcheck source=/dev/null
	. "$(dirname "$0")/lib-rest.sh"
fi

D=$EXP_ROOT/e09
ROOT=$D/projects
REF=exp09000000000000000
UID_PG=700901
CL=e09-pg
DIAL=$SP_BIN/e09
[ -x "$DIAL" ] || die "$DIAL missing: build it on the workstation into bin/"

cleanup() {
	rm_containers "$CL"
	rm -rf "$D"
	rmdir "$EXP_ROOT" 2>/dev/null || :
}
trap 'trap "" INT TERM HUP; [ -n "${KEEP:-}" ] || cleanup' EXIT # a signal during cleanup must not cut it short
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
cleanup

PG_IMAGE=$(pinned_image supabase/postgres)
say "postgres image: $PG_IMAGE"

fail=0
expect() { # expect PATTERN LABEL: a line of $OUT must match PATTERN
	if printf '%s\n' "$OUT" | grep -q "$1"; then say "ok    $2"; else
		say "FAIL  $2"
		fail=1
	fi
}

step "first boot under the image's own pg_hba; supabase_admin gets a password"
mkdir -p "$ROOT"
chmod 0755 "$D" "$ROOT"
mkdir -p "$ROOT/$REF"
start_cluster "$CL" "$UID_PG" "$ROOT/$REF" --network none
PW=$(rand_hex 24)
(
	umask 077
	printf '%s\n' "$PW" >"$D/pass"
)
printf "set password_encryption = 'scram-sha-256';\nalter role supabase_admin password '%s';\n" "$PW" | sql "$CL"
say "stored verifier: $(printf "select left(rolpassword, 14) from pg_authid where rolname = 'supabase_admin';" | sql "$CL")..."
docker stop -t 30 "$CL" >/dev/null
rm_containers "$CL"

step "second start: socket logins for supabase_admin by SCRAM only"
printf 'local all supabase_admin scram-sha-256\nlocal all all reject\n' >"$D/pg_hba.conf"
chmod 0444 "$D/pg_hba.conf"
WAIT_LOGIN=0 start_cluster "$CL" "$UID_PG" "$ROOT/$REF" --network none \
	-v "$D/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro"
sleep 1
printf 'pg_hba in force: '
docker exec "$CL" sh -c 'cat /etc/postgresql/pg_hba.conf' | tr '\n' ';'
say
INIT=$(docker inspect -f '{{.State.Pid}}' "$CL")
say "init pid (docker inspect): $INIT"

step "descriptor-relative dial"
OUT=$("$DIAL" "$ROOT" "$REF" supabase_admin "$D/pass" 2>&1) || :
printf '%s\n' "$OUT" | sed 's/^/  /'
say
expect '^o_path: ok .*set=true$' "O_PATH = 0x200000 is reported back by F_GETFL"
expect "^stat: ok socket=true uid=$UID_PG\$" "the entry is a socket owned by the project uid"
expect '^nofollow: ok ' "O_NOFOLLOW refuses a link in place of the directory"
expect '^fd-dial: ok current_user=supabase_admin system_user=scram-sha-256:supabase_admin (auth messages \[10 11 12 0\]' "SCRAM login through /proc/self/fd/N (SASL, continue, final, ok)"
expect '^abs-dial: ok ' "control: the absolute path works before the rename"
expect '^fd-dial-wrong-password: error .*password authentication failed.*(auth messages \[10 11\],' "control: a wrong password fails inside the SCRAM exchange"
expect '^fd-dial-after-rename: ok current_user=supabase_admin' "the descriptor path still reaches the socket after the rename"
expect '^abs-dial-after-rename: error .*no such file or directory' "control: the absolute path fails after the rename"
expect "^inode-dial: ok current_user=supabase_admin system_user=scram-sha-256:supabase_admin (auth messages \\[10 11 12 0\\], peer pid $INIT)" "SCRAM login through /proc/self/fd/M of the checked socket inode"
expect "^inode-dial-after-swap: ok current_user=supabase_admin .*peer pid $INIT)" "after the name is swapped for a link to a decoy, the inode dial still reaches the postmaster"
DPID=$(printf '%s\n' "$OUT" | sed -n 's/^decoy: .* this process is pid \([0-9]*\)$/\1/p')
expect "^name-dial-after-swap: error .*peer pid $DPID)" "control: the name-based dial is redirected to the decoy (peer pid $DPID = the helper itself)"
expect '^decoy: 1 connection(s)' "control: the decoy received exactly that one connection"

step "result"
if [ "$fail" = 0 ]; then
	say "VERDICT E9: confirmed — net.Dial(\"unix\") accepts /proc/self/fd/N/.s.PGSQL.5432 for an O_PATH|O_DIRECTORY|O_NOFOLLOW descriptor, pgx completes SCRAM over it, and it keeps working after the directory is renamed while the absolute path fails; a dial through the checked socket inode (/proc/self/fd/M) is not redirected by a link swapped in after the check."
else
	say "VERDICT E9: fallback — the descriptor-relative dial did not behave as required (FAIL lines above); dial by absolute path after the stat check."
fi
