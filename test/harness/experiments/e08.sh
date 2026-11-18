# E8: the peer credentials (SO_PEERCRED) a cluster's Unix socket reports to a
# client in the node's root namespace, against the container's init pid from
# docker inspect: across many connections, forked backends, a configuration
# reload and a crash-restart cycle; /proc/<pid>/stat start time readable and
# stable; and, as the control, what a different process listening at the same
# path reports.
#
# The helper refuses a peer pid of 0 or 1 (exit 3) and an unreadable
# /proc/<pid>/stat (exit 4); both refusals are shown.
#
# Needs bin/e08 (CGO_ENABLED=0 go build -o bin/ ./test/harness/experiments/e08).
# Run inside the bare node:
#   cat lib-rest.sh e08.sh | docker exec -i <node> sh -s
set -eu
if [ -z "${LIB_REST:-}" ]; then
	# shellcheck source=/dev/null
	. "$(dirname "$0")/lib-rest.sh"
fi

D=$EXP_ROOT/e08
UID_PG=700801
CL=e08-pg
PEER=$SP_BIN/e08
[ -x "$PEER" ] || die "$PEER missing: build it on the workstation into bin/"

cleanup() {
	rm_containers "$CL"
	pkill -f 'serve-fd' 2>/dev/null || :
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
say "kernel: $(uname -r), yama ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent)"

fail=0
check() { # check LABEL WANT GOT
	if [ "$2" = "$3" ]; then say "ok    $1: $3"; else
		say "FAIL  $1: want $2, got $3"
		fail=1
	fi
}

step "cluster at uid $UID_PG, socket directory mounted from the node"
start_cluster "$CL" "$UID_PG" "$D" --network none -v "$SP_BIN:/opt/sp-bin:ro"
S=$D/sock/.s.PGSQL.5432
ls -ln "$S"
PID=$(docker inspect -f '{{.State.Pid}}' "$CL")
START=$(proc_start "$PID")
say "docker inspect .State.Pid: $PID"
say "/proc/$PID: cmdline '$(tr '\0' ' ' <"/proc/$PID/cmdline" | sed 's/ $//')', $(grep '^NSpid:' "/proc/$PID/status" | tr '\t' ' '), parent '$(tr -d '\0' <"/proc/$(awk '/^PPid:/ { print $2 }' "/proc/$PID/status")/comm")'"
say "/proc/$PID/stat starttime: $START"
check "the container's init is pid 1 of its namespace" 1 "$(awk '/^NSpid:/ { print $NF }' "/proc/$PID/status")"

step "peer credentials"
check "one connection" "$PID $UID_PG $UID_PG $START" "$("$PEER" peer "$S" 1)"
i=0
bp=
while [ "$i" -lt 20 ]; do
	bp="$bp $(docker exec "$CL" psql -X -U supabase_admin -d postgres -Atqc 'select pg_backend_pid()')"
	i=$((i + 1))
done
say "20 sessions, backend pids (container namespace):$bp"
check "distinct backends" 20 "$(echo "$bp" | tr ' ' '\n' | sort -u | grep -c .)"
check "50 connections held at once: distinct credentials" "1 $PID $UID_PG $UID_PG $START" "$("$PEER" peer "$S" 50 | sort | uniq -c | awk '{ print $1 == 50 ? 1 : $1, $2, $3, $4, $5 }')"
docker kill -s HUP "$CL" >/dev/null
sleep 1
check "after a configuration reload (SIGHUP)" "$PID $UID_PG $UID_PG $START" "$("$PEER" peer "$S" 1)"
docker exec -d "$CL" psql -X -U supabase_admin -d postgres -Atqc 'select pg_sleep(60)'
sleep 2
victim=$(docker exec "$CL" psql -X -U supabase_admin -d postgres -Atqc "select pid from pg_stat_activity where query like 'select pg_sleep%' and pid <> pg_backend_pid()")
docker exec "$CL" kill -9 "$victim"
wait_cluster "$CL"
say "a backend killed with SIGKILL; the postmaster went through crash recovery:"
docker logs "$CL" 2>&1 | grep -m2 'terminated by signal 9\|all server processes terminated' | sed 's/^/  /'
check "after crash recovery: pid" "$PID" "$(docker inspect -f '{{.State.Pid}}' "$CL")"
check "after crash recovery: peer" "$PID $UID_PG $UID_PG $START" "$("$PEER" peer "$S" 1)"
check "start time stable" "$START" "$(proc_start "$PID")"

step "control: a different process of the tenant listening at the same path"
docker exec "$CL" mv /var/run/postgresql/.s.PGSQL.5432 /var/run/postgresql/.s.real
docker exec -d "$CL" /opt/sp-bin/e08 listen /var/run/postgresql/.s.PGSQL.5432
n=0
until [ -S "$S" ]; do
	n=$((n + 1))
	[ "$n" -le 50 ] || die "impostor did not listen"
	sleep 0.1
done
imp=$(pgrep -f 'e08 listen /var/run/postgresql' | head -n 1)
got=$("$PEER" peer "$S" 1)
say "impostor host pid $imp ($(grep '^NSpid:' "/proc/$imp/status" | tr '\t' ' ')), peer credentials: $got"
check "peer pid is the impostor's" "$imp" "${got%% *}"
check "peer uid is still the project uid (a uid check alone cannot tell)" "$UID_PG" "$(echo "$got" | cut -d' ' -f2)"
if [ "${got%% *}" != "$PID" ]; then say "ok    the pid check refuses it: $got is not $PID"; else
	say "FAIL  the impostor reports the init pid"
	fail=1
fi
kill "$imp"
docker exec "$CL" sh -c 'rm -f /var/run/postgresql/.s.PGSQL.5432 && mv /var/run/postgresql/.s.real /var/run/postgresql/.s.PGSQL.5432'
check "socket restored: peer is the init again" "$PID $UID_PG $UID_PG $START" "$("$PEER" peer "$S" 1)"

step "refusals: peer pid 0 or 1, unreadable start time"
# refused LABEL CODE MESSAGE CMD...: CMD must exit CODE and print MESSAGE.
refused() {
	_l=$1 _c=$2 _m=$3
	shift 3
	_s=0
	_o=$("$@" 2>&1) || _s=$?
	if [ "$_s" = "$_c" ] && printf '%s' "$_o" | grep -q "$_m"; then say "ok    $_l: exit $_s, $_o"; else
		say "FAIL  $_l: want exit $_c and '$_m', got exit $_s, $_o"
		fail=1
	fi
}
refused "inside the container the postmaster is pid 1" 3 "refused: peer pid 1 " \
	docker exec "$CL" /opt/sp-bin/e08 peer /var/run/postgresql/.s.PGSQL.5432 1
"$PEER" listen "$D/sock/outside.sock" >/dev/null &
lp=$!
n=0
until [ -S "$D/sock/outside.sock" ]; do
	n=$((n + 1))
	[ "$n" -le 50 ] || die "node-side listener did not start"
	sleep 0.1
done
chmod 0777 "$D/sock/outside.sock"
refused "a listener outside the container's pid namespace reads as pid 0 inside it" 3 "refused: peer pid 0 " \
	docker exec "$CL" /opt/sp-bin/e08 peer /var/run/postgresql/outside.sock 1
kill "$lp"
rm -f "$D/sock/outside.sock"
say "handoff: $("$PEER" handoff "$D/handoff.sock")"
sleep 0.3
refused "listener whose creator has exited: its /proc/<pid>/stat is gone" 4 "refused: /proc/[0-9]*/stat unreadable" \
	"$PEER" peer "$D/handoff.sock" 1
pkill -f 'serve-fd' || :
check "control: the init's credentials still pass" "$PID $UID_PG $UID_PG $START" "$("$PEER" peer "$S" 1)"

step "result"
if [ "$fail" = 0 ]; then
	say "VERDICT E8: confirmed — SO_PEERCRED on the mounted socket reports the container's init (docker inspect .State.Pid, pid 1 inside) for every connection, through backend forks, reload and crash recovery, with a stable start time, and a different listener at the same path reports its own pid."
else
	say "VERDICT E8: fallback — the listener is not identified by the init pid (FAIL lines above)."
fi
