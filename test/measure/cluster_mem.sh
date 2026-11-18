#!/bin/sh
# cluster_mem.sh — memory of one project's cluster container, idle and under load.
# A test-node tool: it runs as root inside a node (make measure, or by hand):
#
#   docker exec -i [-e VAR=VALUE]... NODE sh -s < test/measure/cluster_mem.sh
#
#   REF      the project to measure (default: the first active project)
#   IDLE     seconds to leave the cluster idle first (default 300)
#   LOAD     seconds of load (default 300)
#   CLIENTS  concurrent sessions of the load (default 72)
#
# Phases: start; IDLE seconds untouched; pgbench -i (scale 10, about 160 MiB
# written into the project's disk quota until the end); LOAD seconds of load.
# Readings are the cgroup v2 files of the container pg-REF. During the idle
# and load phases memory.current and the anon line of memory.stat are sampled
# every second and their highest values reported, so each phase has its own
# maximum. memory.peak (the highest value since the container started) is
# printed for reference only: it is never reset here (a reset needs Linux 6.12
# and a descriptor kept open across reads, which sh cannot do), so after
# pgbench -i it includes the page cache that run filled. file is page cache,
# which the kernel reclaims under pressure.
#
# The load is pgbench from the cluster image, mixed read/write (built-in
# scripts tpcb-like and select-only, 3:7), in a database of its own
# (sp_measure, created and dropped here), as the role postgres. The client
# runs in a separate container that shares the cluster's network namespace
# (127.0.0.1, where the postgres role is admitted), so its own memory is not
# counted in the cluster's cgroup; it drops every capability, as every
# container sharing a tenant's namespace must. On a real node it would be a
# container admission does not count: keep it to test nodes.
#
# docker exec without a terminal forwards no signal: `make measure` stops a
# run on Ctrl-C by sending TERM to the pid in /run/sp-measure.pid; the script
# then removes the client and the database.
set -eu
PIDFILE=/run/sp-measure.pid
echo $$ >"$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT # replaced by the full cleanup below
trap 'exit 130' INT TERM

IDLE=${IDLE:-300}
LOAD=${LOAD:-300}
CLIENTS=${CLIENTS:-72}
CLI=${CLI:-/opt/supapace/bin/supapace}
[ -x "$CLI" ] || CLI=supapace
DB=sp_measure
CLIENT=sp-measure-client

log() { echo "cluster_mem: $*" >&2; }
die() {
	log "$*"
	exit 1
}

if [ -z "${REF:-}" ]; then
	REF=$("$CLI" project list --state active | sed -n 's/^{"projects":\[{"ref":"\([a-z0-9]*\)".*/\1/p')
	[ -n "$REF" ] || die "no active project; create one or set REF"
fi
pg=pg-$REF
pid=$(docker inspect -f '{{.State.Pid}}' -- "$pg" 2>/dev/null) || die "no cluster container $pg"
[ "$pid" -gt 0 ] || die "$pg is not running"
cg=/sys/fs/cgroup$(sed -n 's/^0:://p' "/proc/$pid/cgroup")
[ -r "$cg/memory.peak" ] || die "$cg/memory.peak not readable (cgroup v2 and Linux 5.19 or later needed)"
image=$(docker inspect -f '{{index .Config.Labels "supapace.image"}}' -- "$pg")
PGPASSWORD=$("$CLI" project keys "$REF" | sed -n 's/.*"postgres_password":"\([^"]*\)".*/\1/p')
[ -n "$PGPASSWORD" ] || die "no postgres password for $REF"
export PGPASSWORD

# client CMD...: one run of the cluster image beside the cluster, as nobody.
client() {
	entry=$1
	shift
	docker run --rm --name "$CLIENT" --label supapace.test=1 --network "container:$pg" \
		--cap-drop ALL --security-opt no-new-privileges --read-only --user 65534:65534 \
		--memory 512m --pids-limit 256 --no-healthcheck \
		-e PGPASSWORD -e PGHOST=127.0.0.1 -e PGUSER=postgres \
		--entrypoint "$entry" -- "$image" "$@"
}
out=''
cleanup() {
	docker rm -f "$CLIENT" >/dev/null 2>&1 || :
	client psql -X -q -d postgres -c "drop database if exists $DB" >/dev/null 2>&1 || :
	rm -f "$PIDFILE" "${out:-}"
}
trap cleanup EXIT

mib() { echo $(($1 / 1048576)); }
stat_of() { awk -v k="$1" '$1 == k { print $2 }' "$cg/memory.stat"; }
max_cur=0 max_anon=0
# watch SECONDS: sample memory.current and anon every second (from 0).
watch() {
	max_cur=0 max_anon=0
	n=0
	while [ "$n" -lt "$1" ]; do
		c=$(cat "$cg/memory.current") a=$(stat_of anon)
		[ "$c" -le "$max_cur" ] || max_cur=$c
		[ "$a" -le "$max_anon" ] || max_anon=$a
		sleep 1
		n=$((n + 1))
	done
}
# row PHASE MAX_CURRENT MAX_ANON: the phase's maxima (or "-") and the readings now.
row() {
	printf '%-12s %8s %8s %8s %8s %8s %9s\n' "$1" "$2" "$3" "$(mib "$(cat "$cg/memory.current")")" \
		"$(mib "$(stat_of anon)")" "$(mib "$(stat_of file)")" "$(mib "$(cat "$cg/memory.peak")")"
}

log "project $REF, idle ${IDLE}s, then $CLIENTS sessions for ${LOAD}s"
printf '%-12s %8s %8s %8s %8s %8s %9s\n' phase max_cur max_anon current anon file peak_all
row start - -
watch "$IDLE"
row "idle ${IDLE}s" "$(mib "$max_cur")" "$(mib "$max_anon")"
client psql -X -q -v ON_ERROR_STOP=1 -d postgres -c "set client_min_messages to warning" \
	-c "drop database if exists $DB" \
	-c "create database $DB" >/dev/null || die "cannot create database $DB as postgres"
out=$(mktemp)
client pgbench -i -q -s 10 "$DB" >"$out" 2>&1 || { tail -n 20 "$out" >&2; die "pgbench -i failed"; }
row "pgbench -i" - -
client pgbench -n -c "$CLIENTS" -j 4 -T "$LOAD" -b tpcb-like@3 -b select-only@7 "$DB" >"$out" 2>&1 &
bench=$!
watch "$LOAD"
s=0
wait "$bench" || s=$?
[ "$s" = 0 ] || { tail -n 5 "$out" >&2; die "pgbench run failed"; }
row "load ${LOAD}s" "$(mib "$max_cur")" "$(mib "$max_anon")"
grep -E '^(number of failed|tps)' "$out" | sed 's/ (without initial connection time)//'
printf 'MiB; limit %s; max_* sampled every second within the phase; peak_all since the container started\n' \
	"$(mib "$(cat "$cg/memory.max")")"
