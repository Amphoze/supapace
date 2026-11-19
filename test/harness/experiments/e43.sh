# shellcheck shell=sh disable=SC2154 # run after lib-pool.sh, which sets the lab's variables
# e43.sh — two of the pooler's tenant settings, recorded (no pass criterion):
#   1. an empty allow_list as a way to disable a tenant: what the update
#      answers, what the registry then holds, what a new login and a live
#      session in each mode see, and whether the open list brings it back;
#   2. txn_mode_leak_action (ignore, log, error): what a transaction-mode
#      client sees for a session-level SET, PREPARE and LISTEN, whether the next
#      client of the same pool sees the SET, and what the pooler logs.
#
# Run by the wrapper: test/harness/experiments/pool-lab.sh <node> e43.sh

lab_up
R=$(ref_of 0)
registry() { docker exec "$META" psql -X -At -U postgres -d supavisor -c "$1" 2>&1 | tr '\n' ' '; }

step "1. allow_list [] as a disable"
hold live5432 0 postgres 5432 40
hold live6543 0 postgres 6543 40
# Both sessions are open once the cluster shows two pg_sleep backends.
w=0
until [ "$(echo "select count(*) from pg_stat_activity where query like 'select pg_sleep%'" | asadmin 0)" -ge 2 ]; do
	w=$((w + 1))
	[ "$w" -le 60 ] || die "the two live sessions did not open"
	sleep 1
done
st=$(register 0 EMPTY)
res RECORDED "update with \"allow_list\": [] answers" "HTTP $st"
res RECORDED "registry row after it" "allow_list = $(registry "select allow_list from _supavisor.tenants where external_id = '$R'")"
for port in 5432 6543; do
	s=0
	pq 0 postgres "$port" 127.0.0.1 'select 1' || s=$?
	res RECORDED "new login, port $port, with the empty list" "status $s: $PQ"
done
res RECORDED "live session, port 5432, across the update" "$(held live5432)"
res RECORDED "live session, port 6543, across the update" "$(held live6543)"
st=$(register 0)
ok=0
pq 0 postgres 5432 127.0.0.1 'select 1' && pq 0 postgres 6543 127.0.0.1 'select 1' && ok=1
res RECORDED "the open list again: update answers HTTP $st, logins in both modes" "$([ "$ok" = 1 ] && echo served || echo "refused: $PQ")"

step "2. txn_mode_leak_action, transaction mode, pool size 1 (one backend)"
for action in ignore log error; do
	st=$(POOL=1 register 0 '' ",\"txn_mode_leak_action\":\"$action\"")
	since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	res RECORDED "[$action] update answers" "HTTP $st; registry: $(registry "select txn_mode_leak_action from _supavisor.tenants where external_id = '$R'")"
	s=0
	pq 0 postgres 6543 127.0.0.1 "set myapp.tag = 'from-x'" || s=$?
	res RECORDED "[$action] client X: SET myapp.tag" "status $s: $PQ"
	pq 0 postgres 6543 127.0.0.1 "select coalesce(current_setting('myapp.tag', true), '<unset>')" || :
	res RECORDED "[$action] client Y (new connection) reads myapp.tag" "$PQ"
	s=0
	pq 0 postgres 6543 127.0.0.1 "prepare leaky as select 'stmt-from-x'" || s=$?
	res RECORDED "[$action] client X: PREPARE" "status $s: $PQ"
	pq 0 postgres 6543 127.0.0.1 "execute leaky" || :
	res RECORDED "[$action] client Y: EXECUTE" "$PQ"
	s=0
	pq 0 postgres 6543 127.0.0.1 "listen chan" || s=$?
	res RECORDED "[$action] client X: LISTEN" "status $s: $PQ"
	s=0
	pq 0 postgres 6543 127.0.0.1 "set local myapp.tag = 'x'" || s=$?
	res RECORDED "[$action] client X: SET LOCAL (transaction-scoped)" "status $s: $PQ"
	logs=$(docker logs --since "$since" "$SV" 2>&1 | grep -i -c -E 'session-level|session leak|leak' || :)
	res RECORDED "[$action] pooler log lines naming a session-level statement" "$logs"
	# Each client's SET reached the one backend; reset it for the next action.
	pq 0 postgres 6543 127.0.0.1 "reset all; deallocate all; unlisten *" || :
done
st=$(register 0)
[ "$st" = 200 ] || [ "$st" = 201 ] || die "restoring the tenant answered $st"

scan_result
say "VERDICT E43: RECORDED — see the lines above"
finish e43
