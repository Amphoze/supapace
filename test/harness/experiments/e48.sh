# shellcheck shell=sh disable=SC2154 # run after lib-pool.sh, which sets the lab's variables
# e48.sh — can one login be given a pooler tenant of its own? Recorded (no
# pass criterion). On the cluster of slice 1:
#   - the first helper no longer returns supabase_read_only_user;
#   - a second helper returns the manager's row and that login's alone;
#   - a second tenant "<ref>-ro" of the same cluster uses the second helper
#     and the same manager role, with a pool size of its own (2).
# Recorded: whether both tenants register and serve with one manager role;
# whether the read-only login is refused on the first and served on the
# second (and the owner's login refused on the second); whether filling the
# second leaves the first's logins working; how many backends that login then
# holds, and whether more pools (one per search_path) take it past its pool
# size. The lab has no proxy: both tenants name the cluster's own address and
# port, so a second proxy port per slice is not part of this run.
#
# Run by the wrapper: test/harness/experiments/pool-lab.sh <node> e48.sh

lab_up
R=$(ref_of 1)
RO=$R-ro
RO_LOGIN=supabase_read_only_user

step "the helpers split in two"
{
	helper get_auth "and a.rolname !~ '^pg_' and a.rolname <> 'supabase_read_only_user'"
	helper get_auth_ro "and a.rolname in ('supapace_pooler', 'supabase_read_only_user')"
} | asadmin 1 >/dev/null
st=$(terminate "$R")
res RECORDED "first tenant terminated after its helper changed (cache)" "HTTP $st"
# shellcheck disable=SC2016 # $1 is the pooler's placeholder
st=$(POOL=2 register 1 '' '' "$RO" 'SELECT * FROM supapace_pooler.get_auth_ro($1)')
res RECORDED "second tenant $RO registers with the same manager role" "HTTP $st"

step "who is served where"
for port in 5432 6543; do
	s=0
	pq 1 postgres "$port" 127.0.0.1 'select current_user' || s=$?
	res RECORDED "owner's login on the first tenant, port $port" "status $s: $PQ"
	s=0
	pq 1 "$RO_LOGIN" "$port" 127.0.0.1 'select current_user' || s=$?
	res RECORDED "read-only login on the first tenant, port $port" "status $s: $PQ"
	s=0
	pq 1 "$RO_LOGIN" "$port" 127.0.0.1 'select current_user' "$RO" || s=$?
	res RECORDED "read-only login on the second tenant, port $port" "status $s: $PQ"
	s=0
	pq 1 postgres "$port" 127.0.0.1 'select current_user' "$RO" || s=$?
	res RECORDED "owner's login on the second tenant, port $port" "status $s: $PQ"
done

step "filling the second tenant (pool size 2), session mode"
for k in 1 2 3 4; do hold "fill$k" 1 "$RO_LOGIN" 5432 45 "$RO"; done
w=0
until [ "$(backends 1 "$RO_LOGIN")" -ge 2 ]; do
	w=$((w + 1))
	[ "$w" -le 60 ] || break
	sleep 1
done
res RECORDED "read-only backends on the cluster with the second tenant filled" "$(backends 1 "$RO_LOGIN")"
for port in 5432 6543; do
	s=0
	pq 1 postgres "$port" 127.0.0.1 'select 1' || s=$?
	res RECORDED "owner's login on the first tenant meanwhile, port $port" "status $s: $PQ"
done
for k in 1 2 3 4; do res RECORDED "session $k on the filled second tenant" "$(held "fill$k")"; done

step "more pools for the same login: one per search_path"
for k in 1 2 3; do hold "sp$k" 1 "$RO_LOGIN" 5432 45 "$RO" "-c search_path=s$k"; done
for k in 4 5 6; do hold "sp$k" 1 "$RO_LOGIN" 5432 45 "$RO" "-c search_path=s$((k - 3))"; done
w=0
until [ "$(backends 1 "$RO_LOGIN")" -ge 6 ]; do
	w=$((w + 1))
	[ "$w" -le 60 ] || break
	sleep 1
done
res RECORDED "read-only backends with six sessions over three search_path values (pool size 2)" "$(backends 1 "$RO_LOGIN")"
for k in 1 2 3 4 5 6; do res RECORDED "search_path session $k" "$(held "sp$k")"; done

scan_result
say "VERDICT E48: RECORDED — see the lines above"
finish e48
