# shellcheck shell=sh disable=SC2154 # run after lib-pool.sh, which sets the lab's variables
# e42.sh — does Supavisor run as a user that is not root, with a read-only
# root? The pooler of lib-pool.sh: uid 65526, no capabilities, read-only root
# with a tmpfs at /tmp, the hardened Erlang settings (a per-node cookie, epmd
# and distribution on the loopback, a 16 MiB per-process heap cap). Pass: it
# starts, serves both modes with a verified certificate, and each of the
# hostile walks ends as the hardened runs before it did:
#   distribution: epmd and the distribution port listen on the loopback
#       only; the image's built-in cookie is refused (control: the node's own
#       cookie is accepted); nothing of the pooler answers on a project bridge
#       (control: the cluster's port on the same bridge does);
#   shard listeners: they skip enforce_ssl — still so at the pin (recorded,
#       from the pooler's own namespace, with the session port's refusal as
#       control); not reachable from a project bridge nor, unrouted, from
#       outside the node; what a neighbour that routes to the ingress subnet
#       reaches under the node's tables as built is recorded;
#   lockout: a lockout of another address through the shard listener's client_ip
#       and the breaker (recorded, with the bans cleared through the API), and
#       the shared-address lockout of node-local clients without it (recorded);
#   auth-query size: a tenant's helper returning 800,000 rows of 1 KB, eight logins at
#       once: the pooler is not killed and another tenant's probe loses
#       nothing (control: the restored helper serves);
#   verifier cost: the manager's verifier at 20,000,000 iterations, eight new logins: the
#       pooler is not killed and another tenant's probe loses nothing; the CPU
#       it costs is recorded (control: at 4,096 iterations again).
#
# Run by the wrapper: test/harness/experiments/pool-lab.sh <node> e42.sh

lab_up
R0=$(ref_of 0) R2=$(ref_of 2)
say "pooler memory after start: current $(pooler_mem_mib current) MiB, peak $(pooler_mem_mib peak) MiB"

step "the container"
uid=$(docker exec "$SV" awk '/^Uid:/ {print $2}' /proc/1/status)
capeff=$(docker exec "$SV" awk '/^CapEff:/ {print $2}' /proc/1/status)
beam=$(docker exec "$SV" sh -c 'for p in /proc/[0-9]*; do case $(readlink "$p/exe") in *beam.smp) ;; *) continue ;; esac; awk "/^Uid:/ {print \$2}" "$p/status" && break; done')
if [ "$uid" = "$POOLER_UID" ] && [ "$beam" = "$POOLER_UID" ] && [ "$capeff" = 0000000000000000 ]; then
	res PASS "runs as uid $POOLER_UID with no capabilities" "init uid $uid, beam uid $beam, CapEff $capeff"
else
	res FAIL "runs as uid $POOLER_UID with no capabilities" "init uid $uid, beam uid ${beam:-none}, CapEff $capeff"
fi
ro=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$SV")
if [ "$ro" = true ] && ! docker exec "$SV" sh -c 'touch /app/probe-write' 2>/dev/null; then
	res PASS "the root filesystem is read-only" "ReadonlyRootfs $ro, a write to /app refused"
else
	res FAIL "the root filesystem is read-only" "ReadonlyRootfs $ro"
fi
ok=0
docker exec "$SV" sh -c 'touch /tmp/probe-write && rm /tmp/probe-write' && ok=1
control "a write to the tmpfs at /tmp" "$ok" "the same write, permitted path"
for port in 5432 6543; do
	if pq 0 postgres "$port" 127.0.0.1 'select current_user'; then
		res PASS "serves port $port with sslmode=verify-full" "answer: $PQ"
	else
		res FAIL "serves port $port with sslmode=verify-full" "$PQ"
	fi
done

step "distribution"
tcp=$(docker exec "$SV" cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk '$4 == "0A" {print $2}')
bad=$(printf '%s\n' "$tcp" | grep -E ':(1111|4E20)$' | grep -v -E '^0100007F:' || :)
seen=$(printf '%s\n' "$tcp" | grep -c -E ':(1111|4E20)$' || :)
if [ "$seen" -ge 2 ] && [ -z "$bad" ]; then
	res PASS "distribution: epmd (4369) and distribution (20000) listen on 127.0.0.1 only" "$(printf '%s\n' "$tcp" | grep -E ':(1111|4E20)$' | tr '\n' ' ')"
else
	res FAIL "distribution: epmd (4369) and distribution (20000) listen on 127.0.0.1 only" "listening: $(printf '%s\n' "$tcp" | tr '\n' ' ')"
fi
# rpc COOKIEFILE: from a throwaway container in the pooler's own network
# namespace, an Erlang node asks the pooler's node to run `id`. The cookie is
# the mounted file $HOME/.erlang.cookie (owner-only), never an argument.
rpc() {
	docker run --rm --label supapace.test=1 --network "container:$SV" --memory 256m --cap-drop ALL \
		--security-opt no-new-privileges -e "ERL_AFLAGS=-proto_dist inet_tcp" -e HOME=/cookie \
		-v "$1:/cookie/.erlang.cookie:ro" --entrypoint sh "$SV_IMAGE" -c "
E=\$(ls -d /app/erts-*); V=\$(ls -d /app/releases/[0-9]*); export BINDIR=\$E/bin ROOTDIR=/app EMU=beam PROGNAME=erl
cd /tmp && timeout 60 \$E/bin/erlexec -boot \$V/start_clean -boot_var RELEASE_LIB /app/lib \
 -proto_dist inet_tcp -name probe@127.0.0.1 -hidden -noshell \
 -eval 'io:format(\"rpc: ~p~n\", [rpc:call(list_to_atom(\"supavisor@127.0.0.1\"), os, cmd, [\"id -u\"], 10000)]), halt().'
" 2>&1 | grep '^rpc:' | tr '\n' ' '
}
(umask 077 && docker run --rm --entrypoint cat "$SV_IMAGE" /app/releases/COOKIE >"$S/image-cookie")
out=$(rpc "$S/image-cookie")
case $out in
*badrpc*) res PASS "distribution: the image's built-in cookie is refused" "$out" ;;
*) res FAIL "distribution: the image's built-in cookie is refused" "${out:-no answer}" ;;
esac
out=$(rpc "$S/cookie")
ok=0
case $out in *"$POOLER_UID"*) ok=1 ;; esac
control "distribution: the node's own cookie" "$ok" "$out"
# A member of project bridge 0, to every port of the pooler's address there.
pslice=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$P-proj0\").IPAddress}}" "$SV")
docker run -d --name "$P-peer" --label supapace.test=1 --network "$P-proj0" --memory 64m --cap-drop ALL \
	--entrypoint sleep "$CP_IMAGE" infinity >/dev/null
open=''
for port in 4369 20000 4000 5432 6543 12100 12104; do
	docker exec "$P-peer" nc -z -w 3 "$pslice" "$port" 2>/dev/null && open="$open $port"
done
if [ -z "$open" ]; then
	res PASS "distribution, shard listeners: nothing of the pooler answers on a project bridge ($pslice: 4369 20000 4000 5432 6543 12100 12104)" "none open"
else
	res FAIL "distribution, shard listeners: nothing of the pooler answers on a project bridge" "open:$open"
fi
ok=0
docker exec "$P-peer" nc -z -w 3 "$(cluster_ip 0)" 5432 && ok=1
control "distribution: the cluster's port from the same member" "$ok" "$(cluster_ip 0):5432"
docker rm -f "$P-peer" >/dev/null

step "the shard listeners and enforce_ssl"
# insider SQL PORT SSLMODE [OPTIONS] [PASSWORD]: psql from the pooler's own namespace.
insider() {
	PGPASSWORD=${5:-$(password 0 postgres)} docker run --rm --label supapace.test=1 --network "container:$SV" --memory 128m --cap-drop ALL \
		-e PGPASSWORD -e PGOPTIONS="${4:-}" --entrypoint timeout "$CP_IMAGE" 60 \
		psql "host=127.0.0.1 port=$2 user=postgres.$R0 dbname=postgres sslmode=$3 connect_timeout=15" -X -At -c "$1" 2>&1 | tr '\n' ' '
}
res RECORDED "shard listeners: sslmode=disable to the shard port 12100 from the pooler's namespace" "$(insider 'select 1' 12100 disable)"
res RECORDED "shard listeners: sslmode=disable to the shard port 12104 from the pooler's namespace" "$(insider 'select 1' 12104 disable)"
out=$(insider 'select 1' 5432 disable)
ok=0
case $out in *ESSLREQUIRED*) ok=1 ;; esac
control "shard listeners: sslmode=disable to the session port is refused" "$ok" "$out"
s=0
outside "nc -z -w 3 $OUT_NODE_IP 12100" || s=$?
if [ "$s" != 0 ]; then
	res PASS "shard listeners: the shard port is not published (outside to $OUT_NODE_IP:12100)" "nc status $s"
else
	res FAIL "shard listeners: the shard port is not published (outside to $OUT_NODE_IP:12100)" "connected"
fi
ok=0
outside "nc -z -w 3 $OUT_NODE_IP 6543" && ok=1
control "shard listeners: the transaction port from outside" "$ok" "$OUT_NODE_IP:6543"
# A neighbour that routes the ingress subnet through the node.
outside "ip route replace $ING_SUB via $OUT_NODE_IP" || die "cannot add the route in the outside client: $OUT"
for port in 12100 4000 4369; do
	s=0
	outside "nc -z -w 3 $POOLER_ING_IP $port" || s=$?
	res RECORDED "shard listeners: a routed neighbour to the pooler's ingress address, port $port" "$([ "$s" = 0 ] && echo reached || echo "not reached (nc $s)")"
done
s=0
outside "PGPASSWORD='$(password 0 postgres)' timeout 40 psql 'host=$POOLER_ING_IP port=12100 user=postgres.$R0 dbname=postgres sslmode=disable connect_timeout=15' -X -At -c 'select 1' 2>&1" || s=$?
res RECORDED "shard listeners: a routed neighbour, sslmode=disable on the shard port" "status $s: $(printf '%s' "$OUT" | tr '\n' ' ')"
outside "ip route del $ING_SUB via $OUT_NODE_IP" || :

step "lockout through the shard listener's client_ip"
victim=$OUT_CLIENT_IP
for k in 1 2 3 4 5 6 7 8 9 10 11; do
	insider 'select 1' 12100 disable "-c client_ip=$victim" wrong-password >/dev/null
done
pq_out 0 postgres 6543 'select 1' || :
res RECORDED "lockout: the victim ($victim), correct password, after 11 failures sent from the namespace in its name" "$PQ"
ok=0
pq 0 postgres 6543 127.0.0.1 'select 1' && ok=1
res RECORDED "lockout: a client of another address meanwhile (node-local)" "$([ "$ok" = 1 ] && echo served || echo "$PQ")"
printf '{"ipv4_addresses":["%s"]}' "$victim" >"$S/bans.json"
st=$(admin DELETE "/api/tenants/$R0/network_bans" "$S/bans.json")
s=0
pq_out 0 postgres 6543 'select 1' || s=$?
res RECORDED "lockout: bans cleared through the admin API (HTTP $st), the victim again" "status $s: $PQ"
# Without the shard port: every node-local client shares one address.
for k in 1 2 3 4 5 6 7 8 9 10 11; do
	docker exec -e PGPASSWORD=wrong-password "$CLI" psql "$(conninfo 0 postgres 6543 127.0.0.1)" -X -At -c 'select 1' >/dev/null 2>&1 || :
done
pq 0 postgres 6543 127.0.0.1 'select 1' || :
res RECORDED "lockout: shared address: a node-local client with the correct password after 11 wrong ones from another node-local client" "$PQ"
printf '{"ipv4_addresses":["%s"]}' "$ING_GW" >"$S/bans.json"
st=$(admin DELETE "/api/tenants/$R0/network_bans" "$S/bans.json")
rm -f "$S/bans.json"
s=0
pq 0 postgres 6543 127.0.0.1 'select 1' || s=$?
res RECORDED "lockout: bans of $ING_GW cleared (HTTP $st), node-local again" "status $s: $PQ"

# served_again INDEX: the failed secret fetches open the tenant's credential
# breaker (5 failures in 300 s block it for 30 s): up to 120 s for a login of
# tenant INDEX to be served; prints the seconds waited, status as the login's.
served_again() {
	_sa=0
	until pq "$1" postgres 6543 127.0.0.1 'select 1'; do
		_sa=$((_sa + 5))
		[ "$_sa" -le 120 ] || break
		sleep 5
	done
	echo "$_sa"
	[ "$_sa" -le 120 ]
}
# attack_logins INDEX FIRST LAST: logins of users FIRST..LAST of tenant INDEX at
# once (users the cluster does not hold: each runs the auth query); prints the
# distinct answers.
attack_logins() {
	_al=
	for k in $(seq "$2" "$3"); do
		mksecret "user$1-atk$k" "$(rand_hex 12)"
		(pq "$1" "atk$k" 6543 127.0.0.1 'select 1' || :; printf '%s\n' "$PQ" >"$S/atk$k") &
		_al="$_al $!"
	done
	# shellcheck disable=SC2086 # a list of pids
	wait $_al || :
	for k in $(seq "$2" "$3"); do sed 's/.*FATAL: *//' "$S/atk$k"; done | sort | uniq -c | tr '\n' ' '
	for k in $(seq "$2" "$3"); do rm -f "$S/atk$k"; done
}

step "an oversized auth-query result"
oom0=$(pooler_oom)
asadmin 2 >/dev/null <<-'SQL'
	create or replace function supapace_pooler.get_auth(p_usename text) returns table (username text, password text)
	language plpgsql security definer set search_path = '' as $f$ begin
	return query select p_usename, pg_catalog.repeat('B', 1000) from pg_catalog.generate_series(1, 800000);
	end $f$;
SQL
probe_start 1 40
answers=$(attack_logins 2 1 8)
probe=$(probe_wait)
oom1=$(pooler_oom)
res RECORDED "auth-query size: the eight attacking logins" "$answers"
if pooler_running && [ "$oom1" = "$oom0" ]; then
	res PASS "auth-query size: the pooler survives (no OOM kill)" "running; oom_kill $oom0 -> $oom1; memory peak $(pooler_mem_mib peak) MiB of 1024"
else
	res FAIL "auth-query size: the pooler survives (no OOM kill)" "running: $(pooler_running && echo yes || echo no); oom_kill $oom0 -> $oom1"
fi
# shellcheck disable=SC2086 # three figures
set -- $probe
if [ "${1:-0}" -gt 0 ] && [ "${2:-1}" = 0 ] && [ "${4:-1}" = 0 ] && [ "${5:-1}" = 0 ]; then
	res PASS "auth-query size: another tenant's probe loses nothing" "$1 transactions, $2 failed, $3 tps, pgbench status $4, $5 aborted"
else
	res FAIL "auth-query size: another tenant's probe loses nothing" "transactions ${1:-?}, failed ${2:-?}, tps ${3:-?}, pgbench status ${4:-?}, ${5:-?} aborted"
fi
helper get_auth "and a.rolname !~ '^pg_'" | asadmin 2 >/dev/null
terminate "$R2" >/dev/null
ok=0
waited=$(served_again 2) && ok=1
control "auth-query size: the restored helper serves tenant 2" "$ok" "after about $waited s: $PQ"
pooler_running || die "the pooler is not running after the oversized auth-query run"

step "the manager's verifier at 20,000,000 iterations"
printf "set scram_iterations = 20000000; alter role supapace_pooler password '%s';\n" "$(secret mgr2)" | asadmin 2 >/dev/null
terminate "$R2" >/dev/null
oom0=$(pooler_oom)
cpu0=$(pooler_cpu_ms) t0=$(now_cs)
probe_start 1 60
answers=$(attack_logins 2 9 16)
cpu1=$(pooler_cpu_ms) t1=$(now_cs)
probe=$(probe_wait)
oom1=$(pooler_oom)
res RECORDED "verifier cost: the eight logins" "$answers"
res RECORDED "verifier cost: pooler CPU while they ran" "$(((cpu1 - cpu0) / 1000)).$(((cpu1 - cpu0) % 1000 / 100)) CPU-seconds in $(((t1 - t0) / 100)).$(((t1 - t0) % 100 / 10)) s"
if pooler_running && [ "$oom1" = "$oom0" ]; then
	res PASS "verifier cost: the pooler survives" "running; oom_kill $oom0 -> $oom1"
else
	res FAIL "verifier cost: the pooler survives" "running: $(pooler_running && echo yes || echo no); oom_kill $oom0 -> $oom1"
fi
# shellcheck disable=SC2086 # three figures
set -- $probe
if [ "${1:-0}" -gt 0 ] && [ "${2:-1}" = 0 ] && [ "${4:-1}" = 0 ] && [ "${5:-1}" = 0 ]; then
	res PASS "verifier cost: another tenant's probe loses nothing" "$1 transactions, $2 failed, $3 tps, pgbench status $4, $5 aborted"
else
	res FAIL "verifier cost: another tenant's probe loses nothing" "transactions ${1:-?}, failed ${2:-?}, tps ${3:-?}, pgbench status ${4:-?}, ${5:-?} aborted"
fi
printf "set scram_iterations = 4096; alter role supapace_pooler password '%s';\n" "$(secret mgr2)" | asadmin 2 >/dev/null
terminate "$R2" >/dev/null
ok=0
w=$(served_again 2) && ok=1
res RECORDED "verifier cost: tenant 2 served again after the verifier was restored" "after about $w s: $PQ"
# Roles that exist this time, so that no login fails and no breaker counts it.
for k in 17 18 19 20; do
	mksecret "user2-atk$k" "$(rand_hex 12)"
	printf "create role atk%s login password %s;\n" "$k" "'$(secret "user2-atk$k")'" | asadmin 2 >/dev/null
done
cpu0=$(pooler_cpu_ms) t0=$(now_cs)
answers=$(attack_logins 2 17 20)
cpu1=$(pooler_cpu_ms) t1=$(now_cs)
# All four served: uniq -c of four answers "1".
case $answers in *" 4 1 "*) ;; *) ok=0 ;; esac
control "verifier cost: at 4,096 iterations: tenant 2 serves; four new logins of existing roles cost $(((cpu1 - cpu0) / 1000)).$(((cpu1 - cpu0) % 1000 / 100)) CPU-seconds in $(((t1 - t0) / 100)).$(((t1 - t0) % 100 / 10)) s" "$ok" "logins: $answers"

say ""
say "pooler memory at the end: current $(pooler_mem_mib current) MiB, peak $(pooler_mem_mib peak) MiB; oom_kill $(pooler_oom)"
scan_result
if [ "$FAILS" = 0 ]; then
	say "VERDICT E42: PASS — Supavisor runs as uid $POOLER_UID with a read-only root, serves both modes, and each hostile walk ends as the hardened runs did"
else
	say "VERDICT E42: FAIL — see the lines above; fallback: a derived image of one line that sets the user"
fi
finish e42
