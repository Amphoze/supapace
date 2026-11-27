# shellcheck shell=sh disable=SC2154,SC2034 # run after lib-backup.sh and lib-agent.sh, which set the lab's variables
# e23.sh — the backup network's way out, with an endpoint whose addresses
# change. The node ruleset is the platform's (internal/nft: the off-site set
# and its rules, installed by nft.InstallSet, checked by nft.Check), the network
# is the agent's (EnsureBackupNetwork), the replication job is the platform's
# (agent.RunJob, `supapaced replicate copy`, the address list handed in
# SUPAPACE_S3_ADDRS, no lookup). The stand-in is one endpoint with two
# addresses, A and B. Probes for single TCP connections run in containers
# beside the jobs: on the backup network, at the replicator's uid, without a
# capability, with the jobs' resolver (192.0.2.1).
#
#   - set {A}: a replication job dialing A uploads; dialing B (the endpoint's
#     other address) it fails; probes: A:port connects, B:port, A on another
#     port, the bridge gateway, the node's lab and uplink addresses and the other
#     member of the network do not — each beside a control from the node, or a
#     control that opens the path by hand and loads the ruleset again;
#   - with the rule that carries an accepted connection's later packets (F7)
#     deleted, the handshake completes but the request does not; loaded again
#     it does;
#   - no lookup: a guard in the node counts every packet to port 53 leaving the
#     node; three replication jobs leave it unchanged (control: one lookup from
#     a probe through the jobs' resolver is counted);
#   - set {A} -> {B}, one install: B works, a new connection to A fails (control
#     from the node); a transfer through A that is in flight when A leaves the
#     set completes with its bytes;
#   - the drift check: an element added by hand is drift; and while the set is
#     installed back and forth, back-to-back checks see no drift (one lock for
#     writers and checks).
#
# Not asked: another server on the lab network — a
# node cannot make one beside itself; the rule variants the build did not take.
#
#   test/harness/experiments/ag/lab.sh <node> test/harness/experiments/e23.sh
#
# Exit 0 when the verdict is the expected one (confirmed), 1 otherwise, 3 a lab error.

ag_lab E23
PORT=${S3_PORT:-$(sed 's|.*:||' "$S3D/endpoint")}
A=$(sed -n 1p "$S3D/addrs"):$PORT B=$(sed -n 2p "$S3D/addrs"):$PORT
NODEA=$(ip -4 -o addr show | awk -v p=" ${A%.*}." 'index(" " $4, p) == 1 { sub(/\/.*/, "", $4); print $4; exit }')
UPL=$(ip -4 -o addr show eth0 | awk '{ sub(/\/.*/, "", $4); print $4; exit }')
GW=$(ip -4 -o addr show spb0 | awk '{ sub(/\/.*/, "", $4); print $4; exit }')
say "lab: endpoint $A and $B; the node at $NODEA (lab) and $UPL (uplink); backup bridge $GW"

R=e23eg000000000000001 U=700823
stage "a project with a small repository"
ag_project "$R" "$U" 1 2048 1024
ajob "$R" stanza-create || die "stanza-create: $JSUM"

# probe containers beside the jobs
for j in pj1 pj2; do
	docker run -d --name "$N-$j" --label supapace.test=1 --user "$REPL:$REPL" --cap-drop ALL --security-opt no-new-privileges \
		--read-only --tmpfs /tmp:rw,size=64m --memory 256m --pids-limit 64 --network backup --dns 192.0.2.1 \
		--sysctl net.ipv6.conf.all.disable_ipv6=1 -v "$SP_BIN/sp-probe:/sp-probe:ro" --entrypoint /sp-probe \
		"$WK_IMAGE" listen tcp 0.0.0.0:7002 >/dev/null
done
J2=$(docker inspect -f '{{.NetworkSettings.Networks.backup.IPAddress}}' "$N-pj2")
"$SP_BIN/sp-probe" listen tcp 0.0.0.0:7001 >/dev/null 2>&1 &
LPID=$!
AG_CLEAN="kill $LPID; docker rm -f $N-pj1 $N-pj2 $N-flight; nft delete table inet sp_test_guard"
sleep 1
jp() { docker exec "$N-pj1" /sp-probe tcp "$1" --timeout 2s | sed -n 1p | cut -d' ' -f1; }
np() { "$SP_BIN/sp-probe" tcp "$1" --timeout 2s | sed -n 1p | cut -d' ' -f1; }
want() { # CRITERION WANT GOT
	check "$1" "$3" test "$3" = "$2"
}
# copy ADDR: a replication job handed ADDR alone; $COPY ok (every file taken or found equal) or failed.
copy() {
	ajob "$R" replicate -prefix "$PFX" -addrs "$1" || :
	COPY=failed
	case $JSUM in *'complete true stopped ""'*) COPY=ok ;; esac
}

stage "the set {A}"
ag set "$A"
nft list table inet supapace | grep -E 'offsite4|elements|"F[567]"' | sed 's/^[[:space:]]*/  /'
copy "$A"
jsay "$R" replicate
check "a replication job dialing A gets through" "$COPY: $(echo "$JSUM" | cut -d' ' -f1-2)" test "$COPY" = ok
copy "$B"
jsay "$R" replicate
check "a replication job dialing B (not in the set) does not" "$COPY: $(echo "$JSUM" | cut -c1-120)" test "$COPY" = failed
want "probe -> A" connected "$(jp "$A")"
want "probe -> B" timeout "$(jp "$B")"
control "node -> B" "$([ "$(np "$B")" = connected ] && echo 1 || echo 0)" "the same address from the node"
want "probe -> A on another port" timeout "$(jp "${A%:*}:8333")"
control "node -> A on another port" "$([ "$(np "${A%:*}:8333")" = connected ] && echo 1 || echo 0)" "${A%:*}:8333 from the node"
want "probe -> the bridge gateway" timeout "$(jp "$GW:7001")"
want "probe -> the node's lab address" timeout "$(jp "$NODEA:7001")"
want "probe -> the node's uplink address" timeout "$(jp "$UPL:7001")"
control "node -> its lab address" "$([ "$(np "$NODEA:7001")" = connected ] && echo 1 || echo 0)" "$NODEA:7001"
want "probe -> the other member of the network" timeout "$(jp "$J2:7002")"
nft insert rule bridge supapace forward meta ibrname spb0 accept
control "with an accept for the bridge inserted by hand the member is reached" "$([ "$(jp "$J2:7002")" = connected ] && echo 1 || echo 0)" "$J2:7002"
ag set "$A"
want "loaded again: the member is not reached" timeout "$(jp "$J2:7002")"

stage "the rule for an accepted connection's later packets"
h=$(nft -a list chain inet supapace forward | sed -n 's/.*comment "F7" # handle \([0-9]*\)$/\1/p')
nft delete rule inet supapace forward handle "$h"
want "without F7: the handshake to A completes" connected "$(jp "$A")"
copy "$A"
check "without F7 the replication job does not get through" "$COPY: $(echo "$JSUM" | cut -c1-100)" test "$COPY" = failed
ag set "$A"
copy "$A"
control "F7 loaded again: the job gets through" "$([ "$COPY" = ok ] && echo 1 || echo 0)" "$COPY"

stage "no lookup"
# A guard in the node: every packet to port 53 from the node's own stack is counted and dropped, every
# one forwarded from a container is counted (before the node ruleset, which drops it).
nft -f - <<'GUARD'
table inet sp_test_guard {
	chain g_out {
		type filter hook output priority raw; policy accept;
		udp dport 53 counter drop
		tcp dport 53 counter drop
	}
	chain g_fwd {
		type filter hook forward priority -300; policy accept;
		udp dport 53 counter
		tcp dport 53 counter
	}
}
GUARD
gc() { nft list table inet sp_test_guard | sed -n 's/.*counter packets \([0-9]*\) .*/\1/p' | awk '{ s += $1 } END { print s + 0 }'; }
c0=$(gc)
for i in 1 2 3; do copy "$A"; done
c1=$(gc)
check "three replication jobs: no packet to port 53, from the node or forwarded" "$c0 -> $c1 ($COPY)" test "$c0" = "$c1" -a "$COPY" = ok
say "  a probe's resolver: $(docker exec "$N-pj1" grep '^nameserver' /etc/resolv.conf | tr '\n' ' ')"
docker exec "$N-pj1" /sp-probe dns s3.sp.test --server 127.0.0.11 --timeout 3s >/dev/null 2>&1 || :
docker exec "$N-pj1" /sp-probe dns s3.sp.test --server 192.0.2.1 --timeout 2s >/dev/null 2>&1 || :
c2=$(gc)
control "lookups from a probe (its resolver, then the jobs' resolver address directly) are counted" "$([ "$c2" -gt "$c1" ] && echo 1 || echo 0)" "$c1 -> $c2"

stage "the set {A} -> {B}"
ag set "$B"
copy "$B"
check "after one install B works" "$COPY" test "$COPY" = ok
want "a new connection to A fails" timeout "$(jp "$A")"
control "node -> A" "$([ "$(np "$A")" = connected ] && echo 1 || echo 0)" "$A"

stage "a transfer through A in flight when A leaves the set"
ag set "$A"
head -c 41943040 /dev/urandom >"$KIT/flight"
want_sum=$(sha256sum <"$KIT/flight" | cut -d' ' -f1)
s3 projects-write put "$PFX/flight" <"$KIT/flight" >/dev/null
cp "$S3D/projects-read.keys" "$KIT/ro.keys" && chown "$REPL:$REPL" "$KIT/ro.keys" && chmod 0400 "$KIT/ro.keys"
cp "$S3D/ca.pem" "$KIT/ca.pem" && chmod 0444 "$KIT/ca.pem"
# A slow reader (1 MiB a second through a FIFO) holds the connection open for about 40 s.
docker run -d --name "$N-flight" --label supapace.test=1 --user "$REPL:$REPL" --cap-drop ALL --security-opt no-new-privileges \
	--read-only --tmpfs /tmp:rw,size=64m --memory 256m --pids-limit 64 --network backup --dns 192.0.2.1 \
	-v "$SP_BIN/sp-probe:/sp-probe:ro" -v "$KIT/ro.keys:/keys:ro" -v "$KIT/ca.pem:/ca.pem:ro" --entrypoint sh "$WK_IMAGE" -c "
	mkfifo /tmp/f
	( /sp-probe s3 get '$PFX/flight' --out /tmp/f --endpoint $(cat "$S3D/endpoint") --addr $A --bucket sp-projects \
		--keys /keys --ca /ca.pem --timeout 180s >/tmp/got 2>&1; echo rc=\$? >>/tmp/got ) &
	exec 3</tmp/f
	n=0; while [ \$n -lt 60 ] && head -c 1048576 <&3 | wc -c | grep -qv '^0\$'; do n=\$((n + 1)); sleep 1; done
	cat /tmp/got" >/dev/null
sleep 8
ag set "$B"
say "  installed {B} at t=8 s"
sleep 2
want "during the flight: a new connection to A fails" timeout "$(jp "$A")"
timeout 120 docker wait "$N-flight" >/dev/null || :
got=$(docker logs "$N-flight" 2>&1 | tail -2 | tr '\n' ' ')
say "  flight: $got"
check "the flight completed with the object's bytes" "$(echo "$got" | cut -c1-120)" \
	sh -c "echo \"\$1\" | grep -q \"^object 41943040 $want_sum .*rc=0\"" sh "$got"

stage "the drift check and the set"
ag set "$A"
nft add element inet supapace offsite4 "{ ${B%:*} . $PORT }"
d=$(ag nftcheck 2>&1 | cut -c1-120) || :
check "an element added by hand is drift" "$d" sh -c "echo \"\$1\" | grep -qi drift" sh "$d"
ag set "$A"
bad=0 ok=0
( i=0; while [ "$i" -lt 15 ]; do ag set "$A" >/dev/null 2>&1; ag set "$B" >/dev/null 2>&1; i=$((i + 1)); done; touch "$KIT/writer.done" ) &
w=$!
while [ ! -e "$KIT/writer.done" ]; do
	if ag nftcheck >/dev/null 2>"$KIT/chk.err"; then ok=$((ok + 1)); else bad=$((bad + 1)); say "  check: $(head -c 160 "$KIT/chk.err")"; fi
done
wait "$w"
check "30 installs against back-to-back checks: no check sees drift" "checks ok $ok, failed $bad" test "$bad" = 0 -a "$ok" -gt 10
ag set "$A"

verdict E23 "with the off-site set and its rules a job on the backup network reaches the set's address and port and nothing else (the endpoint's other address, another port, the node, the other member), the rule for an accepted connection's later packets is load-bearing, the job makes no lookup, one install moves it to the new address while a transfer in flight completes, and the drift check sees no drift while the set changes"
