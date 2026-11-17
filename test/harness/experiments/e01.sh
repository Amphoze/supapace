#!/bin/sh
# e01: does the bridge-family forward ruleset work in a nested network namespace?
# Checks connection tracking in the bridge family (ct state), the bridge-name
# wildcard (meta ibrname "spp*") and the masked destination match
# (ip daddr & 0.0.0.63 == 0.0.0.2) on a project-style bridge, plus the platform
# bridge rules, then runs the same probes against the stateless variant that
# replaces every ct state match with TCP flag tests. Every blocked probe is
# repeated with the blocking rule (or the chain's drop policy) removed.
# Last, a platform member with NET_RAW (Docker's default) takes over a PostgREST
# address by unsolicited ARP; a member with no capabilities cannot.
# Runs as root on the test node; reports which kernel modules appeared.
set -eu

P=${SP_PROBE:-/opt/supapace/bin/sp-probe}
IMG=${IMG:-$(docker image ls -q postgres | head -n 1)}
W=$(mktemp -d)
fail=0 cfail=0

cleanup() {
	trap '' INT TERM # a signal during cleanup must not cut it short
	set +e
	[ -f "$W/pids" ] && xargs -r kill <"$W/pids" 2>/dev/null
	nft delete table bridge supapace 2>/dev/null
	nft delete table inet supapace 2>/dev/null
	docker rm -f e01-pg e01-rest e01-other e01-gw e01-mem e01-nocap e01-u1 e01-u2 >/dev/null 2>&1
	docker network rm e01-proj e01-plat e01-unk >/dev/null 2>&1
	rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 3' INT TERM

die() { echo "e01: $*" >&2; exit 3; }
[ -x "$P" ] || die "probe binary $P missing"
[ -n "$IMG" ] || die "no postgres image on this node"

cpid() { docker inspect -f '{{.State.Pid}}' "$1"; }

# probe CONTAINER ADDR:PORT -> R (verdict word); the line must agree with the exit code
probe() {
	set +e
	out=$(nsenter --net="/proc/$(cpid "$1")/ns/net" "$P" tcp "$2" --timeout 1s 2>&1)
	rc=$?
	set -e
	R=${out%% *}
	case "$R:$rc" in
	connected:0 | refused:1 | unreachable:1 | timeout:2) ;;
	*) die "probe $1 -> $2: verdict and exit code disagree: '$out' rc=$rc" ;;
	esac
}

# expect KIND LABEL WANT CONTAINER ADDR:PORT  (KIND: test | ctl)
expect() {
	probe "$4" "$5"
	if [ "$R" = "$3" ]; then
		echo "  ok    $2: $R"
	else
		echo "  FAIL  $2: $R (want $3)"
		if [ "$1" = ctl ]; then cfail=$((cfail + 1)); else fail=$((fail + 1)); fi
	fi
}

# listen CONTAINER ADDR:PORT
listen() {
	f="$W/l.$1.${2##*:}"
	nsenter --net="/proc/$(cpid "$1")/ns/net" "$P" listen tcp "$2" >"$f" 2>&1 &
	echo $! >>"$W/pids"
	i=0
	until grep -qs '^listening' "$f"; do
		i=$((i + 1))
		[ "$i" -lt 50 ] || die "listener $1 $2 did not start: $(cat "$f")"
		sleep 0.1
	done
}

run() { # NAME NETWORK IP [more docker run args]
	n=$1 net=$2 ip=$3
	shift 3
	if [ -n "$ip" ]; then set -- --ip "$ip" "$@"; fi
	docker run -d --name "$n" --label e01=1 --network "$net" "$@" --entrypoint sleep "$IMG" 86400 >/dev/null
}

handle() { # PATTERN -> handle of the one rule in bridge supapace forward containing it
	h=$(nft -a list chain bridge supapace forward | grep -F -- "$1" | sed -n 's/.*# handle \([0-9]*\)$/\1/p')
	[ "$(echo "$h" | wc -w)" = 1 ] || die "pattern '$1' matches $(echo "$h" | wc -w) rules"
	echo "$h"
}

mods() { awk '{print $1}' /proc/modules | sort; }

# Ruleset under test: both tables, exactly as the node installs them.
cat >"$W/stateful.nft" <<'EOF'
table inet supapace
delete table inet supapace
table bridge supapace
delete table bridge supapace

define GATEWAY_IP = 10.212.0.2

table inet supapace {
  chain input {
    type filter hook input priority filter - 10; policy accept;
    iifname "spi0" ct state established,related accept
    meta iifkind "bridge" drop
  }
  chain forward {
    type filter hook forward priority filter - 10; policy accept;
    iifname "spi0" ct state established,related accept
    meta iifkind "bridge" drop
    oifname "spi0" accept
    meta oifkind "bridge" drop
  }
}
table bridge supapace {
  chain forward {
    type filter hook forward priority filter - 10; policy drop;
    meta ibrname "spp*" ether type arp accept
    meta ibrname "spp*" ether type ip ct state established,related accept
    meta ibrname "spp*" ether type ip ip daddr & 0.0.0.63 == 0.0.0.2 tcp dport 5432 ct state new accept
    meta ibrname "spl0" ether type arp accept
    meta ibrname "spl0" ether type ip ip saddr != $GATEWAY_IP tcp dport { 3000, 3001 } ct state != established drop
    meta ibrname "spl0" ether type ip accept
    meta ibrname "spi0" ether type { arp, ip } accept
  }
}
EOF
# Stateless variant: the two ct rules of the project bridge become a forward rule
# for the cluster port and a reply rule that never lets the cluster send a bare
# SYN; the platform drop matches connection openings by flags.
sed \
	-e 's|ether type ip ct state established,related accept|ether type ip ip saddr \& 0.0.0.63 == 0.0.0.2 tcp sport 5432 tcp flags \& (syn\|ack) != syn accept|' \
	-e 's|tcp dport 5432 ct state new accept|tcp dport 5432 accept|' \
	-e 's|ct state != established drop|tcp flags \& (syn\|ack) == syn drop|' \
	"$W/stateful.nft" >"$W/stateless.nft"
[ "$(grep -c 'ct state' "$W/stateless.nft")" = 2 ] || die "stateless rendering left bridge ct matches"

echo "== e01: kernel $(uname -r), docker $(docker version -f '{{.Server.Version}}'), $(nft --version)"
mods >"$W/mods.0"
echo "modules: br_netfilter=$(grep -cx br_netfilter "$W/mods.0") nf_conntrack_bridge=$(grep -cx nf_conntrack_bridge "$W/mods.0") (before)"

# Topology. Project slice 1: 10.213.0.64/26, cluster .66, PostgREST .67, a third
# member .68. Platform: gateway .2, PostgREST of slice 1 at .17, a member from the
# allocator range. An unknown bridge with default name and two members.
docker network create --label e01=1 --internal --ipv6=false --subnet 10.213.0.64/26 \
	-o com.docker.network.bridge.name=spp1 -o com.docker.network.bridge.gateway_mode_ipv4=isolated e01-proj >/dev/null
docker network create --label e01=1 --internal --ipv6=false --subnet 10.212.0.0/21 --ip-range 10.212.6.0/23 \
	-o com.docker.network.bridge.name=spl0 -o com.docker.network.bridge.gateway_mode_ipv4=isolated e01-plat >/dev/null
docker network create --label e01=1 --internal --ipv6=false --subnet 10.214.0.0/26 e01-unk >/dev/null
run e01-pg e01-proj 10.213.0.66
docker create --name e01-rest --label e01=1 --network e01-proj --ip 10.213.0.67 --entrypoint sleep "$IMG" 86400 >/dev/null
docker network connect --ip 10.212.0.17 e01-plat e01-rest
docker start e01-rest >/dev/null
run e01-other e01-proj 10.213.0.68
run e01-gw e01-plat 10.212.0.2
run e01-mem e01-plat ''
run e01-nocap e01-plat '' --cap-drop ALL
run e01-u1 e01-unk 10.214.0.2
run e01-u2 e01-unk 10.214.0.3
MEM=$(docker inspect -f '{{(index .NetworkSettings.Networks "e01-plat").IPAddress}}' e01-mem)
echo "platform member from the allocator range: $MEM"
listen e01-pg 10.213.0.66:5432
listen e01-pg 10.213.0.66:5433
listen e01-rest 10.213.0.67:3000
listen e01-other 10.213.0.68:5432
listen e01-rest 10.212.0.17:3000
listen e01-rest 10.212.0.17:3001
listen e01-rest 10.212.0.17:8000
listen e01-u1 10.214.0.2:5432

echo "-- without any table (all must connect)"
for t in "e01-rest 10.213.0.66:5432" "e01-rest 10.213.0.66:5433" "e01-rest 10.213.0.68:5432" \
	"e01-pg 10.213.0.67:3000" "e01-mem 10.212.0.17:3000" "e01-u2 10.214.0.2:5432"; do
	# shellcheck disable=SC2086
	expect ctl "baseline $t" connected $t
done

# matrix VARIANT FILE REPLY-PATTERN OPEN-PATTERN PLATFORM-DROP-PATTERN
matrix() {
	v=$1 f=$2
	echo "-- $v: load"
	M=fail
	if ! nft -f "$f" 2>"$W/err"; then
		echo "  load failed: $(cat "$W/err")"
		return 0
	fi
	nft list chain bridge supapace forward | sed 's/^/  | /'
	fail=0
	expect test "rest -> cluster:5432 (new, replies established)" connected e01-rest 10.213.0.66:5432
	expect test "rest -> cluster:5433 (other port)" timeout e01-rest 10.213.0.66:5433
	expect test "rest -> .68:5432 (mask mismatch)" timeout e01-rest 10.213.0.68:5432
	expect test "cluster -> rest:3000 (cluster opens)" timeout e01-pg 10.213.0.67:3000
	expect test "gateway -> rest:3000 (platform)" connected e01-gw 10.212.0.17:3000
	expect test "member -> rest:3000 (platform)" timeout e01-mem 10.212.0.17:3000
	expect test "member -> rest:3001 (platform)" timeout e01-mem 10.212.0.17:3001
	expect test "member -> rest:8000 (platform, other port)" connected e01-mem 10.212.0.17:8000
	expect test "unknown bridge member -> member:5432" timeout e01-u2 10.214.0.2:5432

	echo "-- $v control: chain policy accept"
	nft 'chain bridge supapace forward { policy accept; }'
	expect ctl "rest -> cluster:5433" connected e01-rest 10.213.0.66:5433
	expect ctl "rest -> .68:5432" connected e01-rest 10.213.0.68:5432
	expect ctl "cluster -> rest:3000" connected e01-pg 10.213.0.67:3000
	expect ctl "unknown bridge member -> member:5432" connected e01-u2 10.214.0.2:5432
	nft -f "$f"

	h=$(handle "$3")
	echo "-- $v control: reply rule deleted (handle $h)"
	nft delete rule bridge supapace forward handle "$h"
	expect test "rest -> cluster:5432 without reply rule" timeout e01-rest 10.213.0.66:5432
	nft -f "$f"
	expect ctl "rest -> cluster:5432 restored" connected e01-rest 10.213.0.66:5432

	h=$(handle "$4")
	echo "-- $v control: opening rule deleted (handle $h)"
	nft delete rule bridge supapace forward handle "$h"
	expect test "rest -> cluster:5432 without opening rule" timeout e01-rest 10.213.0.66:5432
	nft -f "$f"

	h=$(handle "$5")
	echo "-- $v control: platform drop deleted (handle $h)"
	nft delete rule bridge supapace forward handle "$h"
	expect ctl "member -> rest:3000 without platform drop" connected e01-mem 10.212.0.17:3000
	expect ctl "member -> rest:3001 without platform drop" connected e01-mem 10.212.0.17:3001
	nft -f "$f"
	expect test "member -> rest:3000 restored" timeout e01-mem 10.212.0.17:3000
	if [ "$fail" = 0 ]; then M=ok; fi
}

matrix stateful "$W/stateful.nft" 'ct state established,related accept' 'ct state new accept' '3000, 3001'
sf=$M
matrix stateless "$W/stateless.nft" 'tcp sport 5432' 'tcp dport 5432 accept' '3000, 3001'
sl=$M

# Address takeover on the platform bridge: the bridge rules accept every ARP
# frame there, so a member able to send raw frames (NET_RAW, in Docker's default
# capability set) can repoint the gateway's neighbour entry for a PostgREST
# address to itself with one unsolicited ARP. The same attempt from a member
# started with --cap-drop ALL is the control.
echo "-- platform bridge: unsolicited ARP for the PostgREST address (stateful rules loaded)"
nft -f "$W/stateful.nft"
mac() { docker inspect -f '{{(index .NetworkSettings.Networks "e01-plat").MacAddress}}' "$1"; }
gwneigh() { nsenter --net="/proc/$(cpid e01-gw)/ns/net" ip neigh show 10.212.0.17 | sed -n 's/.*lladdr \([0-9a-f:]*\).*/\1/p'; }
# busybox arping first binds a UDP socket to the claimed address as a sanity
# check; ip_nonlocal_bind (set from outside, identically for both members) only
# lets that check pass. Emitting the forged frame itself needs an AF_PACKET
# socket, i.e. NET_RAW, which is what the two members differ in.
garp() { # CONTAINER: one unsolicited ARP claiming 10.212.0.17, at the container's own privileges
	nsenter --net="/proc/$(cpid "$1")/ns/net" sh -c 'echo 1 >/proc/sys/net/ipv4/ip_nonlocal_bind'
	sleep 1.2 # past the neighbour lock time
	docker exec "$1" arping -U -c 1 -I eth0 -s 10.212.0.17 10.212.0.17 >"$W/arp" 2>&1 && echo sent || echo "refused: $(tr '\n' ' ' <"$W/arp" | cut -c1-120)"
}
REST=$(mac e01-rest) MEM=$(mac e01-mem) NOCAP=$(mac e01-nocap)
echo "  macs: rest $REST, default-caps member $MEM, no-caps member $NOCAP"
expect test "gateway -> rest:3000 before" connected e01-gw 10.212.0.17:3000
echo "  gateway's neighbour entry for 10.212.0.17: $(gwneigh)"
echo "  member with --cap-drop ALL: $(garp e01-nocap)"
n1=$(gwneigh)
echo "  gateway's neighbour entry afterwards: $n1"
expect ctl "gateway -> rest:3000 after the no-caps attempt" connected e01-gw 10.212.0.17:3000
echo "  member with Docker's default capabilities: $(garp e01-mem)"
n2=$(gwneigh)
echo "  gateway's neighbour entry afterwards: $n2"
# packets received and sent by the default-caps member's eth0
rxtx() { nsenter --net="/proc/$(cpid e01-mem)/ns/net" sed -n 's/^ *eth0: *//p' /proc/net/dev | awk '{print $2 + 0, $10 + 0}'; }
before=$(rxtx)
probe e01-gw 10.212.0.17:3000
after=$(rxtx)
rel=$(echo "$before $after" | awk '{print "received " $3 - $1 ", sent " $4 - $2}')
echo "  gateway -> rest:3000 after the default-caps attempt: $R; meanwhile the member's eth0 $rel packets (its ip_forward: $(nsenter --net="/proc/$(cpid e01-mem)/ns/net" cat /proc/sys/net/ipv4/ip_forward), so it relays what it intercepts)"
arp=unchanged
[ "$n1" = "$REST" ] && [ "$n2" = "$MEM" ] && arp=taken
nsenter --net="/proc/$(cpid e01-gw)/ns/net" ip neigh flush to 10.212.0.17
expect ctl "gateway -> rest:3000 after flushing the entry" connected e01-gw 10.212.0.17:3000
echo "address takeover by a platform member: with NET_RAW $arp; without capabilities $([ "$n1" = "$REST" ] && echo impossible || echo POSSIBLE)"

echo "-- kernel modules that appeared during this run:"
mods >"$W/mods.2"
comm -13 "$W/mods.0" "$W/mods.2" | sed 's/^/  + /'
echo "modules: br_netfilter=$(grep -cx br_netfilter "$W/mods.2") nf_conntrack_bridge=$(grep -cx nf_conntrack_bridge "$W/mods.2") (after)"
echo "stateful=$sf stateless=$sl control-failures=$cfail"

if [ "$cfail" != 0 ]; then
	echo "VERDICT E01: unknown — $cfail control probe(s) failed, so a blocked probe proves nothing."
elif [ "$sf" = ok ]; then
	echo "VERDICT E01: confirmed — bridge-family ct state, the spp* wildcard and the masked match behave as written in a nested namespace (stateless variant: $sl); on the platform bridge a member with NET_RAW $( [ "$arp" = taken ] && echo "can" || echo "could not") take over an address by ARP."
elif [ "$sl" = ok ]; then
	echo "VERDICT E01: fallback — the stateful bridge rules do not hold here, the stateless variant does."
else
	echo "VERDICT E01: unknown — neither the stateful rules nor the stateless variant hold on this kernel."
fi
