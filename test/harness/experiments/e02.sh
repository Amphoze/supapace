#!/bin/sh
# e02: do interface-kind matches select bridge traffic in the inet input and
# forward hooks? "meta iifkind bridge" (input and forward) and "meta oifkind
# bridge" (forward) are probed with traffic from members of a bridge with a
# chosen name and of a bridge with Docker's default name, to and from a
# neighbour namespace behind a veth pair (an uplink stand-in), and towards a
# canary on the node itself, and from a macvlan child (also not a bridge, so the
# kind match lets it through like an uplink). Each rule is shown blocking, then removed by
# handle to show the same probe connecting. The name-based variant (interface
# not an uplink and not loopback) is probed the same way.
# Runs as root on the test node.
set -eu

P=${SP_PROBE:-/opt/supapace/bin/sp-probe}
IMG=${IMG:-$(docker image ls -q postgres | head -n 1)}
W=$(mktemp -d)
NS=e02n MV=e02v
netns_dir_existed=no
[ -d /run/netns ] && netns_dir_existed=yes
fail=0 cfail=0

cleanup() {
	trap '' INT TERM # a signal during cleanup must not cut it short
	set +e
	[ -f "$W/pids" ] && xargs -r kill <"$W/pids" 2>/dev/null
	nft delete table inet supapace 2>/dev/null
	docker rm -f e02-a e02-b >/dev/null 2>&1
	docker network rm e02-named e02-unnamed >/dev/null 2>&1
	ip link del e02h 2>/dev/null
	ip link del e02m0 2>/dev/null
	ip link del e02d 2>/dev/null
	ip netns del "$NS" 2>/dev/null
	ip netns del "$MV" 2>/dev/null
	if [ "$netns_dir_existed" = no ] && [ -z "$(ls -A /run/netns 2>/dev/null)" ]; then
		while mountpoint -q /run/netns; do umount /run/netns || break; done
		rmdir /run/netns 2>/dev/null
	fi
	rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 3' INT TERM

die() { echo "e02: $*" >&2; exit 3; }
[ -x "$P" ] || die "probe binary $P missing"
[ -n "$IMG" ] || die "no postgres image on this node"

# at WHERE CMD...: WHERE is a container name, "ns" (the neighbour) or "node"
at() {
	w=$1
	shift
	case $w in
	node) exec "$@" ;;
	ns) exec ip netns exec "$NS" "$@" ;;
	mv) exec ip netns exec "$MV" "$@" ;;
	*) exec nsenter --net="/proc/$(docker inspect -f '{{.State.Pid}}' "$w")/ns/net" "$@" ;;
	esac
}

probe() { # WHERE ADDR:PORT -> R; the verdict line must agree with the exit code
	set +e
	out=$(at "$1" "$P" tcp "$2" --timeout 1s 2>&1)
	rc=$?
	set -e
	R=${out%% *}
	case "$R:$rc" in
	connected:0 | refused:1 | unreachable:1 | timeout:2) ;;
	*) die "probe $1 -> $2: verdict and exit code disagree: '$out' rc=$rc" ;;
	esac
}

expect() { # KIND(test|ctl) LABEL WANT WHERE ADDR:PORT
	probe "$4" "$5"
	if [ "$R" = "$3" ]; then
		echo "  ok    $2: $R"
	else
		echo "  FAIL  $2: $R (want $3)"
		if [ "$1" = ctl ]; then cfail=$((cfail + 1)); else fail=$((fail + 1)); fi
	fi
}

listen() { # WHERE ADDR:PORT
	f="$W/l.$1.${2##*:}"
	at "$1" "$P" listen tcp "$2" >"$f" 2>&1 &
	echo $! >>"$W/pids"
	i=0
	until grep -qs '^listening' "$f"; do
		i=$((i + 1))
		[ "$i" -lt 50 ] || die "listener $1 $2 did not start: $(cat "$f" 2>/dev/null)"
		sleep 0.1
	done
}

handle() { # CHAIN PATTERN -> handle of the one rule containing PATTERN
	h=$(nft -a list chain inet supapace "$1" | grep -F -- "$2" | sed -n 's/.*# handle \([0-9]*\)$/\1/p')
	[ "$(echo "$h" | wc -w)" = 1 ] || die "pattern '$2' in $1 matches $(echo "$h" | wc -w) rules"
	echo "$h"
}

off() { # CHAIN PATTERN: delete that rule
	h=$(handle "$1" "$2")
	nft delete rule inet supapace "$1" handle "$h"
	echo "   (deleted from $1: '$2', handle $h)"
}

echo "== e02: kernel $(uname -r), docker $(docker version -f '{{.Server.Version}}'), $(nft --version)"

# Two routable bridges (not internal; direct routing allowed so Docker's own
# chains do not hide the effect of ours): one with a chosen name, one unnamed.
docker network create --label e02=1 --ipv6=false --subnet 10.213.1.0/26 \
	-o com.docker.network.bridge.name=spp4 -o com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected e02-named >/dev/null
docker network create --label e02=1 --ipv6=false --subnet 10.214.0.64/26 \
	-o com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected e02-unnamed >/dev/null
docker run -d --name e02-a --label e02=1 --network e02-named --ip 10.213.1.2 --entrypoint sleep "$IMG" 86400 >/dev/null
docker run -d --name e02-b --label e02=1 --network e02-unnamed --ip 10.214.0.66 --entrypoint sleep "$IMG" 86400 >/dev/null
UB=$(ip -o -4 addr show to 10.214.0.65/32 | awk '{print $2}')
echo "unnamed bridge device: $UB"

# Neighbour namespace on a veth pair.
ip netns add "$NS"
ip link add e02h type veth peer name e02p
ip link set e02p netns "$NS"
ip addr add 10.214.250.1/30 dev e02h
ip link set e02h up
ip -n "$NS" addr add 10.214.250.2/30 dev e02p
ip -n "$NS" link set e02p up
ip -n "$NS" link set lo up
ip -n "$NS" route add default via 10.214.250.1
# A macvlan pair on a dummy parent: one child on the node, one in a namespace.
awk '{print $1}' /proc/modules | sort >"$W/m0"
ip netns add "$MV"
ip link add e02d type dummy
ip link set e02d up
ip link add e02m0 link e02d type macvlan mode bridge
ip link add e02m1 link e02d type macvlan mode bridge
ip link set e02m1 netns "$MV"
ip addr add 10.214.251.1/30 dev e02m0
ip link set e02m0 up
ip -n "$MV" addr add 10.214.251.2/30 dev e02m1
ip -n "$MV" link set e02m1 up
UPL=$(ip -4 route show default | awk '{print $5; exit}')
echo "node default-route interface: ${UPL:-none}; neighbour veth: e02h"
[ -n "$UPL" ] || die "the node has no default route"

listen node 0.0.0.0:7001
listen ns 10.214.250.2:7002
listen e02-a 10.213.1.2:7003
listen e02-b 10.214.0.66:7003

# The inet table as the node installs it.
cat >"$W/kind.nft" <<'EOF'
table inet supapace
delete table inet supapace
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
EOF
# Name-based variant: every interface that is neither an uplink nor loopback.
sed -e "s|meta iifkind \"bridge\" drop|iifname != { \"$UPL\", \"e02h\", \"lo\" } drop|" \
	-e "s|meta oifkind \"bridge\" drop|oifname != { \"$UPL\", \"e02h\", \"lo\" } drop|" \
	"$W/kind.nft" >"$W/name.nft"

echo "-- without our table (all must connect)"
expect ctl "neighbour on a macvlan child -> node" connected mv 10.214.251.1:7001
expect ctl "named member -> node (bridge address)" connected e02-a 10.213.1.1:7001
expect ctl "unnamed member -> node (bridge address)" connected e02-b 10.214.0.65:7001
expect ctl "named member -> neighbour (routed)" connected e02-a 10.214.250.2:7002
expect ctl "neighbour -> named member (routed)" connected ns 10.213.1.2:7003
expect ctl "neighbour -> unnamed member (routed)" connected ns 10.214.0.66:7003

# matrix VARIANT FILE IN-PATTERN FWD-IN-PATTERN FWD-OUT-PATTERN -> M
matrix() {
	v=$1 f=$2 M=fail
	echo "-- $v: load"
	if ! nft -f "$f" 2>"$W/err"; then
		echo "  load failed: $(cat "$W/err")"
		return 0
	fi
	nft list table inet supapace | sed 's/^/  | /'
	fail=0
	echo "-- $v: all rules on"
	expect test "named member -> node (bridge address)" timeout e02-a 10.213.1.1:7001
	expect test "unnamed member -> node (bridge address)" timeout e02-b 10.214.0.65:7001
	expect test "named member -> node (neighbour-side address)" timeout e02-a 10.214.250.1:7001
	expect test "neighbour on a veth (not a bridge port) -> node" connected ns 10.214.250.1:7001
	expect test "neighbour on a macvlan child -> node" "$6" mv 10.214.251.1:7001
	expect test "named member -> neighbour" timeout e02-a 10.214.250.2:7002
	expect test "unnamed member -> neighbour" timeout e02-b 10.214.250.2:7002
	expect test "neighbour -> named member" timeout ns 10.213.1.2:7003
	expect test "neighbour -> unnamed member" timeout ns 10.214.0.66:7003

	echo "-- $v: input drop off"
	off input "$3"
	expect ctl "named member -> node (bridge address)" connected e02-a 10.213.1.1:7001
	expect ctl "unnamed member -> node (bridge address)" connected e02-b 10.214.0.65:7001
	expect ctl "named member -> node (neighbour-side address)" connected e02-a 10.214.250.1:7001
	nft -f "$f"

	# A TCP exchange crosses both forward drops (request one way, reply the
	# other), so each drop is shown alone on the opening packet's direction,
	# then both are removed together.
	echo "-- $v: from-bridge drop off, into-bridge drop on (blocks the SYN into the bridge)"
	off forward "$4"
	expect test "neighbour -> named member" timeout ns 10.213.1.2:7003
	expect test "neighbour -> unnamed member" timeout ns 10.214.0.66:7003
	nft -f "$f"
	echo "-- $v: into-bridge drop off, from-bridge drop on (blocks the SYN out of the bridge)"
	off forward "$5"
	expect test "named member -> neighbour" timeout e02-a 10.214.250.2:7002
	expect test "unnamed member -> neighbour" timeout e02-b 10.214.250.2:7002
	echo "-- $v: both forward drops off"
	off forward "$4"
	expect ctl "named member -> neighbour" connected e02-a 10.214.250.2:7002
	expect ctl "unnamed member -> neighbour" connected e02-b 10.214.250.2:7002
	expect ctl "neighbour -> named member" connected ns 10.213.1.2:7003
	expect ctl "neighbour -> unnamed member" connected ns 10.214.0.66:7003
	nft -f "$f"
	echo "-- $v: restored"
	expect test "named member -> neighbour" timeout e02-a 10.214.250.2:7002
	expect test "neighbour -> named member" timeout ns 10.213.1.2:7003
	if [ "$fail" = 0 ]; then M=ok; fi
	nft delete table inet supapace
}

matrix kind "$W/kind.nft" 'iifkind "bridge" drop' 'iifkind "bridge" drop' 'oifkind "bridge" drop' connected
kind=$M
matrix name "$W/name.nft" 'iifname !=' 'iifname !=' 'oifname !=' timeout
name=$M
awk '{print $1}' /proc/modules | sort >"$W/m1"
echo "kernel modules that appeared during this run: $(comm -13 "$W/m0" "$W/m1" | tr '\n' ' ')"
echo "kind=$kind name=$name control-failures=$cfail"

if [ "$cfail" != 0 ]; then
	echo "VERDICT E02: unknown — $cfail control probe(s) failed, so a blocked probe proves nothing."
elif [ "$kind" = ok ]; then
	echo "VERDICT E02: confirmed — iifkind/oifkind \"bridge\" select traffic from and to named and unnamed bridges in inet input and forward, and nothing from the neighbour (name-based variant: $name)."
elif [ "$name" = ok ]; then
	echo "VERDICT E02: fallback — the interface-kind matches do not select bridge traffic here; the uplink-name variant does."
else
	echo "VERDICT E02: unknown — neither the interface-kind matches nor the uplink-name variant hold on this kernel."
fi
