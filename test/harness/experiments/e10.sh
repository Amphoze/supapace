#!/bin/sh
# e10: with Docker's userland proxy on, does dockerd leave br_netfilter and the
# bridge-nf-call-* switches alone, and does the published-port path behave?
# A second dockerd runs in its own network namespace with the userland proxy on
# (Docker's default), first with module loading possible, then with
# CAP_SYS_MODULE removed from its bounding set (neither modprobe nor the kernel's
# interface-name autoload can load anything for it - the in-container stand-in
# for a module blocked on the host). Across daemon start, every network class
# (internal isolated project network, ranged platform network, published-port
# network), network connect, a port-publishing container and its restart, a
# network create while containers run and a daemon restart, it checks that the
# module never appears and the switches never exist, and probes a project pair
# under the node ruleset after every event (one allowed port, one blocked port
# with its control). The published port is probed from a neighbour namespace,
# from the dockerd namespace with an explicitly bound second source address,
# from a container on the same bridge (hairpin) and over IPv6; the server side
# records each connection's source address. With the module unloadable, a
# network with enable_icc=false must be refused.
# Opt-in (E10_LOAD_MODULE=1 only): a dockerd with the userland proxy off, which
# loads br_netfilter into the running kernel - a host-wide change that stays
# until reboot - and rewrites bridge-nf-call-iptables on network create.
# Runs as root on the test node.
set -eu

P=${SP_PROBE:-/opt/supapace/bin/sp-probe}
IMG=${IMG:-$(docker image ls -q postgres | head -n 1)}
W=$(mktemp -d)
NS=e10 NB=e10n
ROOT=/var/lib/docker/e10-daemon
EXEC=/run/e10-docker
DPID='' BLOCK=0 CONF=''
UPL=10.214.250.1 NBR=10.214.250.2 SRC2=10.214.250.6
fail=0 cfail=0
netns_dir_existed=no
[ -d /run/netns ] && netns_dir_existed=yes

d() { docker -H "unix://$EXEC/docker.sock" "$@"; }
loaded() { awk '{print $1}' /proc/modules | grep -qx br_netfilter; }

stop_d() {
	[ -n "$DPID" ] || return 0
	kill "$DPID" 2>/dev/null || :
	i=0
	while kill -0 "$DPID" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -lt 300 ] || { kill -9 "$DPID" 2>/dev/null || :; break; }
		sleep 0.1
	done
	DPID=
}
wipe_d() { # remove the daemon's objects, stop it
	if [ -n "$DPID" ]; then
		d ps -aq 2>/dev/null | xargs -r docker -H "unix://$EXEC/docker.sock" rm -f >/dev/null 2>&1 || :
		d network prune -f >/dev/null 2>&1 || :
	fi
	stop_d
}
cleanup() {
	trap '' INT TERM # a signal during cleanup must not cut it short
	set +e
	[ -f "$W/pids" ] && xargs -r kill <"$W/pids" 2>/dev/null
	wipe_d
	ip netns del "$NS" 2>/dev/null
	ip netns del "$NB" 2>/dev/null
	ip netns del e10x 2>/dev/null
	if [ "$netns_dir_existed" = no ] && [ -z "$(ls -A /run/netns 2>/dev/null)" ]; then
		while mountpoint -q /run/netns; do umount /run/netns || break; done
		rmdir /run/netns 2>/dev/null
	fi
	rm -rf "$ROOT" "$EXEC" "$W"
}
trap cleanup EXIT
trap 'exit 3' INT TERM

die() { echo "e10: $*" >&2; exit 3; }
[ -x "$P" ] || die "probe binary $P missing"
[ -n "$IMG" ] || die "no postgres image on this node"

check() { # KIND(test|ctl) LABEL GOT WANT
	if [ "$3" = "$4" ]; then
		echo "  ok    $2: $3"
	else
		echo "  FAIL  $2: $3 (want $4)"
		if [ "$1" = ctl ]; then cfail=$((cfail + 1)); else fail=$((fail + 1)); fi
	fi
}
sw() { # switches in the dockerd namespace: "absent" or "iptables,ip6tables,arptables"
	n=${1:-/run/netns/$NS}
	if ! nsenter --net="$n" test -e /proc/sys/net/bridge/bridge-nf-call-iptables; then
		echo absent
		return
	fi
	o=
	for k in iptables ip6tables arptables; do o="$o$(nsenter --net="$n" cat "/proc/sys/net/bridge/bridge-nf-call-$k"),"; done
	echo "${o%,}"
}
zero() {
	for k in iptables ip6tables arptables; do
		f=/proc/sys/net/bridge/bridge-nf-call-$k
		if nsenter --net="/run/netns/$NS" test -e "$f"; then nsenter --net="/run/netns/$NS" sh -c "echo 0 >$f"; fi
	done
}
modstate() { if loaded; then echo loaded; else echo absent; fi; }

cpid() { d inspect -f '{{.State.Pid}}' "$1"; }
netof() { # WHERE -> netns path: a container of the second daemon, "ns" (dockerd's) or "nb" (neighbour)
	case $1 in
	ns) echo "/run/netns/$NS" ;;
	nb) echo "/run/netns/$NB" ;;
	*) echo "/proc/$(cpid "$1")/ns/net" ;;
	esac
}
probe() { # WHERE ADDR:PORT -> R
	set +e
	out=$(nsenter --net="$(netof "$1")" "$P" tcp "$2" --timeout 1s 2>&1)
	rc=$?
	set -e
	R=${out%% *}
	case "$R:$rc" in
	connected:0 | refused:1 | unreachable:1 | timeout:2) ;;
	*) die "probe $1 -> $2: verdict and exit code disagree: '$out' rc=$rc" ;;
	esac
}
listen() { # CONTAINER ADDR:PORT
	f="$W/l.$1.${2##*:}"
	rm -f "$f"
	nsenter --net="$(netof "$1")" "$P" listen tcp "$2" >"$f" 2>&1 &
	echo $! >>"$W/pids"
	i=0
	until grep -qs '^listening' "$f"; do
		i=$((i + 1))
		[ "$i" -lt 50 ] || die "listener $1 $2 did not start"
		sleep 0.1
	done
}
# The server side records the source address of every connection opening (SYN)
# to port 8443 inside a gateway container.
seen_init() { # CONTAINER
	nsenter --net="$(netof "$1")" nft -f - <<'EOF'
table ip e10seen
delete table ip e10seen
table ip e10seen {
  set src { type ipv4_addr; }
  chain in {
    type filter hook input priority filter; policy accept;
    tcp dport 8443 tcp flags & (syn | ack) == syn add @src { ip saddr }
  }
}
EOF
}
seen() { # CONTAINER -> source addresses since the last call
	n=$(netof "$1")
	s=$(nsenter --net="$n" nft list set ip e10seen src | tr -d '\n\t' | sed -n 's/.*elements = { \([^}]*\) }.*/\1/p')
	nsenter --net="$n" nft flush set ip e10seen src
	echo "${s:-none}"
}

# start_d BLOCKED CONFIG [keep]: dockerd in the e10 namespace; 0 if it serves.
# Without "keep" both namespaces are created afresh (uplink veth to the neighbour).
start_d() {
	BLOCK=$1 CONF=$2
	if [ "${3:-}" != keep ]; then
		ip netns del "$NS" 2>/dev/null || :
		ip netns del "$NB" 2>/dev/null || :
		ip netns add "$NS"
		ip netns add "$NB"
		ip link add e10u netns "$NS" type veth peer name e10v netns "$NB"
		ip -n "$NS" addr add "$UPL/30" dev e10u
		ip -n "$NS" addr add "$SRC2/32" dev e10u
		ip -n "$NB" addr add "$NBR/30" dev e10v
		for n in "$NS" "$NB"; do ip -n "$n" link set lo up; done
		ip -n "$NS" link set e10u up
		ip -n "$NB" link set e10v up
		V6=no
		if ip -n "$NS" addr add 2001:db8::1/64 dev e10u nodad 2>/dev/null &&
			ip -n "$NB" addr add 2001:db8::2/64 dev e10v nodad 2>/dev/null; then V6=yes; fi
	fi
	mkdir -p "$ROOT" "$EXEC"
	pre=
	[ "$BLOCK" = 0 ] || pre="setpriv --inh-caps=-sys_module --bounding-set=-sys_module"
	# shellcheck disable=SC2086
	$pre nsenter --net="/run/netns/$NS" dockerd --config-file "$CONF" --data-root "$ROOT" \
		--exec-root "$EXEC" --pidfile "$EXEC/dockerd.pid" -H "unix://$EXEC/docker.sock" >"$W/d.log" 2>&1 &
	DPID=$!
	i=0
	until d info >/dev/null 2>&1; do
		if ! kill -0 "$DPID" 2>/dev/null; then
			DPID=
			return 1
		fi
		i=$((i + 1))
		[ "$i" -lt 600 ] || die "dockerd did not come up: $(tail -n 3 "$W/d.log")"
		sleep 0.1
	done
	[ "$BLOCK" = 0 ] || echo "  dockerd $(grep CapBnd "/proc/$DPID/status") (bit 16, CAP_SYS_MODULE, is clear)"
	if ! d image inspect "$IMG" >/dev/null 2>&1; then docker save "$IMG" | d load -q >/dev/null; fi
}
derr() { grep -o 'failed to start daemon: .*' "$W/d.log" | head -n 1 | sed 's/\\"/"/g' | cut -c1-400; }

run() { # NAME NETWORK IP [docker run options]
	n=$1 net=$2 ip=$3
	shift 3
	d run -d --name "$n" --network "$net" --ip "$ip" "$@" --entrypoint sleep "$IMG" 86400 >/dev/null
}
mkproj() { # NAME SUBNET BRIDGE
	d network create --internal --ipv6=false --subnet "$2" -o com.docker.network.bridge.name="$3" \
		-o com.docker.network.bridge.gateway_mode_ipv4=isolated "$1" >/dev/null
}

cat >"$W/proxy-on.json" <<'EOF'
{"default-address-pools":[{"base":"10.214.0.0/16","size":26}],"ipv6":false,
 "log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}
EOF
sed 's/"ipv6":false,/"ipv6":false,"userland-proxy":false,/' "$W/proxy-on.json" >"$W/proxy-off.json"

cat >"$W/rules.nft" <<'EOF'
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
rules() { nsenter --net="/run/netns/$NS" nft "$@"; }

# Listeners of the project pair and the gateway (again after container restarts).
up_pair() {
	listen e10-pg 10.213.0.2:5432
	listen e10-pg 10.213.0.2:5433
}
up_gw() {
	listen e10-gw 0.0.0.0:8443
	seen_init e10-gw
}

# ev LABEL CMD...: one Docker event, then module, switches and the pair under the ruleset.
ev() {
	l=$1
	shift
	"$@" >/dev/null
	m=$(modstate) s=$(sw)
	probe e10-rest 10.213.0.2:5432
	a=$R
	probe e10-rest 10.213.0.2:5433
	b=$R
	echo "  | $l | module $m | switches $s | rest->pg:5432 $a | rest->pg:5433 $b |"
	[ "$m" = "$EXPECT_MOD" ] || { echo "  FAIL  module state changed"; fail=$((fail + 1)); }
	[ "$s" = "$EXPECT_SW" ] || { echo "  FAIL  switches changed"; fail=$((fail + 1)); }
	[ "$a" = connected ] || { echo "  FAIL  allowed pair blocked"; fail=$((fail + 1)); }
	[ "$b" = timeout ] || { echo "  FAIL  blocked port reached"; fail=$((fail + 1)); }
}
restart_d() {
	stop_d
	start_d "$BLOCK" "$CONF" keep || die "dockerd did not restart: $(derr)"
	# No restart policy: the agent starts tenants itself after a daemon start.
	d start e10-pg e10-rest e10-gw >/dev/null
	up_pair
	up_gw
}

# phase LABEL BLOCKED: the proxy-on daemon through every event, then the published port.
phase() {
	echo "-- $1"
	start_d "$2" "$W/proxy-on.json" || {
		echo "  FAIL  dockerd does not start: $(derr)"
		fail=$((fail + 1))
		return 0
	}
	EXPECT_MOD=$(modstate)
	if [ "$EXPECT_MOD" = loaded ]; then
		zero
		echo "  (br_netfilter was already loaded: switches written to 0, they must stay 0)"
	fi
	EXPECT_SW=$(sw)
	echo "  after dockerd start: module $EXPECT_MOD; switches in its namespace $EXPECT_SW"
	mkproj e10-pa 10.213.0.0/26 spp0
	run e10-pg e10-pa 10.213.0.2
	run e10-rest e10-pa 10.213.0.3
	rules -f "$W/rules.nft"
	up_pair
	echo "  | event | module | switches | allowed | blocked |"
	ev "dockerd start, project network, two members" true
	ev "platform network create" d network create --internal --ipv6=false --subnet 10.212.0.0/21 \
		--ip-range 10.212.6.0/23 -o com.docker.network.bridge.name=spl0 \
		-o com.docker.network.bridge.gateway_mode_ipv4=isolated e10-plat
	ev "network connect --ip (postgrest to platform)" d network connect --ip 10.212.0.16 e10-plat e10-rest
	ev "published-port network create" d network create --ipv6=false --subnet 10.212.8.0/24 \
		-o com.docker.network.bridge.name=spi0 e10-ing
	ev "gateway with published ports" run e10-gw e10-ing 10.212.8.2 -p 0.0.0.0:443:8443 -p 0.0.0.0:80:8080
	ev "network connect --ip (gateway to platform)" d network connect --ip 10.212.0.2 e10-plat e10-gw
	up_gw
	ev "gateway restart" d restart -t 1 e10-gw
	up_gw
	ev "project network create while containers run" mkproj e10-pb 10.213.0.64/26 spp1
	ev "member start on the new project network" run e10-pg2 e10-pb 10.213.0.66
	ev "dockerd restart (members started again)" restart_d
	echo "  control: bridge chain policy accept"
	rules 'chain bridge supapace forward { policy accept; }'
	probe e10-rest 10.213.0.2:5433
	check ctl "rest->pg:5433 without the drop policy" "$R" connected
	rules -f "$W/rules.nft"

	echo "  published port (ruleset loaded):"
	seen e10-gw >/dev/null
	probe nb "$UPL:443"
	check test "neighbour -> $UPL:443" "$R" connected
	check test "  source seen by the gateway" "$(seen e10-gw)" "$NBR"
	set +e
	nsenter --net="/run/netns/$NS" nc -z -w 2 -s "$SRC2" "$UPL" 443
	rc=$?
	set -e
	check test "dockerd namespace, source $SRC2 -> $UPL:443 (nc exit)" "$rc" 0
	check test "  source seen by the gateway" "$(seen e10-gw)" "$SRC2"
	run e10-hp e10-ing 10.212.8.9
	probe e10-hp "$UPL:443"
	echo "  hairpin e10-hp (10.212.8.9) -> $UPL:443 under the ruleset: $R; source seen: $(seen e10-gw)"
	rules delete table inet supapace
	rules delete table bridge supapace
	probe e10-hp "$UPL:443"
	echo "  hairpin without our tables: $R; source seen: $(seen e10-gw)"
	rules -f "$W/rules.nft"
	echo "  listeners in the dockerd namespace:"
	nsenter --net="/run/netns/$NS" ss -lntH | awk '{print "    " $4}' | sort -u
	if nsenter --net="/run/netns/$NS" ss -lntH | awk '{print $4}' | grep -q '^\[::\]:443$'; then
		echo "  FAIL  an IPv6 listener exists for 443"
		fail=$((fail + 1))
	else
		echo "  ok    no IPv6 listener for the published 443"
	fi
	if [ "$V6" = yes ]; then
		probe nb "[2001:db8::1]:443"
		check test "IPv6 neighbour -> [2001:db8::1]:443" "$R" refused
		run e10-gw2 e10-ing 10.212.8.3 -p 8444:8443
		listen e10-gw2 0.0.0.0:8443
		seen_init e10-gw2
		echo "  control, published without a host address (-p 8444:8443):"
		nsenter --net="/run/netns/$NS" ss -lntpH | grep ':8444 ' | awk '{print "    " $4 " " $6}'
		probe nb "[2001:db8::1]:8444"
		echo "    IPv6 neighbour -> [2001:db8::1]:8444: $R; source seen by the gateway: $(seen e10-gw2)"
		probe nb "$UPL:8444"
		echo "    IPv4 neighbour -> $UPL:8444: $R; source seen by the gateway: $(seen e10-gw2)"
	else
		echo "  IPv6 could not be configured in the namespaces: IPv6 client cases not tested"
	fi

	if [ "$2" = 1 ]; then
		if d network create --ipv6=false --subnet 10.214.9.128/26 -o com.docker.network.bridge.enable_icc=false e10-noicc >/dev/null 2>"$W/err"; then
			echo "  FAIL  a network with enable_icc=false was created without the module"
			fail=$((fail + 1))
		else
			echo "  ok    enable_icc=false network refused: $(head -c 300 "$W/err" | tr '\n' ' ')"
		fi
	fi
	echo "  module at the end of the phase: $(modstate); switches $(sw)"
	wipe_d
}

echo "== e10: kernel $(uname -r), node docker $(docker version -f '{{.Server.Version}}')"
awk '{print $1}' /proc/modules | sort >"$W/m0"
pre_loaded=$(modstate)
echo "br_netfilter at start: $pre_loaded"

phase "U: userland proxy on, module loadable" 0
phase "B: userland proxy on, module unloadable for dockerd (no environment override)" 1

if [ "${E10_LOAD_MODULE:-}" = 1 ]; then
	echo "-- L (opt-in): userland proxy off, module loadable"
	start_d 0 "$W/proxy-off.json" || die "dockerd does not start: $(derr)"
	echo "  after dockerd start: module $(modstate); switches $(sw)"
	mkproj e10-pa 10.213.0.0/26 spp0
	run e10-pg e10-pa 10.213.0.2
	run e10-rest e10-pa 10.213.0.3
	rules -f "$W/rules.nft"
	up_pair
	zero
	probe e10-rest 10.213.0.2:5432
	echo "  switches written to 0: $(sw); rest->pg:5432 $R"
	mkproj e10-pb 10.213.0.64/26 spp1
	probe e10-rest 10.213.0.2:5432
	echo "  after a project network create: switches $(sw); rest->pg:5432 $R"
	h2=$(rules -a list chain inet supapace forward | sed -n '/iifkind "bridge" drop/s/.*# handle \([0-9]*\)$/\1/p')
	rules delete rule inet supapace forward handle "$h2"
	probe e10-rest 10.213.0.2:5432
	echo "  forward from-bridge drop deleted only: $R"
	rules -f "$W/rules.nft"
	h4=$(rules -a list chain inet supapace forward | sed -n '/oifkind "bridge" drop/s/.*# handle \([0-9]*\)$/\1/p')
	rules delete rule inet supapace forward handle "$h4"
	probe e10-rest 10.213.0.2:5432
	echo "  forward into-bridge drop deleted only: $R"
	h2=$(rules -a list chain inet supapace forward | sed -n '/iifkind "bridge" drop/s/.*# handle \([0-9]*\)$/\1/p')
	rules delete rule inet supapace forward handle "$h2"
	probe e10-rest 10.213.0.2:5432
	echo "  both forward drops deleted: $R (diverted frames carry the bridge as input and output device)"
	rules -f "$W/rules.nft"
	wipe_d
	if [ "$pre_loaded" = absent ] && loaded; then
		ip netns add e10x
		echo "  br_netfilter was loaded by this phase and REMAINS LOADED until reboot (this script never unloads it)."
		echo "  It created net.bridge.bridge-nf-call-{iptables,ip6tables,arptables} in every network namespace,"
		echo "  the host's initial one included, at the module default (a new namespace reads $(sw /run/netns/e10x))."
		ip netns del e10x
	fi
else
	echo "-- L skipped (set E10_LOAD_MODULE=1 to show a proxy-off dockerd loading br_netfilter; host-wide, stays until reboot)"
fi

awk '{print $1}' /proc/modules | sort >"$W/m1"
echo "-- kernel modules that appeared during this run:"
comm -13 "$W/m0" "$W/m1" | sed 's/^/  + /'
echo "failures=$fail control-failures=$cfail"
if [ "$cfail" != 0 ] || [ "$fail" != 0 ]; then
	echo "VERDICT E10: unknown — $fail check(s) and $cfail control(s) failed with the userland proxy on."
else
	echo "VERDICT E10: fallback — the userland proxy stays on, so dockerd never loads br_netfilter (nor needs it, except for enable_icc=false networks, which fail loudly) and the containment path holds through every event."
fi
