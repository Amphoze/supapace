#!/bin/sh
# e11: can a container hold a fixed address outside the allocator range of an
# internal, isolated network? On a /21 created with a /23 --ip-range: is
# "docker network connect --ip" accepted for an address outside the range, is
# the address the same after start, stop/start and rm + re-create, do ten
# containers connected without --ip all land inside the range, can another
# container take the fixed address while its holder runs (run, or create +
# network connect + start) or is stopped, and does a
# process bound to 0.0.0.0 in a container on two networks accept connections
# on both? The same network created without --ip-range is checked as well.
# Runs as root on the test node.
set -eu

P=${SP_PROBE:-/opt/supapace/bin/sp-probe}
IMG=${IMG:-$(docker image ls -q postgres | head -n 1)}
W=$(mktemp -d)
FIXED=10.212.0.16
fail=0 cfail=0

cleanup() {
	trap '' INT TERM # a signal during cleanup must not cut it short
	set +e
	[ -f "$W/pids" ] && xargs -r kill <"$W/pids" 2>/dev/null
	docker ps -aq --filter label=e11=1 | xargs -r docker rm -f >/dev/null 2>&1
	docker network rm e11-proj e11-plat e11-plat2 >/dev/null 2>&1
	rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 3' INT TERM

die() { echo "e11: $*" >&2; exit 3; }
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
addr() { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1"; }
live() { # CONTAINER IFADDR: the address the kernel has inside the container on that network
	nsenter --net="/proc/$(docker inspect -f '{{.State.Pid}}' "$1")/ns/net" ip -o -4 addr show |
		awk -v p="$2" 'index($4, p) == 1 {sub("/.*", "", $4); print $4}'
}
inrange() { # ADDR: inside 10.212.6.0/23?
	case $1 in 10.212.6.* | 10.212.7.*) return 0 ;; *) return 1 ;; esac
}
probe() { # CONTAINER ADDR:PORT -> R
	set +e
	out=$(nsenter --net="/proc/$(docker inspect -f '{{.State.Pid}}' "$1")/ns/net" "$P" tcp "$2" --timeout 1s 2>&1)
	rc=$?
	set -e
	R=${out%% *}
	case "$R:$rc" in
	connected:0 | refused:1 | unreachable:1 | timeout:2) ;;
	*) die "probe $1 -> $2: verdict and exit code disagree: '$out' rc=$rc" ;;
	esac
}

# The PostgREST sequence: created on its project network, connected to the
# platform network at its fixed address, then started.
make_rest() {
	docker create --name e11-rest --label e11=1 --network e11-proj --ip 10.213.0.3 --entrypoint sleep "$IMG" 86400 >/dev/null
	if ! docker network connect --ip "$FIXED" e11-plat e11-rest 2>"$W/err"; then
		echo "  connect --ip $FIXED refused: $(cat "$W/err")"
		return 1
	fi
	docker start e11-rest >/dev/null
}

echo "== e11: kernel $(uname -r), docker $(docker version -f '{{.Server.Version}}')"
docker network create --label e11=1 --internal --ipv6=false --subnet 10.213.0.0/26 \
	-o com.docker.network.bridge.name=spp0 -o com.docker.network.bridge.gateway_mode_ipv4=isolated e11-proj >/dev/null
docker network create --label e11=1 --internal --ipv6=false --subnet 10.212.0.0/21 --ip-range 10.212.6.0/23 \
	-o com.docker.network.bridge.name=spl0 -o com.docker.network.bridge.gateway_mode_ipv4=isolated e11-plat >/dev/null

accepted=yes
echo "-- fixed address outside the range"
if make_rest; then
	check test "after create, connect, start (inspect)" "$(addr e11-rest e11-plat)" "$FIXED"
	check test "after create, connect, start (kernel)" "$(live e11-rest 10.212.)" "$FIXED"
	docker stop -t 1 e11-rest >/dev/null
	docker start e11-rest >/dev/null
	check test "after stop/start (inspect)" "$(addr e11-rest e11-plat)" "$FIXED"
	check test "after stop/start (kernel)" "$(live e11-rest 10.212.)" "$FIXED"
	docker rm -f e11-rest >/dev/null
	make_rest || fail=$((fail + 1))
	check test "after rm + re-create (inspect)" "$(addr e11-rest e11-plat)" "$FIXED"
	check test "after rm + re-create (kernel)" "$(live e11-rest 10.212.)" "$FIXED"
	docker run -d --name e11-gw --label e11=1 --network e11-plat --ip 10.212.0.2 --entrypoint sleep "$IMG" 86400 >/dev/null
	check test "gateway address (kernel)" "$(live e11-gw 10.212.)" 10.212.0.2

	echo "-- a second container asking for the address while its holder runs"
	if docker run -d --name e11-dup1 --label e11=1 --network e11-plat --ip "$FIXED" --entrypoint sleep "$IMG" 86400 >/dev/null 2>"$W/err"; then
		echo "  run --ip: accepted and started (address now $(live e11-dup1 10.212.))"
	else
		echo "  run --ip: refused: $(head -c 200 "$W/err" | tr '\n' ' ')"
	fi
	docker rm -f e11-dup1 >/dev/null 2>&1 || :
	docker create --name e11-dup2 --label e11=1 --network e11-proj --ip 10.213.0.10 --entrypoint sleep "$IMG" 86400 >/dev/null
	if docker network connect --ip "$FIXED" e11-plat e11-dup2 2>"$W/err"; then
		echo "  create + network connect --ip: connect accepted"
		if docker start e11-dup2 >/dev/null 2>"$W/err"; then
			echo "  then start: started with $(live e11-dup2 10.212.)"
		else
			echo "  then start: fails: $(head -c 200 "$W/err" | tr '\n' ' ')"
		fi
	else
		echo "  create + network connect --ip: connect refused: $(head -c 200 "$W/err" | tr '\n' ' ')"
	fi
	docker rm -f e11-dup2 >/dev/null
	check test "holder still has the address" "$(live e11-rest 10.212.)" "$FIXED"
else
	accepted=no
	fail=$((fail + 1))
fi

echo "-- ten containers without --ip, fixed-address holder stopped"
[ "$accepted" = no ] || docker stop -t 1 e11-rest >/dev/null
out=0 list=
for i in 0 1 2 3 4 5 6 7 8 9; do
	docker run -d --name "e11-dyn$i" --label e11=1 --network e11-plat --entrypoint sleep "$IMG" 86400 >/dev/null
	a=$(live "e11-dyn$i" 10.212.)
	list="$list $a"
	inrange "$a" || out=$((out + 1))
done
echo "  addresses:$list"
check test "dynamic addresses outside 10.212.6.0/23" "$out" 0

echo "-- another container asking for the stopped holder's address"
if docker run -d --name e11-thief --label e11=1 --network e11-plat --ip "$FIXED" --entrypoint sleep "$IMG" 86400 >/dev/null 2>"$W/err"; then
	thief="taken (Docker does not reserve it for a stopped container)"
	if [ "$accepted" = yes ]; then
		if docker start e11-rest >/dev/null 2>"$W/err"; then
			thief="$thief; the holder then starts anyway with $(live e11-rest 10.212.)"
			docker stop -t 1 e11-rest >/dev/null
		else
			thief="$thief; the holder then fails to start: $(head -c 160 "$W/err" | tr "\n" " ")"
		fi
	fi
	docker rm -f e11-thief >/dev/null
else
	thief="refused: $(head -c 200 "$W/err")"
	docker rm -f e11-thief >/dev/null 2>&1 || :
fi
echo "  $thief"

if [ "$accepted" = yes ]; then
	docker start e11-rest >/dev/null
	echo "-- 0.0.0.0 listener in a two-network container"
	nsenter --net="/proc/$(docker inspect -f '{{.State.Pid}}' e11-rest)/ns/net" "$P" listen tcp 0.0.0.0:3000 >"$W/l" 2>&1 &
	echo $! >>"$W/pids"
	i=0
	until grep -qs '^listening' "$W/l"; do
		i=$((i + 1))
		[ "$i" -lt 50 ] || die "listener did not start: $(cat "$W/l")"
		sleep 0.1
	done
	docker run -d --name e11-pg --label e11=1 --network e11-proj --ip 10.213.0.2 --entrypoint sleep "$IMG" 86400 >/dev/null
	probe e11-pg 10.213.0.3:3000
	check test "project member -> 10.213.0.3:3000" "$R" connected
	probe e11-gw "$FIXED:3000"
	check test "platform member -> $FIXED:3000" "$R" connected
	probe e11-gw "$FIXED:3999"
	check ctl "platform member -> $FIXED:3999 (nothing listens)" "$R" refused
fi

echo "-- same network without --ip-range"
docker ps -aq --filter label=e11=1 | xargs -r docker rm -f >/dev/null
docker network rm e11-plat >/dev/null
docker network create --label e11=1 --internal --ipv6=false --subnet 10.212.0.0/21 \
	-o com.docker.network.bridge.name=spl0 -o com.docker.network.bridge.gateway_mode_ipv4=isolated e11-plat2 >/dev/null
docker create --name e11-rest2 --label e11=1 --network e11-proj --ip 10.213.0.3 --entrypoint sleep "$IMG" 86400 >/dev/null
nr=fail
if docker network connect --ip "$FIXED" e11-plat2 e11-rest2 2>"$W/err" && docker start e11-rest2 >/dev/null &&
	[ "$(live e11-rest2 10.212.)" = "$FIXED" ]; then
	nr=ok
fi
docker run -d --name e11-dynx --label e11=1 --network e11-plat2 --entrypoint sleep "$IMG" 86400 >/dev/null
echo "  without range: fixed address $nr; a container without --ip got $(live e11-dynx 10.212.)"

echo "fixed-address=$accepted without-range=$nr control-failures=$cfail"
if [ "$cfail" != 0 ]; then
	echo "VERDICT E11: unknown — $cfail control check(s) failed."
elif [ "$fail" = 0 ]; then
	echo "VERDICT E11: confirmed — a fixed address outside --ip-range is accepted and kept across stop/start and re-create, dynamic members stay in the range, and a 0.0.0.0 listener serves both networks."
elif [ "$nr" = ok ]; then
	echo "VERDICT E11: fallback — the ranged network does not hold the fixed address as required; the network without --ip-range does."
else
	echo "VERDICT E11: unknown — neither the ranged network nor the fallback holds the fixed address."
fi
