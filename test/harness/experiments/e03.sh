#!/bin/sh
# e03: what does Docker's isolated IPv4 gateway mode leave on an internal bridge?
# For a project-style and a platform-style internal network in that mode: does
# the embedded DNS resolver still answer member names (and refuse names of
# containers on other networks), does the bridge carry no IPv4 address, does
# it carry an IPv6 link-local address? A plain internal network is the control
# (it must show a bridge IPv4 address, so an empty answer is not a tool fault)
# and the fallback (its resolver must work too).
# Runs as root on the test node.
set -eu

P=${SP_PROBE:-/opt/supapace/bin/sp-probe}
IMG=${IMG:-$(docker image ls -q postgres | head -n 1)}
fail=0 cfail=0

cleanup() {
	trap '' INT TERM # a signal during cleanup must not cut it short
	set +e
	docker rm -f e03-pg e03-rest e03-gw e03-c1 e03-c2 >/dev/null 2>&1
	docker network rm e03-proj e03-plat e03-plain >/dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 3' INT TERM

die() { echo "e03: $*" >&2; exit 3; }
[ -x "$P" ] || die "probe binary $P missing"
[ -n "$IMG" ] || die "no postgres image on this node"

# dns CONTAINER NAME -> R (answered|negative|timeout); line and exit code must agree
dns() {
	set +e
	out=$(nsenter --net="/proc/$(docker inspect -f '{{.State.Pid}}' "$1")/ns/net" \
		"$P" dns "$2" --server 127.0.0.11 --type A --timeout 2s 2>&1)
	rc=$?
	set -e
	R=${out%% *}
	case "$R:$rc" in
	answered:0 | negative:1 | timeout:2) ;;
	*) die "dns $1 $2: verdict and exit code disagree: '$out' rc=$rc" ;;
	esac
	A=$out
}

expect() { # KIND(test|ctl) WANT CONTAINER NAME [ADDR]
	dns "$3" "$4"
	ok=0
	if [ "$R" = "$2" ]; then
		ok=1
		case "$A" in "answered $5"*) ;; answered*) ok=0 ;; esac
	fi
	if [ "$ok" = 1 ]; then
		echo "  ok    $3 resolves $4: $A"
	else
		echo "  FAIL  $3 resolves $4: $A (want $2 $5)"
		if [ "$1" = ctl ]; then cfail=$((cfail + 1)); else fail=$((fail + 1)); fi
	fi
}

v4() { ip -o -4 addr show dev "$1" | awk '{print $4}' | tr '\n' ' '; }
ll() { ip -o -6 addr show dev "$1" scope link | awk '{print $4}' | tr '\n' ' '; }
bridge_of() { # NETWORK -> bridge device
	b=$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$1")
	[ -n "$b" ] && [ "$b" != "<no value>" ] || b=br-$(docker network inspect -f '{{.Id}}' "$1" | cut -c1-12)
	echo "$b"
}

echo "== e03: kernel $(uname -r), docker $(docker version -f '{{.Server.Version}}')"

docker network create --label e03=1 --internal --ipv6=false --subnet 10.213.0.192/26 \
	-o com.docker.network.bridge.name=spp3 -o com.docker.network.bridge.gateway_mode_ipv4=isolated e03-proj >/dev/null
docker network create --label e03=1 --internal --ipv6=false --subnet 10.212.0.0/21 --ip-range 10.212.6.0/23 \
	-o com.docker.network.bridge.name=spl0 -o com.docker.network.bridge.gateway_mode_ipv4=isolated e03-plat >/dev/null
docker network create --label e03=1 --internal --ipv6=false --subnet 10.214.0.128/26 e03-plain >/dev/null
docker run -d --name e03-pg --label e03=1 --network e03-proj --ip 10.213.0.194 --entrypoint sleep "$IMG" 86400 >/dev/null
docker create --name e03-rest --label e03=1 --network e03-proj --ip 10.213.0.195 --entrypoint sleep "$IMG" 86400 >/dev/null
docker network connect --ip 10.212.0.19 e03-plat e03-rest
docker start e03-rest >/dev/null
docker run -d --name e03-gw --label e03=1 --network e03-plat --ip 10.212.0.2 --entrypoint sleep "$IMG" 86400 >/dev/null
docker run -d --name e03-c1 --label e03=1 --network e03-plain --ip 10.214.0.130 --entrypoint sleep "$IMG" 86400 >/dev/null
docker run -d --name e03-c2 --label e03=1 --network e03-plain --ip 10.214.0.131 --entrypoint sleep "$IMG" 86400 >/dev/null

echo "-- embedded resolver"
expect test answered e03-rest e03-pg 10.213.0.194
expect test answered e03-pg e03-rest 10.213.0.195
expect test answered e03-gw e03-rest 10.212.0.19
expect test answered e03-rest e03-gw 10.212.0.2
expect test negative e03-pg e03-gw ''
expect test negative e03-pg e03-c1 ''
expect test negative e03-pg no-such-member ''
echo "-- plain internal network (control and fallback)"
expect ctl answered e03-c2 e03-c1 10.214.0.130
expect ctl negative e03-c2 e03-pg ''

echo "-- bridge addresses"
noaddr=1
for n in e03-proj e03-plat e03-plain; do
	b=$(bridge_of "$n")
	echo "  $n: bridge $b state $(cat "/sys/class/net/$b/operstate") ipv4 [$(v4 "$b")] link-local [$(ll "$b")]" \
		"disable_ipv6=$(cat "/proc/sys/net/ipv6/conf/$b/disable_ipv6")" \
		"gateway='$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' "$n")'"
done
for n in e03-proj e03-plat; do
	[ -z "$(v4 "$(bridge_of "$n")")" ] || { echo "  FAIL  $n: bridge has an IPv4 address"; noaddr=0; fail=$((fail + 1)); }
done
[ -n "$(v4 "$(bridge_of e03-plain)")" ] || { echo "  FAIL  control: the plain internal bridge shows no IPv4 address"; cfail=$((cfail + 1)); }
pid=$(docker inspect -f '{{.State.Pid}}' e03-pg)
echo "  member e03-pg: eth0 link-local [$(nsenter --net="/proc/$pid/ns/net" ip -o -6 addr show dev eth0 scope link | awk '{print $4}')]" \
	"disable_ipv6=$(nsenter --net="/proc/$pid/ns/net" cat /proc/sys/net/ipv6/conf/eth0/disable_ipv6)"
LL=$( for n in e03-proj e03-plat; do [ -z "$(ll "$(bridge_of "$n")")" ] || echo yes; done | head -n 1)
echo "isolated bridges without IPv4: $([ "$noaddr" = 1 ] && echo yes || echo no); link-local IPv6 on them: ${LL:-no}"

if [ "$cfail" != 0 ]; then
	echo "VERDICT E03: unknown — $cfail control check(s) on the plain internal network failed."
elif [ "$fail" = 0 ]; then
	echo "VERDICT E03: confirmed — in isolated mode the resolver answers member names only and the bridge has no IPv4 address; it $([ -n "$LL" ] && echo does || echo "does not") carry an IPv6 link-local address."
else
	echo "VERDICT E03: fallback — isolated mode breaks the resolver or leaves an IPv4 address; the plain internal network resolves members."
fi
