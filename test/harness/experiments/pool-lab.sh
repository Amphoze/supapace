#!/usr/bin/env bash
# pool-lab.sh NODE SCRIPT — run one pooler experiment script (e40.sh, e41.sh,
# e42.sh, e43.sh, e48.sh) inside the bare test node NODE, with what only the
# host can provide around it:
#
#   1. the kit's cluster flags checked against internal/agent/cluster.go;
#   2. Supavisor's image index of pins-pool.env resolved to this machine's
#      architecture (the index's own digest checked), both per-architecture
#      digests written back into pins-pool.env on the first run, the image
#      pulled by digest once and saved into $IMAGE_CACHE/pool/ (a directory the
#      node's boot does not load from, so other nodes are not given it), then
#      loaded into NODE from its read-only /images mount;
#   3. the lab bridge <prefix>-out (a documentation-range subnet), one client
#      container on it and NODE's connection to it, all labelled
#      supapace.test=1 and removed on every exit path;
#   4. SCRIPT, with lib-pool.sh, run inside NODE (docker exec). Its steps
#      against the outside client are lines "@@outside <base64 command>" on its
#      output; this wrapper runs each in the client container and answers on
#      the script's input with "<status> <base64 output>" (the command travels
#      on the client's standard input, never on a command line).
#
# It refuses to start when the lab bridge or the client container already
# exists, or the kit's directory is in the node (a run going on there, or one
# that ended without cleaning up). It removes only what this run created, each
# object only once created and only when it carries the test label, and on
# every exit path it first stops the run inside the node by the pid that run
# recorded.
#
# It loads no kernel module and calls no sudo. e41.sh needs nft_connlimit:
# when the host has not loaded it, the wrapper says so in one line with the
# command an operator runs, and e41.sh runs only what needs no limit rule
# (its verdict is UNRUN, never a pass).
#
# Prerequisites: make build and make node-bare NODE=NODE. Environment:
# IMAGE_CACHE as in the Makefile; LAB_PREFIX (default sp-test-<NODE without
# "sp-">); OUT_SUBNET (default 192.0.2.32/27). Exit status: the script's.
set -euo pipefail

usage() { echo "usage: pool-lab.sh NODE SCRIPT" >&2; exit 2; }
[[ $# -eq 2 ]] || usage
node=$1 script=$2
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
[[ -f $script && $(basename "$script") =~ ^e4[0-9]\.sh$ ]] || { echo "pool-lab: $script is not an experiment script" >&2; exit 2; }
[[ $node =~ ^[a-z0-9][a-z0-9-]*$ ]] || { echo "pool-lab: bad node name $node" >&2; exit 2; }
[[ $(docker inspect -f '{{.State.Running}}' "$node" 2>/dev/null) == true ]] || { echo "pool-lab: node $node is not running" >&2; exit 2; }

pins=$here/pins-pool.env
# shellcheck source=test/harness/experiments/pins-pool.env
. "$pins"
cache=${IMAGE_CACHE:-$HOME/.cache/supapace/images}
prefix=${LAB_PREFIX:-sp-test-${node#sp-}}
out_subnet=${OUT_SUBNET:-192.0.2.32/27}
say() { echo "pool-lab: $*"; }

# 1. The kit starts clusters itself, with the agent's flags: every option the
# agent's create argv names must be in the kit's, and every value the kit
# passes for them must be a literal of cluster.go.
src=$repo/internal/agent/cluster.go
body=$(awk '/^func \(a \*Agent\) clusterRunArgs/,/^}/' "$src")
[[ -n $body ]] || { say "cannot find clusterRunArgs in $src"; exit 1; }
kitline=$(sed -n 's/^CLUSTER_FLAGS="\(.*\)"$/\1/p' "$here/lib-pool.sh")
[[ -n $kitline ]] || { say "lib-pool.sh has no CLUSTER_FLAGS line"; exit 1; }
for opt in $(grep -o '"--[a-z][a-z-]*"' <<<"$body" | tr -d '"' | sort -u); do
	case $opt in --name | --hostname | --user | --memory | --memory-swap | --pids-limit | --label | --network | --ip | --sysctl) continue ;; esac
	[[ " $kitline " == *" $opt "* ]] || { say "cluster flag $opt of cluster.go is missing from lib-pool.sh"; exit 1; }
done
for tok in $kitline; do
	grep -qF "\"$tok\"" <<<"$body" || { say "lib-pool.sh flag $tok is not in cluster.go"; exit 1; }
done
say "cluster flags match internal/agent/cluster.go"

# The module check, for e41.sh alone.
module=present
if [[ $(basename "$script") == e41.sh ]] && [[ ! -e /sys/module/nft_connlimit ]]; then
	module=absent
	say "kernel module nft_connlimit is not loaded (no /sys/module/nft_connlimit; a kernel with it built in that shows no such directory is treated as without it); an operator runs: sudo modprobe nft_connlimit"
fi

# 2. The image, by digest.
case $(uname -m) in
x86_64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) say "unsupported machine $(uname -m)"; exit 2 ;;
esac
repo_name=${SUPAVISOR_TAG%:*}
ref=$repo_name@$SUPAVISOR_INDEX
raw=$(docker buildx imagetools inspect --raw "$ref")
got=sha256:$(printf '%s' "$raw" | sha256sum | cut -d' ' -f1)
[[ $got == "$SUPAVISOR_INDEX" ]] || { say "the index fetched for $ref has digest $got"; exit 1; }
# One manifest object per platform; its digest line precedes its architecture.
manifest() { awk -v a="$1" '/"digest"/{d=$2} /"architecture"/{if ($2=="\""a"\",") {gsub(/[",]/,"",d); print d; exit}}' <<<"$raw"; }
amd64=$(manifest amd64) arm64=$(manifest arm64)
[[ $amd64 =~ ^sha256:[0-9a-f]{64}$ && $arm64 =~ ^sha256:[0-9a-f]{64}$ ]] || { say "cannot read both platform digests of $ref"; exit 1; }
if [[ -z $SUPAVISOR_AMD64 && -z $SUPAVISOR_ARM64 ]]; then
	sed -i "s/^SUPAVISOR_AMD64=.*/SUPAVISOR_AMD64=$amd64/; s/^SUPAVISOR_ARM64=.*/SUPAVISOR_ARM64=$arm64/" "$pins"
	say "wrote the platform digests into pins-pool.env"
elif [[ $SUPAVISOR_AMD64 != "$amd64" || $SUPAVISOR_ARM64 != "$arm64" ]]; then
	say "pins-pool.env names other platform digests than the index: amd64 $amd64, arm64 $arm64"
	exit 1
fi
say "supavisor index $SUPAVISOR_INDEX: amd64 $amd64, arm64 $arm64"

mkdir -p "$cache/pool"
tar=$cache/pool/supavisor-${SUPAVISOR_INDEX:7:12}.tar
kit=/var/lib/sp-exp/pool
# Nothing of a run that is still going, or that ended without cleaning up, is
# ever reused or removed: refuse before creating anything.
! docker network inspect "$prefix-out" >/dev/null 2>&1 ||
	{ say "network $prefix-out exists; if no run uses it: docker network rm $prefix-out"; exit 1; }
! docker container inspect "$prefix-client" >/dev/null 2>&1 ||
	{ say "container $prefix-client exists; if no run uses it: docker rm -f $prefix-client"; exit 1; }
! docker exec "$node" test -e "$kit" ||
	{ say "$kit exists in $node: another run is going there, or one ended without cleaning up; make node-down NODE=$node"; exit 1; }

# One flag per object, set only once this run has created it; every removal
# also checks the test label.
tmp='' fifos='' net_made='' client_made='' conn_made='' kit_made='' run_pid=''
# shellcheck disable=SC2329 # called by cleanup
labelled() { [[ $(docker "$1" inspect -f "$2" "$3" 2>/dev/null) == 1 ]]; }
# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
	trap '' INT TERM
	set +e
	[[ -z $tmp ]] || rm -rf "$tmp" "$tar.tmp"
	if [[ -n $kit_made ]]; then
		# The run inside the node first, by the pid it recorded; its own exit
		# removes its lab. Then whatever of it is left, by the kit's prefix and label.
		docker exec "$node" sh -c "p=\$(cat $kit/pid 2>/dev/null) && kill \$p 2>/dev/null; i=0; while [ -n \"\$p\" ] && kill -0 \$p 2>/dev/null && [ \$i -lt 30 ]; do sleep 1; i=\$((i + 1)); done; [ -z \"\$p\" ] || kill -9 \$p 2>/dev/null; :"
		docker exec "$node" sh -c "docker ps -aq --filter label=supapace.test=1 --filter name=sp-test-pool- | xargs -r docker rm -f -v >/dev/null 2>&1; docker network ls -q --filter label=supapace.test=1 --filter name=sp-test-pool- | xargs -r docker network rm >/dev/null 2>&1; rm -rf $kit"
	fi
	[[ -z $run_pid ]] || { kill "$run_pid" 2>/dev/null; wait "$run_pid" 2>/dev/null; }
	[[ -z $fifos ]] || rm -rf "$fifos"
	[[ -z $conn_made ]] || docker network disconnect -f "$prefix-out" "$node" >/dev/null 2>&1
	if [[ -n $client_made ]] && labelled container '{{index .Config.Labels "supapace.test"}}' "$prefix-client"; then docker rm -f -v "$prefix-client" >/dev/null 2>&1; fi
	if [[ -n $net_made ]] && labelled network '{{index .Labels "supapace.test"}}' "$prefix-out"; then docker network rm "$prefix-out" >/dev/null 2>&1; fi
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
if ! { [[ -s $tar ]] && tar -xOf "$tar" index.json | grep -q "\"io.containerd.image.name\":\"[^\"]*@$SUPAVISOR_INDEX\""; }; then
	# As scripts/cache-images.sh saves an image: named in its index.json.
	name=$(docker pull -q --platform "linux/$arch" "$ref")
	tmp=$(mktemp -d)
	docker save --platform "linux/$arch" -o "$tar.tmp" "$ref"
	tar -xf "$tar.tmp" -C "$tmp"
	annotation="\"io.containerd.image.name\":\"$name\""
	sed -i "s|\"annotations\":{|\"annotations\":{$annotation,|" "$tmp/index.json"
	grep -qF "$annotation" "$tmp/index.json" || { say "cannot name $ref in its archive"; exit 1; }
	# shellcheck disable=SC2046 # docker save writes a few fixed top-level names
	tar -cf "$tar.tmp" -C "$tmp" $(ls -A "$tmp")
	mv "$tar.tmp" "$tar"
	rm -rf "$tmp"
	tmp=''
	say "saved $ref ($(du -m "$tar" | cut -f1) MiB) to $tar"
fi
# The archive holds this platform's manifest alone, and the node's image store
# names the image by that manifest's digest, not by the index's.
if [[ $arch == amd64 ]]; then img=$repo_name@$amd64; else img=$repo_name@$arm64; fi
if ! docker exec "$node" docker image inspect "$img" >/dev/null 2>&1; then
	docker exec "$node" docker load -q -i "/images/pool/${tar##*/}" >/dev/null
	docker exec "$node" docker image inspect "$img" >/dev/null || { say "$img is not addressable in $node after load"; exit 1; }
	say "loaded $img into $node"
fi

# 3. The lab bridge: Docker allocates from its first eight addresses; the rest
# are the node's and the client's fixed and extra addresses.
base=${out_subnet%/*}
o4=${base##*.}
pre=${base%.*}
node_ip=$pre.$((o4 + 8))
client_ip=$pre.$((o4 + 9))
cp_image=$(sed -n 's/^ *"control_plane": *{"tag": *"\([^":]*\)[^"]*", *"digest": *"\([^"]*\)".*/\1@\2/p' "$repo/internal/nodecfg/images.lock")
docker network create --label supapace.test=1 --subnet "$out_subnet" --ip-range "$pre.$o4/29" "$prefix-out" >/dev/null
net_made=1
docker run -d --name "$prefix-client" --label supapace.test=1 --network "$prefix-out" --ip "$client_ip" \
	--cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges --memory 512m --pids-limit 1024 \
	--init --entrypoint sleep "$cp_image" infinity >/dev/null
client_made=1
docker network connect --ip "$node_ip" "$prefix-out" "$node"
conn_made=1
say "lab bridge $prefix-out $out_subnet: node $node_ip, client $client_ip"

# 4. The kit and the script inside the node; the seccomp profile the agent
# gives every cluster goes beside them.
docker exec "$node" sh -c "mkdir -p $(dirname "$kit") && mkdir -m 0700 $kit"
kit_made=1
docker cp -q "$repo/internal/agent/seccomp/default.json" "$node:$kit/seccomp.json"
{
	printf 'SV_IMAGE=%s\nOUT_NODE_IP=%s\nOUT_CLIENT_IP=%s\nOUT_SUBNET=%s\nCONNLIMIT=%s\nKIT=%s\n' \
		"$img" "$node_ip" "$client_ip" "$out_subnet" "$module" "$kit"
	cat "$here/lib-pool.sh" "$script"
} | docker exec -i "$node" sh -c "cat > $kit/run.sh"

# The run's input and output are two named pipes, opened here before it can end.
fifos=$(mktemp -d)
mkfifo "$fifos/in" "$fifos/out"
docker exec -i "$node" sh "$kit/run.sh" <"$fifos/in" >"$fifos/out" &
run_pid=$!
exec {to}>"$fifos/in" {from}<"$fifos/out"
while IFS= read -r line <&"$from"; do
	case $line in
	'@@outside '*)
		# The command, which can hold a lab password, goes on standard input,
		# never on a command line.
		s=0
		o=$(base64 -d <<<"${line#@@outside }" | docker exec -i "$prefix-client" sh 2>&1) || s=$?
		printf '%s %s\n' "$s" "$(printf '%s' "$o" | base64 -w0)" >&"$to" || :
		;;
	*) printf '%s\n' "$line" ;;
	esac
done
exec {to}>&- {from}<&-
s=0
wait "$run_pid" || s=$?
run_pid=''
# The node's own peak since it started (cgroup v2), for the lab's memory budget.
nid=$(docker inspect -f '{{.Id}}' "$node")
peak=$(cat /sys/fs/cgroup/system.slice/docker-"$nid".scope/memory.peak 2>/dev/null || echo 0)
say "node $node memory.peak since its start: $((peak / 1048576)) MiB"
if [[ $module == absent ]]; then
	echo "VERDICT E41: UNRUN — module nft_connlimit absent"
fi
exit "$s"
