#!/usr/bin/env bash
# lab.sh NODE SCRIPT — run one backup experiment script (or the kit's own
# lib-backup-selftest.sh) inside the bare test node NODE:
#
#   1. the kit's cluster flags (CLUSTER_FLAGS of lib-backup.sh) checked against
#      clusterRunArgs in internal/agent/cluster.go;
#   2. the helper bk built from this tree into a scratch directory (never into
#      bin/, so no image and no node install carries it);
#   3. bk, the cluster's seccomp profile, lib-backup.sh and SCRIPT copied into
#      the node's /var/lib/sp-exp/bk (root 0700) and run there as root.
#
# It refuses a node in which the daemon runs (the kit stands projects up by
# hand) or in which the kit's directory exists (a run going on, or one that
# ended without cleaning up). On every exit path it stops the run in the node by
# the pid that run recorded, then removes what is left of the lab (the kit's
# lab_down: containers and networks named sp-test-bk-… with the label
# supapace.test=1, the lab projects' trees and quotas, the kit's directory).
#
# Prerequisites: make build, make images (the worker image), then
#   make node-bare NODE=NODE            (the object-store stand-in beside it), or
#   make node-bare NODE=NODE SP_OFFSITE=0   (no stand-in: copy steps are UNRUN).
# Exit status: the script's (0 pass, 1 a criterion failed, 3 a lab error, 4 a
# criterion not run); 2 usage or node not usable; 1 a refusal above.
set -euo pipefail

usage() {
	echo "usage: lab.sh NODE SCRIPT" >&2
	exit 2
}
[[ $# -eq 2 ]] || usage
node=$1 script=$2
here=$(cd "$(dirname "$0")" && pwd)
exp=$(dirname "$here")
repo=$(cd "$exp/../../.." && pwd)
say() { echo "bk-lab: $*"; }
[[ -f $script ]] || { say "no script $script"; exit 2; }
[[ $node =~ ^[a-z0-9][a-z0-9-]*$ ]] || { say "bad node name $node"; exit 2; }
[[ $(docker inspect -f '{{.State.Running}}' "$node" 2>/dev/null) == true ]] || { say "node $node is not running"; exit 2; }
! docker exec "$node" test -S /run/supapace/admin.sock || { say "supapaced runs in $node: use a bare node (make node-bare)"; exit 2; }

# 1. The kit creates clusters itself: every option the agent's create names must
# be in the kit's list, and every token of the kit's list a literal of cluster.go.
src=$repo/internal/agent/cluster.go
body=$(awk '/^func \(a \*Agent\) clusterRunArgs/,/^}/' "$src")
[[ -n $body ]] || { say "cannot find clusterRunArgs in $src"; exit 1; }
kitline=$(sed -n 's/^CLUSTER_FLAGS="\(.*\)"$/\1/p' "$exp/lib-backup.sh")
[[ -n $kitline ]] || { say "lib-backup.sh has no CLUSTER_FLAGS line"; exit 1; }
for opt in $(grep -o '"--[a-z][a-z-]*"' <<<"$body" | tr -d '"' | sort -u); do
	case $opt in --name | --hostname | --user | --memory | --memory-swap | --pids-limit | --label | --network | --ip | --sysctl) continue ;; esac
	[[ " $kitline " == *" $opt "* ]] || { say "cluster flag $opt of cluster.go is missing from lib-backup.sh"; exit 1; }
done
for tok in $kitline; do
	grep -qF "\"$tok\"" <<<"$body" || { say "lib-backup.sh flag $tok is not in cluster.go"; exit 1; }
done
# The container-side mount literals of cluster.go (data, sock, passwd, group, tools, spool, rspool, tmpfs)
# must each appear in lib-backup.sh, in the same order.
last=-1
for m in $(grep -o '"/[a-z_.]*:/[^"]*"' <<<"$body" | tr -d '"'); do
	off=$(grep -boF -e "$m\"" -e "$m " "$exp/lib-backup.sh" | head -1 | cut -d: -f1) || :
	[[ -n $off ]] || { say "mount $m of cluster.go is missing from lib-backup.sh"; exit 1; }
	((off > last)) || { say "mount $m of cluster.go is in another order in lib-backup.sh"; exit 1; }
	last=$off
done
say "cluster flags and mounts match internal/agent/cluster.go"

kit=/var/lib/sp-exp/bk
! docker exec "$node" test -e "$kit" ||
	{ say "$kit exists in $node: a run is going on there, or one ended without cleaning up; make node-down NODE=$node"; exit 1; }

tmp='' kit_made=''
# shellcheck disable=SC2329 # the EXIT trap
cleanup() {
	trap '' INT TERM
	set +e
	if [[ -n $kit_made ]]; then
		docker exec "$node" sh -c "p=\$(cat $kit/pid 2>/dev/null) && kill \$p 2>/dev/null; i=0; while [ -n \"\$p\" ] && kill -0 \$p 2>/dev/null && [ \$i -lt 30 ]; do sleep 1; i=\$((i + 1)); done; [ -z \"\$p\" ] || kill -9 \$p 2>/dev/null; :"
		docker exec "$node" sh -c "test ! -e $kit/lib-backup.sh || KIT=$kit BK_DOWN=1 sh -c '. $kit/lib-backup.sh'; rm -rf $kit"
	fi
	[[ -z $tmp ]] || rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# 2. The helper, static, from this tree.
tmp=$(mktemp -d)
(cd "$repo" && CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "$tmp/bk" ./test/harness/experiments/bk)

# 3. Into the node, and run.
docker exec "$node" sh -c "mkdir -p ${kit%/*} && mkdir -m 0700 $kit"
kit_made=1
docker cp -q "$tmp/bk" "$node:$kit/bk"
docker cp -q "$repo/internal/agent/seccomp/default.json" "$node:$kit/seccomp.json"
docker cp -q "$exp/lib-backup.sh" "$node:$kit/lib-backup.sh"
{
	# shellcheck disable=SC2016 # expanded in the node
	printf 'KIT=%s\n. "$KIT/lib-backup.sh"\n' "$kit"
	cat "$script"
} | docker exec -i "$node" sh -c "cat > $kit/run.sh"
# In the background and waited for: bash runs a trap only after a foreground command ends, so a
# TERM sent to this script alone would otherwise let the whole run finish first.
s=0
docker exec "$node" sh "$kit/run.sh" &
wait $! || s=$?
exit "$s"
