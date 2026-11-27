#!/usr/bin/env bash
# lab.sh NODE SCRIPT — run one experiment script that drives the platform's
# own code inside the bare test node NODE:
#
#   1. the daemon built from this tree with one more command, `supapaced exp`
#      (ag/exp.go, added by `go build -overlay -tags supapace_exp`; the product
#      build never contains it), into a scratch directory — never into bin/;
#   2. that binary (root 0755) with the node's installed supapace-arch beside it,
#      the cluster's seccomp profile, lib-backup.sh, lib-agent.sh and SCRIPT
#      copied into the node's /var/lib/sp-exp/ag (root 0700) and run there as
#      root. The binary is the daemon's executable for every call it makes, so
#      each job, task and cluster it starts runs the platform's programs from it.
#
# It refuses a node in which the daemon runs or in which the directory exists
# (a run going on, or one that ended without cleaning up). On every exit path
# it stops the run by the pid that run recorded, then removes what is left:
# `supapaced exp downall` (the lab's projects, the control-plane database, the
# networks and ruleset it made, by their names) and lib-backup.sh's lab_down
# (containers and networks named sp-test-bk-…, the directory).
#
# Prerequisites: bash, docker and a Go toolchain on the host; then
#   make images                (builds the binaries and the worker image archive)
#   make node-bare NODE=NODE   (the object-store stand-in beside it; not SP_OFFSITE=0)
# ag/exp.go is a fragment of cmd/supapaced: `go vet -tags supapace_exp ./...`
# fails by design; `make check-exp` vets it in place through the overlay.
# Exit status: the script's (0 its verdict is the expected one, 1 it is not, 3 a
# lab error); 2 usage or node not usable; 1 a refusal above.
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
say() { echo "ag-lab: $*"; }
[[ -f $script ]] || { say "no script $script"; exit 2; }
[[ $node =~ ^[a-z0-9][a-z0-9-]*$ ]] || { say "bad node name $node"; exit 2; }
[[ $(docker inspect -f '{{.State.Running}}' "$node" 2>/dev/null) == true ]] || { say "node $node is not running"; exit 2; }
! docker exec "$node" test -S /run/supapace/admin.sock || { say "supapaced runs in $node: use a bare node (make node-bare)"; exit 2; }
kit=/var/lib/sp-exp/ag
! docker exec "$node" test -e "$kit" ||
	{ say "$kit exists in $node: a run is going on there, or one ended without cleaning up; make node-down NODE=$node"; exit 1; }

tmp='' kit_made=''
# shellcheck disable=SC2329 # the EXIT trap
cleanup() {
	trap '' INT TERM
	set +e
	if [[ -n $kit_made ]]; then
		docker exec "$node" sh -c "p=\$(cat $kit/pid 2>/dev/null) && kill \$p 2>/dev/null; i=0; while [ -n \"\$p\" ] && kill -0 \$p 2>/dev/null && [ \$i -lt 60 ]; do sleep 1; i=\$((i + 1)); done; [ -z \"\$p\" ] || kill -9 \$p 2>/dev/null; :"
		docker exec "$node" sh -c "test ! -x $kit/bin/supapaced || SUPAPACE_EXP_DIR=$kit/a $kit/bin/supapaced exp downall; test ! -e $kit/lib-backup.sh || KIT=$kit BK_DOWN=1 sh -c '. $kit/lib-backup.sh'; rm -rf $kit"
	fi
	[[ -z $tmp ]] || rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP

# 1. The daemon with the experiments' command, static, from this tree.
tmp=$(mktemp -d)
printf '{"Replace":{"%s/cmd/supapaced/zz_exp.go":"%s/ag/exp.go"}}\n' "$repo" "$exp" >"$tmp/overlay.json"
(cd "$repo" && CGO_ENABLED=0 go build -buildvcs=false -trimpath -tags supapace_exp -overlay "$tmp/overlay.json" \
	-o "$tmp/supapaced" ./cmd/supapaced)

# 2. Into the node, and run.
docker exec "$node" sh -c "mkdir -p ${kit%/*} && mkdir -m 0700 $kit && mkdir -m 0755 $kit/bin"
kit_made=1
docker cp -q "$tmp/supapaced" "$node:$kit/bin/supapaced"
docker exec "$node" sh -c "cp /opt/supapace/bin/supapace-arch $kit/bin/ && chown 0:0 $kit/bin/* && chmod 0755 $kit/bin/*"
docker cp -q "$repo/internal/agent/seccomp/default.json" "$node:$kit/seccomp.json"
docker cp -q "$exp/lib-backup.sh" "$node:$kit/lib-backup.sh"
docker cp -q "$exp/lib-agent.sh" "$node:$kit/lib-agent.sh"
{
	# shellcheck disable=SC2016 # expanded in the node
	printf 'KIT=%s\n. "$KIT/lib-backup.sh"\n. "$KIT/lib-agent.sh"\n' "$kit"
	cat "$script"
} | docker exec -i "$node" sh -c "cat > $kit/run.sh"
s=0
docker exec "$node" sh "$kit/run.sh" &
wait $! || s=$?
exit "$s"
