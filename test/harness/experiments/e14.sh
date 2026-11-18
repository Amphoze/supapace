#!/bin/sh
# E14: restart replay of a test node, driven from the workstation.
# `docker restart <node>` twice; after each restart:
#   - the node's XFS image is attached to exactly one loop device (the old one
#     was released, nothing leaked), identified by the image file's inode;
#   - the filesystem is mounted again with user and project quotas, both
#     accounting and enforcing, and a quota limit set before survives;
#   - the boot counter went up by one;
#   - no image archive was loaded again and every image ID is unchanged.
# Control: the device the node uses is visible in the listing that is checked.
#
# Usage (on the workstation): e14.sh <node container name>
set -eu

NODE=${1:?usage: e14.sh <node container name>}
P=/var/lib/supapace/projects
IMG=/var/lib/sp/projects.img
SENTINEL_UID=700999

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}
n() { docker exec "$NODE" "$@"; }

[ "$(docker inspect -f '{{.State.Running}}' "$NODE" 2>/dev/null)" = true ] || die "$NODE is not running"
n test -e /run/sp-node-ready || die "$NODE has not finished booting"

cleanup() { n xfs_quota -x -c "limit -u bhard=0 $SENTINEL_UID" "$P" >/dev/null 2>&1 || :; }
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP

fail=0
check() { # check LABEL WANT GOT
	if [ "$2" = "$3" ]; then say "ok    $1: $3"; else
		say "FAIL  $1: want $2, got $3"
		fail=1
	fi
}

# Loop devices backed by this node's image file, matched by inode and device
# (the listing inside the privileged node shows every loop device of the host).
# shellcheck disable=SC2016 # expanded by the node's shell
image_loops() {
	n sh -c '
		set -- $(stat -c "%i %d" '"$IMG"')
		d=$2
		mm="$(( (d & 0xfff00) >> 8 )):$(( (d & 0xff) | ((d >> 12) & 0xfff00) ))"
		losetup -l -n -O NAME,BACK-INO,BACK-MAJ:MIN | awk -v i="$1" -v mm="$mm" "\$2 == i && \$3 == mm { print \$1 }" | sort'
}
state() { # state: one line per fact, compared across restarts (the device may differ)
	say "mount=$(n findmnt -no FSTYPE,OPTIONS "$P" | awk '{ print $1, ($2 ~ /usrquota/ && $2 ~ /prjquota/) ? "usrquota,prjquota" : $2 }')"
	say "user=$(n xfs_quota -x -c 'state -u' "$P" | awk '/Accounting|Enforcement/ { printf "%s%s ", $1, $2 }')"
	say "project=$(n xfs_quota -x -c 'state -p' "$P" | awk '/Accounting|Enforcement/ { printf "%s%s ", $1, $2 }')"
	say "sentinel=$(n xfs_quota -x -c "quota -u -N -b $SENTINEL_UID" "$P" | awk '{ print $4 }')"
}
images() { n docker images --digests --format '{{.Repository}}@{{.Digest}} {{.ID}}' | sort | tr '\n' ' '; }

step "before"
say "node $NODE, $(docker version -f 'workstation docker {{.Server.Version}}')"
n xfs_quota -x -c "limit -u bhard=1m $SENTINEL_UID" "$P"
dev=$(n findmnt -no SOURCE "$P")
loops0=$(image_loops)
ws0=$(losetup -a | wc -l)
boot0=$(n cat /var/lib/sp/boot/count)
img0=$(images)
st0=$(state)
say "mounted from $dev; image-backed loop devices: $loops0; workstation losetup -a entries: $ws0; boot count $boot0"
say "$st0"
say "images: $img0"
check "control: the mounted device is in the listing" "$dev" "$loops0"
check "control: and in the workstation's losetup -a" 1 "$(losetup -a | grep -c "^$dev:")"
say "control: archive loads recorded in the node's log so far (earlier boots): $(docker logs "$NODE" 2>&1 | grep -c 'node-init: loading ' || :)"

for round in 1 2; do
	step "restart $round"
	since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	t0=$(date +%s)
	docker restart -t 60 "$NODE" >/dev/null
	i=0
	until n sh -c 'test -e /run/sp-node-ready && docker info' >/dev/null 2>&1; do
		[ "$(docker inspect -f '{{.State.Running}}' "$NODE")" = true ] || { docker logs --tail 20 "$NODE" >&2; die "$NODE stopped during boot"; }
		i=$((i + 1))
		[ "$i" -le 300 ] || die "$NODE did not come back"
		sleep 1
	done
	say "ready after $(($(date +%s) - t0)) s"
	newdev=$(n findmnt -no SOURCE "$P")
	loops=$(image_loops)
	say "mounted from $newdev (was $dev); image-backed loop devices: $loops; workstation losetup -a entries: $(losetup -a | wc -l) (was $ws0)"
	check "exactly one loop device for the image, the mounted one" "$newdev" "$loops"
	if [ "$newdev" != "$dev" ]; then
		check "the previous device $dev is no longer bound to the image" "" "$(printf '%s\n' "$loops" | grep -x "$dev" || :)"
	fi
	check "boot counter" $((boot0 + round)) "$(n cat /var/lib/sp/boot/count)"
	check "mount, quota state and the limit set before" "$st0" "$(state)"
	check "image archives loaded during this boot" 0 "$(docker logs --since "$since" "$NODE" 2>&1 | grep -c 'node-init: loading ' || :)"
	check "image IDs" "$img0" "$(images)"
	dev=$newdev
done

step "result"
if [ "$fail" = 0 ]; then
	say "VERDICT E14: confirmed — two docker restarts each re-attach the image to one loop device with the old one released, remount XFS with user and project quotas on and limits intact, bump the boot counter and load no image again."
else
	say "VERDICT E14: fallback — restart replay is not reliable (FAIL lines above): detach loop devices in a pre-stop hook, or run reach-reboot on the CI VM only."
fi
