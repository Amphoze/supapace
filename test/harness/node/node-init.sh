#!/bin/sh
# Boot sequence of the test node (PID 1), in the order a real node boots:
#   0  fresh /run (tmpfs, as on a real boot); boot counter
#   1  loop-backed XFS with user and project quotas at /var/lib/supapace/projects
#   2  supapaced init, first boot only                  (full)
#   3  supapaced nft load before dockerd; table record  (full)
#   4  dockerd; docker load the cached images it lacks; /run/sp-node-ready
#   5  supervisor loop: supapaced serve, again after 1 s (full)
# SP_NODE_MODE=bare, or full without bin/supapaced, runs steps 0, 1 and 4 only.
set -eu

BIN=/opt/supapace/bin
STATE=/var/lib/sp
PROJECTS=/var/lib/supapace/projects
log() { echo "node-init: $*" >&2; }

# docker stop (and a TERM during boot): the supervisor loop, then the daemon
# (waited for), then the nested containers and dockerd, then the XFS mount.
loop_pid='' dockerd_pid=''
stop() {
	trap - TERM INT
	[ -z "$loop_pid" ] || kill -TERM "$loop_pid" 2>/dev/null || :
	pkill -TERM -x supapaced || :
	while pgrep -x supapaced >/dev/null; do sleep 0.2; done
	if [ -n "$dockerd_pid" ]; then
		docker ps -q 2>/dev/null | xargs -r docker stop -t 10 >/dev/null 2>&1 || :
		kill -TERM "$dockerd_pid" 2>/dev/null || :
	fi
	wait
	! mountpoint -q "$PROJECTS" || umount "$PROJECTS" || :
	exit 0
}
trap stop TERM INT

mode=${SP_NODE_MODE:-full}
if [ "$mode" = full ] && [ ! -x "$BIN/supapaced" ]; then
	log "$BIN/supapaced absent, booting bare"
	mode=bare
fi

# 0. Nothing in /run survives a boot: not /run/supapace (boot record, test hooks),
# not the pid files and sockets of a dockerd that was killed.
mountpoint -q /run || mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
mkdir -p /run/lock /run/supapace "$STATE/boot"
chmod 0700 /run/supapace
rm -f "$STATE/boot/pre-dockerd.txt"
count=$(cat "$STATE/boot/count" 2>/dev/null || echo 0)
echo $((count + 1)) >"$STATE/boot/count.tmp"
mv "$STATE/boot/count.tmp" "$STATE/boot/count"
log "boot $((count + 1)), mode $mode"

# 1. The container's /dev is a snapshot taken at start: create the node of every
# loop device the kernel has, and of the next free one, before mount picks one.
# Another user of the workstation's loop devices can win that race; retry.
mknod_loops() {
	for d in /sys/block/loop*; do
		[ -e "$d/dev" ] || continue
		n=/dev/${d##*/}
		[ -b "$n" ] || mknod "$n" b "$(cut -d: -f1 "$d/dev")" "$(cut -d: -f2 "$d/dev")"
	done
}
mkdir -p "$PROJECTS"
chmod 0700 /var/lib/supapace
img=$STATE/projects.img
if [ ! -e "$img" ]; then
	truncate -s 6G "$img.tmp"
	mkfs.xfs -q "$img.tmp"
	mv "$img.tmp" "$img"
fi
# A mount -o loop device is autoclear: released with this mount namespace.
try=1
until mountpoint -q "$PROJECTS"; do
	mknod_loops
	losetup -f >/dev/null
	mknod_loops
	mount -o loop,usrquota,prjquota "$img" "$PROJECTS" && break
	[ "$try" -lt 3 ] || { log "cannot mount $img"; exit 1; }
	try=$((try + 1))
	sleep 1
done

# 2, 3. Node configuration, then our tables before Docker's.
if [ "$mode" = full ]; then
	[ -e /etc/supapace/node.json ] ||
		"$BIN/supapaced" init --dev --no-systemd --ack-escrow --domain sp.test
	"$BIN/supapaced" nft load
	nft list tables >"$STATE/boot/pre-dockerd.txt"
fi

# 4. Docker, through the image's dind wrapper (cgroup v2 nesting), Unix socket only.
dind dockerd --host=unix:///var/run/docker.sock >/var/log/dockerd.log 2>&1 &
dockerd_pid=$!
i=0
until docker info >/dev/null 2>&1; do
	kill -0 "$dockerd_pid" 2>/dev/null || { log "dockerd exited"; tail -n 20 /var/log/dockerd.log >&2; exit 1; }
	i=$((i + 1))
	[ "$i" -le 120 ] || { log "dockerd did not come up"; exit 1; }
	sleep 1
done

# Each archive's index.json names its image (scripts/cache-images.sh); load what
# this daemon lacks, then require every name to resolve. docker load can exit 0
# after an unpack error, leaving a name that inspects but cannot run and that
# every later boot would skip: an error in its output fails the boot too, after
# removing that name.
loaded=0 refs=
for tar in /images/*.tar; do
	[ -e "$tar" ] || continue
	ref=$(tar -xOf "$tar" index.json | sed -n 's/.*"io.containerd.image.name":"\([^"]*\)".*/\1/p')
	[ -n "$ref" ] || { log "$tar names no image; run make images"; exit 1; }
	refs="$refs $ref"
	docker image inspect "$ref" >/dev/null 2>&1 && continue
	log "loading $tar"
	s=0
	out=$(docker load -q -i "$tar" 2>&1) || s=$?
	printf '%s\n' "$out" >&2
	case "$s $out" in
	0\ *[Ee]rror*) s=1 ;;
	esac
	if [ "$s" != 0 ]; then
		log "docker load of $tar failed; removing $ref"
		docker image rm -f "$ref" >/dev/null 2>&1 || :
		exit 1
	fi
	loaded=1
done
[ -n "$refs" ] || log "warning: /images holds no image archive; run make images"
for ref in $refs; do
	docker image inspect "$ref" >/dev/null 2>&1 || {
		log "$ref is not addressable after docker load; image store: $(docker info -f '{{.Driver}} {{.DriverStatus}}')"
		log "the classic (non-containerd) store loads these archives untagged"
		exit 1
	}
done
# Unpacking charged its page cache to this container: reclaim this cgroup's file
# pages only (the write reports EAGAIN when it falls short; that is fine).
if [ "$loaded" = 1 ]; then
	echo "$(awk '/^file /{print $2}' /sys/fs/cgroup/memory.stat) swappiness=0" >/sys/fs/cgroup/memory.reclaim 2>/dev/null || :
fi

# 5. The supervisor a real node gets from Restart=always. The daemon's output
# also goes to $LOG (emptied at node start); before each daemon start the loop
# cuts the file to its last 4 MiB once it exceeds 8 MiB, so the file is bounded
# by 8 MiB plus what one daemon run writes. docker logs still shows it.
LOG=/var/log/supapaced.log
if [ "$mode" = full ]; then
	: >"$LOG"
	(while :; do
		if [ "$(wc -c <"$LOG")" -gt 8388608 ]; then
			tail -c 4194304 "$LOG" >"$LOG.tmp" && cat "$LOG.tmp" >"$LOG"
			rm -f "$LOG.tmp"
		fi
		"$BIN/supapaced" serve 2>&1 | tee -a "$LOG" >&2 || :
		sleep 1
	done) &
	loop_pid=$!
fi
# The harness (make node-up) waits for this, so no caller races the image load.
touch /run/sp-node-ready
log ready
wait "$dockerd_pid"
