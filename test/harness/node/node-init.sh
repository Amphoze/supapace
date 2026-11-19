#!/bin/sh
# Boot sequence of the test node (PID 1), in the order a real node boots:
#   0  fresh /run (tmpfs, as on a real boot); boot counter
#   1  loop-backed XFS with user and project quotas at /var/lib/supapace/projects,
#      and the repository filesystem (user quota, nosuid, nodev, noexec) at
#      /var/lib/supapace/repo
#   2  supapaced init, first boot only; the object-store stand-in declared  (full)
#   3  supapaced nft load before dockerd; table record  (full)
#   4  dockerd; docker load the cached images it lacks; /run/sp-node-ready
#   5  supervisor loop: supapaced serve, again after 1 s, never while
#      /run/sp-hold exists (full)
# SP_NODE_MODE=bare, or full without bin/supapaced, runs steps 0, 1 and 4 only.
#
# node-init.sh declare-offsite (docker exec, after the harness has copied the
# stand-in's files in) runs only the declaration of step 2.
set -eu

BIN=/opt/supapace/bin
STATE=/var/lib/sp
PROJECTS=/var/lib/supapace/projects
REPO=/var/lib/supapace/repo
S3=$STATE/s3
log() { echo "node-init: $*" >&2; }

# docker stop (and a TERM during boot): the supervisor loop, then the daemon
# (waited for), then the nested containers and dockerd, then the XFS mount.
loop_pid='' dockerd_pid=''
stop() {
	trap - TERM INT
	[ -z "$loop_pid" ] || kill -TERM "$loop_pid" 2>/dev/null || :
	# BusyBox matches -x against the full command line only with -f.
	pkill -TERM -x -f "$BIN/supapaced serve" || :
	while pgrep -x -f "$BIN/supapaced serve" >/dev/null; do sleep 0.2; done
	if [ -n "$dockerd_pid" ]; then
		docker ps -q 2>/dev/null | xargs -r docker stop -t 10 >/dev/null 2>&1 || :
		kill -TERM "$dockerd_pid" 2>/dev/null || :
	fi
	wait
	! mountpoint -q "$REPO" || umount "$REPO" || :
	! mountpoint -q "$PROJECTS" || umount "$PROJECTS" || :
	exit 0
}

# The object-store stand-in beside the node (make node-up) is declared when its
# files are here and the node has no declaration yet, through the daemon's
# own command. A daemon binary without `offsite` answers it with 2 (an unknown
# subcommand): such a node runs without a declaration.
declare_offsite() {
	[ -e "$S3/endpoint" ] || return 0
	s=0
	out=$("$BIN/supapaced" offsite show 2>&1) || s=$?
	case $s in
	0) ;;
	2)
		log "supapaced has no offsite subcommand: the object-store stand-in is not declared"
		return 0
		;;
	*)
		log "supapaced offsite show failed: $out"
		return 1
		;;
	esac
	printf '%s\n' "$out" | grep -q '"state": "undeclared"' || return 0
	"$BIN/supapaced" offsite set --endpoint "$(cat "$S3/endpoint")" --region us-east-1 --ca-file "$S3/ca.pem" \
		--projects-bucket sp-projects --cp-bucket sp-cp \
		--projects-write-keys "$S3/projects-write.keys" --projects-read-keys "$S3/projects-read.keys" \
		--cp-write-keys "$S3/cp-write.keys" --cp-read-keys "$S3/cp-read.keys" >&2
}

mode=${SP_NODE_MODE:-full}
if [ "$mode" = full ] && [ ! -x "$BIN/supapaced" ]; then
	[ $# -gt 0 ] || log "$BIN/supapaced absent, booting bare"
	mode=bare
fi
if [ "${1:-}" = declare-offsite ]; then
	[ "$mode" != full ] || declare_offsite
	exit
fi
trap stop TERM INT

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
# mount_xfs IMAGE SIZE DIR OPTIONS: a sparse XFS image, made once, mounted at
# DIR. A mount -o loop device is autoclear: released with this mount namespace.
mount_xfs() {
	mkdir -p "$3"
	if [ ! -e "$1" ]; then
		truncate -s "$2" "$1.tmp"
		mkfs.xfs -q "$1.tmp"
		mv "$1.tmp" "$1"
	fi
	try=1
	until mountpoint -q "$3"; do
		mknod_loops
		losetup -f >/dev/null
		mknod_loops
		mount -o "loop,$4" "$1" "$3" && break
		[ "$try" -lt 3 ] || { log "cannot mount $1"; exit 1; }
		try=$((try + 1))
		sleep 1
	done
}
mkdir -p /var/lib/supapace
chmod 0700 /var/lib/supapace
mount_xfs "$STATE/projects.img" 6G "$PROJECTS" usrquota,prjquota
mount_xfs "$STATE/repo.img" 8G "$REPO" usrquota,nosuid,nodev,noexec

# 2, 3. Node configuration, then our tables before Docker's. init shows the
# key escrow (the key-encryption key) on its output: that goes to a file only
# root reads, never to the node's log.
if [ "$mode" = full ]; then
	if [ ! -e /etc/supapace/node.json ]; then
		(umask 077 && "$BIN/supapaced" init --dev --no-systemd --ack-escrow --domain sp.test >"$STATE/init.out" 2>&1) ||
			{ log "supapaced init failed; its output is in $STATE/init.out"; exit 1; }
	fi
	declare_offsite || { log "declaring the object-store stand-in failed"; exit 1; }
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
		# A harness test holds the daemon (a wiped-node drill); the daemon itself
		# never reads this file.
		if [ -e /run/sp-hold ]; then
			echo "node-init: /run/sp-hold exists; supapaced held" | tee -a "$LOG" >&2 || :
			while [ -e /run/sp-hold ]; do sleep 1; done
		fi
		# The shell reports a daemon killed by a signal on the waited command's
		# stderr: that is /dev/null here, and the loop says what ended instead.
		{ sh -c 'exec "$0" serve 2>&1' "$BIN/supapaced" 2>/dev/null && s=0 || s=$?
			[ "$s" -gt 128 ] && s="signal $((s - 128))" || s="status $s"
			echo "node-init: supapaced serve ended ($s); starting it again in 1 s"; } | tee -a "$LOG" >&2 || :
		sleep 1
	done) &
	loop_pid=$!
fi
# The harness (make node-up) waits for this, so no caller races the image load.
touch /run/sp-node-ready
log ready
wait "$dockerd_pid"
