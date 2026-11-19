#!/usr/bin/env bash
# harness-test.sh — checks of the test node harness itself, against a running
# node (make harness-test NODE=…). Run from the repository root on the host.
# Which cases run depends on the node: a bare or a full node, with or without
# its object-store stand-in ($NODE-s3); a case that cannot run says why.
#
#   repo-mount            the repository filesystem: XFS, usrquota, nosuid,
#                         nodev, noexec; a user quota enforced, also after a
#                         node restart
#   standin-up            the stand-in's buckets, TLS, versioning, lock,
#                         lifecycle, identities, addresses, reachability
#   standin-not-in-node   no stand-in archive in the image cache, no stand-in
#                         image in the node
#   standin-digest        every test file that pins the stand-in names the
#                         digest of images.lock
#   worker-image          the worker image built from source, its contents
#   hold                  /run/sp-hold keeps the supervisor from starting the daemon
#   offsite-declared      a full node declares the stand-in
#   boot-without-offsite  a daemon binary without `offsite` boots and serves
#
# Prints PASS, FAIL or SKIP per case (and the reason), exits 1 on any FAIL.
#   lab-slots             two lab slots give disjoint subnets (computed by make lab)
#
# Environment (make harness-test sets it): NODE, NODE_IMAGE, IMAGE_CACHE,
# BIN, LOCK. The stand-in's addresses are read from the node (/var/lib/sp/s3/addrs).
set -uo pipefail
shopt -s extglob

: "${NODE:?}" "${NODE_IMAGE:?}" "${IMAGE_CACHE:?}" "${BIN:?}" "${LOCK:?}"
. "$(dirname "$0")/s3/lab.env"
NODE_BIN=/opt/supapace/bin
S3=/var/lib/sp/s3
REPO=/var/lib/supapace/repo
WORKER=supapace-worker:local
fails=0

nx() { docker exec "$NODE" "$@"; }
pass() { echo "PASS $1"; }
fail() {
	echo "FAIL $1: $2"
	fails=$((fails + 1))
}
skip() { echo "SKIP $1: $2"; }
# lock_field KEY N: field N (1 tag, 2 digest) of an images.lock entry.
lock_field() { sed -n "s/^ *\"$1\": *{\"tag\": *\"\([^\"]*\)\", *\"digest\": *\"\([^\"]*\)\".*/\\$2/p" "$LOCK"; }

full=''
nx test -e /etc/supapace/node.json && full=1
standin=''
docker container inspect "$NODE-s3" >/dev/null 2>&1 && standin=1

# wait_ready [daemon]: the node is up again (and, with an argument, its daemon
# answers), within 300 s.
wait_ready() {
	for _ in $(seq 300); do
		if nx sh -c 'test -e /run/sp-node-ready && docker info' >/dev/null 2>&1; then
			[ -z "${1:-}" ] && return 0
			nx "$NODE_BIN/supapace" node check 2>/dev/null | grep -q '"checks"' && return 0
		fi
		sleep 1
	done
	return 1
}

# The repository filesystem and its user quota. A uid outside every range the
# platform uses writes into a directory of its own (entered as root first:
# /var/lib/supapace is root's 0700).
repo_mount() {
	local n=repo-mount uid=69123 d=$REPO/harness-quota opts
	opts=$(nx awk -v m=$REPO '$2 == m { t = $3; o = $4 } END { print t, o }' /proc/mounts)
	case $opts in
	xfs\ *) ;;
	*) fail $n "$REPO is not an XFS mount: '$opts'"; return ;;
	esac
	for o in usrquota nosuid nodev noexec; do
		case ",${opts#xfs },"  in
		*,$o,*) ;;
		*) fail $n "$REPO lacks $o: $opts"; return ;;
		esac
	done
	nx sh -c "rm -rf $d && mkdir $d && chown $uid:$uid $d && xfs_quota -x -c 'limit -u bhard=16m $uid' $REPO" ||
		{ fail $n "cannot set the quota"; return; }
	as_uid() { nx sh -c 'cd "$0" && u=$1 && shift && exec setpriv --reuid $u --regid $u --clear-groups "$@"' $d $uid "$@"; }
	quota_writes() { # control: 8 MiB fit; then 12 MiB more must fail on the quota
		local out
		nx rm -f $d/a $d/b
		out=$(as_uid dd if=/dev/zero of=a bs=1M count=8 conv=fsync 2>&1) ||
			{ echo "8 MiB under the quota failed: $out"; return 1; }
		if out=$(as_uid dd if=/dev/zero of=b bs=1M count=12 conv=fsync 2>&1); then
			echo "20 MiB written past a 16 MiB quota"
			return 1
		fi
		case $out in
		*[Qq]"uota exceeded"*) return 0 ;;
		*) echo "the write failed, but not on the quota: $out"; return 1 ;;
		esac
	}
	local why
	if ! why=$(quota_writes); then
		fail $n "$why"
	elif ! docker restart -t 60 "$NODE" >/dev/null || ! wait_ready $full; then
		fail $n "the node did not come back after a restart"
	elif ! why=$(quota_writes); then
		fail $n "after a restart: $why"
	else
		pass $n
	fi
	nx sh -c "rm -rf $d; xfs_quota -x -c 'limit -u bhard=0 $uid' $REPO" || fail $n "cleanup failed"
}

# s3 ROLE BUCKET SUBCOMMAND [ARG]…: sp-probe s3 in the node with a role's keys,
# the harness CA and the endpoint; prints the verdict line and "exit N".
s3() {
	local role=$1 bucket=$2 out s=0
	shift 2
	out=$(nx "$NODE_BIN/sp-probe" s3 "$@" --endpoint "https://$S3_NAME:$S3_PORT" --keys $S3/$role.keys \
		--bucket "$bucket" --ca $S3/ca.pem --timeout 10s </dev/null 2>&1) || s=$?
	printf '%s exit %s\n' "$(printf '%s' "$out" | tail -n 1)" "$s"
}

# put ROLE BUCKET KEY: a small object; prints the verdict and the exit status.
put() {
	local out s=0
	out=$(echo harness | docker exec -i "$NODE" "$NODE_BIN/sp-probe" s3 put "$3" --endpoint "https://$S3_NAME:$S3_PORT" \
		--keys $S3/$1.keys --bucket "$2" --ca $S3/ca.pem --timeout 10s 2>&1) || s=$?
	printf '%s exit %s\n' "$(printf '%s' "$out" | tail -n 1)" "$s"
}

standin_up() {
	local n=standin-up b got key v
	[ -n "$standin" ] || { skip $n "no stand-in beside $NODE (SP_OFFSITE=0)"; return; }
	local addrs
	addrs=$(nx cat $S3/addrs) && [ "$(wc -w <<<"$addrs")" = 2 ] || { fail $n "no two addresses in $S3/addrs: '$addrs'"; return; }
	expect() { # expect WHAT GOT WANT-PATTERN
		# shellcheck disable=SC2254
		case $2 in
		$3) ;;
		*) fail $n "$1: got '$2'"; return 1 ;;
		esac
	}
	for b in sp-projects sp-cp; do
		expect "head $b" "$(s3 admin $b head)" "bucket ok exit 0" || return
		got=$(nx "$NODE_BIN/sp-probe" s3 head --endpoint "https://$S3_NAME:$S3_PORT" --keys $S3/admin.keys \
			--bucket $b --timeout 10s 2>&1)
		expect "head $b without the harness CA" "$got exit $?" "error *exit 3" || return
		expect "versioning $b" "$(s3 admin $b versioning)" "versioning Enabled exit 0" || return
		expect "lock $b" "$(s3 admin $b lock)" "lock COMPLIANCE 1 exit 0" || return
		expect "lifecycle $b" "$(s3 admin $b lifecycle)" "lifecycle sp 1 1 exit 0" || return
	done
	# A fresh version cannot be removed before its retain date, even by the
	# admin keys; control: the same keys can place a delete marker.
	key=harness/lock-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
	got=$(put admin sp-projects "$key")
	expect "put $key" "$got" "version * exit 0" || return
	v=$(set -- $got; echo "$2")
	expect "rm of a locked version" "$(s3 admin sp-projects rm "$key" --version "$v")" "denied exit 1" || return
	expect "the locked version after rm" "$(s3 admin sp-projects head "$key" --version "$v")" "object 8 $v * exit 0" || return
	expect "delete marker (control)" "$(s3 admin sp-projects rm "$key")" "removed * marker=true exit 0" || return
	# The projects' identities reach nothing in sp-cp; controls: the same keys
	# in sp-projects, and the control plane's own keys in sp-cp.
	key=harness/scope-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
	expect "cp-write put on sp-cp" "$(put cp-write sp-cp "$key")" "version * exit 0" || return
	expect "projects-write put on sp-projects" "$(put projects-write sp-projects "$key")" "version * exit 0" || return
	for r in projects-write projects-read; do
		expect "$r get on sp-projects" "$(s3 $r sp-projects get "$key")" "object 8 * exit 0" || return
		expect "$r list on sp-projects" "$(s3 $r sp-projects versions harness/scope-)" "version * exit 0" || return
		expect "$r put on sp-cp" "$(put $r sp-cp "$key")" "denied exit 1" || return
		expect "$r get on sp-cp" "$(s3 $r sp-cp get "$key")" "denied exit 1" || return
		expect "$r list on sp-cp" "$(s3 $r sp-cp versions harness/)" "denied exit 1" || return
	done
	# One endpoint, two addresses: each answers.
	for a in $addrs; do
		expect "head at $a" "$(s3 admin sp-projects head --addr $a:$S3_PORT)" "bucket ok exit 0" || return
	done
	# Nothing outside the two lab networks reaches it: neither this machine nor
	# a container on its default network; control: one on the first lab
	# network does.
	probe() {
		docker run --rm --label supapace.test=1 --name "sp-test-harness-$1-$$" --network "$2" -v "$PWD/$BIN:/b:ro" \
			--entrypoint /b/sp-probe "$NODE_IMAGE" tcp "$3:$S3_PORT" --timeout 3s 2>&1
	}
	for a in $addrs; do
		expect "from this machine to $a" "$("$BIN/sp-probe" tcp $a:$S3_PORT --timeout 3s 2>&1)" "@(timeout|unreachable *)" || return
		expect "from the default network to $a" "$(probe out bridge $a)" "@(timeout|unreachable *)" || return
	done
	expect "from the lab network (control)" "$(probe in "$NODE-net" "${addrs%%$'\n'*}")" "connected" || return
	pass $n
}

standin_not_in_node() {
	local n=standin-not-in-node digest tar imgs
	digest=$(lock_field s3_standin 2)
	[ -n "$digest" ] || { fail $n "no s3_standin entry in $LOCK"; return; }
	while IFS= read -r tar; do
		if tar -xOf "$tar" index.json 2>/dev/null | grep -q -e seaweedfs -e "$digest"; then
			fail $n "the image cache holds the stand-in: $tar"
			return
		fi
	done < <(find "$IMAGE_CACHE" -name '*.tar')
	imgs=$(nx docker image ls --digests --format '{{.Repository}} {{.Digest}}') || { fail $n "cannot list the node's images"; return; }
	# Control: the listing shows what the node loaded.
	grep -q supapace-worker <<<"$imgs" || { fail $n "the node lists no worker image: the listing is not what was loaded"; return; }
	if grep -q -e seaweedfs -e "$digest" <<<"$imgs"; then
		fail $n "the node's Docker holds the stand-in image"
		return
	fi
	pass $n
}

standin_digest() {
	local n=standin-digest want files f got
	want=$(lock_field s3_standin 2)
	[ -n "$want" ] || { fail $n "no s3_standin entry in $LOCK"; return; }
	files=$(grep -rl --include='*_test.go' 'seaweedfs@sha256:' .)
	[ -n "$files" ] || { fail $n "no test file pins the stand-in"; return; }
	for f in $files; do
		for got in $(grep -o 'seaweedfs@sha256:[0-9a-f]*' "$f"); do
			[ "${got#seaweedfs@}" = "$want" ] || { fail $n "$f pins $got, images.lock $want"; return; }
		done
	done
	pass $n
}

worker_image() {
	local n=worker-image base src sum out id want
	base=$(lock_field worker_base 1) && base=${base%:*}@$(lock_field worker_base 2)
	src=$(lock_field worker_source 1)
	sum=$(lock_field worker_source 2)
	build() { # build SHA256: the worker's build, exported nowhere
		docker build --progress plain --output type=cacheonly --build-arg WORKER_BASE="$base" --build-arg WORKER_SRC="$src" \
			--build-arg WORKER_SRC_SHA256="$1" -f deploy/worker/Dockerfile "$IMAGE_CACHE/src" 2>&1
	}
	# A wrong source checksum fails the build at the check; control: the right one builds.
	if out=$(build "sha256:$(printf '%064d' 0)"); then
		fail $n "a wrong source checksum built"
		return
	fi
	case $out in
	*"src.tar.gz: FAILED"*) ;;
	*) fail $n "the wrong checksum failed elsewhere than at the check: $(tail -n 5 <<<"$out")"; return ;;
	esac
	out=$(build "$sum") || { fail $n "the build with the pinned checksum failed: $(tail -n 5 <<<"$out")"; return; }
	run() { nx docker run --rm --network none --entrypoint "$1" "$WORKER" "${@:2}" 2>&1; }
	out=$(run pgbackrest version)
	[ "$out" = "pgBackRest 2.58.0" ] || { fail $n "pgbackrest version: '$out'"; return; }
	# worker-image-has-no-server; control: the same walk finds the binary.
	out=$(run find / -xdev '(' -name postgres -o -name initdb -o -name pg_ctl -o -name pg_resetwal -o -name psql \
		-o -name pgbackrest.conf -o -name pgbackrest ')' -print)
	[ "$out" = /usr/bin/pgbackrest ] || { fail $n "worker-image-has-no-server: found '$out'"; return; }
	# No set-uid or set-gid file; control: the same walk with an empty mode finds files.
	out=$(run find / -xdev -type f -perm /6000 -print)
	[ -z "$out" ] || { fail $n "set-uid or set-gid files: '$out'"; return; }
	[ -n "$(run find /usr/bin -xdev -type f -perm /0100 -print)" ] || { fail $n "the walk finds no file (control)"; return; }
	out=$(run awk -F: '$3 == 70 { print FILENAME ":" $1 ":" $4 }' /etc/passwd /etc/group)
	[ "$out" = "$(printf '/etc/passwd:postgres:70\n/etc/group:postgres:')" ] || { fail $n "uid and gid 70: '$out'"; return; }
	want=$(tar -xOf "$IMAGE_CACHE/supapace-worker.tar" index.json | grep -o '"digest":"sha256:[0-9a-f]*"' | head -n 1 | cut -d'"' -f4)
	id=$(nx docker image inspect -f '{{.Id}}' "$WORKER")
	[ -n "$want" ] && [ "$id" = "$want" ] || { fail $n "the node's image id $id, the archive's $want"; return; }
	pass $n
}

daemon_pid() { nx pgrep -x -f "$NODE_BIN/supapaced serve"; }
# held: how often the supervisor has said it holds the daemon.
held() { nx grep -c "supapaced held" /var/log/supapaced.log; }

hold() {
	local n=hold ok=1 seen
	[ -n "$full" ] || { skip $n "a bare node runs no daemon"; return; }
	daemon_pid >/dev/null || { fail $n "no daemon before the hold (control)"; return; }
	seen=$(held)
	nx touch /run/sp-hold || { fail $n "cannot create /run/sp-hold"; return; }
	nx pkill -TERM -x -f "$NODE_BIN/supapaced serve"
	# The supervisor says it holds before it waits; from then on no daemon starts.
	for _ in $(seq 120); do
		[ "$(held)" -gt "$seen" ] && break
		sleep 1
	done
	if [ "$(held)" -le "$seen" ]; then
		fail $n "the supervisor did not hold within 120 s"
		ok=
	elif daemon_pid >/dev/null; then
		fail $n "a daemon runs while /run/sp-hold exists"
		ok=
	fi
	nx rm -f /run/sp-hold
	wait_ready daemon || { fail $n "the daemon did not answer within 300 s after the hold was removed"; return; }
	[ -z "$ok" ] || pass $n
}

# Two slots give four distinct /25 subnets of 10.215.0.0/16 (so disjoint), each
# address in its own subnet; the default slot follows the node name. Computed by
# make lab, no node needed.
lab_slots() {
	local n=lab-slots a b
	lab() { env -u MAKEFLAGS -u MAKEOVERRIDES -u S3_SLOT make -s --no-print-directory lab "$@" | tr '\n' ' '; }
	a=$(lab NODE=sp-a S3_SLOT=1) b=$(lab NODE=sp-a S3_SLOT=2)
	case "$a|$b" in
	*"S3_NET1=10.215.1.0/25 S3_NET2=10.215.1.128/25 S3_ADDR1=10.215.1.10 S3_ADDR2=10.215.1.138 S3_NODE1=10.215.1.5 S3_NODE2=10.215.1.133 |"*"S3_NET1=10.215.2.0/25 S3_NET2=10.215.2.128/25 S3_ADDR1=10.215.2.10 S3_ADDR2=10.215.2.138 S3_NODE1=10.215.2.5 S3_NODE2=10.215.2.133 ") ;;
	*) fail $n "slots 1 and 2: '$a' '$b'"; return ;;
	esac
	# The default: the same name gives the same slot, in 1..250.
	a=$(lab NODE=sp-a) b=$(lab NODE=sp-a)
	[ "$a" = "$b" ] && [[ $a =~ ^S3_SLOT=([0-9]+)\  ]] && ((BASH_REMATCH[1] >= 1 && BASH_REMATCH[1] <= 250)) ||
		{ fail $n "default slot of sp-a: '$a' '$b'"; return; }
	pass $n
}

# offsite_show: the daemon binary's `offsite show` output and exit status.
offsite_show() {
	local out s=0
	out=$(nx "$NODE_BIN/supapaced" offsite show 2>&1) || s=$?
	printf '%s\nexit %s\n' "$out" "$s"
}

offsite_declared() {
	local n=offsite-declared out
	[ -n "$full" ] || { skip $n "a bare node has no daemon configuration"; return; }
	out=$(offsite_show)
	case $out in *"exit 2") skip $n "the daemon binary has no offsite subcommand"; return ;; esac
	[ -n "$standin" ] || { skip $n "no stand-in beside $NODE (SP_OFFSITE=0)"; return; }
	case $out in
	*'"state": "declared"'*'"endpoint": "https://'$S3_NAME:$S3_PORT'"'*"exit 0") pass $n ;;
	*) fail $n "offsite show: $out" ;;
	esac
}

boot_without_offsite() {
	local n=boot-without-offsite
	[ -n "$full" ] || { skip $n "a bare node runs no daemon"; return; }
	case $(offsite_show) in
	*"exit 2") ;;
	*) skip $n "the daemon binary has the offsite subcommand"; return ;;
	esac
	nx "$NODE_BIN/supapace" node check 2>/dev/null | grep -q '"checks"' || { fail $n "the daemon does not serve"; return; }
	nx test ! -e /etc/supapace/offsite.sealed || { fail $n "a declaration exists"; return; }
	pass $n
}

repo_mount
standin_up
standin_not_in_node
standin_digest
worker_image
lab_slots
hold
offsite_declared
boot_without_offsite
[ "$fails" = 0 ] || { echo "harness-test: $fails failed"; exit 1; }
echo "harness-test: ok"
