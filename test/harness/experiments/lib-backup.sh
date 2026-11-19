# shellcheck shell=sh disable=SC2034 # the variables are used by the scripts that run after this file
# lib-backup.sh — the backup experiments' kit, inside a bare test node. Not run
# by itself: bk/lab.sh copies it, the helper bk and one experiment script into
# the node and runs them there as root (POSIX sh, the node's busybox ash):
#
#   test/harness/experiments/bk/lab.sh NODE SCRIPT
#
# What it stands up, by hand, with the platform's own code where it exists:
#   - a project of layout 2: its directories and both quotas (internal/nodefs),
#     its rendered files, the cluster's command line with the archive pins and
#     the jobs' PGOPTIONS (internal/pgconf, internal/pgsock) — `bk render`;
#   - its cluster: the agent's create flags (CLUSTER_FLAGS, checked against
#     internal/agent/cluster.go by the wrapper) with the layout-2 mounts and
#     pins: a first boot (A) without a network, the networked start (B), and the
#     recovery start (R) without a network, with the image's own access files
#     and the recovery pins last;
#   - job containers of the worker image at the project's ids, without a
#     network, with every pgBackRest option by environment (one env file, root
#     0600, which also holds the stanza's passphrase);
#   - the object-store stand-in beside the node (make node-bare without
#     SP_OFFSITE=0), driven with sp-probe s3 and one identity at a time.
# The jobs' programs are shell stand-ins (push.sh, job.sh, serve.sh, copy.sh,
# written below), not the platform's.
#
# Functions (REF is a 20-character ref; the project's uid is also its gid):
#   lab_up                       checks the node, loads nothing; the image's files
#   project REF UID IDX          directories, quotas, rendered files, passphrase,
#                                the archive binary, the slice network
#   cluster REF A|B|R            (re)creates and starts the cluster; for R the
#                                arguments in $PINS (one per line) end its command
#   mk REF UID IDX               project, first boot, bootstrap, networked start
#   stopc REF                    stops and removes the cluster
#   sql REF SQL / tsql REF SQL   SQL by SCRAM (the current generation) / by trust
#   rekey REF GEN                the re-key after a restore (bk scram), then GEN is current
#   worker REF KIND CMD…         KIND push | db | restore | serve; $REPOSRC replaces
#                                the repository, $WARGS adds docker options
#   job REF ARGS…                one pgBackRest command, the spool pushed meanwhile
#   pushall REF                  push the spool; $ADMIT the admitted timelines
#   restore_files REF [OPTS]     pgbackrest restore --type=none, then recovery.signal
#   wipe REF                     empties the data directory at the project's uid
#   serve_start REF / serve_stop REF   the restore spool's server
#   recover REF PINS-ARGS…       serve, recovery start with `bk pins PINS-ARGS…`,
#                                until promoted (the promoted cluster keeps running)
#   s3 ROLE SUBCOMMAND ARGS…     sp-probe s3 with ROLE's keys; bucket by the role's
#                                prefix (cp-: sp-cp, else sp-projects) or $BUCKET
#   copy_out REF PREFIX [ROLE]   repo/ to PREFIX in the store, at the replicator's
#                                uid with the project's group
#   copy_back REF PREFIX [ROLE]  PREFIX's current objects into fetch/ (2750,
#                                files 0640), the same way; read it with REPOSRC
#   res, control, finish         verdict lines; finish exits 1 on a FAIL, 4 when a
#                                criterion is UNRUN, else 0
# Every container and network is named sp-test-bk-… and labelled
# supapace.test=1; lab_down (the EXIT trap) removes them and the projects'
# trees. Lab passwords and passphrases are lab values, never real ones.

set -eu
: "${KIT:?}" # from bk/lab.sh
SP_BIN=/opt/supapace/bin
BK=$KIT/bk
P=/var/lib/supapace/projects
REPO=/var/lib/supapace/repo
RD=/var/lib/supapace/platform/projects
S3D=/var/lib/sp/s3
X=$KIT/x S=$KIT/s IMGDIR=$KIT/img
N=sp-test-bk
WK_IMAGE=supapace-worker:local
REPL=65530
NL='
'
# The agent's options of a cluster's `docker create` (internal/agent/cluster.go).
CLUSTER_FLAGS="--cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cpus 1 --shm-size 64m --ulimit core=0 --ulimit nofile=65536:65536 --no-healthcheck --ipc private --stop-timeout 45"
# Every job container: the cluster's flags without --shm-size and --stop-timeout,
# with the jobs' tmpfs, memory and pids, and the cluster's seccomp profile.
JOB_FLAGS="$(echo "$CLUSTER_FLAGS" | sed 's/size=64m/size=128m/; s/ --shm-size [^ ]*//; s/ --stop-timeout [^ ]*//') --security-opt seccomp=$KIT/seccomp.json --memory 512m --memory-swap 512m --pids-limit 256"

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 3
}

# --- verdict lines -----------------------------------------------------------
FAILS=0 UNRUNS=0
# res WORD CRITERION FIGURE: WORD is PASS, FAIL, RECORDED, UNRUN or CONTROL.
res() {
	printf '%s %s — %s\n' "$1" "$2" "$3"
	case $1 in FAIL) FAILS=$((FAILS + 1)) ;; UNRUN) UNRUNS=$((UNRUNS + 1)) ;; esac
}
# check CRITERION FIGURE COMMAND…: PASS when COMMAND succeeds, else FAIL.
check() {
	_c=$1 _f=$2
	shift 2
	if "$@"; then res PASS "$_c" "$_f"; else res FAIL "$_c" "$_f"; fi
}
# control NAME OK FIGURE: a failed control fails the run (its negative proves nothing).
control() { if [ "$2" = 1 ]; then res CONTROL "$1" "$3"; else res FAIL "control $1" "$3"; fi; }
finish() {
	say ""
	say "$1: $FAILS criterion line(s) failed, $UNRUNS not run"
	[ "$FAILS" = 0 ] || return 1
	[ "$UNRUNS" = 0 ] || return 4
}

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
uid_of() { sed -n 1p "$KIT/p/$1" 2>/dev/null | grep . || die "no project $1"; }
gen_of() { cat "$KIT/p/$1.gen"; }
pid_of() { docker inspect -f '{{.State.Pid}}' "$N-pg-$1"; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

pinned_image() {
	_r=$(docker images --digests --format '{{.Repository}}@{{.Digest}}' | grep -x "$1@sha256:[0-9a-f]*" | sort -u)
	[ "$(printf '%s\n' "$_r" | grep -c .)" = 1 ] || die "need exactly one loaded $1 image by digest, have: ${_r:-none}"
	printf '%s\n' "$_r"
}

# --- lab ---------------------------------------------------------------------
lab_up() {
	[ ! -S /run/supapace/admin.sock ] || die "a daemon runs in this node: the kit needs a bare node (make node-bare)"
	mountpoint -q "$REPO" || die "$REPO is not mounted"
	LAB_T0=$(date +%s)
	PG_IMAGE=$(pinned_image supabase/postgres)
	docker image inspect "$WK_IMAGE" >/dev/null 2>&1 || die "$WK_IMAGE is not loaded (make images, then a new node)"
	mkdir -p "$S" "$X" "$KIT/p"
	chmod 0700 "$S"
	worker_scripts
	chmod 0755 "$X" && chmod 0444 "$X"/*
	if [ ! -e "$IMGDIR/postgresql.conf" ]; then
		mkdir -p "$IMGDIR/conf.d"
		docker create --name "$N-extract" --label supapace.test=1 --network none "$PG_IMAGE" >/dev/null
		for _f in /etc/passwd /etc/group /etc/postgresql-custom/supautils.conf /etc/postgresql/postgresql.conf; do
			docker cp -L "$N-extract:$_f" "$IMGDIR/${_f##*/}"
		done
		docker cp "$N-extract:/etc/postgresql-custom/conf.d/." "$IMGDIR/conf.d/"
		docker rm -f "$N-extract" >/dev/null
	fi
	say "lab: $PG_IMAGE, $WK_IMAGE ($(docker image inspect -f '{{.Id}}' "$WK_IMAGE" | cut -c1-19))"
}

# lab_down: every lab container and network, the projects' trees and quotas, the kit.
lab_down() {
	trap '' INT TERM
	set +e
	docker ps -aq --filter label=supapace.test=1 --filter name="$N-" | xargs -r docker rm -f -v >/dev/null 2>&1
	docker network ls -q --filter label=supapace.test=1 --filter name="$N-" | xargs -r docker network rm >/dev/null 2>&1
	for _f in "$KIT"/p/*; do
		case $_f in *.gen | *.lab | *'*') continue ;; esac
		_r=${_f##*/} _u=$(sed -n 1p "$_f")
		rm -rf "${P:?}/$_r" "${REPO:?}/$_r" "${RD:?}/$_r"
		xfs_quota -x -c "limit -u bhard=0 ihard=0 $_u" "$P" 2>/dev/null
		xfs_quota -x -c "limit -u bhard=0 ihard=0 $_u" "$REPO" 2>/dev/null
	done
	rm -rf "$KIT"
}

# --- projects and clusters ---------------------------------------------------
project() {
	_r=$1 _u=$2 _i=$3
	printf '%s\n' "$_u" >"$KIT/p/$_r"
	echo 0 >"$KIT/p/$_r.gen"
	_o=$("$BK" render "$_r" "$_u" "$_i" "${DISK_MB:-4096}" "${REPO_MB:-1024}" "$IMGDIR") || die "bk render $_r failed"
	# shellcheck disable=SC2086 # "slice PREFIX cluster ADDR"
	set -- $_o
	printf '%s %s\n' "$2" "$4" >"$KIT/p/$_r.lab"
	cp "$SP_BIN/supapace-arch" "$RD/$_r/tools/.supapace-arch.tmp"
	chmod 0555 "$RD/$_r/tools/.supapace-arch.tmp"
	mv "$RD/$_r/tools/.supapace-arch.tmp" "$RD/$_r/tools/supapace-arch"
	[ -s "$S/$_r.pass" ] || (umask 077 && printf 'lab-%s' "$(rand_hex 24)" >"$S/$_r.pass")
	docker network inspect "$N-proj-$_r" >/dev/null 2>&1 ||
		docker network create --label supapace.test=1 --internal --ipv6=false --subnet "$2" \
			-o "com.docker.network.bridge.name=spp$_i" -o com.docker.network.bridge.gateway_mode_ipv4=isolated "$N-proj-$_r" >/dev/null
}

cluster() {
	_r=$1 _ph=$2 _u=$(uid_of "$1")
	_d=$P/$_r _o=$RD/$_r
	docker rm -f "$N-pg-$_r" >/dev/null 2>&1 || :
	set -f
	_old=$IFS IFS=$NL
	# shellcheck disable=SC2046,SC2086 # one argument per line
	set -- $(cat "$_o/cmdline") ${PINS:-}
	IFS=$_old
	set +f
	_pw=
	case $_ph in
	A)
		_pw=$(rand_hex 32)
		set -- --network none -e POSTGRES_PASSWORD -- "$PG_IMAGE" postgres -D /etc/postgresql "$@"
		;;
	B)
		_ip=$(cut -d' ' -f2 "$KIT/p/$_r.lab")
		set -- --network "$N-proj-$_r" --ip "$_ip" --sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl "net.ipv4.ping_group_range=1 0" \
			-v "$_o/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro" -v "$_o/pg_ident.conf:/etc/postgresql/pg_ident.conf:ro" \
			-- "$PG_IMAGE" postgres -D /etc/postgresql "$@"
		;;
	R) set -- --network none -- "$PG_IMAGE" postgres -D /etc/postgresql "$@" ;;
	*) die "cluster: phase $_ph" ;;
	esac
	# shellcheck disable=SC2086 # CLUSTER_FLAGS is a list of options
	POSTGRES_PASSWORD=$_pw docker create --name "$N-pg-$_r" --hostname "$N-pg-$_r" --user "$_u:$_u" $CLUSTER_FLAGS \
		--security-opt "seccomp=$KIT/seccomp.json" --memory 512m --memory-swap 512m --pids-limit 512 \
		--label supapace.test=1 --label "supapace.phase=$_ph" \
		-v "$_d/data:/var/lib/postgresql/data" -v "$_d/sock:/var/run/postgresql" \
		-v "$_o/passwd:/etc/passwd:ro" -v "$_o/group:/etc/group:ro" \
		-v "$_o/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro" \
		-v "$_o/conf.d:/etc/postgresql-custom/conf.d:ro" -v "$_o/supautils.conf:/etc/postgresql-custom/supautils.conf:ro" \
		-v "$_o/tools:/opt/supapace/tools:ro" -v "$_d/spool:/opt/supapace/spool" -v "$_d/rspool:/opt/supapace/rspool" \
		"$@" >/dev/null
	docker start "$N-pg-$_r" >/dev/null
}
stopc() {
	docker stop -t 45 "$N-pg-$1" >/dev/null 2>&1 || :
	docker rm -f "$N-pg-$1" >/dev/null 2>&1 || :
}

sql() { "$BK" sql "$1" "$(uid_of "$1")" "$(pid_of "$1")" "$(gen_of "$1")" "$2"; }
tsql() { "$BK" trust -su "$P/$1/sock" supabase_admin "$2" 2>/dev/null; }
rekey() {
	"$BK" scram "$1" "$(uid_of "$1")" "$(pid_of "$1")" "$2" || return 1
	echo "$2" >"$KIT/p/$1.gen"
}
# wait_sql REF: a SCRAM session answers (120 s), unless the cluster stops.
wait_sql() {
	_w=0
	until sql "$1" 'select 1' >/dev/null 2>&1; do
		running "$N-pg-$1" || { docker logs --tail 20 "$N-pg-$1" >&2; die "cluster $1 stopped"; }
		_w=$((_w + 1))
		[ "$_w" -le 120 ] || { sql "$1" 'select 1' || :; die "cluster $1 not ready after 120 s"; }
		sleep 1
	done
}
mk() {
	project "$1" "$2" "$3"
	cluster "$1" A
	_w=0
	until "$BK" bootstrap "$1" "$2" "$(pid_of "$1")" >/dev/null 2>"$KIT/bootstrap.err"; do
		running "$N-pg-$1" || { docker logs --tail 20 "$N-pg-$1" >&2; die "cluster $1 stopped at its first boot"; }
		_w=$((_w + 1))
		[ "$_w" -le 120 ] || die "bootstrap of $1: $(cat "$KIT/bootstrap.err")"
		sleep 1
	done
	stopc "$1"
	cluster "$1" B
	wait_sql "$1"
}

# --- jobs --------------------------------------------------------------------
worker() {
	_r=$1 _k=$2 _u=$(uid_of "$1")
	shift 2
	_rp=${REPOSRC:-$REPO/$_r/repo} _d=$P/$_r _e=$S/$_r.$_k.env
	case $_k in
	push) _m="-v $_d/spool:/spool -v $_rp:/repo" ;;
	db) _m="-v $_d/data:/var/lib/postgresql/data:ro -v $_d/sock:/var/run/postgresql -v $_d/spool:/spool -v $_rp:/repo" ;;
	restore) _m="-v $_d/data:/var/lib/postgresql/data -v $_rp:/repo:ro" ;;
	serve) _m="-v $_d/data:/var/lib/postgresql/data:ro -v $_d/rspool:/rspool -v $_rp:/repo:ro" ;;
	*) die "worker: kind $_k" ;;
	esac
	# The pgBackRest environment of the jobs, every option named, and the passphrase.
	(
		umask 077
		printf '%s\n' "PGBACKREST_STANZA=$_r-1" PGBACKREST_REPO1_PATH=/repo PGBACKREST_REPO1_CIPHER_TYPE=aes-256-cbc \
			"PGBACKREST_REPO1_CIPHER_PASS=$(cat "$S/$_r.pass")" PGBACKREST_LOCK_PATH=/tmp/lock PGBACKREST_LOG_PATH=/tmp/log \
			PGBACKREST_SPOOL_PATH=/tmp/spool PGBACKREST_LOG_LEVEL_FILE=off "PGBACKREST_LOG_LEVEL_CONSOLE=${LLC:-warn}" \
			PGBACKREST_COMPRESS_TYPE=zst PGBACKREST_PROCESS_MAX=1 PGBACKREST_START_FAST=y PGBACKREST_REPO1_BUNDLE=n \
			PGBACKREST_REPO1_BLOCK=n PGBACKREST_RESUME=n PGBACKREST_REPO1_HARDLINK=n PGBACKREST_ARCHIVE_COPY=n \
			PGBACKREST_NEUTRAL_UMASK=y PGBACKREST_CONFIG=/dev/null "ADMIT=${ADMIT:-00000001}"
		[ "$_k" = push ] || echo PGBACKREST_PG1_PATH=/var/lib/postgresql/data
		[ "$_k" != db ] || printf '%s\n' PGBACKREST_PG1_SOCKET_PATH=/var/run/postgresql PGBACKREST_PG1_USER=supapace_backup \
			"PGOPTIONS=$(cat "$RD/$_r/pgoptions")"
	) >"$_e"
	_n=$N-job-$_r
	[ "$_k" != serve ] || _n=$N-serve-$_r
	docker rm -f "$_n" >/dev/null 2>&1 || :
	# shellcheck disable=SC2086 # option lists
	docker run ${WDETACH:---rm} --name "$_n" --label supapace.test=1 --user "$_u:$_u" $JOB_FLAGS --network none \
		$_m -v "$X:/x:ro" --env-file "$_e" ${WARGS:-} "$WK_IMAGE" "$@"
}
job() {
	_r=$1
	shift
	worker "$_r" db sh /x/job.sh "$@"
}
pushall() { worker "$1" push sh /x/push.sh; }
restore_files() {
	_r=$1
	shift
	worker "$_r" restore sh -c "pgbackrest --type=none $* restore && touch /var/lib/postgresql/data/recovery.signal"
}
wipe() {
	_u=$(uid_of "$1")
	# shellcheck disable=SC2086 # option list
	docker run --rm --name "$N-job-$1" --label supapace.test=1 --user "$_u:$_u" $JOB_FLAGS --network none \
		-v "$P/$1/data:/d" "$WK_IMAGE" find /d -mindepth 1 -delete
}
serve_start() {
	rm -f "$P/$1/rspool/stop" "$P/$1/rspool/req/"* "$P/$1/rspool/out/"* 2>/dev/null || :
	WDETACH=-d worker "$1" serve sh /x/serve.sh >/dev/null
}
serve_stop() {
	touch "$P/$1/rspool/stop"
	timeout 30 docker wait "$N-serve-$1" >/dev/null 2>&1 || :
	docker logs "$N-serve-$1" 2>&1 | tail -3
	docker rm -f "$N-serve-$1" >/dev/null 2>&1 || :
	rm -f "$P/$1/rspool/stop"
}
# wait_promoted REF: prints the seconds until pg_is_in_recovery() is false.
wait_promoted() {
	_w=0
	until [ "$(tsql "$1" 'select pg_catalog.pg_is_in_recovery()')" = f ]; do
		running "$N-pg-$1" || { say "cluster $1 exited ($(docker logs --tail 3 "$N-pg-$1" 2>&1 | tr '\n' ' '))"; return 1; }
		_w=$((_w + 1))
		[ "$_w" -le "${PROMOTE_WAIT:-180}" ] || { say "cluster $1 not promoted after $_w s"; return 1; }
		sleep 1
	done
	echo "$_w"
}
recover() {
	_r=$1
	shift
	_pins=$("$BK" pins "$@") || die "bk pins $*"
	stopc "$_r"
	serve_start "$_r"
	PINS=$_pins cluster "$_r" R
	if _t=$(wait_promoted "$_r"); then
		say "$_r promoted after $_t s"
		serve_stop "$_r"
	else
		serve_stop "$_r"
		return 1
	fi
}

# --- the object store --------------------------------------------------------
s3_conn() { # ROLE: the connection options (the endpoint's two addresses; the name is never resolved)
	_ep=$(cat "$S3D/endpoint")
	_port=${_ep##*:}
	_b=sp-projects
	case $1 in cp-*) _b=sp-cp ;; esac
	printf '%s\n' --endpoint "$_ep" --bucket "${BUCKET:-$_b}" --timeout "${S3_TIMEOUT:-60s}"
	while read -r _a; do printf '%s\n' --addr "$_a:$_port"; done <"$S3D/addrs"
}
s3() {
	_role=$1
	shift
	set -f
	_old=$IFS IFS=$NL
	# shellcheck disable=SC2046 # one option per line
	set -- "$@" $(s3_conn "$_role") --keys "$S3D/$_role.keys" --ca "$S3D/ca.pem"
	IFS=$_old
	set +f
	"$SP_BIN/sp-probe" s3 "$@"
}
# s3_job REF ROLE MOUNTS CMD…: CMD at the replicator's uid with the project's
# group, on the node's own network stack (a bare node has no ruleset), with
# ROLE's keys at /cred (65530, 0400) and the connection in its environment.
s3_job() {
	_r=$1 _role=$2 _m=$3 _u=$(uid_of "$1")
	shift 3
	_c=$S/$_r.cred
	install -m 0400 -o "$REPL" -g "$REPL" "$S3D/$_role.keys" "$_c"
	cp "$S3D/ca.pem" "$S/ca.pem" && chmod 0444 "$S/ca.pem"
	_conn=$(s3_conn "$_role" | tr '\n' ' ')
	_s=0
	# shellcheck disable=SC2086 # option lists
	docker run --rm --name "$N-copy-$_r" --label supapace.test=1 --user "$REPL:$REPL" --group-add "$_u" $JOB_FLAGS \
		--network host $_m -v "$_c:/cred:ro" -v "$S/ca.pem:/ca.pem:ro" -v "$SP_BIN/sp-probe:/sp-probe:ro" \
		-v "$X:/x:ro" -e "CONN=$_conn" "$WK_IMAGE" "$@" || _s=$?
	rm -f "$_c"
	return $_s
}
copy_out() { s3_job "$1" "${3:-projects-write}" "-v $REPO/$1/repo:/repo:ro" sh /x/copy.sh out "$2"; }
copy_back() {
	_f=$REPO/$1/fetch
	rm -rf "$_f"
	mkdir -m 2750 "$_f"
	chown "$REPL:$(uid_of "$1")" "$_f"
	s3_job "$1" "${3:-projects-read}" "-v $_f:/fetch" sh /x/copy.sh back "$2"
}

# --- the jobs' programs (stand-ins), mounted at /x -----------------------------
worker_scripts() {
	cat >"$X/push.sh" <<'EOF'
# push.sh: push every spool entry with a spool name (segment, history, backup
# label), oldest first. ADMIT (8-hex timelines, space-separated) is the
# admitted set: an entry of another timeline is moved to /spool/quarantine/,
# never pushed. An entry is removed only after archive-push succeeded; the first
# failure stops the run (exit 1).
cd /spool || exit 1
n=0 q=0
for f in $(ls -tr | grep -E '^([0-9A-F]{24}(\.[0-9A-F]{8}\.backup)?|[0-9A-F]{8}\.history)$'); do
	tl=$(echo "$f" | cut -c1-8)
	case " $ADMIT " in *" $tl "*) ;; *)
		mkdir -p /spool/quarantine && mv "/spool/$f" "/spool/quarantine/$f" && q=$((q + 1))
		echo "push: quarantined $f (timeline $tl not admitted)"
		continue ;;
	esac
	if pgbackrest archive-push "/spool/$f"; then rm -f "/spool/$f"; n=$((n + 1)); else
		echo "push: failed $f"; echo "push: pushed $n quarantined $q"; exit 1
	fi
done
echo "push: pushed $n quarantined $q"
EOF
	cat >"$X/job.sh" <<'EOF'
# job.sh: one pgBackRest command while the spool is pushed every 0.5 s; the
# loop stops by a flag and is waited for, then a final push.
rm -f /tmp/job-stop
( while [ ! -e /tmp/job-stop ]; do sh /x/push.sh >/dev/null 2>&1; sleep 0.5; done ) & lp=$!
pgbackrest "$@"; rc=$?
touch /tmp/job-stop; wait $lp 2>/dev/null
sh /x/push.sh >&2
echo "job: pgbackrest $1 rc=$rc"
exit $rc
EOF
	cat >"$X/serve.sh" <<'EOF'
# serve.sh: answer the restore spool's requests from the repository until
# /rspool/stop exists. Names by pattern only; archive-get into the private
# tmpfs, then a temporary name and a rename inside /rspool/out; ".none" only on
# pgBackRest's not-found result (1), every other error retried.
n=0 m=0
while [ ! -e /rspool/stop ]; do
	for r in /rspool/req/*; do
		[ -f "$r" ] || continue
		f=${r##*/}
		echo "$f" | grep -qE '^([0-9A-F]{24}|[0-9A-F]{8}\.history)$' || { echo "serve: refused a name" >&2; rm -f "$r"; continue; }
		rm -f "$r" "/tmp/$f.part"
		pgbackrest --log-level-console=error archive-get "$f" "/tmp/$f.part"; rc=$?
		if [ $rc = 0 ]; then cp "/tmp/$f.part" "/rspool/out/.tmp-$f" && rm "/tmp/$f.part" && mv "/rspool/out/.tmp-$f" "/rspool/out/$f"; n=$((n + 1))
		elif [ $rc = 1 ]; then : >"/rspool/out/.tmp-$f.none"; mv "/rspool/out/.tmp-$f.none" "/rspool/out/$f.none"; m=$((m + 1))
		else echo "serve: archive-get rc=$rc for $f, retrying" >&2; : >"$r"; fi
	done
	sleep 0.1
done
echo "serve: served $n, not found $m"
EOF
	cat >"$X/copy.sh" <<'EOF'
# copy.sh out PREFIX: every regular file of /repo to PREFIX<path>. The info
# files are read first and uploaded last; every other file is created once
# (If-None-Match), an existing one is counted, not replaced.
# copy.sh back PREFIX: every current object under PREFIX into /fetch (dirs
# 2750 through the set-gid bit, files 0640); a name outside the repository's
# characters, or with an empty, "." or ".." part, is refused.
set -u
umask 027
p() { /sp-probe s3 "$@" --keys /cred --ca /ca.pem $CONN; }
n=0 e=0 f=0
case $1 in
out)
	cd /repo || exit 1
	mkdir /tmp/info
	# One name per line (a name may hold a space or a glob character; one with a newline is not supported).
	find . -type f \( -name '*.info' -o -name '*.info.copy' \) >/tmp/il
	while IFS= read -r i; do mkdir -p "/tmp/info/${i%/*}"; cp "$i" "/tmp/info/$i"; done </tmp/il
	{ find . -type f ! -name '*.info' ! -name '*.info.copy'; (cd /tmp/info && find . -type f); } >/tmp/ol
	while IFS= read -r i; do
		k=$2${i#./} src=$i c=--if-absent
		case $i in *.info | *.info.copy) src=/tmp/info/$i c= ;; esac
		case $(p put "$k" $c <"$src") in version*) n=$((n + 1)) ;; exists) e=$((e + 1)) ;; *) f=$((f + 1)); echo "copy: put $k failed" ;; esac
	done </tmp/ol
	echo "copy: uploaded $n existing $e failed $f" ;;
back)
	p versions "$2" >/tmp/v || { echo "copy: listing failed: $(tail -1 /tmp/v)"; exit 1; }
	# One key per line (a key may hold a space); an escaped character is refused below.
	sed -n 's/^version "\(.*\)" [^ ]* latest$/\1/p' /tmp/v >/tmp/k
	while IFS= read -r k; do
		rel=${k#"$2"}
		if ! echo "$rel" | grep -Eq '^[A-Za-z0-9_+-][A-Za-z0-9_.+-]*(/[A-Za-z0-9_+-][A-Za-z0-9_.+-]*)*$'; then
			e=$((e + 1)); echo "copy: refused a name"; continue
		fi
		case $rel in */*) mkdir -p "/fetch/${rel%/*}" ;; esac
		if p get "$k" --out "/fetch/$rel" --max 268435456 </dev/null >/dev/null && chmod 0640 "/fetch/$rel"; then n=$((n + 1)); else f=$((f + 1)); echo "copy: get $k failed"; fi
	done </tmp/k
	echo "copy: fetched $n refused $e failed $f" ;;
esac
[ "$f" = 0 ]
EOF
}

if [ "${BK_DOWN:-}" = 1 ]; then
	lab_down
	exit 0
fi
mkdir -p "$KIT/p"
echo $$ >"$KIT/pid"
trap 'lab_down' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
