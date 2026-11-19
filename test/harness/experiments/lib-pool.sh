# shellcheck shell=sh disable=SC2034 # the variables are used by the scripts that run after this file
# lib-pool.sh — the pooler lab, inside a bare test node. Not run by itself:
# pool-lab.sh prepends its settings (SV_IMAGE, OUT_NODE_IP, OUT_CLIENT_IP,
# OUT_SUBNET, CONNLIMIT, KIT) and appends one experiment script, and runs the
# whole inside the node as root. POSIX sh (the node's busybox ash).
#
# The lab, on the node's default addresses (nodecfg.Default):
#   - the node's own tables, loaded by `supapaced nft load` after a
#     development init (the bare node has none), and verified;
#   - networks with the platform's bridge names: ingress spi0, platform spl0,
#     project slices spp0 to spp3;
#   - three clusters of the pinned image on slices 0 to 2, created with the
#     agent's flags (CLUSTER_FLAGS, checked against the agent's source by the
#     wrapper) in the agent's two phases: a first boot without a network, then
#     the cluster on its slice with the platform's host-based access file;
#     bootstrapped with the pooler's manager role and its helper;
#   - the registry database (the control_plane image) at the cluster address of
#     slice 3, so that the node's tables admit the pooler's connection to it as
#     they admit one to any cluster;
#   - Supavisor by digest with its hardened settings, published on the ingress
#     address with an explicit IPv4 bind, joined to the platform network and to
#     the four slices (the lab has no proxy between pooler and clusters);
#   - a client on the node's own network (psql, pgbench) and the outside client
#     of the wrapper, reached through `outside`.
#
# Every secret is random, kept under $KIT/s (root 0700) and never printed.

set -eu
: "${SV_IMAGE:?}" "${OUT_NODE_IP:?}" "${OUT_CLIENT_IP:?}" "${OUT_SUBNET:?}" "${CONNLIMIT:?}" "${KIT:?}" # from pool-lab.sh
# The wrapper's answers arrive on standard input, which nothing else may read;
# requests to it go to the real standard output, also from inside $(...).
exec 3<&0 4>&1 </dev/null

SP_BIN=/opt/supapace/bin
P=sp-test-pool
DOMAIN=sp.test LABEL=db
ZONE=$LABEL.$DOMAIN
ING_SUB=10.212.8.0/24 POOLER_ING_IP=10.212.8.3
ING_GW=${ING_SUB%.*}.1 # the ingress bridge's own address
PLAT_SUB=10.212.0.0/21 PLAT_RANGE=10.212.6.0/23 POOLER_IP=10.212.0.8
POOLER_UID=65526
META_IP=10.213.0.194
SV=$P-pooler META=$P-meta CLI=$P-cli
# The agent's options of a cluster's `docker create` (internal/agent/cluster.go).
CLUSTER_FLAGS="--cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cpus 1 --shm-size 64m --ulimit core=0 --ulimit nofile=65536:65536 --no-healthcheck --ipc private --stop-timeout 45"
S=$KIT/s
mkdir -p "$S" && chmod 0700 "$S"
# The wrapper stops this run by this pid before it removes anything.
echo $$ >"$KIT/pid"

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 3
}

# --- verdict lines ---------------------------------------------------------
FAILS=0
# res WORD CRITERION FIGURE: one line per criterion; WORD is PASS, FAIL,
# RECORDED, UNRUN or CONTROL (the permitted form of a negative's probe).
res() {
	printf '%s %s — %s\n' "$1" "$2" "$3"
	[ "$1" != FAIL ] || FAILS=$((FAILS + 1))
}
# control NAME OK FIGURE: a control line; a control that does not hold fails
# the run, since its negative then proves nothing.
control() {
	if [ "$2" = 1 ]; then res CONTROL "$1" "$3"; else res FAIL "control $1" "$3"; fi
}
finish() {
	scan_result
	say ""
	say "$1: $FAILS criterion line(s) failed"
	[ "$FAILS" = 0 ]
}

# --- no secret on a command line -------------------------------------------
# A sampler reads every process's command line in the node twice a second —
# the node's process table holds every nested container's processes, which the
# workstation's own `ps` also shows — and counts the samples in which one holds
# a lab secret (the secret itself is never printed). It ends with the run;
# finish reports it as a criterion line. The release cookie is left out: the
# pin's own start script hands it to the Erlang VM by --cookie (recorded by
# lab_up), which no setting of ours changes.
scan_patterns() {
	for _f in "$S"/admin* "$S"/pg[0-9]* "$S"/ro[0-9]* "$S"/mgr* "$S"/meta* "$S"/vault "$S"/api "$S"/metrics "$S"/keybase "$S"/user*; do
		[ -s "$_f" ] && { cat "$_f"; echo; }
	done >"$S/patterns.tmp" 2>/dev/null
	mv "$S/patterns.tmp" "$S/patterns"
}
scan_start() {
	_parent=$$
	(
		while [ -d "$S" ] && kill -0 "$_parent" 2>/dev/null && [ ! -e "$S/scan.stop" ]; do
			scan_patterns 2>/dev/null || break
			if [ -s "$S/patterns" ]; then
				echo >>"$S/scan.samples"
				cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' '\n' >"$S/scan.dump"
				if grep -q -F -f "$S/patterns" "$S/scan.dump"; then
					# Which secret (its file's name, never its value).
					for _g in "$S"/admin* "$S"/pg[0-9]* "$S"/ro[0-9]* "$S"/mgr* "$S"/meta* "$S"/vault "$S"/api "$S"/metrics "$S"/keybase "$S"/user*; do
						[ -s "$_g" ] && grep -q -F -f "$_g" "$S/scan.dump" && printf '%s ' "${_g##*/}"
					done >>"$S/scan.hits"
					echo >>"$S/scan.hits"
				fi
				rm -f "$S/scan.dump"
			fi
			sleep 0.5
		done
	) >/dev/null 2>&1 &
}
scan_result() {
	[ ! -e "$S/scan.stop" ] || return 0
	touch "$S/scan.stop"
	_n=$(wc -l <"$S/scan.samples" 2>/dev/null || echo 0)
	_h=$(wc -l <"$S/scan.hits" 2>/dev/null || echo 0)
	if [ "$_n" -gt 0 ] && [ "$_h" = 0 ]; then
		res PASS "no lab secret on any process command line in the node" "$_n samples, 0 holding one"
	else
		res FAIL "no lab secret on any process command line in the node" "$_n samples, $_h holding one: $(sort "$S/scan.hits" | uniq -c | tr -s " \n" " ")"
	fi
}

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
# rand_alnum N: N characters of [A-Za-z0-9].
rand_alnum() { head -c $(($1 * 3)) /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
now_cs() { awk '{ printf "%d\n", $1 * 100 }' /proc/uptime; }
secret() { cat "$S/$1"; }
# mksecret NAME VALUE: written once, root 0600.
mksecret() { [ -s "$S/$1" ] || (umask 077 && printf '%s' "$2" >"$S/$1"); }

pinned_image() {
	_r=$(docker images --digests --format '{{.Repository}}@{{.Digest}}' | grep -x "$1@sha256:[0-9a-f]*" | sort -u)
	[ "$(printf '%s\n' "$_r" | grep -c .)" = 1 ] || die "need exactly one loaded $1 image by digest, have: ${_r:-none}"
	printf '%s\n' "$_r"
}

# --- outside client (through the wrapper) ----------------------------------
# outside CMD: runs CMD in the outside client; sets OUT (its output) and returns its status.
outside() {
	printf '@@outside %s\n' "$(printf '%s' "$1" | base64 | tr -d '\n')" >&4
	IFS=' ' read -r _st _b64 <&3 || die "no answer from the wrapper"
	OUT=$(printf '%s' "$_b64" | base64 -d)
	return "$_st"
}

# --- node, networks ---------------------------------------------------------
lab_node() {
	if [ ! -e /etc/supapace/node.json ]; then
		# init shows the key escrow on its output: a root-only file, never the log.
		(umask 077 && "$SP_BIN/supapaced" init --dev --no-systemd --ack-escrow --domain "$DOMAIN" >"$S/init.out" 2>&1) ||
			die "supapaced init failed (output in $S/init.out)"
	fi
	"$SP_BIN/supapaced" nft load >/dev/null || die "supapaced nft load failed"
	"$SP_BIN/supapaced" nft check >/dev/null || die "the node's tables are not verified"
}

net() { # NAME ARGS...
	docker network inspect "$1" >/dev/null 2>&1 && return 0
	_n=$1
	shift
	docker network create --label supapace.test=1 --ipv6=false "$@" "$_n" >/dev/null
}
# The kit's slice addressing (10.213.0.<index × 64>, /26) holds four slices, 0 to
# 3: the three clusters and the registry. A lab of more clusters needs the
# node's own slice arithmetic first; until then every slice index is checked.
SLICES=4
slice_ok() { [ "$1" -ge 0 ] && [ "$1" -lt "$SLICES" ] || die "slice $1: the kit addresses slices 0 to $((SLICES - 1)) only (10.213.0.<index × 64>); more clusters need the node's slice arithmetic"; }
slice() { slice_ok "$1"; echo "10.213.0.$(($1 * 64))"; }
cluster_ip() { slice_ok "$1"; echo "10.213.0.$(($1 * 64 + 2))"; }
lab_nets() {
	net "$P-ing" --subnet "$ING_SUB" -o com.docker.network.bridge.name=spi0
	net "$P-plat" --internal --subnet "$PLAT_SUB" --ip-range "$PLAT_RANGE" \
		-o com.docker.network.bridge.name=spl0 -o com.docker.network.bridge.gateway_mode_ipv4=isolated
	_i=0
	while [ "$_i" -lt "$SLICES" ]; do
		slice_ok "$_i"
		net "$P-proj$_i" --internal --subnet "$(slice "$_i")/26" \
			-o "com.docker.network.bridge.name=spp$_i" -o com.docker.network.bridge.gateway_mode_ipv4=isolated
		_i=$((_i + 1))
	done
}

# --- clusters ---------------------------------------------------------------
ref_of() { printf 'lab%017d' "$1"; } # a 20-character ref
wait_ready() { # NAME LOGIN(1|0)
	_w=0
	until docker exec "$1" pg_isready -q -h 127.0.0.1 -p 5432 2>/dev/null &&
		{ [ "$2" = 0 ] || docker exec "$1" psql -U supabase_admin -d postgres -Atqc 'select 1' >/dev/null 2>&1; }; do
		[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] ||
			{ docker logs --tail 20 "$1" >&2; die "cluster $1 stopped"; }
		_w=$((_w + 1))
		[ "$_w" -le 300 ] || die "cluster $1 not ready after 300 s"
		sleep 1
	done
}

# cluster_run INDEX PHASE: docker run of the cluster of slice INDEX; PHASE a is
# the first boot (no network, the image's own access file), b the cluster on
# its slice with the platform's access file.
cluster_run() {
	_i=$1 _ph=$2 _d=$KIT/pg$1 _u=$((700000 + $1)) _pw=
	set -- --name "$P-pg$_i" --hostname "$P-pg$_i" --user "$_u:$_u" --label supapace.test=1 \
		--memory 512m --memory-swap 512m --pids-limit 512 \
		--security-opt "seccomp=$KIT/seccomp.json" \
		-v "$_d/data:/var/lib/postgresql/data" -v "$_d/sock:/var/run/postgresql" \
		-v "$_d/etc/passwd:/etc/passwd:ro" -v "$_d/etc/group:/etc/group:ro" \
		-v "$_d/etc/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro"
	if [ "$_ph" = a ]; then
		# A first-boot password the image's init scripts may pass on a command line:
		# random and discarded, as the agent's; bootstrap sets the real ones.
		_pw=$(rand_hex 32)
		set -- "$@" --network none -e POSTGRES_PASSWORD
	else
		set -- "$@" --network "$P-proj$_i" --ip "$(cluster_ip "$_i")" \
			--sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl "net.ipv4.ping_group_range=1 0" \
			-v "$_d/etc/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro" -v "$_d/etc/pg_ident.conf:/etc/postgresql/pg_ident.conf:ro"
	fi
	# shellcheck disable=SC2086 # CLUSTER_FLAGS is a list of options
	POSTGRES_PASSWORD=$_pw docker run -d $CLUSTER_FLAGS "$@" "$PG_IMAGE" postgres -D /etc/postgresql \
		-c max_connections=120 -c superuser_reserved_connections=3 -c reserved_connections=2 >/dev/null
}

# lab_cluster INDEX: the cluster of slice INDEX, bootstrapped; nothing when running.
lab_cluster() {
	slice_ok "$1"
	_c=$1 _d=$KIT/pg$1 _u=$((700000 + $1))
	[ "$(docker inspect -f '{{.State.Running}}' "$P-pg$_c" 2>/dev/null)" = true ] && return 0
	for _s in admin pg ro mgr; do mksecret "$_s$_c" "$(rand_hex 24)"; done
	mkdir -p "$_d/data" "$_d/sock" "$_d/etc"
	docker run --rm --entrypoint cat "$PG_IMAGE" /etc/passwd | sed "s/^postgres:x:[0-9]*:[0-9]*:/postgres:x:$_u:$_u:/" >"$_d/etc/passwd"
	docker run --rm --entrypoint cat "$PG_IMAGE" /etc/group | sed "s/^postgres:x:[0-9]*:/postgres:x:$_u:/" >"$_d/etc/group"
	rand_hex 32 >"$_d/etc/pgsodium_root.key"
	# internal/pgconf HBA and Ident, for this slice.
	cat >"$_d/etc/pg_hba.conf" <<-EOF
		local   all  supabase_admin                 scram-sha-256
		local   all  supapace_backup                peer map=supapace
		local   all  all                            reject
		host    all  supabase_admin   all           reject
		host    all  supapace_backup  all           reject
		host    all  all              127.0.0.1/32  scram-sha-256
		host    all  all              ::1/128       scram-sha-256
		host    all  all              $(slice "$_c")/26    scram-sha-256
		host    all  all              0.0.0.0/0     reject
		host    all  all              ::/0          reject
	EOF
	echo "supapace  postgres  supapace_backup" >"$_d/etc/pg_ident.conf"
	chown "$_u:$_u" "$_d/etc/pgsodium_root.key" "$_d/data" "$_d/sock"
	chmod 0400 "$_d/etc/pgsodium_root.key"
	chmod 0700 "$_d/data" "$_d/sock"
	chmod 0444 "$_d/etc/passwd" "$_d/etc/group" "$_d/etc/pg_hba.conf" "$_d/etc/pg_ident.conf"
	if [ ! -e "$_d/data/PG_VERSION" ]; then
		cluster_run "$_c" a
		wait_ready "$P-pg$_c" 1
		bootstrap "$_c" | docker exec -i "$P-pg$_c" psql -X -q -U supabase_admin -d postgres -v ON_ERROR_STOP=1 >/dev/null
		docker stop -t 45 "$P-pg$_c" >/dev/null
		docker rm -v "$P-pg$_c" >/dev/null
	fi
	cluster_run "$_c" b
	wait_ready "$P-pg$_c" 0
}

# bootstrap INDEX: the SQL that sets the platform logins' passwords and makes
# the manager role and its helper (the helper returns the manager's own row:
# registration runs the auth query for the manager and refuses without it).
bootstrap() {
	cat <<-SQL
		alter role supabase_admin password '$(secret "admin$1")';
		alter role postgres password '$(secret "pg$1")';
		alter role supabase_read_only_user password '$(secret "ro$1")';
		create role supapace_pooler login noinherit nocreatedb nocreaterole noreplication nobypassrls password '$(secret "mgr$1")';
		create schema supapace_pooler authorization supabase_admin;
		revoke all on schema supapace_pooler from public;
		grant usage on schema supapace_pooler to supapace_pooler;
	SQL
	helper get_auth "and a.rolname !~ '^pg_'"
}

# helper NAME CONDITION: (re)defines supapace_pooler.NAME with the platform's
# filter and CONDITION added.
helper() {
	cat <<-SQL
		create or replace function supapace_pooler.$1(p_usename text)
		  returns table (username text, password text)
		  language sql stable security definer set search_path = ''
		as \$f\$
		  select a.rolname::text, a.rolpassword::text from pg_catalog.pg_authid a
		  where a.rolname = p_usename and a.rolcanlogin and not a.rolsuper
		    and (a.rolvaliduntil is null or a.rolvaliduntil > pg_catalog.now())
		    and a.rolpassword like 'SCRAM-SHA-256\$%'
		    and a.rolname not in ('supabase_admin','supabase_auth_admin','supabase_storage_admin',
		      'supabase_realtime_admin','supabase_replication_admin','supabase_etl_admin',
		      'dashboard_user','pgbouncer','authenticator','supapace_backup')
		    $2
		\$f\$;
		revoke all on function supapace_pooler.$1(text) from public;
		grant execute on function supapace_pooler.$1(text) to supapace_pooler;
	SQL
}

# asadmin INDEX: standard input as supabase_admin over the cluster's socket.
asadmin() {
	PGPASSWORD=$(secret "admin$1") docker exec -i -e PGPASSWORD "$P-pg$1" psql -X -q -At -U supabase_admin -d postgres -v ON_ERROR_STOP=1
}

# --- registry database --------------------------------------------------------
lab_meta() {
	[ "$(docker inspect -f '{{.State.Running}}' "$META" 2>/dev/null)" = true ] && return 0
	mksecret metasu "$(rand_hex 24)"
	mksecret meta "$(rand_hex 24)"
	POSTGRES_PASSWORD=$(secret metasu) docker run -d --name "$META" --label supapace.test=1 --user 70:70 --cap-drop ALL \
		--security-opt no-new-privileges --read-only --memory 256m --memory-swap 256m --pids-limit 128 \
		--tmpfs /var/lib/postgresql/data:uid=70,gid=70,mode=0700 --tmpfs /var/run/postgresql:uid=70,gid=70 \
		--tmpfs /tmp --network "$P-proj3" --ip "$META_IP" -e POSTGRES_PASSWORD \
		"$CP_IMAGE" -c max_connections=40 -c password_encryption=scram-sha-256 >/dev/null
	_m=0
	until docker exec "$META" pg_isready -q -h 127.0.0.1 2>/dev/null && docker exec "$META" psql -U postgres -Atqc 'select 1' >/dev/null 2>&1; do
		_m=$((_m + 1))
		[ "$_m" -le 120 ] || die "registry database not ready"
		sleep 1
	done
	docker exec -i "$META" psql -X -q -U postgres -v ON_ERROR_STOP=1 >/dev/null <<-SQL
		create role supavisor_meta login nosuperuser nocreatedb nocreaterole noreplication connection limit 30 password '$(secret meta)';
		create database supavisor owner supavisor_meta;
		revoke connect on database supavisor from public;
		revoke connect on database postgres from public;
		grant connect on database supavisor to supavisor_meta;
	SQL
}

# --- the pooler -------------------------------------------------------------
lab_tls() {
	_t=$KIT/tls
	[ -s "$_t/cert.pem" ] && return 0
	mkdir -p "$S/ca" "$_t"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 -subj /CN=pool-lab-ca \
		-keyout "$S/ca/key.pem" -out "$KIT/ca.pem" 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=*.$ZONE" \
		-keyout "$_t/key.pem" -out "$S/ca/csr.pem" 2>/dev/null
	printf 'subjectAltName=DNS:*.%s\n' "$ZONE" >"$S/ca/ext"
	openssl x509 -req -in "$S/ca/csr.pem" -CA "$KIT/ca.pem" -CAkey "$S/ca/key.pem" -CAcreateserial -days 7 \
		-extfile "$S/ca/ext" -out "$_t/cert.pem" 2>/dev/null
	chown "$POOLER_UID:$POOLER_UID" "$_t/key.pem"
	chmod 0400 "$_t/key.pem"
	chmod 0444 "$_t/cert.pem" "$KIT/ca.pem"
}

lab_secrets() {
	mksecret cookie "$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
	mksecret vault "$(rand_alnum 32)"
	mksecret api "$(rand_alnum 64)"
	mksecret metrics "$(rand_alnum 64)"
	mksecret keybase "$(rand_alnum 64)"
}

# The pooler's environment: the mandatory set, plus RLIMIT_NOFILE — the image's
# entrypoint raises the descriptor limit to its own default (100000) and exits
# when the container's hard limit is lower.
pooler_env() {
	cat <<-EOF
		RELEASE_COOKIE=$(secret cookie)
		ERL_EPMD_ADDRESS=127.0.0.1
		NODE_IP=127.0.0.1
		ERL_AFLAGS=-proto_dist inet_tcp -kernel inet_dist_use_interface {127,0,0,1} +hmax 2097152 +hmaxib true +hmaxk true +hmaxel true
		VAULT_ENC_KEY=$(secret vault)
		API_JWT_SECRET=$(secret api)
		METRICS_JWT_SECRET=$(secret metrics)
		SECRET_KEY_BASE=$(secret keybase)
		DATABASE_URL=ecto://supavisor_meta:$(secret meta)@$META_IP:5432/supavisor
		REGION=local
		GLOBAL_DOWNSTREAM_CERT_PATH=/etc/pooler/tls/cert.pem
		GLOBAL_DOWNSTREAM_KEY_PATH=/etc/pooler/tls/key.pem
		RLIMIT_NOFILE=16384
	EOF
}

# The pooler's options: the hardened container.
POOLER_FLAGS="--user $POOLER_UID:$POOLER_UID --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp --memory 1024m --memory-swap 1024m --cpus 2 --pids-limit 1024 --ulimit core=0 --ulimit nofile=16384:16384 --no-healthcheck --ipc private --sysctl net.ipv4.ip_forward=0 --sysctl net.ipv4.conf.all.rp_filter=1 --sysctl net.ipv4.conf.all.arp_ignore=1 --sysctl net.ipv6.conf.all.disable_ipv6=1"

# lab_pooler: creates and starts the pooler (the image's migrations, then its
# server), waits for its health answer; nothing when running.
lab_pooler() {
	[ "$(docker inspect -f '{{.State.Running}}' "$SV" 2>/dev/null)" = true ] && return 0
	docker rm -f "$SV" >/dev/null 2>&1 || :
	(umask 077 && pooler_env >"$S/pooler.env")
	# shellcheck disable=SC2086 # POOLER_FLAGS is a list of options
	docker create --name "$SV" --label supapace.test=1 $POOLER_FLAGS \
		--security-opt "seccomp=$KIT/seccomp.json" \
		--network "$P-ing" --ip "$POOLER_ING_IP" -p 0.0.0.0:5432:5432 -p 0.0.0.0:6543:6543 \
		-v "$KIT/tls:/etc/pooler/tls:ro" --env-file "$S/pooler.env" \
		"$SV_IMAGE" sh -c '/app/bin/migrate && exec /app/bin/server' >/dev/null
	rm -f "$S/pooler.env"
	docker network connect --ip "$POOLER_IP" "$P-plat" "$SV"
	for _k in 0 1 2 3; do docker network connect "$P-proj$_k" "$SV"; done
	_t0=$(now_cs)
	docker start "$SV" >/dev/null
	_h=0
	until [ "$(docker exec "$SV" curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4000/api/health 2>/dev/null)" = 204 ]; do
		[ "$(docker inspect -f '{{.State.Running}}' "$SV")" = true ] || { docker logs --tail 20 "$SV" 2>&1 | grep -v -i secret >&2; die "the pooler exited"; }
		_h=$((_h + 1))
		[ "$_h" -le 180 ] || die "the pooler did not answer its health check in 180 s"
		sleep 1
	done
	POOLER_START_CS=$(($(now_cs) - _t0))
}

# The pooler's cgroup directory in the node.
pooler_cg() {
	_id=$(docker inspect -f '{{.Id}}' "$SV")
	find /sys/fs/cgroup -maxdepth 4 -type d -name "*$_id*" | head -n 1
}
pooler_oom() { awk '$1 == "oom_kill" {print $2}' "$(pooler_cg)/memory.events"; }
pooler_mem_mib() { echo $(($(cat "$(pooler_cg)/memory.$1") / 1048576)); } # current|peak
pooler_cpu_ms() { awk '$1 == "usage_usec" {printf "%d\n", $2 / 1000}' "$(pooler_cg)/cpu.stat"; }
pooler_running() { [ "$(docker inspect -f '{{.State.Running}}' "$SV" 2>/dev/null)" = true ]; }

# --- the admin API, from inside the pooler's own network namespace ----------
b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }
# pad_xor BYTE: the API secret (64 bytes, one SHA-256 block) XOR BYTE, as hex;
# the key travels on pipes only, never on a command line.
pad_xor() {
	od -An -v -tu1 "$S/api" | awk -v x="$1" '
		function bxor(a, b,   r, i) { r = 0; for (i = 1; i < 256; i *= 2) { if ((int(a / i) % 2) != (int(b / i) % 2)) r += i }; return r }
		{ for (i = 1; i <= NF; i++) { printf "%02x", bxor($i, x); n++ } }
		END { for (; n < 64; n++) printf "%02x", x }'
}
# jwt: an HS256 token over the API secret (HMAC-SHA256 written out: the
# secret is exactly one block, so it is the key as it stands).
jwt() {
	[ "$(wc -c <"$S/api")" -le 64 ] || die "the API secret is longer than one block"
	_jh=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
	_p=$(printf '{"role":"admin","exp":%d}' $(($(date +%s) + 600)) | b64url)
	{ pad_xor 54 | xxd -r -p; printf '%s.%s' "$_jh" "$_p"; } | openssl dgst -sha256 -binary >"$S/inner"
	_s=$({ pad_xor 92 | xxd -r -p; cat "$S/inner"; } | openssl dgst -sha256 -binary | b64url)
	rm -f "$S/inner"
	printf '%s.%s.%s' "$_jh" "$_p" "$_s"
}
# admin METHOD PATH [BODYFILE]: prints the HTTP status alone; the body is
# discarded unread (it can hold the manager's password). The token reaches
# curl in the container's environment and a here-document, never its argv.
admin() {
	TOK=$(jwt) docker exec -i -e TOK "$SV" sh -c 'curl -s -o /dev/null -w "%{http_code}" -X "$0" -K /dev/fd/3 \
		-H "Content-Type: application/json" ${2:+--data-binary @-} "http://127.0.0.1:4000$1" 3<<EOF
header = "Authorization: Bearer $TOK"
EOF' "$1" "$2" "${3:+body}" <"${3:-/dev/null}"
}

# tenant_body INDEX [ALLOW_JSON|EMPTY] [EXTRA_JSON] [AUTH_QUERY]: the tenant document
# (poolcfg.Tenant.Body's shape: no sni_hostname, one user — the manager), with
# db_host the cluster's own address (the lab has no proxy).
tenant_body() {
	_q=${4:-SELECT * FROM supapace_pooler.get_auth(\$1)}
	_a=${2:-\"0.0.0.0/0\"}
	[ "$_a" != EMPTY ] || _a=
	printf '{"tenant":{"db_host":"%s","db_port":5432,"db_database":"postgres","ip_version":"v4",' "$(cluster_ip "$1")"
	printf '"require_user":false,"enforce_ssl":true,"auth_query":"%s",' "$_q"
	printf '"default_pool_size":%d,"default_max_clients":%d,"allow_list":[%s],' "${POOL:-5}" "${MAXC:-100}" "$_a"
	printf '"feature_flags":{"named_prepared_statements":true}%s,' "${3:-}"
	printf '"users":[{"db_user":"supapace_pooler","db_password":"%s","pool_size":%d,"mode_type":"transaction","is_manager":true}]}}' \
		"$(secret "mgr$1")" "${POOL:-5}"
}
# register INDEX [ALLOW_JSON] [EXTRA_JSON] [EXTERNAL_ID] [AUTH_QUERY]: PUT; prints the status.
register() {
	(umask 077 && tenant_body "$1" "${2:-}" "${3:-}" "${5:-}" >"$S/body.json")
	admin PUT "/api/tenants/${4:-$(ref_of "$1")}" "$S/body.json"
	rm -f "$S/body.json"
}
terminate() { admin GET "/api/tenants/$1/terminate"; }

# --- clients ----------------------------------------------------------------
# The node-local client: host network, the lab CA.
lab_cli() {
	[ "$(docker inspect -f '{{.State.Running}}' "$CLI" 2>/dev/null)" = true ] && return 0
	docker run -d --name "$CLI" --label supapace.test=1 --network host --memory 512m --pids-limit 2048 \
		-v "$KIT/ca.pem:/ca.pem:ro" --entrypoint sleep "$CP_IMAGE" infinity >/dev/null
}
# conninfo INDEX LOGIN PORT ADDR [TENANT]: TLS, verified against the zone's name.
conninfo() {
	_r=${5:-$(ref_of "$1")}
	printf 'host=%s.%s hostaddr=%s port=%s user=%s.%s dbname=postgres sslmode=verify-full sslrootcert=/ca.pem connect_timeout=30' \
		"$(ref_of "$1")" "$ZONE" "$4" "$3" "$2" "$_r"
}
# password INDEX LOGIN: the lab password of a platform login.
password() {
	case $2 in
	postgres) secret "pg$1" ;;
	supabase_read_only_user) secret "ro$1" ;;
	*) secret "user$1-$2" ;;
	esac
}
# pq INDEX LOGIN PORT ADDR SQL [TENANT]: one psql run in the node-local client;
# output in PQ (one line), status returned.
pq() {
	_s=0
	PQ=$(PGPASSWORD=$(password "$1" "$2") docker exec -e PGPASSWORD "$CLI" timeout 90 \
		psql "$(conninfo "$1" "$2" "$3" "$4" "${6:-}")" -X -At -c "$5" 2>&1) || _s=$?
	PQ=$(printf '%s' "$PQ" | tr '\n' ' ')
	case $PQ in *FATAL* | *ERROR* | *error* | *timeout* | *"could not"* | *refused*) [ "$_s" != 0 ] || _s=1 ;; esac
	return "$_s"
}
# pq_out INDEX LOGIN PORT SQL: the same from the outside client, to the node's
# address on the lab bridge (sslmode=require: the outside has no CA).
pq_out() {
	_s=0
	outside "PGPASSWORD='$(password "$1" "$2")' timeout 90 psql 'host=$OUT_NODE_IP port=$3 user=$2.$(ref_of "$1") dbname=postgres sslmode=require connect_timeout=30' -X -At -c \"$4\" 2>&1" || _s=$?
	PQ=$(printf '%s' "$OUT" | tr '\n' ' ')
	case $PQ in *FATAL* | *ERROR* | *error* | *timeout* | *"could not"* | *refused*) [ "$_s" != 0 ] || _s=1 ;; esac
	return "$_s"
}
# hold NAME INDEX LOGIN PORT SECONDS [TENANT] [OPTIONS]: a session in the
# node-local client that runs pg_sleep(SECONDS), in the background; OPTIONS go
# into the startup packet (e.g. -c search_path=s1). held NAME waits for it
# and prints its status and output on one line.
hold() {
	_n=$1
	shift
	PGPASSWORD=$(password "$1" "$2") docker exec -d -e PGPASSWORD -e PGOPTIONS="${6:-}" "$CLI" sh -c \
		"psql '$(conninfo "$1" "$2" "$3" 127.0.0.1 "${5:-}")' -X -At -c 'select pg_sleep($4)' >/tmp/hold-$_n 2>&1; echo \"rc=\$?\" >>/tmp/hold-$_n"
}
held() {
	_hw=0
	until docker exec "$CLI" grep -q '^rc=' "/tmp/hold-$1" 2>/dev/null; do
		_hw=$((_hw + 1))
		[ "$_hw" -le 300 ] || die "session $1 did not end"
		sleep 1
	done
	docker exec "$CLI" cat "/tmp/hold-$1" | tr '\n' ' '
}
# backends INDEX LOGIN: the cluster's sessions of LOGIN.
backends() { echo "select count(*) from pg_stat_activity where usename = '$2'" | asadmin "$1"; }
# peer_of TEXT: the address in an EADDRNOTALLOWED refusal ("{a, b, c, d}").
peer_of() { printf '%s' "$1" | sed -n 's/.*{\([0-9]*\), \([0-9]*\), \([0-9]*\), \([0-9]*\)}.*/\1.\2.\3.\4/p'; }

# B's health: pgbench through the transaction port, a new connection per
# transaction, two clients, while an attack runs. probe_start INDEX SECONDS;
# probe_wait prints "<transactions> <failed> <tps> <pgbench status> <aborted clients>"
# (pgbench counts a client aborted on a failed connection as aborted, not failed).
probe_start() {
	docker exec "$CLI" sh -c "echo 'select 1;' > /tmp/one.sql"
	PGPASSWORD=$(password "$1" postgres) docker exec -d -e PGPASSWORD -e PGSSLMODE=verify-full -e PGSSLROOTCERT=/ca.pem -e PGHOSTADDR=127.0.0.1 "$CLI" \
		sh -c "pgbench -n -C -f /tmp/one.sql -T $2 -c 2 -j 2 -h $(ref_of "$1").$ZONE -p 6543 -U postgres.$(ref_of "$1") postgres >/tmp/probe.out 2>&1; echo \"rc=\$?\" >>/tmp/probe.out; echo done >>/tmp/probe.out"
}
probe_wait() {
	_pw=0
	until docker exec "$CLI" grep -q '^done' /tmp/probe.out 2>/dev/null; do
		_pw=$((_pw + 1))
		[ "$_pw" -le 600 ] || die "probe did not end"
		sleep 1
	done
	docker exec "$CLI" awk '/number of transactions actually processed/ {t=$NF; sub(/\/.*/, "", t)}
		/number of failed transactions/ {f=$5}
		/^tps/ {p=$3}
		/^rc=/ {sub(/rc=/, ""); r=$0}
		/aborted/ {a++}
		END {printf "%s %s %s %s %s\n", t+0, f+0, p+0, (r == "" ? 99 : r), a+0}' /tmp/probe.out
}

# lab_up: everything above, in order; the client resolves the zone's names to the loopback.
lab_up() {
	step "lab up"
	scan_start
	PG_IMAGE=$(pinned_image supabase/postgres)
	CP_IMAGE=$(pinned_image postgres)
	docker image inspect "$SV_IMAGE" >/dev/null || die "$SV_IMAGE is not loaded"
	lab_node
	lab_nets
	_t0=$(now_cs)
	# Wait for these three alone: the secret sampler is a background job too.
	_pids=
	for _i in 0 1 2; do
		lab_cluster "$_i" &
		_pids="$_pids $!"
	done
	# shellcheck disable=SC2086 # a list of pids
	wait $_pids || :
	for _i in 0 1 2; do [ "$(docker inspect -f '{{.State.Running}}' "$P-pg$_i" 2>/dev/null)" = true ] || die "cluster $_i did not start"; done
	say "three clusters up in $((($(now_cs) - _t0) / 100)) s"
	lab_meta
	lab_tls
	lab_secrets
	lab_pooler
	say "pooler up in $((POOLER_START_CS / 100)).$((POOLER_START_CS % 100)) s (migrations and server)"
	_ck=$(docker exec "$SV" sh -c 'for p in /proc/[0-9]*; do tr "\\0" "\\n" <"$p/cmdline"; done' 2>/dev/null | grep -c -F -f "$S/cookie" || :)
	res RECORDED "the pin's start script puts the node's cookie on the Erlang VM's command line" "$_ck argument(s) of the pooler's processes hold it"
	lab_cli
	for _i in 0 1 2; do
		_st=$(register "$_i")
		case $_st in 200 | 201) ;; *) die "registration of tenant $_i answered $_st" ;; esac
	done
	say "three tenants registered; images: $PG_IMAGE $CP_IMAGE $SV_IMAGE"
	"$SP_BIN/supapaced" nft check >/dev/null || die "the node's tables are not verified after lab up"
}

# lab_down: removes every lab object of the node (the kit's directory too).
lab_down() {
	trap "" PIPE # the wrapper may be gone: nothing here may die writing to it
	trap '' INT TERM
	set +e
	docker ps -aq --filter label=supapace.test=1 --filter name="$P-" | xargs -r docker rm -f -v >/dev/null 2>&1
	docker network ls -q --filter label=supapace.test=1 --filter name="$P-" | xargs -r docker network rm >/dev/null 2>&1
	rm -rf "$KIT"
}
trap 'lab_down' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
