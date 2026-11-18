# shellcheck shell=sh disable=SC2034 # the variables are used by the scripts that source this file
# Shared shell helpers for the cluster and REST experiments (e05, e08, e09).
# Sourced, not run: it is prepended to the experiment on standard input,
#   cat lib-rest.sh e05.sh | docker exec -i <node> sh -s
# or, when both files sit side by side on the node, found next to the script.
# POSIX sh (the node's busybox ash). Everything runs as root inside the node.

LIB_REST=1
SP_BIN=/opt/supapace/bin
EXP_ROOT=/var/lib/sp-exp

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

# pinned_image REPOSITORY: the one name@digest of REPOSITORY loaded on this node.
pinned_image() {
	_r=$(docker images --digests --format '{{.Repository}}@{{.Digest}}' | grep -x "$1@sha256:[0-9a-f]*" | sort -u)
	[ "$(printf '%s\n' "$_r" | grep -c .)" = 1 ] || die "need exactly one loaded $1 image by digest, have: ${_r:-none}"
	printf '%s\n' "$_r"
}

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# now_cs: monotonic time in centiseconds (busybox date has no %N).
now_cs() { awk '{ printf "%d\n", $1 * 100 }' /proc/uptime; }

# proc_start PID: field 22 (starttime, clock ticks since boot) of /proc/PID/stat,
# read after the last ')' so a command name with spaces cannot shift it.
proc_start() { sed 's/.*) //' "/proc/$1/stat" | awk '{ print $20 }'; }

# start_cluster NAME UID DIR [docker run args ...]
# Runs the pinned Postgres image as NAME at UID:UID with DIR/data and DIR/sock
# mounted, the image's passwd and group rewritten so that "postgres" is UID, and a
# fresh pgsodium root key. A first start initialises the cluster with a random,
# discarded POSTGRES_PASSWORD. Waits until the final server accepts connections.
start_cluster() {
	_n=$1 _u=$2 _d=$3
	shift 3
	mkdir -p "$_d/data" "$_d/sock" "$_d/etc"
	if [ ! -e "$_d/etc/passwd" ]; then
		docker run --rm --entrypoint cat "$PG_IMAGE" /etc/passwd |
			sed "s/^postgres:x:[0-9]*:[0-9]*:/postgres:x:$_u:$_u:/" >"$_d/etc/passwd"
		docker run --rm --entrypoint cat "$PG_IMAGE" /etc/group |
			sed "s/^postgres:x:[0-9]*:/postgres:x:$_u:/" >"$_d/etc/group"
		rand_hex 32 >"$_d/etc/pgsodium_root.key"
		chown "$_u:$_u" "$_d/etc/pgsodium_root.key" "$_d/data" "$_d/sock"
		chmod 0400 "$_d/etc/pgsodium_root.key"
		chmod 0700 "$_d/data" "$_d/sock"
	fi
	docker run -d --name "$_n" --user "$_u:$_u" \
		--cap-drop ALL --security-opt no-new-privileges --ulimit core=0 \
		--memory 512m --memory-swap 512m --cpus 1 --pids-limit 512 --shm-size 64m \
		-e POSTGRES_PASSWORD="$(rand_hex 32)" \
		-v "$_d/data:/var/lib/postgresql/data" -v "$_d/sock:/var/run/postgresql" \
		-v "$_d/etc/passwd:/etc/passwd:ro" -v "$_d/etc/group:/etc/group:ro" \
		-v "$_d/etc/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro" \
		"$@" "$PG_IMAGE" >/dev/null
	wait_cluster "$_n"
}

# wait_cluster NAME: up to 180 s for the final server (not the image's temporary
# initialisation server, which listens on no TCP port) to answer, and, unless
# WAIT_LOGIN=0, to admit supabase_admin over the socket without a password.
wait_cluster() {
	_i=0
	until docker exec "$1" pg_isready -q -h 127.0.0.1 -p 5432 2>/dev/null &&
		{ [ "${WAIT_LOGIN:-1}" = 0 ] ||
			docker exec "$1" psql -U supabase_admin -d postgres -Atqc 'select 1' >/dev/null 2>&1; }; do
		[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] ||
			{ docker logs --tail 20 "$1" >&2; die "cluster $1 stopped"; }
		_i=$((_i + 1))
		[ "$_i" -le 180 ] || die "cluster $1 not ready after 180 s"
		sleep 1
	done
}

# sql NAME: runs standard input as supabase_admin over the container's socket.
sql() { docker exec -i "$1" psql -X -U supabase_admin -d postgres -v ON_ERROR_STOP=1 -Atq; }

# rm_containers NAME...: removes containers, ignoring absent ones.
rm_containers() { for _c in "$@"; do docker rm -f "$_c" >/dev/null 2>&1 || :; done; }

# --- RS256 tokens with openssl --------------------------------------------------

b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }

# rsa_key FILE: a new RSA-2048 private key.
rsa_key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" 2>/dev/null; }

# jwk KEYFILE KID: the public JWK of KEYFILE (e = 65537).
jwk() {
	_m=$(openssl rsa -in "$1" -noout -modulus | cut -d= -f2 | xxd -r -p | b64url)
	printf '{"kty":"RSA","kid":"%s","use":"sig","alg":"RS256","n":"%s","e":"AQAB"}' "$2" "$_m"
}

# jwt_raw KEYFILE HEADER PAYLOAD: an RS256 signature over the given header and
# payload JSON, used verbatim (so a header or payload may be unusual on purpose).
jwt_raw() {
	_h=$(printf '%s' "$2" | b64url)
	_p=$(printf '%s' "$3" | b64url)
	_s=$(printf '%s.%s' "$_h" "$_p" | openssl dgst -sha256 -sign "$1" -binary | b64url)
	printf '%s.%s.%s' "$_h" "$_p" "$_s"
}

# jwt KEYFILE KID PAYLOAD: an RS256 token; an empty KID leaves kid out of the header.
jwt() {
	if [ -n "$2" ]; then jwt_raw "$1" "$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "$2")" "$3"; else
		jwt_raw "$1" '{"alg":"RS256","typ":"JWT"}' "$3"; fi
}

# jwt_hs SECRETFILE HEADER PAYLOAD: an HMAC-SHA256 signature keyed with the exact
# bytes of SECRETFILE.
jwt_hs() {
	_h=$(printf '%s' "$2" | b64url)
	_p=$(printf '%s' "$3" | b64url)
	_s=$(printf '%s.%s' "$_h" "$_p" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(xxd -p "$1" | tr -d '\n')" -binary | b64url)
	printf '%s.%s.%s' "$_h" "$_p" "$_s"
}

# claims ROLE [EXTRA]: a payload with role, sub, exp an hour ahead and EXTRA members.
claims() {
	printf '{"role":"%s","sub":"00000000-0000-4000-8000-000000000001","exp":%d%s}' \
		"$1" $(($(date +%s) + 3600)) "${2:+,$2}"
}

# http URL [TOKEN]: prints "<status> <body>" ("000" when nothing answered).
http() {
	if [ -n "${2:-}" ]; then
		_o=$(wget -S -q -T 5 -O - --header "Authorization: Bearer $2" "$1" 2>&1) || :
	else
		_o=$(wget -S -q -T 5 -O - "$1" 2>&1) || :
	fi
	_st=$(printf '%s\n' "$_o" | sed -n 's/^ *HTTP\/1\.[01] \([0-9][0-9][0-9]\).*/\1/p' | tail -n 1)
	_b=$(printf '%s\n' "$_o" | grep -v '^ \|^wget: ' | tr -d '\n')
	printf '%s %s\n' "${_st:-000}" "$_b"
}
