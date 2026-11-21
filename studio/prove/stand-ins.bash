# stand-ins.bash — sourced by the proofs of this directory (it is no proof itself): the built
# image as a node runs it, against stand-ins of the control plane's socket and of postgres-meta
# (cmd/sp-dashstub), with three projects and a key pair of the run's own.
#
# Host needs: bash, docker, go, openssl (3.x, for Ed25519), curl. Everything it starts is
# named $PREFIX-* and labelled supapace.test=1, sits on one internal network — nothing here
# can reach outside the host — and is removed when the proof ends, as is its directory.
#
# After `standins_up IMAGE`:
#   A, B, C         the refs of three projects; C has no read-only login
#   PA, PB, PC      the wire-proxy port of each: postgres-meta's stand-in answers the login and
#                   the port of the connection string a request reached it with
#   U               the server's address, http://<address>:3000
#   tok REF SUB ROLE [PURPOSE [IAT_OFFSET [LIFETIME]]]   an assertion as the gateway signs one
#   studio [docker args]    (re)start the server; its memory is empty, its data volume stays
#   socket [MODE]           (re)start the control plane's stand-in (answer, silent, refuse:CODE)
#   seen                    how many requests postgres-meta's stand-in has received
# Members: of A the owner oa, the developer da, the read_only member ra; of B ob and rb; of C
# oc and rc; `both` is an owner of A and of B. Every answer's time is the clock's.
set -uo pipefail

PREFIX=${PROVE_PREFIX:-sp-test-studio-prove}-$$
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
NODE_BASE=$(awk '$1 == "node" { print $2 }' "$HERE/../PIN")
L=(--label supapace.test=1)
A=aaaaaaaaaaaaaaaaaaa1 B=bbbbbbbbbbbbbbbbbbb2 C=ccccccccccccccccccc3
PA=20001 PB=20002 PC=20003
ISS=https://issuer.test
NODE=node-1
# Until the address of postgres-meta and the key of its header come from the node's settings,
# the server takes both from these two names.
CRYPTO='proof-only-header-key_0123456789abcdefghijklmnopqrstuvwxyzABCDEF'
fails=0 rows=0

row() { # row ID WHAT GOT VERDICT
  printf '| %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4"
  rows=$((rows + 1))
  [ "$4" = ok ] || fails=$((fails + 1))
}
check() { # check ID WHAT GOT WANT
  if [ "$3" = "$4" ]; then row "$1" "$2" "$3" ok; else row "$1" "$2" "$3 (want: $4)" FAIL; fi
}
finish() {
  echo
  echo "rows: $rows, failed: $fails"
  [ "$fails" -eq 0 ]
}

standins_down() {
  docker rm -f "$PREFIX-studio" "$PREFIX-socket" "$PREFIX-pgmeta" >/dev/null 2>&1
  docker network rm "$PREFIX-net" >/dev/null 2>&1
  # files the server and the stand-ins wrote under other uids
  [ -z "${T:-}" ] || docker run --rm "${L[@]}" --network none -v "$T:/t" "$NODE_BASE" rm -rf /t/data /t/sock >/dev/null 2>&1
  [ -z "${T:-}" ] || rm -rf "$T"
}

b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }

tok() {
  local iat p f=$T/sign.$BASHPID.$RANDOM
  iat=$(($(date +%s) + ${5:-0}))
  p=$(printf '{"node":"%s","iss":"%s","sub":"%s","name":"%s","ref":"%s","role":"%s","purpose":"%s","iat":%d,"exp":%d}' \
    "$NODE" "$ISS" "$2" "$2" "$1" "$3" "${4:-}" "$iat" "$((iat + ${6:-30}))" | b64url)
  printf 'supapace-assertion-v1.%s' "$p" >"$f"
  printf 'v1.%s.%s' "$p" "$(openssl pkeyutl -sign -inkey "$T/assert.pem" -rawin -in "$f" | b64url)"
  rm -f "$f"
}

socket() {
  docker rm -f "$PREFIX-socket" >/dev/null 2>&1
  rm -f "$T/sock/dash.sock"
  docker run -d --name "$PREFIX-socket" "${L[@]}" --network none --user "$(id -u):$(id -g)" \
    -v "$T/bin/sp-dashstub:/sp-dashstub:ro" -v "$T/sock:/run/dash" -v "$T/keys/assert.pub:/assert.pub:ro" \
    -v "$T/table.json:/table.json:ro" "$NODE_BASE" /sp-dashstub socket --listen /run/dash/dash.sock \
    --public /assert.pub --node "$NODE" --table /table.json ${1:+--mode "$1"} >/dev/null || return 1
  local i
  for i in $(seq 100); do
    [ -S "$T/sock/dash.sock" ] && return 0
    sleep 0.1
  done
  echo "the control plane's stand-in did not start" >&2
  return 1
}

# The server as a node runs it: its uid, a read-only root, no capability, the eight settings.
STUDIO_ENV=()
studio() {
  docker rm -f "$PREFIX-studio" >/dev/null 2>&1
  docker run -d --name "$PREFIX-studio" "${L[@]}" --network "$PREFIX-net" \
    --user 65527:65527 --read-only --tmpfs /tmp --memory 1g --cap-drop ALL --security-opt no-new-privileges \
    -v "$T/sock:/run/dash:ro" -v "$T/keys:/etc/dash:ro" -v "$T/data:/var/lib/dash" \
    "${STUDIO_ENV[@]}" "$@" "$IMAGE" >/dev/null || return 1
  local i ip
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PREFIX-studio")
  U=http://$ip:3000
  for i in $(seq 240); do
    [ "$(docker inspect -f '{{.State.Running}}' "$PREFIX-studio" 2>/dev/null)" = true ] || return 1
    curl -s -o /dev/null -m 2 "$U/api/platform/profile" && return 0
    sleep 0.5
  done
  return 1
}

seen() {
  docker exec "$PREFIX-studio" node -e \
    'fetch("http://pgmeta:8080/_seen").then((r) => r.json()).then((j) => console.log(j.length ? j[j.length - 1].n : 0))'
}

dsn() { printf 'postgresql://%s:%s@10.212.0.6:%s/postgres?sslmode=disable' "$1" "$2" "$3"; }

standins_up() {
  IMAGE=$1
  T=$(mktemp -d)
  trap standins_down EXIT
  mkdir -p "$T/bin" "$T/keys" "$T/sock" "$T/data"
  chmod 0755 "$T"
  chmod 0777 "$T/data" "$T/sock"
  (cd "$ROOT" && CGO_ENABLED=0 go build -buildvcs=false -o "$T/bin/sp-dashstub" ./cmd/sp-dashstub) || return 1
  LIMITS=$("$T/bin/sp-dashstub" limits)

  openssl genpkey -algorithm ed25519 -out "$T/assert.pem" 2>/dev/null || return 1
  openssl pkey -in "$T/assert.pem" -pubout -outform DER | tail -c 32 | b64url >"$T/keys/assert.pub"
  head -c 32 /dev/urandom | b64url >"$T/keys/cache.key"
  printf '\n' | tee -a "$T/keys/assert.pub" >>"$T/keys/cache.key"
  chmod 0644 "$T/keys/assert.pub" "$T/keys/cache.key"
  printf '%s' "$CRYPTO" >"$T/crypto.key"

  # The table of the control plane's stand-in. Every value of a project carries "spmark", so
  # that a proof can look for one where none belongs.
  local at
  at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  project() { # project REF NAME PORT MEMBERS [RO: yes|no]
    local ro=", \"dsn_ro\": \"$(dsn supabase_read_only_user "spmark-ro-$2" "$3")\""
    [ "${5:-yes}" = yes ] || ro=''
    printf '"%s": {"members": [%s], "resolve": {"ref": "%s", "name": "spmark-%s", "state": "active", "db_version": "17.6.1", "pg_meta": %s, "dsn_rw": "%s"%s, "api_url": "https://%s.spmark.example", "data_api": {"schemas": ["public"], "extra_search_path": ["public", "extensions"], "max_rows": null}, "generation": 1, "at": "%s"}, "keys": {"anon_key": "spmark-anon-%s", "signing_keys": []}}' \
      "$1" "$4" "$1" "$2" "$(($3 % 2))" "$(dsn postgres "spmark-rw-$2" "$3")" "$ro" "$1" "$at" "$2"
  }
  m() { printf '{"iss": "%s", "sub": "%s", "role": "%s"}' "$ISS" "$1" "$2"; }
  {
    echo '{'
    project $A alpha $PA "$(m oa owner), $(m da developer), $(m ra read_only), $(m both owner)"
    echo ,
    project $B bravo $PB "$(m ob owner), $(m rb read_only), $(m both owner)"
    echo ,
    project $C charlie $PC "$(m oc owner), $(m rc read_only)" no
    echo '}'
  } >"$T/table.json"

  docker network create --internal "${L[@]}" "$PREFIX-net" >/dev/null || return 1
  docker run -d --name "$PREFIX-pgmeta" "${L[@]}" --network "$PREFIX-net" --network-alias pgmeta \
    --user "$(id -u):$(id -g)" -v "$T/bin/sp-dashstub:/sp-dashstub:ro" -v "$T/crypto.key:/crypto.key:ro" \
    "$NODE_BASE" /sp-dashstub pgmeta --listen :8080 --crypto-key-file /crypto.key --delay-ms 40 >/dev/null || return 1
  STUDIO_ENV=(-e NODE_ENV=production -e PORT=3000 -e "SUPAPACE_NODE_ID=$NODE"
    -e SUPAPACE_DASH_SOCKET=/run/dash/dash.sock -e SUPAPACE_DASH_KEYS=/etc/dash -e SUPAPACE_DASH_DATA=/var/lib/dash
    -e SUPAPACE_PGCAP=10.212.0.6:20000:21023 -e SUPAPACE_PGMETA=http://10.212.0.4:8080,http://10.212.0.5:8080
    -e "SUPAPACE_LIMITS=$LIMITS"
    -e STUDIO_PG_META_URL=http://pgmeta:8080 -e "PG_META_CRYPTO_KEY=$CRYPTO")
  socket && studio
}

# ask METHOD PATH [TOKEN [curl args]] — one request, the path sent as written; prints
# "<status> <what>": the login and port postgres-meta's stand-in answered, else the code of a
# JSON refusal, else the first 60 characters of the body.
ask() {
  local method=$1 path=$2 t=${3:-} out status body what
  shift $(($# < 3 ? $# : 3))
  out=$(curl -s --path-as-is -m 30 -w '\n%{http_code}' -X "$method" "$U$path" ${t:+-H "X-Supapace-Assertion: $t"} "$@")
  status=${out##*$'\n'} body=${out%$'\n'*}
  what=$(printf '%s' "$body" | sed -n 's/.*"login":"\([a-z_]*\)","port":\([0-9]*\).*/\1:\2/p' | sed -n 1p)
  [ -n "$what" ] || what=$(printf '%s' "$body" | sed -n 's/^{"code":"\([a-z_]*\)","message":"[^"]*"}$/\1/p')
  [ -n "$what" ] || what=$(printf '%s' "$body" | tr -d '\n' | cut -c1-60)
  printf '%s %s' "$status" "$what"
}

# raw METHOD TARGET [TOKEN] — the same over a connection of the proof's own, the request target
# as raw bytes (a "#", a dot segment, a space: what a client library would rewrite or refuse).
raw() {
  local host=${U#http://} out status what
  exec 7<>"/dev/tcp/${host%:*}/${host##*:}" || return 1
  printf '%s %s HTTP/1.1\r\nHost: studio\r\nConnection: close\r\n%s\r\n' "$1" "$2" \
    "${3:+X-Supapace-Assertion: $3$'\r\n'}" >&7
  out=$(timeout 30 cat <&7 | tr -d '\r')
  exec 7>&- 7<&-
  status=$(printf '%s' "$out" | sed -n '1s/^HTTP\/1\.1 \([0-9]*\).*/\1/p')
  what=$(printf '%s' "$out" | sed -n 's/^{"code":"\([a-z_]*\)","message":"[^"]*"}$/\1/p' | sed -n 1p)
  printf '%s %s' "$status" "${what:-$(printf '%s' "$out" | tail -1 | cut -c1-60)}"
}
