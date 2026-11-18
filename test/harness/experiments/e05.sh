# E5: PostgREST at the pinned version against a cluster of the pinned Postgres
# image. Checks: a multi-key JWKS file selected by kid, its re-read on SIGUSR2,
# the claims settings PostgREST emits, db-config = false ignoring pgrst.*
# role settings (control: db-config = true), running read-only at uid 65532
# with no capabilities, no admin port, server-host "*4" on two networks, and
# what it logs. Recorded as facts: the thread budget under --pids-limit 64,
# what PostgREST does with a key file that is not a valid RSA JWKS, which
# reload trigger re-reads what, and which tokens PostgREST alone accepts.
#
# Run inside the bare node:
#   cat lib-rest.sh e05.sh | docker exec -i <node> sh -s
set -eu
if [ -z "${LIB_REST:-}" ]; then
	# shellcheck source=/dev/null
	. "$(dirname "$0")/lib-rest.sh"
fi

D=$EXP_ROOT/e05
UID_PG=700501
NET_P=e05-proj NET_L=e05-plat
CL=e05-pg M=e05-rest C=e05-rest-dbconfig B=e05-rest-badpw KC=e05-rest-keys
IP_CL=10.213.0.2 IP_M=10.213.0.3 IP_C=10.213.0.4 IP_B=10.213.0.5 IP_K=10.213.0.6 IP_ML=10.212.0.16

cleanup() {
	rm_containers "$M" "$C" "$B" "$KC" e05-rest-pids "$CL"
	docker network rm "$NET_P" "$NET_L" >/dev/null 2>&1 || :
	rm -rf "$D"
	rmdir "$EXP_ROOT" 2>/dev/null || :
}
trap 'trap "" INT TERM HUP; [ -n "${KEEP:-}" ] || cleanup' EXIT # a signal during cleanup must not cut it short
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
cleanup

PG_IMAGE=$(pinned_image supabase/postgres)
RS_IMAGE=$(pinned_image postgrest/postgrest)
say "postgres image:  $PG_IMAGE"
say "postgrest image: $RS_IMAGE"
say "postgrest: $(docker run --rm "$RS_IMAGE" /bin/postgrest --version)"

fail=0
check() { # check LABEL WANT GOT
	if [ "$2" = "$3" ]; then say "ok    $1: $3"; else
		say "FAIL  $1: want $2, got $3"
		fail=1
	fi
}
status() { http "$1" "${2:-}" | cut -d' ' -f1; }
field() { # field URL TOKEN NAME: one string member of the JSON reply
	http "$1" "$2" | sed -n "s/.*\"$3\" *: *\"\([^\"]*\)\".*/\1/p"
}

step "cluster"
docker network create --subnet 10.213.0.0/26 "$NET_P" >/dev/null
docker network create --subnet 10.212.0.0/21 "$NET_L" >/dev/null
start_cluster "$CL" "$UID_PG" "$D/cluster" --network "$NET_P" --ip "$IP_CL"
PW=$(rand_hex 24)
sql "$CL" <<EOF
do \$\$ begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then create role anon nologin noinherit; end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then create role service_role nologin noinherit bypassrls; end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticator') then create role authenticator login noinherit; end if;
end \$\$;
grant anon, service_role to authenticator;
alter role authenticator password '$PW';
create schema if not exists alt;
create or replace function public.whoami() returns json language sql stable as \$\$
  select json_build_object('schema', 'public', 'user', current_user::text,
    'claims', current_setting('request.jwt.claims', true),
    'claim_role', coalesce(current_setting('request.jwt.claim.role', true), '(unset)')) \$\$;
create or replace function alt.whoami() returns json language sql stable as \$\$
  select json_build_object('schema', 'alt', 'user', current_user::text) \$\$;
create or replace function public.slow() returns int language sql as \$\$ select 1 from pg_sleep(0.3) \$\$;
grant usage on schema alt to anon, service_role;
grant execute on function public.whoami(), alt.whoami(), public.slow() to anon, service_role;
EOF
say "roles: $(printf "select string_agg(rolname, ',' order by rolname) from pg_roles where rolname in ('anon','service_role','authenticator');" | sql "$CL")"

step "keys and JWKS (generated now, removed at exit)"
K=$D/keys
mkdir -p "$K"
chmod 0700 "$K"
for k in k1 k2 k3 kw; do rsa_key "$K/$k.pem"; done
jwks() { # jwks KID...: the set of the named keys
	_s='{"keys":['
	_sep=
	for _k in "$@"; do
		_s="$_s$_sep$(jwk "$K/$_k.pem" "$_k")"
		_sep=,
	done
	printf '%s]}' "$_s"
}
# conf_file DIR DBCONFIG PASSWORD [EXTRA]: (re)writes DIR/postgrest.conf atomically.
conf_file() {
	mkdir -p "$1"
	cat >"$1/postgrest.conf.new" <<EOF
db-uri = "postgres://authenticator:$3@$IP_CL:5432/postgres"
db-schemas = "public, graphql_public"
db-anon-role = "anon"
db-pool = 10
db-extra-search-path = "public, extensions"
jwt-secret = "@/etc/postgrest/jwks.json"
db-config = $2
server-host = "*4"
server-port = 3000
log-level = "debug"
${4:-}
EOF
	chown 65532:65532 "$1/postgrest.conf.new"
	chmod 0400 "$1/postgrest.conf.new"
	mv "$1/postgrest.conf.new" "$1/postgrest.conf"
}
conf() { # conf DIR DBCONFIG PASSWORD: configuration file plus jwks.json with k1 k2
	conf_file "$@"
	jwks k1 k2 >"$1/jwks.json"
	chmod 0444 "$1/jwks.json"
	chmod 0755 "$1"
}
conf "$D/rest-m" false "$PW"
conf "$D/rest-c" true "$PW"
say "jwks.json holds kids: k1 k2"

wait_rest() { # wait_rest URL
	_i=0
	until [ "$(status "$1")" = 200 ]; do
		_i=$((_i + 1))
		[ "$_i" -le 60 ] || die "PostgREST at $1 not ready"
		sleep 1
	done
}
# create_rest NAME CONFDIR IP [RTS]: the hardened PostgREST container. RTS sets
# GHCRTS (the Haskell runtime's options); "-N2" caps its capabilities at two.
create_rest() {
	docker create --name "$1" --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
		--read-only --memory 256m --pids-limit 64 --ulimit core=0 ${4:+-e GHCRTS=$4} \
		--network "$NET_P" --ip "$3" -v "$2:/etc/postgrest:ro" \
		"$RS_IMAGE" /bin/postgrest /etc/postgrest/postgrest.conf >/dev/null
}
threads() { awk '/^Threads:/ { print $2 }' "/proc/$(docker inspect -f '{{.State.Pid}}' "$1")/status" 2>/dev/null || echo -; }
# cgroup_dir NAME: the running container's cgroup directory in this namespace.
cgroup_dir() { echo "/sys/fs/cgroup$(cut -d: -f3 "/proc/$(docker inspect -f '{{.State.Pid}}' "$1")/cgroup")"; }
# load NAME HOST: three rounds of 30 trivial and 30 slow (0.3 s, more than the
# pool of 10) parallel requests, each round followed by SIGUSR2 and SIGUSR1.
load() {
	for _r in 1 2 3; do
		_i=0 _w=
		while [ "$_i" -lt 30 ]; do
			wget -q -T 10 -O /dev/null "http://$2:3000/rpc/whoami" 2>/dev/null &
			_w="$_w $!"
			wget -q -T 10 -O /dev/null "http://$2:3000/rpc/slow" 2>/dev/null &
			_w="$_w $!"
			_i=$((_i + 1))
		done
		# shellcheck disable=SC2086 # a list of pids; a bare wait would also wait for the sampler
		wait $_w || :
		docker kill -s USR2 "$1" >/dev/null 2>&1 || :
		docker kill -s USR1 "$1" >/dev/null 2>&1 || :
		sleep 1
	done
}
# sample NAME FILE: until FILE.stop exists, records the highest thread count in FILE.
sample() {
	_max=0
	while [ ! -e "$2.stop" ]; do
		_t=$(threads "$1")
		case $_t in '' | *[!0-9]*) ;; *) [ "$_t" -le "$_max" ] || _max=$_t ;; esac
		echo "$_max" >"$2"
		sleep 0.02
	done
}

step "thread budget under --pids-limit 64 ($(nproc) CPUs visible)"
conf "$D/rest-p" false "$PW"
for rts in "" -N2; do
	create_rest e05-rest-pids "$D/rest-p" 10.213.0.9 "$rts"
	docker start e05-rest-pids >/dev/null
	wait_rest http://10.213.0.9:3000/
	sleep 1
	idle=$(threads e05-rest-pids)
	cg=$(cgroup_dir e05-rest-pids)
	rm -f "$D/peak" "$D/peak.stop"
	sample e05-rest-pids "$D/peak" &
	sp=$!
	load e05-rest-pids 10.213.0.9
	touch "$D/peak.stop"
	wait "$sp"
	st=$(docker inspect -f '{{.State.Status}}' e05-rest-pids)
	pk=$(cat "$cg/pids.peak" 2>/dev/null || echo "- (cgroup gone)")
	say "info  GHCRTS=${rts:-(unset)}: idle $idle threads; under load (90 trivial + 90 slow, 3 x SIGUSR2+SIGUSR1) sampled peak $(cat "$D/peak") threads, cgroup pids.peak $pk; state $st$(docker logs e05-rest-pids 2>&1 | grep -m1 'OS thread' | sed 's/^/, log: /')"
	if [ -z "$rts" ]; then
		dflt=$st
		say "info  control (runtime default, one capability per CPU): $idle threads at idle on $(nproc) CPUs"
	else
		check "GHCRTS=-N2: survives the load" running "$st"
		check "GHCRTS=-N2: idle threads <= 12" yes "$([ "$idle" -le 12 ] && echo yes || echo "no ($idle)")"
		check "GHCRTS=-N2: peak tasks <= 40 of 64" yes "$([ "$pk" -le 40 ] && [ "$(cat "$D/peak")" -le 40 ] && echo yes || echo "no ($pk)")"
	fi
	rm_containers e05-rest-pids
done
say "every PostgREST below runs with GHCRTS=-N2"
create_rest "$M" "$D/rest-m" "$IP_M" -N2
docker network connect --ip "$IP_ML" "$NET_L" "$M"
docker start "$M" >/dev/null
create_rest "$C" "$D/rest-c" "$IP_C" -N2
docker start "$C" >/dev/null
U=http://$IP_M:3000
UC=http://$IP_C:3000
wait_rest "$U/"
wait_rest "$UC/"

step "multi-key JWKS selected by kid"
T1=$(jwt "$K/k1.pem" k1 "$(claims anon)")
T2=$(jwt "$K/k2.pem" k2 "$(claims anon)")
TS=$(jwt "$K/k2.pem" k2 "$(claims service_role)")
TU=$(jwt "$K/k3.pem" k3 "$(claims anon)")
TW=$(jwt "$K/kw.pem" k1 "$(claims anon)")
TN1=$(jwt "$K/k1.pem" "" "$(claims anon)")
TN3=$(jwt "$K/k3.pem" "" "$(claims anon)")
check "no token (control: anon role)" 200 "$(status "$U/rpc/whoami")"
check "kid k1, signed by k1" 200 "$(status "$U/rpc/whoami" "$T1")"
check "kid k2, signed by k2" 200 "$(status "$U/rpc/whoami" "$T2")"
check "kid k2, role service_role -> current_user" service_role "$(field "$U/rpc/whoami" "$TS" user)"
check "kid k3 (not in the set)" 401 "$(status "$U/rpc/whoami" "$TU")"
check "kid k1, signed by another key" 401 "$(status "$U/rpc/whoami" "$TW")"
say "info  no kid, signed by k1 (in the set): $(status "$U/rpc/whoami" "$TN1")"
say "info  no kid, signed by k3 (not in the set): $(status "$U/rpc/whoami" "$TN3")"

step "claims settings emitted"
say "reply: $(http "$U/rpc/whoami" "$TS" | cut -d' ' -f2-)"
check "legacy request.jwt.claim.role" "(unset)" "$(field "$U/rpc/whoami" "$TS" claim_role)"
case $(http "$U/rpc/whoami" "$TS") in
*'\"role\" : \"service_role\"'* | *'\"role\":\"service_role\"'*) say "ok    request.jwt.claims carries the role" ;;
*) say "FAIL  request.jwt.claims does not carry the role" && fail=1 ;;
esac

step "rotation: file rewritten to k2 k3, then SIGUSR2"
jwks k2 k3 >"$D/rest-m/jwks.new"
chmod 0444 "$D/rest-m/jwks.new"
mv "$D/rest-m/jwks.new" "$D/rest-m/jwks.json"
sleep 2
check "before the signal, k3 (new) still refused" 401 "$(status "$U/rpc/whoami" "$TU")"
check "before the signal, k1 (removed) still accepted" 200 "$(status "$U/rpc/whoami" "$T1")"
t0=$(now_cs)
docker kill -s USR2 "$M" >/dev/null
n=0
until [ "$(status "$U/rpc/whoami" "$TU")" = 200 ]; do
	n=$((n + 1))
	[ "$n" -le 300 ] || break
	sleep 0.05
done
t1=$(now_cs)
check "after SIGUSR2, k3 accepted" 200 "$(status "$U/rpc/whoami" "$TU")"
say "info  reload took $(((t1 - t0) * 10)) ms (10 ms resolution, polling every 50 ms)"
T1B=$(jwt "$K/k1.pem" k1 "$(claims anon '"n":2')")
check "after SIGUSR2, k1 token used before (possibly cached)" 401 "$(status "$U/rpc/whoami" "$T1")"
check "after SIGUSR2, fresh k1 token" 401 "$(status "$U/rpc/whoami" "$T1B")"
check "after SIGUSR2, k2 (kept) accepted" 200 "$(status "$U/rpc/whoami" "$T2")"
say "info  effective JWT cache setting: $(docker exec "$M" /bin/postgrest --dump-config /etc/postgrest/postgrest.conf 2>/dev/null | grep '^jwt-cache' | tr '\n' ' ')"

step "configuration keys of this version (--dump-config, db-uri and jwt-secret omitted)"
docker exec "$M" /bin/postgrest --dump-config /etc/postgrest/postgrest.conf 2>/dev/null |
	grep -v '^db-uri\|^jwt-secret ' | sed 's/^/  /'

step "db-config: pgrst.* settings on the authenticator role"
TO=$(jwt "$K/k2.pem" k2 "$(claims anon '"other":"service_role"')")
check "db-config=false, baseline user" anon "$(field "$U/rpc/whoami" "$TO" user)"
check "db-config=true (control), baseline user" anon "$(field "$UC/rpc/whoami" "$TO" user)"
check "db-config=true (control), baseline schema" public "$(field "$UC/rpc/whoami" "$TO" schema)"
printf "alter role authenticator set pgrst.jwt_role_claim_key = '.other';\nalter role authenticator set pgrst.db_schemas = 'alt';\nnotify pgrst, 'reload config';\n" | sql "$CL"
docker kill -s USR2 "$M" >/dev/null
docker kill -s USR2 "$C" >/dev/null
sleep 1
# The schema cache is rebuilt separately; without it db_schemas = alt has no functions yet.
printf "notify pgrst, 'reload schema';\n" | sql "$CL"
n=0
until [ "$(field "$UC/rpc/whoami" "$TO" user)" = service_role ]; do
	n=$((n + 1))
	[ "$n" -le 100 ] || break
	sleep 0.2
done
check "db-config=true (control): role claim key now .other" service_role "$(field "$UC/rpc/whoami" "$TO" user)"
check "db-config=true (control): schema now alt" alt "$(field "$UC/rpc/whoami" "$TO" schema)"
check "db-config=false: role claim key unchanged" anon "$(field "$U/rpc/whoami" "$TO" user)"
check "db-config=false: schema unchanged" public "$(field "$U/rpc/whoami" "$TO" schema)"
say "info  replies: db-config=true $(http "$UC/rpc/whoami" "$TO"); db-config=false $(http "$U/rpc/whoami" "$TO" | cut -c1-60)"
printf "alter role authenticator set pgrst.jwt_secret = '%s';\nnotify pgrst, 'reload config';\n" "$(rand_hex 24)" | sql "$CL"
docker kill -s USR2 "$M" >/dev/null
docker kill -s USR2 "$C" >/dev/null
n=0
until [ "$(status "$UC/rpc/whoami" "$T2")" = 401 ]; do
	n=$((n + 1))
	[ "$n" -le 100 ] || break
	sleep 0.2
done
check "db-config=true (control): pgrst.jwt_secret replaces the JWKS (RS256 refused)" 401 "$(status "$UC/rpc/whoami" "$T2")"
check "db-config=false: JWKS still in force (RS256 accepted)" 200 "$(status "$U/rpc/whoami" "$T2")"
docker restart "$M" >/dev/null
wait_rest "$U/"
check "db-config=false after a restart: role claim key" anon "$(field "$U/rpc/whoami" "$TO" user)"
check "db-config=false after a restart: schema" public "$(field "$U/rpc/whoami" "$TO" schema)"
check "db-config=false after a restart: JWKS (RS256 accepted)" 200 "$(status "$U/rpc/whoami" "$T2")"
say "settings stored: $(printf "select array_to_string(setconfig, ' ') from pg_db_role_setting s join pg_roles r on r.oid = s.setrole where r.rolname = 'authenticator';" | sql "$CL" | sed 's/jwt_secret=[^ ]*/jwt_secret=<redacted>/')"
say "info  --dump-config, db-config=true:  $(docker exec "$C" /bin/postgrest --dump-config /etc/postgrest/postgrest.conf 2>/dev/null | grep '^db-schemas\|^jwt-role-claim-key' | tr '\n' ' ')"
say "info  --dump-config, db-config=false: $(docker exec "$M" /bin/postgrest --dump-config /etc/postgrest/postgrest.conf 2>/dev/null | grep '^db-schemas\|^jwt-role-claim-key' | tr '\n' ' ')"
printf "alter role authenticator reset all;\n" | sql "$CL"
rm_containers "$C"

step "key files PostgREST accepts (container $KC, db-config = false)"
conf "$D/rest-k" false "$PW"
KF=$D/rest-k/jwks.json
HS='{"alg":"HS256","typ":"JWT"}'
key_reload() { # key_reload: replace jwks.json with standard input, SIGUSR2, settle
	cat >"$KF.new"
	chmod 0444 "$KF.new"
	mv "$KF.new" "$KF"
	docker kill -s USR2 "$KC" >/dev/null
	sleep 1
}
UK=http://$IP_K:3000
jwks k1 k2 | head -c 60 >"$KF"
create_rest "$KC" "$D/rest-k" "$IP_K" -N2
docker start "$KC" >/dev/null
wait_rest "$UK/"
check "truncated JSON key file: starts and serves (no token)" 200 "$(status "$UK/rpc/whoami")"
TK1=$(jwt "$K/k1.pem" k1 "$(claims service_role)")
check "truncated JSON key file: RS256 token of k1" 401 "$(status "$UK/rpc/whoami" "$TK1")"
check "truncated JSON key file: HS256 signed with the file's text, role service_role" "200 service_role" \
	"$(status "$UK/rpc/whoami" "$(jwt_hs "$KF" "$HS" "$(claims service_role)")") $(field "$UK/rpc/whoami" "$(jwt_hs "$KF" "$HS" "$(claims service_role '"n":1')")" user)"
printf 'this is not a key file, only a line of plain text' | key_reload
check "plain-text key file after SIGUSR2: still running" running "$(docker inspect -f '{{.State.Status}}' "$KC")"
check "plain-text key file: HS256 signed with the file's text" 200 "$(status "$UK/rpc/whoami" "$(jwt_hs "$KF" "$HS" "$(claims service_role)")")"
cp "$KF" "$D/plain.txt"
printf 'short plain text' | key_reload
say "info  16-byte plain-text key file: HS256 signed with it -> $(status "$UK/rpc/whoami" "$(jwt_hs "$KF" "$HS" "$(claims service_role)")"), running=$(docker inspect -f '{{.State.Running}}' "$KC")$(docker logs --tail 20 "$KC" 2>&1 | grep -m1 -i 'reload\|secret\|fail' | cut -c1-160 | sed 's/^/, last reload log: /')"
jwks k1 k2 | key_reload
check "control, valid RSA-only JWKS: HS256 signed with the earlier plain text" 401 "$(status "$UK/rpc/whoami" "$(jwt_hs "$D/plain.txt" "$HS" "$(claims service_role '"n":2')")")"
check "control, valid RSA-only JWKS: HS256 signed with the JWKS text itself" 401 "$(status "$UK/rpc/whoami" "$(jwt_hs "$KF" "$HS" "$(claims service_role)")")"
check "control, valid RSA-only JWKS: RS256 token of k1" 200 "$(status "$UK/rpc/whoami" "$TK1")"
rand_hex 32 >"$D/oct.bin"
OCT=$(b64url <"$D/oct.bin")
HSK='{"alg":"HS256","typ":"JWT","kid":"h1"}'
check "control, RSA-only JWKS: HS256 with the oct secret (kid h1)" 401 "$(status "$UK/rpc/whoami" "$(jwt_hs "$D/oct.bin" "$HSK" "$(claims service_role)")")"
printf '{"keys":[%s,{"kty":"oct","kid":"h1","k":"%s"}]}' "$(jwk "$K/k1.pem" k1)" "$OCT" | key_reload
check "JWKS with an oct key: HS256 with that secret (kid h1) accepted" 200 "$(status "$UK/rpc/whoami" "$(jwt_hs "$D/oct.bin" "$HSK" "$(claims service_role '"n":3')")")"
D1=$(openssl rsa -in "$K/k1.pem" -noout -text 2>/dev/null | awk '/^privateExponent:/ { f = 1; next } /^prime1:/ { f = 0 } f' | tr -d ' :\n' | sed 's/^00//' | xxd -r -p | b64url)
jwk "$K/k1.pem" k1 | sed "s/}\$/,\"d\":\"$D1\"}/" | sed 's/^/{"keys":[/; s/$/]}/' | key_reload
say "info  key file now carries the private exponent: $(grep -c '"d":' "$KF") entry"
check "JWKS whose RSA entry carries the private member d: accepted, k1 tokens verify" 200 "$(status "$UK/rpc/whoami" "$(jwt "$K/k1.pem" k1 "$(claims anon '"n":4')")")"
rm -f "$D/plain.txt" "$D/oct.bin"
rm_containers "$KC"

step "reload triggers (main PostgREST; the image's DDL-watch event triggers disabled)"
cat <<'EOF' | sql "$CL"
do $$ declare t text; begin
  for t in select evtname from pg_event_trigger where evtname in ('pgrst_ddl_watch', 'pgrst_drop_watch') loop
    execute format('alter event trigger %I disable', t);
  end loop;
end $$;
EOF
tenant_sql() { docker exec -i "$CL" psql -X -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -Atq; }
say "ordinary session: role postgres, superuser=$(echo "select rolsuper from pg_roles where rolname = current_user;" | tenant_sql)"
wait_for() { # wait_for WANT URL TOKEN FIELD
	_n=0
	until [ "$(field "$2" "$3" "$4")" = "$1" ]; do
		_n=$((_n + 1))
		[ "$_n" -le 50 ] || break
		sleep 0.2
	done
}
wait_status() { # wait_status WANT URL
	_n=0
	until [ "$(status "$2")" = "$1" ]; do
		_n=$((_n + 1))
		[ "$_n" -le 50 ] || break
		sleep 0.2
	done
}
conf_file "$D/rest-m" false "$PW" 'jwt-role-claim-key = ".other"'
sleep 1
check "file gains jwt-role-claim-key; before any signal" anon "$(field "$U/rpc/whoami" "$TO" user)"
docker kill -s USR2 "$M" >/dev/null
wait_for service_role "$U/rpc/whoami" "$TO" user
check "SIGUSR2 re-reads the whole configuration file (role from .other)" service_role "$(field "$U/rpc/whoami" "$TO" user)"
conf_file "$D/rest-m" false "$PW"
sleep 1
check "line removed from the file; before any trigger" service_role "$(field "$U/rpc/whoami" "$TO" user)"
echo "notify pgrst, 'reload config';" | tenant_sql
wait_for anon "$U/rpc/whoami" "$TO" user
check "NOTIFY pgrst 'reload config' from the ordinary session re-reads the file" anon "$(field "$U/rpc/whoami" "$TO" user)"
echo "create function public.fresh1() returns int language sql as 'select 1';" | sql "$CL"
sleep 1
check "new function, before any trigger (schema cache)" 404 "$(status "$U/rpc/fresh1")"
docker kill -s USR2 "$M" >/dev/null
sleep 2
check "after SIGUSR2: still not in the schema cache" 404 "$(status "$U/rpc/fresh1")"
echo "notify pgrst, 'reload config';" | tenant_sql
sleep 2
check "after NOTIFY 'reload config': still not in the schema cache" 404 "$(status "$U/rpc/fresh1")"
docker kill -s USR1 "$M" >/dev/null
wait_status 200 "$U/rpc/fresh1"
check "after SIGUSR1: schema cache rebuilt" 200 "$(status "$U/rpc/fresh1")"
echo "create function public.fresh2() returns int language sql as 'select 2';" | sql "$CL"
sleep 1
check "second new function, before the next trigger" 404 "$(status "$U/rpc/fresh2")"
echo "notify pgrst, 'reload schema';" | tenant_sql
wait_status 200 "$U/rpc/fresh2"
check "after NOTIFY 'reload schema' from the ordinary session: rebuilt" 200 "$(status "$U/rpc/fresh2")"

step "tokens sent to PostgREST alone (key set k2 k3; the gateway refuses every row but the first)"
now=$(date +%s)
SUB='"sub":"00000000-0000-4000-8000-000000000001"'
row() { # row LABEL TOKEN
	_r=$(http "$U/rpc/whoami" "$2")
	_u=$(printf '%s' "$_r" | sed -n 's/.*"user" *: *"\([^"]*\)".*/\1/p')
	printf '| %-44s | %s | %-14s |\n' "$1" "${_r%% *}" "${_u:--}"
}
say "| token                                        | status | current_user   |"
say "|----------------------------------------------|--------|----------------|"
row "control: kid k2, role anon, exp +1 h" "$(jwt "$K/k2.pem" k2 "$(claims anon '"t":0')")"
row "no kid (signed by k2)" "$(jwt "$K/k2.pem" "" "$(claims anon '"t":1')")"
row "crit naming an unknown extension" "$(jwt_raw "$K/k2.pem" '{"alg":"RS256","typ":"JWT","kid":"k2","crit":["x-unknown"],"x-unknown":1}' "$(claims anon '"t":2')")"
row "exp 10 s in the past" "$(jwt "$K/k2.pem" k2 "{\"role\":\"anon\",$SUB,\"exp\":$((now - 10))}")"
row "no exp" "$(jwt "$K/k2.pem" k2 "{\"role\":\"anon\",$SUB}")"
row "no role (exp +1 h)" "$(jwt "$K/k2.pem" k2 "{$SUB,\"exp\":$((now + 3600))}")"
row "role authenticator" "$(jwt "$K/k2.pem" k2 "$(claims authenticator)")"
row "duplicate role: anon, then service_role" "$(jwt "$K/k2.pem" k2 "{\"role\":\"anon\",\"role\":\"service_role\",$SUB,\"exp\":$((now + 3600))}")"
row "duplicate role: service_role, then anon" "$(jwt "$K/k2.pem" k2 "{\"role\":\"service_role\",\"role\":\"anon\",$SUB,\"exp\":$((now + 3600))}")"

step "hardening: read-only, uid 65532, no capabilities"
pid=$(docker inspect -f '{{.State.Pid}}' "$M")
check "read-only root filesystem" true "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$M")"
check "Uid line" "65532 65532 65532 65532" "$(awk '/^Uid:/ { print $2, $3, $4, $5 }' "/proc/$pid/status")"
check "CapEff" 0000000000000000 "$(awk '/^CapEff:/ { print $2 }' "/proc/$pid/status")"
check "CapBnd" 0000000000000000 "$(awk '/^CapBnd:/ { print $2 }' "/proc/$pid/status")"
check "NoNewPrivs" 1 "$(awk '/^NoNewPrivs:/ { print $2 }' "/proc/$pid/status")"
check "serving while hardened" 200 "$(status "$U/rpc/whoami" "$T2")"

step "listeners: no admin-server-port, server-host \"*4\" on two networks"
say "addresses: $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}' "$M")"
say "listening sockets in the container's namespace:"
nsenter -t "$pid" -n ss -Hltnu | sed 's/^/  /'
# 127.0.0.11 is Docker's embedded DNS resolver, present in every user-defined network.
check "TCP listeners other than Docker's resolver" "0.0.0.0:3000" "$(nsenter -t "$pid" -n ss -Hltn | awk '$4 !~ /^127\.0\.0\.11:/ { print $4 }' | sort | tr '\n' ' ' | sed 's/ $//')"
check "port 3000 on the project network" 200 "$(status "http://$IP_M:3000/rpc/whoami" "$T2")"
check "port 3000 on the platform network" 200 "$(status "http://$IP_ML:3000/rpc/whoami" "$T2")"
check "port 3001 (control: a closed port reads as nothing)" 000 "$(status "http://$IP_M:3001/ready")"
say "info  GET /ready on port 3000: $(status "$U/ready")"
say "info  GET / on port 3000 (OpenAPI root): $(status "$U/")"

step "logs (log-level debug): tokens and the database password"
docker logs "$M" >"$D/rest-m.log" 2>&1
say "log lines: $(wc -l <"$D/rest-m.log")"
for v in "$T1" "$T2" "$TS" "$TU" "$TW" "$TO" "$PW"; do
	grep -qF "$v" "$D/rest-m.log" && { say "FAIL  a token or the password appears in the log"; fail=1; }
done
grep -qi 'bearer\|authorization' "$D/rest-m.log" && say "info  the log mentions Authorization/Bearer" || :
say "sample:"
grep -v '^$' "$D/rest-m.log" | sed -n '1,6p;$p' | cut -c1-200 | sed 's/^/  /'
BADPW=$(rand_hex 24)
conf "$D/rest-b" false "$BADPW"
create_rest "$B" "$D/rest-b" "$IP_B" -N2
docker start "$B" >/dev/null
sleep 6
docker logs "$B" >"$D/rest-b.log" 2>&1
say "wrong-password PostgREST, first log lines:"
grep -v '^$' "$D/rest-b.log" | sed -n '1,4p' | cut -c1-200 | sed 's/^/  /'
if grep -qF "$BADPW" "$D/rest-b.log"; then
	say "FAIL  the database password appears in the log of a failed connection"
	fail=1
else say "ok    the database password is absent from the log of a failed connection"; fi
if grep -q 'password authentication failed' "$D/rest-b.log"; then
	say "ok    control: that log does record the failed login"
else say "info  no login failure line in the log"; fi

step "result"
if [ "$dflt" = running ]; then pids="the default runtime also survived --pids-limit 64 on this host"; else
	pids="--pids-limit 64 needs GHCRTS=-N2 here (the default runtime died: one thread per CPU)"; fi
if [ "$fail" = 0 ]; then
	say "VERDICT E5: confirmed — kid-selected JWKS, SIGUSR2 re-read, request.jwt.claims only, db-config = false ignores pgrst.* role settings, read-only at uid 65532 with no capabilities, no admin port, all IPv4 addresses (key file must be validated before it is put in place); $pids."
else
	say "VERDICT E5: fallback — at least one check above failed (FAIL lines); $pids."
fi
