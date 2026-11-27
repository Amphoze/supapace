#!/usr/bin/env bash
# secrets.sh IMAGE — no secret in an answer of the built image, and a project's keys from the
# control plane alone. Against the stand-ins of stand-ins.bash, whose table here also holds a
# marked service_role key and three signing keys for each project, and on a server whose
# process holds a marked value under every name upstream read a key or a secret from:
#   - every served API route and every page, requested as each role — and as an owner under an
#     assertion signed for the purpose `reveal` — answers no secret: no service_role key, no
#     database password or connection string, no member `jwt_secret`, no value of the
#     process, and not the default JWT secret upstream answered when the process had none;
#   - the service_role key is in the owner's answer to the two reveal requests, and in no
#     other: not without the purpose, not for another role whatever its assertion says, not
#     when the request does not ask, not when a header, a query or a cookie claims the purpose,
#     and each project's owner gets that project's key; those two answers are `no-store`, and
#     the control plane is asked every time;
#   - with the control plane silent, refusing or answering what cannot be used, a reveal is
#     refused and its body holds no key, while the settings are still answered;
#   - the signing-keys route lists the control plane's public keys and no other, for each role;
#   - a statement reaches postgres-meta with the content type and the encrypted connection
#     string beside the HTTP client's own headers, and nothing the caller sent;
#   - no file of the image's bundles holds upstream's default JWT secret, and the server's log
#     holds no key, no assertion and no connection string.
# The names the server reads from its environment are held by the build's gate 60-env, whose
# table lists none of the five planted here: a read of one fails the build.
# Prints one row per case; exits 1 when a row fails.
. "$(dirname "${BASH_SOURCE[0]}")/stand-ins.bash"
standins_up "${1:?usage: secrets.sh IMAGE}" || { echo "secrets.sh: the image or a stand-in did not start" >&2; exit 1; }

# The default the series removes, read from the patch that removes it: it is written nowhere else.
DEFAULT=$(sed -n "s/^-export const DEFAULT_AUTH_JWT_SECRET = '\(.*\)'$/\1/p" "$HERE"/../patches/*-secrets-*.patch | sed -n 1p)
[ ${#DEFAULT} -ge 32 ] || { echo "secrets.sh: the series does not name the default JWT secret it removes" >&2; exit 1; }

# The table with keys worth hiding, and one whose answer for A cannot be used.
jwk() { printf '{"kid": "kid-%s-\\1", "class": "%s", "alg": "RS256", "kty": "RSA", "n": "c3BtYXJrLW1vZHVsdXM", "e": "AQAB"}' "$1" "$1"; }
sed -i "s/\"anon_key\": \"spmark-anon-\([a-z]*\)\", \"signing_keys\": \[\]/\"anon_key\": \"spmark-anon-\1\", \"signing_keys\": [$(jwk anon), $(jwk service), $(jwk issuer)], \"service_role_key\": \"spmark-service-\1\"/" "$T/table.json"
[ "$(grep -o 'spmark-service-' "$T/table.json" | wc -l)" = 3 ] || { echo "secrets.sh: the stand-in's table has another form" >&2; exit 1; }
cp "$T/table.json" "$T/table.good"
sed 's/"anon_key": "spmark-anon-alpha"/"anon_key": "spmark anon alpha"/' "$T/table.good" >"$T/table.bad"

PROCESS=(-e AUTH_JWT_SECRET=spmarkJwtSecret -e SUPABASE_ANON_KEY=spmarkAnonKey -e SUPABASE_SERVICE_KEY=spmarkServiceKey
  -e SUPABASE_PUBLISHABLE_KEY=spmarkPublishableKey -e SUPABASE_SECRET_KEY=spmarkSecretKey)
socket && studio "${PROCESS[@]}" || { echo "secrets.sh: the server did not restart" >&2; exit 1; }

# What no answer may hold. The anon key and the public signing keys are every member's.
printf '%s\n' spmark-service- spmark-rw- spmark-ro- postgresql:// jwt_secret \
  spmarkJwtSecret spmarkAnonKey spmarkServiceKey spmarkPublishableKey spmarkSecretKey "$DEFAULT" "$CRYPTO" "$(head -1 "$T/keys/cache.key")" >"$T/secrets"

LIST=/api/v1/projects/$A/api-keys
ONE=$LIST/service_role
SIGNING=/api/v1/projects/$A/config/auth/signing-keys
SETTINGS=/api/platform/projects/$A/settings
# fetch PATH TOKEN [curl args] — the answer's head in $T/h, its body in $T/b; prints the status
fetch() {
  local p=$1 t=$2
  shift 2
  curl -s --path-as-is -m 30 -o "$T/b" -D "$T/h" -w '%{http_code}' "$U$p" -H "X-Supapace-Assertion: $t" "$@"
}
hits() { cat "$T/h" "$T/b" | grep -c -F -f "$T/secrets"; }                    # lines of the answer that hold a secret
ids() { grep -o '"id":"[^"]*"' "$T/b" | cut -d'"' -f4 | tr '\n' ' ' | sed 's/ $//'; } # the ids of the keys listed
key() { grep -o 'spmark-service-[a-z]*' "$T/b" | sort -u | tr '\n' ' ' | sed 's/ $//'; }
got() { printf '%s [%s] [%s]' "$1" "$(ids)" "$(key)"; }                       # got STATUS — status, ids, service key
code() { sed -n 's/^{"code":"\([a-z_]*\)","message":"[^"]*"}$/\1/p' "$T/b"; }
stored() { tr -d '\r' <"$T/h" | awk 'tolower($1) == "cache-control:" { print $2 }'; }
asked() { grep -c "\"path\":\"/v1/keys\".*$1" "$T/sock/dash.sock.log"; }      # asked PATTERN — the control plane's own count

echo '| # | case | answer | |'
echo '|---|---|---|---|'

# --- 1. every served route, each of its methods, as each role
awk -F'\t' '($1 == "api" || $1 == "page") && $4 == "served" { n = $1 == "api" ? split($3, m, ",") : 1; for (i = 1; i <= n; i++) print $1 "\t" $2 "\t" ($1 == "api" ? m[i] : "GET") }' "$HERE/../routes.tsv" >"$T/served"
routes=$(wc -l <"$T/served")
fill() { printf '%s' "$1" | sed "s/\\\$ref/$A/g; s/\\\$[A-Za-z]*/x1/g"; }
sweep() { # sweep SUB ROLE [PURPOSE] — one line per request in $T/sweep: KIND<TAB>STATUS<TAB>HITS<TAB>METHOD PATH
  local kind id methods p m n=0
  : >"$T/sweep"
  while IFS=$'\t' read -r kind id methods; do
    p=$(fill "$id") m=$methods
    (
      f=$T/sweep.$BASHPID body=()
      [ "$m" = GET ] || [ "$m" = DELETE ] || body=(-H 'Content-Type: application/json' -d '{"query":"select 1"}')
      s=$(curl -s --path-as-is -m 60 -o "$f" -D "$f.h" -w '%{http_code}' -X "$m" "$U$p" \
        -H "X-Supapace-Assertion: $(tok $A "$1" "$2" "${3:-}")" -H 'Accept: text/html' "${body[@]}")
      printf '%s\t%s\t%s\t%s %s\n' "$kind" "$s" "$(cat "$f.h" "$f" 2>/dev/null | grep -c -F -f "$T/secrets")" "$m" "$p" >>"$T/sweep"
      rm -f "$f" "$f.h"
    ) &
    n=$((n + 1))
    [ $((n % 8)) -ne 0 ] || wait
  done <"$T/served"
  wait
}
n=0
for who in 'oa owner' 'da developer' 'ra read_only' 'oa owner reveal'; do
  n=$((n + 1))
  # shellcheck disable=SC2086
  sweep $who
  as="as ${who#* }"
  check 1.$n.1 "$as: served API routes and pages requested, each answered" "$(wc -l <"$T/sweep")" "$routes"
  check 1.$n.2 "$as: ... API routes answered 401, or not at all" "$(awk -F'\t' '$1 == "api" && ($2 == 401 || $2 == "000")' "$T/sweep" | wc -l)" 0
  check 1.$n.3 "$as: ... pages answered otherwise than 200 or by a redirect" "$(awk -F'\t' '$1 == "page" && $2 !~ /^(200|30[1278])$/' "$T/sweep" | wc -l)" 0
  check 1.$n.4 "$as: ... answers that hold a secret" "$(awk -F'\t' '$3 != 0' "$T/sweep" | wc -l)" 0
  awk -F'\t' '$3 != 0 { print "  a secret in: " $4 }' "$T/sweep" | sed -n '1,10p' >&2
done

# --- 2. the two reveal requests
s=$(fetch "$LIST?reveal=true" "$(tok $A oa owner reveal)")
check 2.1 "the owner's reveal of the key list, signed for the purpose" "$(got "$s")" "200 [anon service_role] [spmark-service-alpha]"
check 2.1a "... is not to be stored" "$(stored)" no-store
check 2.1b "... and the search of this proof finds the key in it (control)" "$([ "$(hits)" -gt 0 ] && echo found || echo 'not found')" found
s=$(fetch "$ONE?reveal=true" "$(tok $A oa owner reveal)")
check 2.2 "the owner's reveal of the one key, signed for the purpose" "$(got "$s")" "200 [service_role] [spmark-service-alpha]"
check 2.2a "... is not to be stored" "$(stored)" no-store
s=$(fetch "$LIST?reveal=true" "$(tok $A oa owner)")
check 2.3 "the same owner, the same list request, no purpose in the assertion" "$(got "$s") $(hits)" "200 [anon] [] 0"
check 2.3a "... is not to be stored either" "$(stored)" no-store
s=$(fetch "$ONE?reveal=true" "$(tok $A oa owner)")
check 2.4 "... the one key" "$(got "$s") $(hits)" "404 [] [] 0"
n=4
for who in 'da developer' 'ra read_only'; do
  for purpose in '' reveal; do
    n=$((n + 1))
    # shellcheck disable=SC2086
    s=$(fetch "$LIST?reveal=true" "$(tok $A $who $purpose)")
    l="$(got "$s") $(hits)"
    # shellcheck disable=SC2086
    s=$(fetch "$ONE?reveal=true" "$(tok $A $who $purpose)")
    check 2.$n "the ${who#* }'s reveal requests, the assertion's purpose \"$purpose\"" "$l / $(got "$s") $(hits)" "200 [anon] [] 0 / 404 [] [] 0"
  done
done
claim=(-H 'X-Supapace-Purpose: reveal' -H 'Purpose: reveal' -H 'X-Reveal: true' -H 'Cookie: purpose=reveal; reveal=true')
s=$(fetch "$LIST?reveal=true&purpose=reveal&role=owner" "$(tok $A oa owner)" "${claim[@]}")
check 2.9 "the purpose claimed by headers, a cookie and the query: the owner, the list" "$(got "$s") $(hits)" "200 [anon] [] 0"
s=$(fetch "$ONE?purpose=reveal&reveal=true" "$(tok $A da developer)" "${claim[@]}")
check 2.10 "... the developer, the one key" "$(got "$s") $(hits)" "404 [] [] 0"
n=10
for q in '' '?reveal=false' '?reveal=TRUE' '?reveal=1' '?Reveal=true'; do
  n=$((n + 1))
  s=$(fetch "$LIST$q" "$(tok $A oa owner reveal)")
  l="$(got "$s") $(hits)"
  s=$(fetch "$ONE$q" "$(tok $A oa owner reveal)")
  check 2.$n "an assertion with the purpose, the request does not ask (\"$q\")" "$l / $(got "$s") $(hits)" "200 [anon] [] 0 / 404 [] [] 0"
done
s=$(fetch "/api/v1/projects/$B/api-keys?reveal=true" "$(tok $B both owner reveal)")
check 2.16 "an owner of both projects reveals B's key" "$(got "$s")" "200 [anon service_role] [spmark-service-bravo]"
s=$(fetch "$LIST?reveal=true" "$(tok $A both owner reveal)")
check 2.17 "... and then A's" "$(got "$s")" "200 [anon service_role] [spmark-service-alpha]"
s=$(fetch "$LIST?reveal=true" "$(tok $A both owner)")
check 2.18 "... and then asks again without the purpose: nothing was kept" "$(got "$s") $(hits)" "200 [anon] [] 0"
s=$(fetch "/api/v1/projects/$B/api-keys?reveal=true" "$(tok $A oa owner reveal)")
check 2.19 "A's reveal assertion on B's path" "$s $(code) $(hits)" "404 not_found 0"
n0=$(asked '"purpose":"reveal"')
fetch "$LIST?reveal=true" "$(tok $A oa owner reveal)" >/dev/null
fetch "$LIST?reveal=true" "$(tok $A oa owner reveal)" >/dev/null
check 2.20 "the same reveal twice: the control plane was asked twice" "$(($(asked '"purpose":"reveal"') - n0))" 2
n0=$(asked '')
for p in "$SETTINGS" "/api/platform/projects/$A/config" "/api/platform/projects/$A/config/postgrest" "/api/platform/props/project/$A/api"; do
  fetch "$p" "$(tok $A oa owner reveal)" >/dev/null
done
check 2.21 "settings, both configurations and the props under a reveal assertion: keys asked of the control plane" "$(($(asked '') - n0))" 0

# --- 3. the control plane silent, refusing, or answering what cannot be used
fetch "$SETTINGS" "$(tok $A oa owner)" >/dev/null # the owner's answer is kept from here on
socket silent
s=$(fetch "$LIST?reveal=true" "$(tok $A oa owner reveal)")
check 3.1 "the control plane silent: the owner's reveal" "$s $(code) $(hits)" "503 project_unavailable 0"
s=$(fetch "$SETTINGS" "$(tok $A oa owner)")
check 3.2 "... the settings are still answered, with no key" "$s $(hits)" "200 0"
socket refuse:unavailable
s=$(fetch "$ONE?reveal=true" "$(tok $A oa owner reveal)")
check 3.3 "the control plane refusing: the owner's reveal" "$s $(code) $(hits)" "503 unavailable 0"
cp "$T/table.bad" "$T/table.json"
socket
s=$(fetch "$LIST?reveal=true" "$(tok $A oa owner reveal)")
check 3.4 "an answer with the key beside a member that is malformed: refused whole" "$s $(code) $(hits) $(grep -c spmark "$T/b")" "503 project_unavailable 0 0"
s=$(fetch "$SIGNING" "$(tok $A oa owner)")
check 3.5 "... the signing keys of that answer too" "$s $(code)" "503 project_unavailable"
cp "$T/table.good" "$T/table.json"
socket

# --- 4. the public keys, for every member
n=0
for who in 'oa owner' 'da developer' 'ra read_only'; do
  n=$((n + 1))
  # shellcheck disable=SC2086
  s=$(fetch "$SIGNING" "$(tok $A $who)")
  check 4.$n.1 "the signing keys as ${who#* }: the control plane's three" "$s [$(ids)] $(grep -c -e HS256 -e 00000000-0000 -e created_at "$T/b") $(hits)" "200 [kid-anon-alpha kid-service-alpha kid-issuer-alpha] 0 0"
  # shellcheck disable=SC2086
  s=$(fetch "$LIST" "$(tok $A $who)")
  check 4.$n.2 "the key list as ${who#* }: the control plane's anon key alone" "$(got "$s") $(grep -c '"api_key":"spmark-anon-alpha"' "$T/b") $(hits)" "200 [anon] [] 1 0"
done

# --- 5. what a statement carries to postgres-meta
n0=$(seen)
planted=(-H 'Cookie: sid=spplanted' -H 'apikey: spplanted' -H 'apiKey: spplanted2' -H 'Authorization: Bearer spplanted'
  -H 'X-Connection-Encrypted: spplanted' -H 'X-Request-Id: spplanted' -H 'User-Agent: spplanted' -H 'Accept: spplanted/x' -H 'Referer: https://spplanted.example/')
JSON=(-H 'Content-Type: application/json')
check 5.1 "a statement, with a cookie, keys and an authorization planted" "$(ask POST "/api/platform/pg-meta/$A/query" "$(tok $A oa owner)" "${JSON[@]}" -d '{"query":"select 1"}' "${planted[@]}")" "200 postgres:$PA"
check 5.2 "the lints, the same" "$(ask GET "/api/platform/projects/$A/run-lints" "$(tok $A oa owner)" "${planted[@]}")" "200 postgres:$PA"
check 5.3 "the migration list, the same" "$(ask GET "/api/v1/projects/$A/database/migrations" "$(tok $A ra read_only)" "${planted[@]}")" "200 supabase_read_only_user:$PA"
check 5.4 "type generation, the same" "$(ask GET "/api/v1/projects/$A/types/typescript" "$(tok $A oa owner)" "${planted[@]}")" "200 postgres:$PA"
# what postgres-meta's stand-in recorded for them: "<requests>|<names, /query>|<names, the rest>|<planted or marked values>"
recorded=$(docker exec "$PREFIX-studio" node -e '
  const own = ["accept", "accept-encoding", "accept-language", "connection", "content-length", "sec-fetch-mode", "user-agent"]
  fetch("http://pgmeta:8080/_seen").then((r) => r.json()).then((all) => {
    const mine = all.filter((r) => r.n > Number(process.argv[1]))
    const names = (pick) => [...new Set(mine.filter((r) => pick(r.path)).flatMap((r) => Object.keys(r.headers)))]
      .filter((h) => !own.includes(h)).sort().join(" ")
    const bad = JSON.stringify(mine).match(/spplanted|spmark[A-Za-z]|spmark-service/g) || []
    console.log([mine.length, names((p) => p === "/query"), names((p) => p !== "/query"), bad.length].join("|"))
  })' "$n0")
check 5.5 "requests postgres-meta received for them" "$(printf '%s' "$recorded" | cut -d'|' -f1)" 4
check 5.6 "the headers of a statement beside the HTTP client's own" "$(printf '%s' "$recorded" | cut -d'|' -f2)" "content-type x-connection-encrypted"
check 5.7 "the headers of type generation beside them (its sender adds a request id)" "$(printf '%s' "$recorded" | cut -d'|' -f3)" "content-type x-connection-encrypted x-request-id"
check 5.8 "planted values, or values of the process, in any header of them" "$(printf '%s' "$recorded" | cut -d'|' -f4)" 0

# --- 6. the image's files, and the server's log
mkdir "$T/img"
c=$(docker create "${L[@]}" "$IMAGE") && docker export "$c" | tar -x -C "$T/img" app/apps/studio/.output
docker rm -f "$c" >/dev/null
files=$(find "$T/img" -type f | wc -l)
check 6.1 "the image's server and client bundles were read (control)" "$([ "$files" -gt 100 ] && echo yes || echo "$files files")" yes
check 6.2 "files of them that hold the default JWT secret upstream answered" "$(grep -rlF -- "$DEFAULT" "$T/img" | wc -l)" 0
check 6.3 "files of them that hold a marked value of this proof" "$(grep -rl -e 'spmark[A-Za-z-]' "$T/img" | wc -l)" 0
check 6.4 "the same search finds a name the server does read (control)" "$([ "$(grep -rlF SUPAPACE_DASH_SOCKET "$T/img" | wc -l)" -gt 0 ] && echo found || echo 'not found')" found
docker logs "$PREFIX-studio" >"$T/log" 2>&1
check 6.5 "the server's log has lines (control)" "$([ "$(wc -l <"$T/log")" -gt 0 ] && echo yes || echo none)" yes
check 6.6 "lines of it with a key, a secret, an assertion or a connection string" "$(grep -c -e 'v1\.ey' -e postgresql: -e spmark -e "$DEFAULT" "$T/log")" 0

finish
