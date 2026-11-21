#!/usr/bin/env bash
# context.sh IMAGE — the request context on the built image: one server process, many projects.
# Against the stand-ins of stand-ins.bash it shows that every request is answered for the
# project of its assertion and for no other — one at a time, interleaved, on one connection —
# that what the path, the query, the body or a header names changes nothing but a refusal,
# that a request without a valid assertion reaches nothing, and that a server without a node's
# settings, or with the build's prerender switch, does not serve. Prints one row per case;
# exits 1 when a row fails.
. "$(dirname "${BASH_SOURCE[0]}")/stand-ins.bash"
standins_up "${1:?usage: context.sh IMAGE}" || { echo "context.sh: the image or a stand-in did not start" >&2; exit 1; }

SQL='{"query":"select 1"}'
JSON=(-H 'Content-Type: application/json')
door() { printf '/api/platform/pg-meta/%s/query' "$1"; }
sql() { ask POST "$(door "$1")" "$2" "${JSON[@]}" -d "$SQL" "${@:3}"; } # sql PATH-REF TOKEN [curl args]
enc() { printf '%s' "$1" | openssl enc -aes-256-cbc -md md5 -pass "pass:$CRYPTO" -base64 -A 2>/dev/null; }

echo '| # | case | answer | |'
echo '|---|---|---|---|'

# --- 1. each project its own, by every role; the stand-in decrypted the header the server wrote
check 1.1 "A's owner through the SQL door" "$(sql $A "$(tok $A oa owner)")" "200 postgres:$PA"
check 1.2 "B's owner" "$(sql $B "$(tok $B ob owner)")" "200 postgres:$PB"
check 1.3 "A's developer" "$(sql $A "$(tok $A da developer)")" "200 postgres:$PA"
check 1.4 "A's read_only member: the read-only login" "$(sql $A "$(tok $A ra read_only)")" "200 supabase_read_only_user:$PA"
check 1.5 "B's read_only member" "$(sql $B "$(tok $B rb read_only)")" "200 supabase_read_only_user:$PB"
check 1.6 "one principal, an owner of both: asked for A" "$(sql $A "$(tok $A both owner)")" "200 postgres:$PA"
check 1.7 "the same principal: asked for B" "$(sql $B "$(tok $B both owner)")" "200 postgres:$PB"
check 1.8 "type generation for A" "$(ask GET /api/v1/projects/$A/types/typescript "$(tok $A oa owner)")" "200 postgres:$PA"
check 1.9 "lints for B" "$(ask GET /api/platform/projects/$B/run-lints "$(tok $B ob owner)")" "200 postgres:$PB"

# --- 2. without a valid assertion nothing is reached
n0=$(seen)
check 2.1 "no assertion, SQL door" "$(sql $A '')" "401 bad_assertion"
check 2.2 "no assertion, a page" "$(ask GET /project/$A/editor '' -H 'Accept: text/html')" "401 bad_assertion"
check 2.3 "no assertion, a path no route has" "$(ask GET /nothing/here '')" "401 bad_assertion"
check 2.4 "no assertion, the root" "$(ask GET / '' -H 'Accept: text/html')" "401 bad_assertion"
check 2.5 "an expired assertion" "$(sql $A "$(tok $A oa owner '' -31)")" "401 bad_assertion"
check 2.6 "an assertion issued 10 s ahead" "$(sql $A "$(tok $A oa owner '' 10)")" "401 bad_assertion"
check 2.7 "an assertion that lives 61 s" "$(sql $A "$(tok $A oa owner '' 0 61)")" "401 bad_assertion"
check 2.8 "two assertion headers, A's and B's" "$(sql $A "$(tok $A oa owner)" -H "X-Supapace-Assertion: $(tok $B ob owner)")" "401 bad_assertion"
t=$(tok $A oa owner)
forged="v1.$(printf '%s' "$t" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | sed "s/$A/$B/" | b64url).$(printf '%s' "$t" | cut -d. -f3)"
check 2.9 "A's assertion altered to name B (the signature no longer fits)" "$(sql $B "$forged")" "401 bad_assertion"
check 2.10 "an assertion of another node" "$(NODE=node-2 tok $A oa owner | { read -r x; sql $A "$x"; })" "401 bad_assertion"
check 2.11 "an assertion in the query, a cookie and another header" "$(ask POST "$(door $A)?X-Supapace-Assertion=$t" '' "${JSON[@]}" -d "$SQL" -H "Cookie: X-Supapace-Assertion=$t" -H "Authorization: Bearer $t")" "401 bad_assertion"
check 2.11a "no assertion, a request another site sent: the guard answers ahead of every other middleware" "$(sql $A '' -H 'Sec-Fetch-Site: cross-site' -H 'Origin: https://other.example')" "401 bad_assertion"
check 2.12 "postgres-meta received nothing for them" "$(($(seen) - n0))" 0

# --- 3. the path may only agree with the assertion
n0=$(seen)
TA() { tok $A oa owner; }
check 3.1 "A's assertion, the path names B: an API route" "$(sql $B "$(TA)")" "404 not_found"
check 3.2 "... B in capitals" "$(sql "$(printf %s $B | tr a-z A-Z)" "$(TA)")" "404 not_found"
check 3.3 "... a page of B" "$(ask GET /project/$B/editor "$(TA)" -H 'Accept: text/html')" "404 not_found"
check 3.4 "... B percent-encoded" "$(ask GET "/project/%62${B#b}/editor" "$(TA)" -H 'Accept: text/html')" "404 not_found"
check 3.5 "... B behind a dot-dot the server resolves" "$(raw GET "/x/../project/$B" "$(TA)")" "404 not_found"
check 3.6 "... B before a fragment" "$(raw GET "/project/$B#/../x" "$(TA)")" "404 not_found"
check 3.7 "... B before a trailing space, which the server drops" "$(raw GET "/project/$B%20" "$(TA)")" "404 not_found"
check 3.7a "... the same before an empty query" "$(raw GET "/project/$B%20?" "$(TA)")" "404 not_found"
check 3.7b "... B before a segment that is one space" "$(raw GET "/project/$B/%20" "$(TA)")" "404 not_found"
check 3.7c "... a route that is not served, before a trailing space" "$(raw GET "/api/mcp%20" "$(TA)")" "404 not_found"
check 3.8 "... B where no route has a parameter" "$(ask GET "/api/platform/profile/$B" "$(TA)")" "404 not_found"
check 3.9 "... B in a server function's path" "$(ask GET "/_serverFn/$B" "$(TA)")" "404 not_found"
check 3.10 "B's read_only member, the path names A" "$(sql $A "$(tok $B rb read_only)")" "404 not_found"
check 3.11 "postgres-meta received nothing for them" "$(($(seen) - n0))" 0
BDSN=$(dsn postgres spmark-rw-bravo $PB)
check 3.12 "A's assertion and path; the query, the body and the headers name B" "$(ask POST "$(door $A)?ref=$B&project_ref=$B" "$(TA)" "${JSON[@]}" -d "{\"query\":\"select 1\",\"ref\":\"$B\",\"connectionString\":\"$BDSN\"}" -H "x-connection-encrypted: $(enc "$BDSN")" -H "X-Connection-Encrypted: $(enc "$BDSN")" -H "X-Forwarded-Host: $B.studio.example" -H "X-Project-Ref: $B")" "200 postgres:$PA"
check 3.13 "A's read_only member with B's read-write string planted" "$(sql $A "$(tok $A ra read_only)" -H "x-connection-encrypted: $(enc "$BDSN")")" "200 supabase_read_only_user:$PA"
check 3.14 "type generation for A with B's string planted" "$(ask GET /api/v1/projects/$A/types/typescript "$(TA)" -H "x-connection-encrypted: $(enc "$BDSN")")" "200 postgres:$PA"
check 3.15 "the project's own ref in capitals is its own" "$(ask GET "/project/$(printf %s $A | tr a-z A-Z)" "$(TA)" -H 'Accept: text/html' | cut -c1-3)" 200

# --- 4. the control plane decides who is a member; its refusal is the answer
check 4.1 "a member of B alone asks for A" "$(sql $A "$(tok $A ob owner)")" "403 not_a_member"
check 4.2 "A's read_only member claims to be an owner" "$(sql $A "$(tok $A ra owner)")" "403 not_a_member"
check 4.3 "a ref the node does not have" "$(sql ddddddddddddddddddd4 "$(tok ddddddddddddddddddd4 oa owner)")" "404 not_here"
check 4.4 "a read_only member of a project without a read-only login" "$(sql $C "$(tok $C rc read_only)")" "403 no_read_only_login"
check 4.5 "that project's owner is served" "$(sql $C "$(tok $C oc owner)")" "200 postgres:$PC"

# --- 5. interleaved: 40 requests for two projects, each after a delay of its own
n0=$(seen)
: >"$T/interleaved"
ta=$(tok $A oa owner '' 0 55) tb=$(tok $B ob owner '' 0 55) tra=$(tok $A ra read_only '' 0 55) trb=$(tok $B rb read_only '' 0 55)
for i in $(seq 40); do
  case $((i % 4)) in
  0) t=$ta ref=$A want="postgres:$PA" ;;
  1) t=$tb ref=$B want="postgres:$PB" ;;
  2) t=$tra ref=$A want="supabase_read_only_user:$PA" ;;
  3) t=$trb ref=$B want="supabase_read_only_user:$PB" ;;
  esac
  (
    sleep "0.$((RANDOM % 5))$((RANDOM % 10))"
    echo "$want|$(sql $ref "$t")" >>"$T/interleaved"
  ) &
done
wait
check 5.1 "40 interleaved requests for A and B, by four members" "answered $(wc -l <"$T/interleaved"), for another project: $(awk -F'|' '$2 != "200 " $1' "$T/interleaved" | wc -l)" "answered 40, for another project: 0"
check 5.2 "postgres-meta received exactly those" "$(($(seen) - n0))" 40

# --- 6. one connection, kept alive: A, B, nobody and A's read_only member in turn, ten rounds
args=() want=''
for i in $(seq 10); do
  for c in "$ta|$A|postgres:$PA" "$tb|$B|postgres:$PB" "|$A|bad_assertion" "$tra|$A|supabase_read_only_user:$PA" "$ta|$B|not_found"; do
    IFS='|' read -r t ref w <<<"$c"
    [ ${#args[@]} -eq 0 ] || args+=(--next)
    args+=(-s -m 30 -w $'\036%{num_connects}\037' -X POST "$U$(door "$ref")" "${JSON[@]}" -d "$SQL")
    [ -z "$t" ] || args+=(-H "X-Supapace-Assertion: $t")
    want+="$w "
  done
done
curl "${args[@]}" >"$T/kept-alive"
got=$(tr -d '\n' <"$T/kept-alive" | tr '\037' '\n' | awk -F'\036' 'NF == 2 {
  if (match($1, /"login":"[a-z_]*","port":[0-9]*/)) { s = substr($1, RSTART, RLENGTH); gsub(/"login":"|"/, "", s); sub(/,port:/, ":", s) }
  else if (match($1, /"code":"[a-z_]*"/)) { s = substr($1, RSTART + 8, RLENGTH - 9) }
  else s = "?"
  printf "%s ", s }')
check 6.1 "50 requests on one kept-alive connection, each answered for its own assertion" "$got" "$want"
check 6.2 "they used one connection" "$(tr -d '\n' <"$T/kept-alive" | tr '\037' '\n' | awk -F'\036' 'NF == 2 { n += $2 } END { print n }')" 1
# three requests written at once on one connection: A's, nobody's, B's
host=${U#http://}
rq() { printf 'POST %s HTTP/1.1\r\nHost: studio\r\nContent-Type: application/json\r\nContent-Length: %s\r\n%s%s\r\n%s' "$(door "$1")" "${#SQL}" "${2:+X-Supapace-Assertion: $2$'\r\n'}" "${3:-}" "$SQL"; }
exec 8<>"/dev/tcp/${host%:*}/${host##*:}"
{ rq $A "$ta"; rq $A ''; rq $B "$tb" $'Connection: close\r\n'; } >&8
timeout 30 cat <&8 >"$T/pipelined"
exec 8>&- 8<&-
check 6.3 "three requests written at once on one connection: A's, nobody's, B's" "$(grep -a -o -e '"login":"[a-z_]*","port":[0-9]*' -e '"code":"[a-z_]*"' "$T/pipelined" | sed 's/"login":"//; s/","port":/:/; s/"code":"//; s/"$//' | tr '\n' ' ')" "postgres:$PA bad_assertion postgres:$PB "

# --- 7. the control plane silent: a kept answer serves, and only its own project
docker rm -f "$PREFIX-socket" >/dev/null
rm -f "$T/sock/dash.sock"
studio || { echo "context.sh: the server did not restart" >&2; exit 1; }
check 7.1 "the socket gone, a new process: A from its kept answer" "$(sql $A "$(tok $A oa owner)")" "200 postgres:$PA"
check 7.2 "... A's assertion with B in the path is still refused" "$(sql $B "$(tok $A oa owner)")" "404 not_found"
check 7.3 "... a project never answered for" "$(sql ddddddddddddddddddd4 "$(tok ddddddddddddddddddd4 oa owner)")" "503 project_unavailable"
check 7.4 "... still nothing without an assertion" "$(sql $A '')" "401 bad_assertion"
socket || exit 1

# --- 8. the logs hold no credential
docker logs "$PREFIX-studio" >"$T/log" 2>&1
check 8.0 "the server's log has lines (the control)" "$([ "$(wc -l <"$T/log")" -gt 0 ] && echo yes)" yes
check 8.1 "server log: lines with an assertion, a connection string or a password" "$(grep -c -e 'v1\.ey' -e postgresql: -e spmark "$T/log")" 0

# --- 9. a server without a node's settings does not serve, and no request is needed to stop it
stopped() { # stopped WHAT [docker args] — started so, the server is gone within 5 s, unasked
  local what=$1 i
  shift
  docker rm -f "$PREFIX-studio" >/dev/null 2>&1
  docker run -d --name "$PREFIX-studio" "${L[@]}" --network "$PREFIX-net" --user 65527:65527 --read-only --tmpfs /tmp \
    --memory 1g --cap-drop ALL --security-opt no-new-privileges \
    -v "$T/sock:/run/dash:ro" -v "$T/keys:/etc/dash:ro" -v "$T/data:/var/lib/dash" "${STUDIO_ENV[@]}" "$@" "$IMAGE" >/dev/null
  for i in $(seq 10); do
    [ "$(docker inspect -f '{{.State.Running}}' "$PREFIX-studio")" = false ] && break
    sleep 0.5
  done
  printf '%s; last line: %s' "$(docker inspect -f 'running {{.State.Running}}, exit {{.State.ExitCode}}' "$PREFIX-studio")" \
    "$(docker logs "$PREFIX-studio" 2>&1 | grep '^supapace: ' | tail -1 | sed "s/ .*$what.*/ ...$what.../")"
}
check 9.1 "no SUPAPACE_LIMITS" "$(stopped SUPAPACE_LIMITS -e SUPAPACE_LIMITS=)" "running false, exit 1; last line: supapace: ...SUPAPACE_LIMITS..."
check 9.2 "a malformed SUPAPACE_PGCAP" "$(stopped SUPAPACE_PGCAP -e SUPAPACE_PGCAP=pgcap:1:2)" "running false, exit 1; last line: supapace: ...SUPAPACE_PGCAP..."
check 9.3 "no SUPAPACE_NODE_ID" "$(stopped SUPAPACE_NODE_ID -e SUPAPACE_NODE_ID=)" "running false, exit 1; last line: supapace: ...SUPAPACE_NODE_ID..."
check 9.4 "no key directory" "$(stopped 'key file' -e SUPAPACE_DASH_KEYS=/etc/none)" "running false, exit 1; last line: supapace: ...key file..."
check 9.5 "the prerender switch together with a node's settings" "$(stopped TSS_PRERENDERING -e TSS_PRERENDERING=true)" "running false, exit 1; last line: supapace: ...TSS_PRERENDERING..."

# --- 10. the build's prerender is not a mode a request or a node can choose
studio || { echo "context.sh: the server did not restart" >&2; exit 1; }
check 10.1 "a served process asked as the build asks for its shell" "$(ask GET '/?TSS_PRERENDERING=true' '' -H 'X-TSS_SHELL: true' -H 'TSS_PRERENDERING: true' -H 'Accept: text/html')" "401 bad_assertion"
check 10.2 "the same for an API route" "$(ask GET /api/platform/profile '' -H 'X-TSS_SHELL: true')" "401 bad_assertion"
# the switch in the built server: read where a constant is compared with "true", written nowhere
uses=$(docker run --rm "${L[@]}" --network none --entrypoint sh "$IMAGE" -c 'grep -rhoE ".{0,24}TSS_PRERENDERING.{0,12}" /app/apps/studio/.output/server --include="*.mjs"')
check 10.3 "places of the built server that name the switch other than to compare it with \"true\"" "$(printf '%s\n' "$uses" | grep -c -v -e 'process\.env\.TSS_PRERENDERING === "true"' -e 'process\.env\.TSS_PRERENDERING !== "true"' -e 'TSS_PRERENDERING is set on')" 0
check 10.4 "... and it is read at all (the control)" "$([ "$(printf '%s\n' "$uses" | grep -c 'process\.env\.TSS_PRERENDERING')" -ge 2 ] && echo yes)" yes
# a process with the switch and no setting of a node: the build's own way of starting it
docker rm -f "$PREFIX-studio" >/dev/null 2>&1
docker run -d --name "$PREFIX-studio" "${L[@]}" --network "$PREFIX-net" --user 65527:65527 --read-only --tmpfs /tmp \
  --memory 1g --cap-drop ALL --security-opt no-new-privileges -e NODE_ENV=production -e PORT=3000 -e TSS_PRERENDERING=true "$IMAGE" >/dev/null
U=http://$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PREFIX-studio"):3000
for i in $(seq 120); do curl -s -o /dev/null -m 2 "$U/api/platform/profile" && break; sleep 0.5; done
check 10.5 "without any setting, as the build starts it: the shell's request is served, redirects followed" "$(ask GET / '' -L -H 'X-TSS_SHELL: true' -H 'Accept: text/html' | cut -c1-3)" 200
check 10.6 "... and nothing else is: an API route, the header saying false" "$(ask GET /api/platform/profile '' -H 'X-TSS_SHELL: false')" "401 bad_assertion"
FN=$(awk -F'\t' '$1 == "function" { print $2 }' "$HERE/../routes.tsv")
check 10.6a "... an API route, with the shell's header" "$(ask GET /api/platform/profile '' -H 'X-TSS_SHELL: true')" "401 bad_assertion"
check 10.6b "... a route that is not served, with the shell's header" "$(ask GET /api/ai/sql/check-api-key '' -H 'X-TSS_SHELL: true')" "401 bad_assertion"
check 10.6c "... the server function, with the shell's header" "$(ask GET "/_serverFn/$FN" '' -H 'X-TSS_SHELL: true' -H 'x-tsr-serverfn: true')" "401 bad_assertion"
check 10.6d "... the server function, its prefix percent-encoded" "$(ask GET "/%5FserverFn/$FN" '' -H 'X-TSS_SHELL: true' -H 'x-tsr-serverfn: true')" "401 bad_assertion"
check 10.6e "... an API route behind a dot segment the server resolves" "$(ask GET /project/../api/platform/profile '' -H 'X-TSS_SHELL: true')" "401 bad_assertion"
check 10.7 "... the SQL door, with the shell's header" "$(sql $A '' -H 'X-TSS_SHELL: true')" "401 bad_assertion"
check 10.8 "... a request that carries an assertion" "$(ask GET / "$(tok $A oa owner)" -H 'X-TSS_SHELL: true')" "401 bad_assertion"

finish
