#!/usr/bin/env bash
# bounds.sh IMAGE — the path to postgres-meta on the built image, at the bounds a node sets
# (`sp-dashstub limits`): which instance a statement is sent to and that it is on record
# first; that nothing is sent without a record; the byte bounds of an answer and of a request
# body; the wait for a slot and the deadline of a call; that a client's leaving frees its slot;
# that a slot is held while an answer is handed over, and lost at the hand-over's own bound; and the
# connection-string vectors (internal/dashcfg/testdata/dsn.json): each accepted one read by
# the parser inside the pinned postgres-meta image, each refused one never sent on.
# Prints one row per case; exits 1 when a row fails. It takes about five minutes: three of
# the bounds are waited for.
#
# Host needs, beside stand-ins.bash's: the pinned postgres-meta image, loaded (it is never
# pulled here): public.ecr.aws/supabase/postgres-meta:<the tag of studio/PIN>.
#
# A build that gives a slot back when postgres-meta has answered (studio/test-patches) fails
# the rows of section 5 and no other: they are what the product's rule bounds.
. "$(dirname "${BASH_SOURCE[0]}")/stand-ins.bash"
standins_up "${1:?usage: bounds.sh IMAGE}" || { echo "bounds.sh: the image or a stand-in did not start" >&2; exit 1; }

SQL='{"query":"select 1"}'
JSON=(-H 'Content-Type: application/json')
door() { printf '/api/platform/pg-meta/%s/query' "$1"; }
sql() { ask POST "$(door "$1")" "$2" "${JSON[@]}" -d "$SQL" "${@:3}"; } # sql REF TOKEN [curl args]
TA() { tok $A oa owner; }
now() { date +%s; }
# between WHAT GOT LO HI — "ok" when LO <= GOT <= HI
between() { [ "$2" -ge "$3" ] && [ "$2" -le "$4" ] && echo "$1 after $3 to $4 s" || echo "$1 after $2 s (want: $3 to $4)"; }
# ready — waits until both instances answer. A server started again at the address it had is
# not followed by a start of the server under test, and a row must not be the first to find
# that it does not listen yet: its statement would be answered 500.
ready() {
  local i
  for i in $(seq 100); do
    [[ $(seen 2>/dev/null) =~ ^[0-9]+$ ]] && return 0
    sleep 0.1
  done
  return 1
}
# stubs [stub args] — the postgres-meta stand-ins again, and the server when their addresses changed
stubs() {
  local old=$META
  pgmeta "$@" || return 1
  [ "$META" = "$old" ] || studio || return 1
  ready
}
# big SIZE — instead of the stand-ins, two servers of the proof's own that answer every
# request with one JSON text of SIZE bytes: an answer the client receives at that size
big() {
  local i ip old=$META
  META=
  for i in 0 1; do
    docker rm -f "$PREFIX-pgmeta-$i" >/dev/null 2>&1
    docker run -d --name "$PREFIX-pgmeta-$i" "${L[@]}" --network "$PREFIX-net" --user "$(id -u):$(id -g)" "$NODE_BASE" node -e '
      const size = Number(process.argv[1])
      const body = JSON.stringify(["x".repeat(size - 4)])
      let n = 0
      require("http").createServer((req, res) => {
        if (req.url === "/_seen") return res.end(JSON.stringify(n ? [{ n }] : []))
        req.resume().on("end", () => { n++; res.end(body) })
      }).listen(8080)' "$1" >/dev/null || return 1
    ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PREFIX-pgmeta-$i")
    META+="${META:+,}http://$ip:8080"
  done
  [ "$META" = "$old" ] || studio || return 1
  ready
}
# sent INSTANCE COUNT SECONDS — waits until the instance has received COUNT requests more than $n0
sent() {
  local i got
  for i in $(seq $(($3 * 5))); do
    got=$(($(seen "$1") - n0))
    [ "$got" -ge "$2" ] && break
    sleep 0.2
  done
  echo "$got"
}
# stall FD REF TOKEN — a statement on a connection of the proof's own, whose answer is not read
stall() {
  local host=${U#http://}
  eval "exec $1<>/dev/tcp/${host%:*}/${host##*:}" || return 1
  printf 'POST %s HTTP/1.1\r\nHost: studio\r\nContent-Type: application/json\r\nContent-Length: %d\r\nX-Supapace-Assertion: %s\r\nConnection: close\r\n\r\n%s' \
    "$(door "$2")" ${#SQL} "$3" "$SQL" >&"$1"
}
audit() { docker exec "$PREFIX-studio" cat "/var/lib/dash/$1/audit.log" 2>/dev/null; }
field() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

echo '| # | case | answer | |'
echo '|---|---|---|---|'

# --- 1. the instance the control plane names, and the record before the request
n0=$(seen 0) n1=$(seen 1)
check 1.1 "A's statement" "$(sql $A "$(TA)")" "200 postgres:$PA"
check 1.2 "... was sent to instance 1 alone (requests at instance 0, 1)" "$(($(seen 0) - n0)) $(($(seen 1) - n1))" "0 1"
check 1.3 "B's statement" "$(sql $B "$(tok $B ob owner)")" "200 postgres:$PB"
check 1.4 "... was sent to instance 0 alone" "$(($(seen 0) - n0)) $(($(seen 1) - n1))" "1 1"
rec=$(audit $A | tail -1)
check 1.5 "A's audit file: one record, its members in order" "$(audit $A | grep -c .) $(printf '%s' "$rec" | sed -E 's/:"[^"]*"//g')" \
  '1 {"t","ref","iss","sub","role","login","kind","sql_sha256"}'
check 1.6 "... who, as what, with which login, what" "$(field "$rec" ref) $(field "$rec" iss) $(field "$rec" sub) $(field "$rec" role) $(field "$rec" login) $(field "$rec" kind) $(field "$rec" sql_sha256)" \
  "$A $ISS oa owner postgres query $(printf 'select 1' | sha256sum | cut -d' ' -f1)"
t=$(field "$rec" t)
check 1.7 "... its time, UTC with milliseconds, is now" "$([[ $t =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}\.[0-9]{3}Z$ ]] && [ $(($(now) - $(date -d "$t" +%s))) -le 30 ] && echo yes || echo "no: $t")" yes
check 1.8 "a read_only member's statement" "$(sql $A "$(tok $A ra read_only)")" "200 supabase_read_only_user:$PA"
rec=$(audit $A | tail -1)
check 1.9 "... is recorded with the read-only login" "$(audit $A | grep -c .) $(field "$rec" sub) $(field "$rec" role) $(field "$rec" login)" "2 ra read_only supabase_read_only_user"
check 1.10 "type generation for A" "$(ask GET /api/v1/projects/$A/types/typescript "$(TA)")" "200 postgres:$PA"
rec=$(audit $A | tail -1)
check 1.11 "... is recorded as such, with no statement's hash" "$(printf '%s' "$rec" | sed -E 's/:"[^"]*"//g') $(field "$rec" kind)" '{"t","ref","iss","sub","role","login","kind"} typegen'
check 1.12 "B's file holds B's record alone" "$(audit $B | grep -c .) $(field "$(audit $B)" ref)" "1 $B"
check 1.13 "a parse of a statement, for a member of any role" "$(ask POST /api/parse-query "$(tok $A ra read_only)" "${JSON[@]}" -d '{"sql":"select 1 from t"}' | cut -c1-20)" '200 {"tables":["t"],'

# --- 2. a statement that cannot be recorded is not sent
n0=$(seen)
docker exec "$PREFIX-studio" mkdir -p "/var/lib/dash/$C/audit.log"
check 2.1 "C's audit file is a directory: C's statement" "$(sql $C "$(tok $C oc owner)")" "503 audit_unavailable"
check 2.2 "... and its type generation" "$(ask GET /api/v1/projects/$C/types/typescript "$(tok $C oc owner)")" "503 audit_unavailable"
check 2.3 "postgres-meta received nothing for them" "$(($(seen) - n0))" 0
check 2.4 "another project is served meanwhile" "$(sql $A "$(TA)")" "200 postgres:$PA"
docker exec "$PREFIX-studio" rmdir "/var/lib/dash/$C/audit.log"
check 2.5 "the file can be written again: the same statement (control)" "$(sql $C "$(tok $C oc owner)")" "200 postgres:$PC"
check 2.6 "the server's log names the project and the system's error, once per refusal" \
  "$(docker logs "$PREFIX-studio" 2>&1 | grep -c "^supapace: the audit record of $C could not be written (EISDIR)$")" 2

# --- 3. the byte bound of an answer (8,388,608)
stubs --size 8388609 || { echo "bounds.sh: the stand-ins did not restart" >&2; exit 1; }
check 3.1 "an answer one byte past the bound" "$(sql $A "$(TA)")" "400 result_too_large"
stubs --size 8388608
check 3.2 "an answer of exactly the bound (control)" "$(sql $A "$(TA)")" "200 postgres:$PA"
check 3.3 "the slot of the refused statement is free: two more at once" \
  "$(sql $A "$(TA)" & sql $A "$(TA)"; wait)" "200 postgres:${PA}200 postgres:$PA"

# --- 3b. the bound of a request body (3,145,728: what postgres-meta takes)
stubs
n0=$(seen)
body() { { printf '{"query":"'; head -c "$1" /dev/zero | tr '\0' x; printf '"}'; } >"$T/body"; } # a statement of $1 bytes
body $((3145728 - 12))
check 3.4 "a statement whose request body is exactly the bound (control)" "$(ask POST "$(door $A)" "$(TA)" "${JSON[@]}" --data-binary "@$T/body")" "200 postgres:$PA"
body $((3145728 - 11))
check 3.5 "one byte more" "$(ask POST "$(door $A)" "$(TA)" "${JSON[@]}" --data-binary "@$T/body")" "413 body_too_large"
check 3.6 "... was not sent, and is not on record" "$(($(seen) - n0)) $(audit $A | grep -c "$(head -c $((3145728 - 11)) /dev/zero | tr '\0' x | sha256sum | cut -d' ' -f1)")" "1 0"

# --- 4. a client that leaves, the wait for a slot (10 s), the deadline of a call (57 s)
stubs --delay-ms 70000
n0=$(seen 1)
sql $A "$(TA)" -m 2 >/dev/null &
sql $A "$(TA)" -m 2 >/dev/null &
wait
check 4.1 "two statements whose clients give up after 2 s: both had been sent" "$(sent 1 2 5)" 2
t0=$(now)
sql $A "$(TA)" -m 90 >"$T/a1" &
p1=$!
sql $A "$(TA)" -m 90 >"$T/a2" &
p2=$!
check 4.2 "two more are sent at once: the clients' leaving freed the project's two slots" "$(sent 1 4 8)" 4
t1=$(now)
got=$(sql $A "$(TA)" -m 90)
check 4.3 "a third statement of the project waits for a slot" "$(between "$got" $(($(now) - t1)) 10 20)" "429 busy after 10 to 20 s"
check 4.4 "... and was not sent" "$(($(seen 1) - n0))" 4
check 4.5 "another project of the instance has its own slots: C's statement is sent" "$(sql $C "$(tok $C oc owner)" -m 2 >/dev/null; sent 1 5 3)" 5
wait $p1 $p2
check 4.6 "the first of the two, unanswered" "$(between "$(cat "$T/a1")" $(($(now) - t0)) 57 75)" "504 query_deadline after 57 to 75 s"
check 4.7 "the second" "$(cat "$T/a2")" "504 query_deadline"
stubs --delay-ms 40
check 4.8 "their slots are free: two statements at once" "$(sql $A "$(TA)" & sql $A "$(TA)"; wait)" "200 postgres:${PA}200 postgres:$PA"

# --- 5. the hand-over: a slot is held until the client has taken the answer
big 8000000 || { echo "bounds.sh: the proof's servers did not start" >&2; exit 1; }
size() { curl -s -m 60 -o /dev/null -w '%{http_code} %{size_download}' -X POST "$U$(door $A)" -H "X-Supapace-Assertion: $(TA)" "${JSON[@]}" -d "$SQL" "$@"; }
check 5.1 "an answer of 8,000,000 bytes reaches the client whole" "$(size)" "200 8000000"
# two clients that take nothing at first, and then take it all
n0=$(seen 1)
t0=$(now)
stall 5 $A "$(TA)" && stall 6 $A "$(TA)"
check 5.2 "two statements whose clients do not read yet: both were sent" "$(sent 1 2 5)" 2
t1=$(now)
got=$(sql $A "$(TA)" -m 60)
check 5.3 "a third statement finds the project's slots held, though postgres-meta has answered" "$(between "$got" $(($(now) - t1)) 10 20)" "429 busy after 10 to 20 s"
check 5.4 "the two clients now read: each has its answer whole" \
  "$(for fd in 5 6; do n=$(timeout 20 cat <&$fd | wc -c); [ "$n" -gt 8000000 ] && printf 'whole ' || printf '%s bytes ' "$n"; done)" "whole whole "
exec 5>&- 5<&- 6>&- 6<&-
got=$(size)
check 5.5 "taken: the slots are free at once, well before the hand-over's bound" "$(between "$got" $(($(now) - t0)) 10 28)" "200 8000000 after 10 to 28 s"

# two clients that neither read nor close
n0=$(seen 1)
t0=$(now)
stall 7 $A "$(TA)" && stall 8 $A "$(TA)"
check 5.6 "two statements whose clients read nothing: both were sent" "$(sent 1 2 5)" 2
t1=$(now)
got=$(sql $A "$(TA)" -m 60)
check 5.7 "a third statement finds their slots held" "$(between "$got" $(($(now) - t1)) 10 20)" "429 busy after 10 to 20 s"
# the hand-over's own bound, 32 s after postgres-meta answered: asked at 25 s, served past 32
sleep $((25 - ($(now) - t0)))
got=$(size)
check 5.8 "at the hand-over's bound the slots are taken back: a statement asked at 25 s" "$(between "$got" $(($(now) - t0)) 32 45)" "200 8000000 after 32 to 45 s"
for fd in 7 8; do
  n=$(timeout 20 cat <&$fd | wc -c; exit "${PIPESTATUS[0]}")
  rc=$?
  check 5.9.$fd "... and the unread answer was cut: the connection has ended, short of the answer" \
    "$([ $rc -ne 124 ] && [ "$n" -lt 8000000 ] && echo cut || echo "not cut: $n bytes, exit $rc")" cut
  eval "exec $fd>&- $fd<&-"
done

# eight clients that read nothing: how many answers the server holds for them at once
n0=$(seen 1)
m0=$(docker exec "$PREFIX-studio" cat /sys/fs/cgroup/memory.current)
for fd in 10 11 12 13 14 15 16 17; do stall $fd $A "$(TA)"; done
sleep 5
check 5.10 "eight statements whose clients read nothing: sent and answered within 5 s" "$(($(seen 1) - n0))" 2
m1=$(docker exec "$PREFIX-studio" cat /sys/fs/cgroup/memory.current)
for fd in 10 11 12 13 14 15 16 17; do eval "exec $fd>&- $fd<&-"; done
check 5.11 "the clients have gone: the project's slots are free" "$(size)" "200 8000000"

# --- 6. the connection-string vectors
VECTORS=$ROOT/internal/dashcfg/testdata/dsn.json
PGMETA_IMAGE=public.ecr.aws/supabase/postgres-meta:$(awk '$1 == "postgres-meta" { print $2 }' "$HERE/../PIN")
if ! docker image inspect "$PGMETA_IMAGE" >/dev/null 2>&1; then
  row 6.0 "the pinned postgres-meta image $PGMETA_IMAGE" "not loaded on this host (it is not pulled here)" FAIL
else
  # each accepted string, read by the parser the image's database client reads it with: the
  # login, the password, the proxy's address, the project's port, the database, no TLS — and
  # no other member with a value. postgres-meta does not hand the parser the string as it
  # arrives: it takes sslmode out of it first (and sets the client's TLS option from it), so
  # the string is read both ways, as it arrives and as postgres-meta rewrites it.
  docker run --rm -i "${L[@]}" --network none --entrypoint node "$PGMETA_IMAGE" -e '
    const { createRequire } = require("module")
    const { parse } = createRequire(require.resolve("pg"))("pg-connection-string")
    const v = JSON.parse(require("fs").readFileSync(0, "utf8"))
    v.accepted.forEach((a, i) => {
      const want = {
        user: a.login,
        password: decodeURIComponent(/^postgresql:\/\/[^:]+:([^@]*)@/.exec(a.dsn)[1]),
        host: v.pgcap,
        port: String(v.meta_port_lo + a.subnet_index),
        database: "postgres",
        ssl: false,
        sslmode: "disable",
      }
      const read = (s) => Object.entries(parse(s)).filter(([, x]) => x !== undefined && x !== null && x !== "")
      const held = read(a.dsn)
      const same = (x) => JSON.stringify([...x].sort())
      const u = new URL(a.dsn)
      const mode = u.searchParams.get("sslmode")
      for (const k of ["sslmode", "sslca", "sslkey", "sslcert", "sslrootcert"]) u.searchParams.delete(k)
      const { ssl, sslmode, ...rewritten } = want
      const ok = same(held) === same(Object.entries(want)) && mode === "disable" &&
        same(read(u.toString())) === same(Object.entries(rewritten))
      console.log(`${i + 1}\t${a.login} at port ${want.port}\t${ok ? "as named" : "members: " + held.map(([k]) => k).sort()}`)
    })' <"$VECTORS" >"$T/parsed" 2>"$T/parsed.err" || echo "0	the parser	$(sed -n 1p "$T/parsed.err")" >"$T/parsed"
  check 6.0 "accepted vectors read by the parser of $PGMETA_IMAGE ($(docker image inspect -f '{{.Id}}' "$PGMETA_IMAGE" | cut -c8-19))" \
    "$(grep -c . "$T/parsed")" "$(grep -c '"login"' "$VECTORS")"
  # the rewrite above is postgres-meta's own, in the pinned image: when its code changes, this row fails
  check 6.0.1 "the pinned postgres-meta rewrites the string so: its two lines, found in its database module" \
    "$(docker run --rm "${L[@]}" --network none --entrypoint sh "$PGMETA_IMAGE" -c 'grep -c -F -e "new URL(config.connectionString)" -e "u.searchParams.delete('"'"'sslmode'"'"')" dist/lib/db.js' 2>/dev/null)" 2
  while IFS=$'\t' read -r i what got; do
    check "6.1.$i" "accepted vector $i, $what: what the pinned parser reads" "$got" "as named"
  done <"$T/parsed"
fi

# Every vector as a project of the control plane's stand-in: an accepted one is sent to
# postgres-meta with the login and the port it names; a refused one is never sent.
docker run --rm -i "${L[@]}" --network none "$NODE_BASE" node -e '
  const v = JSON.parse(require("fs").readFileSync(0, "utf8"))
  const [iss, at] = process.argv.slice(1)
  const table = {}
  const list = []
  const add = (kind, i, dsn, login, port) => {
    const ref = (kind + "vector").padEnd(20 - String(i).length, "0") + i
    const ro = login === "supabase_read_only_user"
    table[ref] = {
      members: [{ iss, sub: "v", role: ro ? "read_only" : "owner" }],
      resolve: {
        ref, name: "v", state: "active", db_version: "17.6.1", pg_meta: 0, [ro ? "dsn_ro" : "dsn_rw"]: dsn,
        api_url: `https://${ref}.spmark.example`,
        data_api: { schemas: ["public"], extra_search_path: [], max_rows: null }, generation: 1, at,
      },
      keys: { anon_key: "k", signing_keys: [] },
    }
    list.push([kind, i, ref, ro ? "read_only" : "owner", login ?? "", port ?? ""].join("\t"))
  }
  v.accepted.forEach((a, i) => add("a", i + 1, a.dsn, a.login, v.meta_port_lo + a.subnet_index))
  v.refused.forEach((r, i) => add("r", i + 1, r.dsn))
  console.log(JSON.stringify(table))
  console.error(list.join("\n"))' "$ISS" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" <"$VECTORS" >"$T/vectors.json" 2>"$T/vectors.tsv" &&
  cat "$T/vectors.json" >"$T/table.json" && socket && stubs --delay-ms 0 ||
  { echo "bounds.sh: the stand-ins did not restart with the vectors" >&2; exit 1; }
n0=$(seen)
refused=0 unsent=0
while IFS=$'\t' read -r kind i ref role login port; do
  got=$(sql "$ref" "$(tok "$ref" v "$role")")
  if [ "$kind" = a ]; then
    check "6.2.$i" "accepted vector $i through the server: the login and port postgres-meta is sent" "$got" "200 $login:$port"
    n0=$((n0 + 1))
  else
    refused=$((refused + 1))
    [ "$got" = "503 project_unavailable" ] && unsent=$((unsent + 1)) || row "6.3.$i" "refused vector $i" "$got" FAIL
  fi
done <"$T/vectors.tsv"
check 6.3 "refused vectors: each answered 503 project_unavailable ($refused of the file's $(grep -c '"why"' "$VECTORS"))" "$unsent" "$(grep -c '"why"' "$VECTORS")"
check 6.4 "... and postgres-meta received nothing for them" "$(($(seen) - n0))" 0

echo
echo "memory of the server before and with the unread answers of 5.10: $((m0 / 1048576)) MiB, $((m1 / 1048576)) MiB"
finish
