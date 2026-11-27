#!/usr/bin/env bash
# manifest.sh IMAGE — no route of the built image answers without the request guard. The list
# of what the image serves is taken from the image's own route tree and server bundle
# (paths.mjs --routes, run in a container of the image) and must be the non-deleted rows of
# ../routes.tsv. Against the stand-ins of stand-ins.bash, as the owner of project A:
#   - every API route (each of its methods), every page and every server function answers 401
#     without an assertion;
#   - with a valid assertion, every route with a $ref answers 404 when that position holds
#     another project's ref, as written and in capitals;
#   - every route that is not served (under /api/ai, /api/mcp) answers 404, as written,
#     percent-encoded, in capitals and with a trailing slash, and so do the bare paths;
#   - every deleted row of routes.tsv answers the guard's 404 for every method, with and
#     without a trailing slash: no page, no redirect, no 406;
#   - every served API route answers 405 with Allow for a method it does not list;
#   - and the controls: with a valid assertion every served API route is answered by its own
#     handler, and every page by the application — whose HTML holds no value of the project:
#     neither one the control plane answered nor one of the process's own settings, all of
#     them marked for this. No route answers a value of the process any more, so the control
#     plants them: each marked setting, read from the server container's own environment,
#     is appended to a page the server answered, and the search must find every one.
# A row is one request; a row that is answered otherwise fails the proof, and so does a row
# that was started and left no line. Prints the failed rows and the count of rows by kind and
# answer; exits 1 when a row fails.
. "$(dirname "${BASH_SOURCE[0]}")/stand-ins.bash"
standins_up "${1:?usage: manifest.sh IMAGE}" || { echo "manifest.sh: the image or a stand-in did not start" >&2; exit 1; }

docker run --rm -i "${L[@]}" --network none --memory 2g --entrypoint node -v "$HERE:/prove:ro" "$IMAGE" \
  /prove/paths.mjs /app/apps/studio/.output --routes >"$T/built" 2>"$T/built.log" ||
  { echo "manifest.sh: the image's routes could not be listed:" >&2; tail -3 "$T/built.log" >&2; exit 1; }
awk -F'\t' '$1 ~ /^(api|page|function)$/ && $4 != "deleted" { print $1 "\t" $2 "\t" ($1 == "function" ? "-" : $3) }' \
  "$HERE/../routes.tsv" | LC_ALL=C sort >"$T/table"
if ! diff <(LC_ALL=C sort "$T/built") "$T/table" >"$T/diff"; then
  echo "manifest.sh: the image serves otherwise than routes.tsv lists:" >&2
  sed -n '1,10p' "$T/diff" >&2
  exit 1
fi
awk -F'\t' '$1 == "api" && $4 == "deleted" { print $2 }' "$HERE/../routes.tsv" >"$T/deleted"
[ -s "$T/deleted" ] || { echo "manifest.sh: routes.tsv has no deleted row" >&2; exit 1; }

fill() { printf '%s' "$1" | sed "s/\\\$ref/$2/g; s/\\\$[A-Za-z]*/x1/g"; } # fill PATH REF
upper() { printf '%s' "$1" | tr a-z A-Z; }
METHODS='GET HEAD POST PUT PATCH DELETE OPTIONS'

# one METHOD PATH [TOKEN] [curl args] — "<status> <what>"; a HEAD has no body to tell more
one() {
  if [ "$1" = HEAD ]; then
    local t=${3:-}
    printf '%s -' "$(curl -s --path-as-is -m 30 -o /dev/null -w '%{http_code}' --head "$U$2" ${t:+-H "X-Supapace-Assertion: $t"})"
  else
    ask "$@"
  fi
}
# allowed METHOD PATH TOKEN — "<status> <the Allow header>"
allowed() {
  local how=(-X "$1")
  [ "$1" = HEAD ] && how=(--head)
  curl -s --path-as-is -m 30 -o /dev/null -D - "${how[@]}" "$U$2" -H "X-Supapace-Assertion: $3" | tr -d '\r' |
    awk 'NR == 1 { s = $2 } tolower($1) == "allow:" { sub(/^[^:]*: */, ""); a = $0 } END { print s " " a }'
}
# The rows are run eight at a time; each writes one line KIND<TAB>ANSWER<TAB>VERDICT<TAB>ROW.
: >"$T/rows"
running=0 launched=0
put() { # put KIND ANSWER VERDICT ROW — a row of the proof's own making
  launched=$((launched + 1))
  printf '%s\t%s\t%s\t%s\n' "$@" >>"$T/rows"
}
row_() { # row_ KIND WANT METHOD PATH [TOKEN] [curl args] — WANT is a pattern of the answer
  local kind=$1 want=$2 run=one
  shift 2
  [ "$kind" = "api, a method the route does not list" ] && run=allowed
  launched=$((launched + 1))
  (
    got=$($run "$@")
    # shellcheck disable=SC2254
    case $got in $want) v=ok ;; *) v=FAIL ;; esac
    printf '%s\t%s\t%s\t%s %s (want: %s)\n' "$kind" "$got" "$v" "$1" "$2" "$want" >>"$T/rows"
  ) &
  running=$((running + 1))
  if [ $running -ge 8 ]; then
    wait
    running=0
  fi
}
# A fresh assertion every 20 s of the run.
minted=0
own() {
  if [ $((SECONDS - minted)) -ge 20 ] || [ -z "${TOKEN:-}" ]; then
    wait
    running=0
    TOKEN=$(tok $A oa owner '' 0 55)
    minted=$SECONDS
  fi
}
foreign() { # foreign PATH — one line per $ref position: that one filled with B, the others with A
  awk -v p="$1" -v a="$A" -v b="$B" 'BEGIN {
    n = split(p, s, "/")
    for (i = 2; i <= n; i++) if (s[i] == "$ref") {
      out = ""
      for (j = 2; j <= n; j++) out = out "/" (j == i ? b : (s[j] == "$ref" ? a : (s[j] ~ /^\$/ ? "x1" : s[j])))
      print out
    }
  }'
}

while IFS=$'\t' read -r kind id methods; do
  own
  case $kind in
  function)
    for m in GET POST; do
      row_ "function, no assertion" '401 bad_assertion' $m "/_serverFn/$id" '' -H 'x-tsr-serverfn: true'
      row_ "function, another project's ref after it" '404 not_found' $m "/_serverFn/$id/$B" "$TOKEN" -H 'x-tsr-serverfn: true'
    done
    row_ "function, its own answer (control)" '200 *' GET "/_serverFn/$id" "$TOKEN" -H 'x-tsr-serverfn: true'
    ;;
  page)
    p=$(fill "$id" $A)
    row_ "page, no assertion" '401 bad_assertion' GET "$p" '' -H 'Accept: text/html'
    while IFS= read -r f; do
      row_ "page, another project's ref" '404 not_found' GET "$f" "$TOKEN" -H 'Accept: text/html'
      row_ "page, another project's ref in capitals" '404 not_found' GET "$(printf %s "$f" | sed "s/$B/$(upper $B)/")" "$TOKEN" -H 'Accept: text/html'
    done < <(foreign "$id")
    ;;
  api)
    p=$(fill "$id" $A)
    second=$(printf '%s' "$id" | cut -d/ -f3)
    for m in ${methods//,/ }; do
      row_ "api, no assertion" '401 bad_assertion' $m "$p" ''
    done
    if [ "$second" = ai ] || [ "$second" = mcp ]; then
      enc="/%61pi/$(printf %s "${p#/api/}" | sed 's/^a/%61/; s/^m/%6d/')"
      for f in "$p" "$(upper "$p")" "$enc" "${p%/}/" "/Api/${p#/api/}"; do
        for m in GET POST; do
          row_ "api not served, as written, encoded, in capitals, with a slash" '404 not_found' $m "$f" "$TOKEN"
        done
      done
      continue
    fi
    while IFS= read -r f; do
      for m in ${methods//,/ }; do
        row_ "api, another project's ref" '404 not_found' $m "$f" "$TOKEN"
        row_ "api, another project's ref in capitals" '404 not_found' $m "$(printf %s "$f" | sed "s/$B/$(upper $B)/")" "$TOKEN"
      done
    done < <(foreign "$id")
    allow=$(printf '%s\n' "$methods" | tr ',' '\n' | { cat; case ",$methods," in *,GET,*) echo HEAD ;; esac; } | sort -u | paste -sd, | sed 's/,/, /g')
    for m in $METHODS; do
      case ",$methods," in *",$m,"*) continue ;; esac
      [ "$m" = HEAD ] && case ",$methods," in *,GET,*) continue ;; esac
      row_ "api, a method the route does not list" "405 $allow" $m "$p" "$TOKEN"
    done
    ;;
  esac
done <"$T/built"

for bare in /api/ai /api/mcp /API/AI /api/Mcp /api/ai/ /api/mcp/x /api/ai/sql; do
  own
  for m in GET POST; do
    row_ "api not served, a bare path" '404 not_found' $m "$bare" "$TOKEN"
  done
done
while IFS= read -r id; do
  own
  p=$(fill "$id" $A)
  for m in $METHODS; do
    want='404 not_found'
    [ "$m" = HEAD ] && want='404 -'
    row_ "api deleted" "$want" $m "${p%/}" "$TOKEN" -H 'Accept: text/html'
    row_ "api deleted, with a trailing slash" "$want" $m "${p%/}/" "$TOKEN" -H 'Accept: application/json'
  done
done <"$T/deleted"
wait

# The controls, one at a time. First what a served route answers when the guard lets it
# through: the guard's own refusals all have a body of exactly {code, message} with one of
# these codes.
guarded='^(401 bad_assertion|404 not_found|405 method_not_allowed)$'
while IFS=$'\t' read -r kind id methods; do
  [ "$kind" = api ] || continue
  second=$(printf '%s' "$id" | cut -d/ -f3)
  [ "$second" = ai ] || [ "$second" = mcp ] && continue
  own
  p=$(fill "$id" $A) m=${methods%%,*}
  got=$(ask "$m" "$p" "$TOKEN" -H 'Content-Type: application/json' $([ "$m" = GET ] || [ "$m" = DELETE ] || printf '%s' '-d {}'))
  if printf '%s' "$got" | grep -qE "$guarded"; then v=FAIL; else v=ok; fi
  put 'api, its own answer (control)' "$(printf '%s' "$got" | cut -d' ' -f1) its own" "$v" "$m $p: $got"
done <"$T/built"
logged() { # logged — the server's log so far: it has lines, and none holds a credential
  docker logs "$PREFIX-studio" >"$T/log" 2>&1
  local n
  n=$(wc -l <"$T/log")
  put 'server log, has lines (control)' "$([ "$n" -gt 0 ] && echo yes || echo none)" "$([ "$n" -gt 0 ] && echo ok || echo FAIL)" -
  n=$(grep -c -e 'v1\.ey' -e postgresql: -e spmark "$T/log")
  put 'server log, lines with an assertion, a connection string or a marked value' "$n" "$([ "$n" = 0 ] && echo ok || echo FAIL)" -
}
logged

# Then the pages, on a server whose own settings are marked too — the names the application
# still takes from the process. With a valid assertion every page is answered by the
# application, and its HTML holds no marked value: none the control plane answered for the
# project, none of the process. That the marks are in the process and that the search finds
# them is the control: no route answers one, so each is planted — read from the container's
# environment as a process started in it sees it, and appended to a page the server answered.
PLANTED='spmarkurl spmarkPassword spmarkpghost spmarkdb'
studio -e SUPABASE_URL=http://spmarkurl -e POSTGRES_PASSWORD=spmarkPassword \
  -e POSTGRES_HOST=spmarkpghost -e POSTGRES_DB=spmarkdb ||
  { echo "manifest.sh: the server did not restart" >&2; exit 1; }
# a marked value, the wire proxy's address, or the address of a postgres-meta instance
META_ADDRS=$(printf '%s' "$META" | sed 's/http:\/\///g; s/:8080//g; s/\./\\./g; s/,/\\|/g')
marked() { grep -i -c -e spmark -e '10\.212\.' -e "$META_ADDRS" "$1"; }
own
curl -s --path-as-is -m 60 -o "$T/page" "$U/project/$A" -H "X-Supapace-Assertion: $TOKEN" -H 'Accept: text/html'
docker exec "$PREFIX-studio" node -e 'for (const [k, v] of Object.entries(process.env)) console.log(k + "=" + v)' >"$T/env"
n=0
for m in $PLANTED; do
  { cat "$T/page" && grep -F -- "$m" "$T/env"; } >"$T/planted"
  [ "$(marked "$T/planted")" -gt 0 ] && n=$((n + 1))
done
put 'a marked value of the process, planted in a page: the search finds it (control)' "$n of 4, the page alone: $(marked "$T/page")" "$([ "$n" = 4 ] && [ "$(marked "$T/page")" = 0 ] && echo ok || echo FAIL)" "GET /project/$A"
while IFS=$'\t' read -r kind id methods; do
  [ "$kind" = page ] || continue
  own
  p=$(fill "$id" $A)
  curl -s --path-as-is -m 60 -o "$T/page" -w '%{http_code} %{content_type}' "$U$p" -H "X-Supapace-Assertion: $TOKEN" -H 'Accept: text/html' >"$T/page.status"
  got=$(cut -d';' -f1 <"$T/page.status")
  n=$(marked "$T/page")
  case "$got/$n" in '200 text/html/0' | 30[1278]\ */0) v=ok ;; *) v=FAIL ;; esac
  put 'page, the application answers and its HTML holds no marked value' "$got, values: $n" "$v" "GET $p"
done <"$T/built"
logged

echo '| kind | answer | rows | |'
echo '|---|---|---|---|'
cut -f1-3 "$T/rows" | LC_ALL=C sort | uniq -c | sed 's/^ *\([0-9]*\) /\1\t/' |
  awk -F'\t' '{ printf "| %s | %s | %d | %s |\n", $2, $3, $1, $4 }'
echo
if grep -q $'\tFAIL\t' "$T/rows"; then
  echo "failed rows:"
  grep $'\tFAIL\t' "$T/rows" | cut -f1,2,4 | sed -n '1,40p'
fi
rows=$(wc -l <"$T/rows") fails=$(grep -c $'\tFAIL\t' "$T/rows")
# every row that was started left its line, and every entry of the image's list had its rows
if [ "$rows" != "$launched" ] || [ "$rows" -lt "$(wc -l <"$T/built")" ]; then
  echo "rows started: $launched, rows written: $rows, entries of the image's list: $(wc -l <"$T/built")"
  fails=$((fails + 1))
fi
finish
