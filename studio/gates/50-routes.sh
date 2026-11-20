#!/usr/bin/env bash
# 50-routes DIR — fails when the build serves something DIR/routes.tsv does not list, or lists
# something differently. The build's side is generated from its own outputs by manifest.mjs, in
# a container of the pinned Node base with the bundler's parser: the regenerated route tree
# (API and page routes), the server bundle's route registrations (their methods) and the
# bundler's server-function manifest (function ids and methods); nothing is read from the
# source tree. Both sides are compared as sorted lists, both directions. It also fails on:
#   - a row of another shape, or an entry listed twice (a deleted row the build serves is
#     a difference of the two lists);
#   - a disagreement with the gateway's dashboard rules: a row is "api" exactly when its first
#     path segment, lower-cased, is "api" (an API path to the gateway), and it is "opt-in"
#     exactly when its second, lower-cased, is "ai" or "mcp" (the paths the gateway refuses);
#   - a static path segment of a route, a path segment of a public file or a server-function
#     id that has the shape of a ref once lower-cased (20 of [a-z0-9]);
#   - the server's own (Nitro) router routing anything but /** to the SSR renderer, or a route
#     rule of it other than headers; route handlers assigned after registration.
# Limits: the public files are held only by their names' shape (a GET or HEAD of an existing
# public file is answered outside the middleware chain, and their list is not a table); route
# handlers changed by anything other than an assignment to options.server(.handlers) are not
# seen; code compiled at run time is outside any syntax walk.
# Inputs, none of which may be empty:
#   DIR/routes.tsv          the table (comments with #): KIND ID METHODS CLASS REF PHASE, tabs
#   DIR/routeTree.gen.ts    the route tree as the build regenerated it
#   DIR/output/server       the server bundle; DIR/output/public the public files
#   DIR/parser              the bundler's parser, as the build exported it
set -euo pipefail
d=$(cd "$1" && pwd)
g=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
node_base=$(awk '$1 == "node" { print $2 }' "$g/../PIN")
fail() { echo "50-routes: $*" >&2; bad=1; }
bad=0
for f in routes.tsv routeTree.gen.ts; do
  [ -s "$d/$f" ] || { echo "50-routes: $f is empty or missing" >&2; exit 1; }
done
for f in output/server output/public parser; do
  [ -n "$(ls -A "$d/$f" 2>/dev/null)" ] || { echo "50-routes: $f is empty or missing" >&2; exit 1; }
done
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT

docker run --rm --label supapace.build=studio --network none --memory 2g \
  -v "$g:/g:ro" -v "$d/parser:/p:ro" -v "$d/routeTree.gen.ts:/rt.ts:ro" -v "$d/output/server:/s:ro" \
  "$node_base" node /g/manifest.mjs /p /rt.ts /s >"$t/built.all" ||
  { echo "50-routes: the manifest could not be generated" >&2; exit 1; }
if grep '^error' "$t/built.all" | sed 's/^error\t/50-routes: /' >&2; then exit 1; fi
LC_ALL=C sort -u "$t/built.all" >"$t/built"
[ -s "$t/built" ] || { echo "50-routes: the build serves nothing" >&2; exit 1; }

# the table, checked row by row; the rows the build must serve, and the deleted ones
: >"$t/table" && : >"$t/deleted"
while IFS=$'\t' read -r kind id methods class ref phase extra; do
  case $kind in '' | '#'*) continue ;; esac
  row="$kind $id"
  [ -z "$extra" ] && [ -n "$phase" ] || { fail "row \"$row\": not six columns"; continue; }
  case $kind in api | page | function) ;; *) fail "row \"$row\": kind $kind" ;; esac
  case $class/$phase in served/- | opt-in/P1 | opt-in/P2 | opt-in/never | deleted/P1 | deleted/P2 | deleted/never) ;;
  *) fail "row \"$row\": class $class with phase $phase" ;; esac
  [[ $methods =~ ^(-|[A-Z]+(,[A-Z]+)*)$ ]] || fail "row \"$row\": methods $methods"
  [[ $ref =~ ^[yn]$ ]] || fail "row \"$row\": ref $ref"
  if [ "$kind" != function ]; then
    IFS=/ read -r -a seg <<<"${id#/}"
    first=$(tr 'A-Z' 'a-z' <<<"${seg[0]:-}") second=$(tr 'A-Z' 'a-z' <<<"${seg[1]:-}")
    if [ "$kind" = page ] && [ "$first" = api ]; then fail "row \"$row\": a page the gateway takes for an API path"; fi
    optin=n
    [ "$first" = api ] && { [ "$second" = ai ] || [ "$second" = mcp ]; } && optin=y
    if [ "$class" = opt-in ] && [ $optin = n ]; then fail "row \"$row\": opt-in outside /api/ai and /api/mcp"; fi
    if [ "$class" = served ] && [ $optin = y ]; then fail "row \"$row\": served under /api/ai or /api/mcp, which the gateway refuses"; fi
  fi
  if [ "$class" = deleted ]; then
    printf '%s\t%s\n' "$kind" "$id" >>"$t/deleted"
  else
    printf '%s\t%s\t%s\t%s\n' "$kind" "$id" "$methods" "$ref" >>"$t/table"
  fi
done <"$d/routes.tsv"
LC_ALL=C sort -o "$t/table" "$t/table"
dup=$(cat "$t/table" "$t/deleted" | cut -f1,2 | LC_ALL=C sort | uniq -d)
[ -z "$dup" ] || fail "rows listed twice: $(echo "$dup" | tr '\t\n' '  ')"

only_built=$(LC_ALL=C comm -23 "$t/built" "$t/table")
only_table=$(LC_ALL=C comm -13 "$t/built" "$t/table")
if [ -n "$only_built" ]; then
  fail "the build serves what routes.tsv does not list so:"
  echo "$only_built" | sed 's/^/  built: /' >&2
fi
if [ -n "$only_table" ]; then
  fail "routes.tsv lists what the build does not serve so:"
  echo "$only_table" | sed 's/^/  table: /' >&2
fi

# the shape of a ref, once lower-cased, in a static route segment, a public file's path or a
# function id
refshaped() { tr 'A-Z' 'a-z' | grep -E '^[a-z0-9]{20}$' || true; }
while IFS=$'\t' read -r kind id _; do
  if [ "$kind" = function ]; then
    s=$(refshaped <<<"$id")
  else
    s=$(tr '/' '\n' <<<"$id" | grep -v '^\$' | refshaped)
  fi
  [ -z "$s" ] || fail "$kind $id has a segment with the shape of a ref"
done <"$t/built"
s=$(cd "$d/output/public" && find . -mindepth 1 | sed 's|^\./||' | tr '/' '\n' | refshaped | sort -u)
[ -z "$s" ] || fail "public files with a path segment of the shape of a ref: $(echo "$s" | tr '\n' ' ')"
exit $bad
