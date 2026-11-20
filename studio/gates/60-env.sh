#!/usr/bin/env bash
# 60-env DIR — fails when the environment names the server bundle reads differ from
# DIR/env.tsv, when a read cannot be resolved to a name outside a file the table lists as
# dynamic, or when the table's set rows are not exactly the names in the server's process
# environment. The reads are found by envwalk.mjs, a walk of the syntax tree of every file of
# the server bundle with the bundler's own parser, in a container of the pinned Node base.
# The table (comments with #), tab-separated:
#   NAME  set              in the process environment: the agent's fixed names, the names of
#                          the image's label, Docker's HOSTNAME and HOME and the image's own ENV
#   NAME  unset            read, and never in the process environment
#   NAME  dynamic  FILE    FILE (as envwalk.mjs names it) has a read that cannot be resolved;
#                          NAME is one name it can yield, one row each: a name, a family
#                          PREFIX_*, * when it hands the whole environment on, - for none
# It fails on: a name read that is no set or unset row; an unset row nothing reads; an
# unresolved read in a file with no dynamic row, or a dynamic row of a file with none; set rows
# other than the process environment's names; a row of another shape or a name twice (so no
# name in the process environment can be an unset row).
# Inputs, none of which may be empty: DIR/env.tsv, DIR/output/server, DIR/parser,
# DIR/names.json (`sp-dashstub limits --names`), DIR/build-record.json (its env_label, the
# image's label) and DIR/image-env.txt (the names of the image's ENV).
set -euo pipefail
d=$(cd "$1" && pwd)
g=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
node_base=$(awk '$1 == "node" { print $2 }' "$g/../PIN")
fail() { echo "60-env: $*" >&2; bad=1; }
bad=0
for f in env.tsv names.json build-record.json image-env.txt; do
  [ -s "$d/$f" ] || { echo "60-env: $f is empty or missing" >&2; exit 1; }
done
for f in output/server parser; do
  [ -n "$(ls -A "$d/$f" 2>/dev/null)" ] || { echo "60-env: $f is empty or missing" >&2; exit 1; }
done
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT

docker run --rm --label supapace.build=studio --network none --memory 2g \
  -v "$g:/g:ro" -v "$d/parser:/p:ro" -v "$d/output/server:/s:ro" \
  "$node_base" node /g/envwalk.mjs /p /s >"$t/walk" ||
  { echo "60-env: the walk of the server bundle failed" >&2; exit 1; }
grep -q '^read' "$t/walk" || { echo "60-env: the walk found no read at all" >&2; exit 1; }

# the process environment: the agent's fixed names, the label's, Docker's, the image's ENV
{
  sed -n 's/.*"fixed":\[\([^]]*\)\].*/\1/p' "$d/names.json" | tr -d '"' | tr ',' '\n'
  grep -m1 '^ "env_label": ' "$d/build-record.json" | sed 's/^ "env_label": //' | grep -oE '"[^"]+":' | tr -d '":'
  printf '%s\n' HOSTNAME HOME
  cat "$d/image-env.txt"
} | grep -v '^$' | LC_ALL=C sort -u >"$t/process"
[ "$(grep -c . "$t/process")" -gt 4 ] || { echo "60-env: no fixed or label names" >&2; exit 1; }

: >"$t/set" && : >"$t/unset" && : >"$t/dynamic"
while IFS=$'\t' read -r name class file extra; do
  case $name in '' | '#'*) continue ;; esac
  [ -z "$extra" ] || { fail "row \"$name\": more than three columns"; continue; }
  case $class in
  set | unset)
    [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && [ -z "$file" ] || { fail "row \"$name $class\": not NAME $class"; continue; }
    echo "$name" >>"$t/$class" ;;
  dynamic)
    [[ $name =~ ^([A-Za-z_][A-Za-z0-9_]*\*?|\*|-)$ ]] && [ -n "$file" ] || { fail "row \"$name dynamic\": not NAME dynamic FILE"; continue; }
    printf '%s\t%s\n' "$file" "$name" >>"$t/dynamic" ;;
  *) fail "row \"$name\": class \"$class\"" ;;
  esac
done <"$d/env.tsv"
dup=$(cat "$t/set" "$t/unset" | LC_ALL=C sort | uniq -d)
[ -z "$dup" ] || fail "names listed twice: $(echo "$dup" | tr '\n' ' ')"
dup=$(LC_ALL=C sort "$t/dynamic" | uniq -d)
[ -z "$dup" ] || fail "dynamic rows listed twice: $(echo "$dup" | tr '\t\n' '  ')"

# set rows: exactly the process environment's names
diff=$(LC_ALL=C sort -u "$t/set" | LC_ALL=C comm -3 - "$t/process" | tr -d '\t' | tr '\n' ' ')
[ -z "$diff" ] || fail "the set rows differ from the process environment's names in: $diff"
# unset rows: read (a name both set and unset is a name twice, above)
awk -F'\t' '$1 == "read" { print $2 }' "$t/walk" | LC_ALL=C sort -u >"$t/read"
s=$(LC_ALL=C sort -u "$t/unset" | LC_ALL=C comm -23 - "$t/read" | tr '\n' ' ')
[ -z "$s" ] || fail "unset rows that nothing reads: $s"
# every name read is a row
s=$(cat "$t/set" "$t/unset" | LC_ALL=C sort -u | LC_ALL=C comm -13 - "$t/read")
if [ -n "$s" ]; then
  fail "names read that env.tsv does not list:"
  echo "$s" | while IFS= read -r n; do
    echo "  $n ($(awk -F'\t' -v n="$n" '$1 == "read" && $2 == n { print $3 }' "$t/walk" | sed -n 1,3p | tr '\n' ' '))" >&2
  done
fi
# unresolved reads only in the files with dynamic rows, and every such file has one
awk -F'\t' '$1 == "unresolved" { print $2 }' "$t/walk" | LC_ALL=C sort -u >"$t/unresolved"
cut -f1 "$t/dynamic" | LC_ALL=C sort -u >"$t/dynfiles"
s=$(LC_ALL=C comm -23 "$t/unresolved" "$t/dynfiles")
if [ -n "$s" ]; then
  fail "reads that cannot be resolved to a name, in files with no dynamic row:"
  grep -F -f <(echo "$s" | sed 's/^/unresolved\t/; s/$/\t/') "$t/walk" | cut -f2,3 | sed 's/^/  /' >&2
fi
s=$(LC_ALL=C comm -13 "$t/unresolved" "$t/dynfiles" | tr '\n' ' ')
[ -z "$s" ] || fail "dynamic rows of files with no unresolved read: $s"
exit $bad
