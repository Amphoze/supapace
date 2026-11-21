#!/usr/bin/env bash
# 45-paths DIR — fails when the built server reads a request path otherwise than the committed
# vectors say. ../prove/paths.mjs starts the build's own server (DIR/output), in a container of
# the pinned Node base without a network, sends it the paths of DIR/paths.in and those it
# derives from every route of the built route tree, and records the URL the server's parser
# left, the segments its router matched on and the route found; the result is compared byte for
# byte with DIR/paths.json. The gateway's rules are tested against that file
# (internal/gateway/dash_paths_test.go), so a pin or a patch that changes how the server reads
# or routes a path — or that adds, removes or renames a route — cannot build until the file is
# regenerated (`build.sh paths`) and that test has been run on it. The generator itself fails
# when the request guard's reading of a path is not the router's. It is given 600 s.
# Inputs, none of which may be empty:
#   DIR/paths.in     the fixed paths (studio/prove/paths.in)
#   DIR/paths.json   the committed vectors (studio/prove/paths.json)
#   DIR/output       the build's output directory
set -euo pipefail
d=$(cd "$1" && pwd)
g=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
node_base=$(awk '$1 == "node" { print $2 }' "$g/../PIN")
for f in paths.in paths.json; do
  [ -s "$d/$f" ] || { echo "45-paths: $f is empty or missing" >&2; exit 1; }
done
[ -n "$(ls -A "$d/output/server" 2>/dev/null)" ] || { echo "45-paths: output/server is empty or missing" >&2; exit 1; }
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT

docker run --rm -i --label supapace.build=studio --network none --memory 2g \
  -v "$g/../prove:/prove:ro" -v "$d/output:/srv:ro" "$node_base" \
  timeout 600 node /prove/paths.mjs /srv <"$d/paths.in" >"$t/built.json" 2>"$t/log" || {
  rc=$?
  [ $rc != 124 ] || echo "45-paths: the generator did not end within 600 s" >&2
  echo "45-paths: the vectors could not be generated:" >&2
  grep '^paths.mjs: ' "$t/log" >&2 || tail -5 "$t/log" >&2
  exit 1
}
if ! cmp -s "$t/built.json" "$d/paths.json"; then
  echo "45-paths: the built server reads paths otherwise than studio/prove/paths.json says ($(wc -l <"$t/built.json") lines built, $(wc -l <"$d/paths.json") committed); the first differences:" >&2
  diff "$d/paths.json" "$t/built.json" | grep '^[<>]' | sed -n '1,6p' | cut -c1-240 | sed 's/^</  committed:/; s/^>/  built:    /' >&2
  exit 1
fi
