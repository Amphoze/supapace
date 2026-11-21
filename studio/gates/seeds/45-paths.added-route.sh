#!/usr/bin/env bash
# Seed of 45-paths: a route tree with one more route. The built route tree gains an API route
# no vector knows.
set -euo pipefail
f=$(grep -l '_addFileChildren(rootRouteChildren)' "$1"/output/server/_ssr/*.mjs)
root=$(sed -n 's/^var routeTree = \([A-Za-z0-9_$]*\)\._addFileChildren(rootRouteChildren).*/\1/p' "$f")
[ -n "$root" ] && grep -q '^var rootRouteChildren = {$' "$f"
sed -i "s|^var rootRouteChildren = {\$|var SpSeedRoute = createFileRoute(\"/api/sp-seed\")({ server: { handlers: { GET: () => new Response() } } }).update({ id: \"/api/sp-seed\", path: \"/api/sp-seed\", getParentRoute: () => $root });\nvar rootRouteChildren = {\n\tSpSeedRoute,|" "$f"
grep -q 'SpSeedRoute,' "$f"
