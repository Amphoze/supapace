#!/usr/bin/env bash
# Seed of 50-routes: a route of the server's own router, outside the route tree (red until the manifest reads it).
perl -0pi -e 's#\treturn \(\(_m, p\) => \{\n\t\treturn \{\n\t\t\tdata,#\treturn ((_m, p) => {\n\t\tif (p === "/api/sp-seed") return { data: { route: "/api/sp-seed", handler: defineLazyEventHandler(() => import("./_chunks/sp-seed.mjs")) }, params: {} };\n\t\treturn {\n\t\t\tdata,#' "$1/output/server/index.mjs"
grep -q 'sp-seed' "$1/output/server/index.mjs"
echo 'export default () => new Response("seed")' > "$1/output/server/_chunks/sp-seed.mjs"
