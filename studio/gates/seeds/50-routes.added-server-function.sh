#!/usr/bin/env bash
# Seed of 50-routes: a server function nobody classified, with its manifest entry.
cat >"$1/output/server/_ssr/sp-seed-fn.mjs" <<'JS'
var manifest = { "00000000000000000000000000000000000000000000000000000000000000ff": { functionName: "seedFn", importer: () => import("./sp-seed-fn.mjs") } };
var seedFn = createServerFn({ method: "POST" }).handler(seedFn, () => null);
JS
