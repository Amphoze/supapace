#!/usr/bin/env bash
# Seed of 50-routes: a server function whose id has the shape of a ref (classified, so only that
# check can fail).
cat >"$1/output/server/_ssr/sp-seed-fn.mjs" <<'JS'
var manifest = { "Abcdefghij0123456789": { functionName: "seedFn", importer: () => import("./sp-seed-fn.mjs") } };
var seedFn = createServerFn().handler(seedFn, () => null);
JS
printf 'function\tAbcdefghij0123456789\tGET\tserved\tn\t-\n' >>"$1/routes.tsv"
