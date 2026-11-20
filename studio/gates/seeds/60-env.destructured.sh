#!/usr/bin/env bash
# Seed of 60-env: a name read by destructuring process.env that env.tsv does not list.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
const { SP_SEED_NAME } = process.env; export { SP_SEED_NAME };
JS
