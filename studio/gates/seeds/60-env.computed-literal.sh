#!/usr/bin/env bash
# Seed of 60-env: a name read as process.env["NAME"] that env.tsv does not list.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = process.env["SP_SEED_NAME"];
JS
