#!/usr/bin/env bash
# Seed of 60-env: a name read as import.meta.env.NAME that env.tsv does not list.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = import.meta.env.SP_SEED_NAME;
JS
