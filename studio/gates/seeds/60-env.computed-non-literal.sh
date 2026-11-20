#!/usr/bin/env bash
# Seed of 60-env: a computed read of process.env that is not a literal.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = (k) => process.env[k];
JS
