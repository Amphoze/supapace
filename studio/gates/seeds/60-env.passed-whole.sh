#!/usr/bin/env bash
# Seed of 60-env: process.env passed to a function as a whole.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = (f) => f(process.env);
JS
