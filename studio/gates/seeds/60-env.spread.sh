#!/usr/bin/env bash
# Seed of 60-env: process.env spread into an object.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = { ...process.env };
JS
