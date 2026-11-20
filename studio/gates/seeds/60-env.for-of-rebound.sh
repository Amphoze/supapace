#!/usr/bin/env bash
# Seed of 60-env: a constant key rebound by a for-of loop.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
let k = 'HOME'; for (k of ['SP_SEED_NAME']) process.env[k];
JS
