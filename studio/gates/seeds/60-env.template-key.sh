#!/usr/bin/env bash
# Seed of 60-env: a computed read with a template literal key.
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = process.env[`SP_SEED_NAME`];
JS
