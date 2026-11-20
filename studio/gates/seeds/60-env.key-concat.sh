#!/usr/bin/env bash
# Seed of 60-env: a computed read whose key is built from pieces.
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
const k = 'SP_' + 'SEED'; export const a = process.env[k];
JS
