#!/usr/bin/env bash
# Seed of 60-env: the environment member reached by a computed key built from pieces (red until fixed).
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = process['e' + 'nv'].SP_SEED_NAME;
JS
