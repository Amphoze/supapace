#!/usr/bin/env bash
# Seed of 60-env: the process object reached by a computed key on the global object (red until fixed).
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = globalThis['pro' + 'cess'].env.SP_SEED_NAME;
JS
