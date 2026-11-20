#!/usr/bin/env bash
# Seed of 60-env: the process object reached through a conditional choice of the global object.
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = (typeof globalThis === 'object' ? globalThis : global).process.env.SP_SEED_NAME;
JS
