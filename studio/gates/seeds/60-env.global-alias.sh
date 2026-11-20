#!/usr/bin/env bash
# Seed of 60-env: the process object reached through an alias of the global object.
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
const g = globalThis; export const a = g.process.env.SP_SEED_NAME;
JS
