#!/usr/bin/env bash
# Seed of 60-env: the process module reached by the built-in module getter.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = globalThis.process.getBuiltinModule('process').env.SP_SEED_NAME;
JS
