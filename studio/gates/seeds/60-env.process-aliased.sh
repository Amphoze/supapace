#!/usr/bin/env bash
# Seed of 60-env: the process object assigned to another name, its env read through it.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
const p = globalThis.process; export const a = p.env.SP_SEED_NAME;
JS
