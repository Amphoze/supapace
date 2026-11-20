#!/usr/bin/env bash
# Seed of 60-env: the process module reached by a dynamic import.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export async function a() { return (await import('node:process')).env.SP_SEED_NAME; }
JS
