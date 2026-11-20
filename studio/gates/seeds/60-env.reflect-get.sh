#!/usr/bin/env bash
# Seed of 60-env: the environment object passed to a function.
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
export const a = Reflect.get(process.env, 'SP_SEED_NAME');
JS
