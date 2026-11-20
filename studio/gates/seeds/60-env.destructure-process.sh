#!/usr/bin/env bash
# Seed of 60-env: the environment reached by destructuring the process object.
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
const { env: e } = process; export const a = e.SP_SEED_NAME;
JS
