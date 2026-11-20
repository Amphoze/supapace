#!/usr/bin/env bash
# Seed of 60-env: a read through a namespace import of the process module.
cat > "$1/output/server/_ssr/sp-seed.mjs" <<'JS'
import * as P from 'node:process'; export const a = P.env.SP_SEED_NAME;
JS
