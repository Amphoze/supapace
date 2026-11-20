#!/usr/bin/env bash
# Seed of 60-env: the process module reached through a created require.
cat >"$1/output/server/_ssr/sp-seed.mjs" <<'JS'
import { createRequire } from 'node:module'; export const a = createRequire(import.meta.url)('process').env.SP_SEED_NAME;
JS
