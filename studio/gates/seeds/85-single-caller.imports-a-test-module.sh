#!/usr/bin/env bash
# Seed of 85-single-caller: a file that is no test imports a module named as a test, which reads the setting.
# The copy's tree becomes one of its own, holding the wrapper alone.
set -e
w=apps/studio/lib/api/self-hosted
src=$(readlink -f "$1/repo")
rm "$1/repo" && mkdir -p "$1/repo/$w" && cp "$src/$w/pg-meta.ts" "$1/repo/$w/"
echo "$w/pg-meta.ts" >"$1/tree-files.txt"
echo "export const meta = process.env.SUPAPACE_PGMETA" >"$1/repo/$w/sp-seed.test.ts"
echo "export { meta } from './sp-seed.test'" >"$1/repo/$w/sp-seed.ts"
printf '%s\n' "$w/sp-seed.test.ts" "$w/sp-seed.ts" >>"$1/tree-files.txt"
