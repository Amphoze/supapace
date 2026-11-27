#!/usr/bin/env bash
# Seed of 85-single-caller: a second source file names the setting of the address.
# The copy's tree becomes one of its own, holding the wrapper alone.
set -e
w=apps/studio/lib/api/self-hosted
src=$(readlink -f "$1/repo")
rm "$1/repo" && mkdir -p "$1/repo/$w" && cp "$src/$w/pg-meta.ts" "$1/repo/$w/"
echo "$w/pg-meta.ts" >"$1/tree-files.txt"
echo "export const meta = process.env.SUPAPACE_PGMETA" >"$1/repo/$w/sp-seed.ts"
echo "$w/sp-seed.ts" >>"$1/tree-files.txt"
