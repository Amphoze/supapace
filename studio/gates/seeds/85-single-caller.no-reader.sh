#!/usr/bin/env bash
# Seed of 85-single-caller: the wrapper no longer reads the setting: another reader would be the only one.
# The copy's tree becomes one of its own, holding the wrapper alone.
set -e
w=apps/studio/lib/api/self-hosted
src=$(readlink -f "$1/repo")
rm "$1/repo" && mkdir -p "$1/repo/$w" && cp "$src/$w/pg-meta.ts" "$1/repo/$w/"
echo "$w/pg-meta.ts" >"$1/tree-files.txt"
sed -i "s/SUPAPACE_PGMETA/SUPAPACE_ELSEWHERE/g" "$1/repo/$w/pg-meta.ts"
