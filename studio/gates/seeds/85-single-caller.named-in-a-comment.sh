#!/usr/bin/env bash
# Seed of 85-single-caller: another source file names the setting in a comment.
# The copy's tree becomes one of its own, holding the wrapper alone.
set -e
w=apps/studio/lib/api/self-hosted
src=$(readlink -f "$1/repo")
rm "$1/repo" && mkdir -p "$1/repo/$w" && cp "$src/$w/pg-meta.ts" "$1/repo/$w/"
echo "$w/pg-meta.ts" >"$1/tree-files.txt"
echo "// see SUPAPACE_PGMETA" >"$1/repo/$w/sp-seed.tsx"
echo "$w/sp-seed.tsx" >>"$1/tree-files.txt"
