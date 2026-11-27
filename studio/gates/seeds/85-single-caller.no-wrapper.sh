#!/usr/bin/env bash
# Seed of 85-single-caller: the wrapper is not a file of the build tree.
# The copy's tree becomes one of its own, holding the wrapper alone.
set -e
w=apps/studio/lib/api/self-hosted
src=$(readlink -f "$1/repo")
rm "$1/repo" && mkdir -p "$1/repo/$w" && cp "$src/$w/pg-meta.ts" "$1/repo/$w/"
echo "$w/pg-meta.ts" >"$1/tree-files.txt"
rm "$1/repo/$w/pg-meta.ts" && echo "apps/studio/package.json" >"$1/tree-files.txt"
