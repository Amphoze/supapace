#!/usr/bin/env bash
# Seed of 85-single-caller: the wrapper exports the address under another name, with its declaration.
# The copy's tree becomes one of its own, holding the wrapper alone.
set -e
w=apps/studio/lib/api/self-hosted
src=$(readlink -f "$1/repo")
rm "$1/repo" && mkdir -p "$1/repo/$w" && cp "$src/$w/pg-meta.ts" "$1/repo/$w/"
echo "$w/pg-meta.ts" >"$1/tree-files.txt"
sed -i "s/^let instances:/export let instances:/" "$1/repo/$w/pg-meta.ts"
grep -q "^export let instances:" "$1/repo/$w/pg-meta.ts"
