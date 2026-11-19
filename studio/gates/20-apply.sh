#!/usr/bin/env bash
# 20-apply DIR — fails when a patch does not apply. DIR/repo is a git work tree, clean and at
# the commit DIR/base-commit (the pinned tree less delete.txt; a copy of this input gets a work
# tree of its own there, never the build's); each DIR/patches/NNNN-<topic>-<slug>.patch is
# applied with `git am`, one by one, in name order. A file not named that way is refused.
set -euo pipefail
d=$1
base=$(cat "$d/base-commit")
if [ -z "$base" ] || [ "$(git -C "$d/repo" rev-parse HEAD)" != "$base" ]; then
  echo "20-apply: the work tree is not at the base commit" >&2
  exit 1
fi
if [ -n "$(git -C "$d/repo" status --porcelain)" ]; then
  echo "20-apply: the work tree is not clean" >&2
  exit 1
fi
for p in "$d"/patches/*; do
  [ -e "$p" ] || continue
  n=$(basename "$p")
  if ! [[ $n =~ ^[0-9]{4}-[a-z]+-[a-z0-9-]+\.patch$ ]]; then
    echo "20-apply: $n is not named NNNN-<topic>-<slug>.patch" >&2
    exit 1
  fi
  if ! git -C "$d/repo" am -q "$p" >&2; then
    git -C "$d/repo" am --abort >/dev/null 2>&1 || true
    echo "20-apply: $n does not apply" >&2
    exit 1
  fi
done
