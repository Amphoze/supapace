#!/usr/bin/env bash
# 40-compat DIR — fails when the build's own check of an unshimmed `next/*` import fired, or
# is no longer there. The check is upstream's Vite plugin `studio-next-compat`, which stops
# the build with a "[next-compat]" line. DIR/build.log: the build's output (never empty);
# DIR/resolved-config.json: the build's dump of its resolved configuration, whose "plugins"
# array must still name the plugin.
set -euo pipefail
d=$1
[ -s "$d/build.log" ] || { echo "40-compat: no build log" >&2; exit 1; }
if grep -F '[next-compat]' "$d/build.log" >&2; then
  echo "40-compat: the build imports an unshimmed next/* module" >&2
  exit 1
fi
if ! awk '/^ "plugins": \[/ { p = 1 } p && /^ *"studio-next-compat",?$/ { f = 1 } p && /^ \]/ { p = 0 } END { exit !f }' "$d/resolved-config.json"; then
  echo "40-compat: the plugin studio-next-compat is not registered in the resolved configuration" >&2
  exit 1
fi
