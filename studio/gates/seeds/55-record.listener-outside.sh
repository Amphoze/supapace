#!/usr/bin/env bash
# Seed of 55-record: the listener reads a variable outside dashcfg's listener names (recorded
# and expected alike, so only that check can fail).
for f in build-record.json record.expect.json; do
  sed -i 's|^ "listener": \[\(.*\)\]\(,\{0,1\}\)$| "listener": [\1, "NITRO_UNIX_SOCKET"]\2|; s|\[, |[|' "$1/$f"
done
