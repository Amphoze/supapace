#!/usr/bin/env bash
# Seed of 80-licence: NOTICE.supapace that does not list a modified file.
grep -q "^M	" "$1/image-notice.txt" || { echo "seed: no modified file listed" >&2; exit 1; }
sed -i '0,/^M\t/{/^M\t/d}' "$1/image-notice.txt"
