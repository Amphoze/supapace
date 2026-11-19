#!/usr/bin/env bash
# Seed of 80-licence: a change notice moved below the first lines of the file.
f=$(find "$1/modified" -type f -name '*.ts' | sort | sed -n 1p)
[ -n "$f" ] || { echo "seed: no modified .ts file" >&2; exit 1; }
l=$(grep -m1 'see NOTICE\.supapace' "$f")
sed -i '/see NOTICE\.supapace/d' "$f"
for _ in 1 2 3 4; do sed -i '1a\
' "$f"; done
printf '%s\n' "$l" >>"$f"
