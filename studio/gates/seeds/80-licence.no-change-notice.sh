#!/usr/bin/env bash
# Seed of 80-licence: a modified file without its change notice.
f=$(find "$1/modified" -type f -name '*.ts' | sort | sed -n 1p)
[ -n "$f" ] || { echo "seed: no modified .ts file to strip" >&2; exit 1; }
sed -i '/see NOTICE\.supapace/d' "$f"
