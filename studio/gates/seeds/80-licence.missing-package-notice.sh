#!/usr/bin/env bash
# Seed of 80-licence: a package of the server bundle whose notice is missing.
p=$(sed -n 1p "$1/bundle-packages.txt")
awk -v p="$p" 'rule && $1 == p { rule = 0; next } { rule = ($0 ~ /^=+$/ && length($0) == 72); print }' \
  "$1/image-third-party-notices.txt" >"$1/n.tmp" && mv "$1/n.tmp" "$1/image-third-party-notices.txt"
