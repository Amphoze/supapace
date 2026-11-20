#!/usr/bin/env bash
# Seed of 70-public: an origins.txt row that stands for a value of upstream's .env by its
# digest instead of naming it (the value is read from the pinned tree here, never written in
# this file).
row=@upstream:apps/studio/.env:NEXT_PUBLIC_SUPABASE_URL
line=$(grep -m1 "^$row	" "$1/origins.txt")
v=$(git -C "$1/repo" show "$(cat "$1/base-commit")^:apps/studio/.env" | sed -n 's/^NEXT_PUBLIC_SUPABASE_URL=//p' | tr -d '"' | tr 'A-Z' 'a-z')
[ -n "$line" ] && [ -n "$v" ]
{ grep -vF -- "$line" "$1/origins.txt" && printf '%s\t%s\n' "$(printf '%s\n' "$v" | perl -MDigest::SHA=sha256_hex -nle 'print substr(sha256_hex($_), 0, 16)')" "${line#*	}"; } >"$1/o.tmp"
mv "$1/o.tmp" "$1/origins.txt"
