#!/usr/bin/env bash
# Seed of 70-public: a public.tsv row holding a value of upstream's .env, frozen too (so only
# that check can fail; the value is read from the pinned tree here, never written in this file).
v=$(git -C "$1/repo" show "$(cat "$1/base-commit")^:apps/studio/.env" | sed -n 's/^STUDIO_PG_META_URL=//p' | tr -d '"')
[ -n "$v" ]
sed -i "/^ \"define\": {\$/a\\  \"process.env.SP_SEED\": \"\\\\\"$v\\\\\"\"," "$1/resolved-config.json"
printf 'process.env.SP_SEED\t"%s"\n' "$v" >>"$1/public.tsv"
