#!/usr/bin/env bash
# Seed of 70-public: a hosted value the build finds in the bundles, its row removed.
grep -q '^@upstream:apps/studio/.env:NEXT_PUBLIC_SUPABASE_URL	' "$1/public.tsv"
sed -i '/^@upstream:apps\/studio\/.env:NEXT_PUBLIC_SUPABASE_URL\t/d' "$1/public.tsv"
