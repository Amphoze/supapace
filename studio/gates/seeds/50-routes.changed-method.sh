#!/usr/bin/env bash
# Seed of 50-routes: a served route that answers a method its row does not list.
f=$(grep -l 'createFileRoute("/api/get-utc-time")' "$1"/output/server/_ssr/*.mjs)
perl -0pi -e 's/(createFileRoute\("\/api\/get-utc-time"\)\(\{\s*server:\s*\{\s*handlers:\s*\{)/$1 DELETE: null,/ or die "no registration\n"' "$f"
