#!/usr/bin/env bash
# Seed of 50-routes: an opt-in row outside /api/ai and /api/mcp.
grep -q $'^api\t/api/get-utc-time\t[^\t]*\tserved\t' "$1/routes.tsv"
sed -i $'s|^\\(api\t/api/get-utc-time\t[^\t]*\t\\)served\t\\(.\\)\t-$|\\1opt-in\t\\2\tP2|' "$1/routes.tsv"
