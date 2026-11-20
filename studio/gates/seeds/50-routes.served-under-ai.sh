#!/usr/bin/env bash
# Seed of 50-routes: a route under /api/ai, which the gateway refuses, classified served.
grep -q $'^api\t/api/ai/docs\t[^\t]*\topt-in\t' "$1/routes.tsv"
sed -i $'s|^\\(api\t/api/ai/docs\t[^\t]*\t\\)opt-in\t\\(.\\)\t[^\t]*$|\\1served\t\\2\t-|' "$1/routes.tsv"
