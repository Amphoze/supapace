#!/usr/bin/env bash
# Seed of 50-routes: a deleted row that the build still serves.
grep -q $'^api\t/api/get-utc-time\t[^\t]*\tserved\t' "$1/routes.tsv"
sed -i $'s|^\\(api\t/api/get-utc-time\t[^\t]*\t\\)served\t\\(.\\)\t-$|\\1deleted\t\\2\tnever|' "$1/routes.tsv"
