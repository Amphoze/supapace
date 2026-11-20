#!/usr/bin/env bash
# Seed of 50-routes: a served row with the phase of a deleted one.
grep -q $'^api\t/api/get-utc-time\t[^\t]*\tserved\t.\t-$' "$1/routes.tsv"
sed -i $'s|^\\(api\t/api/get-utc-time\t[^\t]*\tserved\t.\t\\)-$|\\1P1|' "$1/routes.tsv"
