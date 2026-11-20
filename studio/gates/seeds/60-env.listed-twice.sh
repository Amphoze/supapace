#!/usr/bin/env bash
# Seed of 60-env: a name of the process environment listed as unset too.
grep -q $'^PORT\tset$' "$1/env.tsv"
printf 'PORT\tunset\n' >>"$1/env.tsv"
