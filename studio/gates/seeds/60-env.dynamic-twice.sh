#!/usr/bin/env bash
# Seed of 60-env: a dynamic row listed twice.
grep -m1 $'\tdynamic\t' "$1/env.tsv" >>"$1/env.tsv"
