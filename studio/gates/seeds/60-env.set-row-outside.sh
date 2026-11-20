#!/usr/bin/env bash
# Seed of 60-env: a set row that is neither a fixed name, a name of the image's label nor one
# Docker or the image's ENV adds.
printf 'SP_SEED_NAME\tset\n' >>"$1/env.tsv"
