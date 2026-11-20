#!/usr/bin/env bash
# Seed of 70-public: a public.tsv row of a name the bundler does not replace.
printf 'process.env.SP_SEED\t"seed"\n' >>"$1/public.tsv"
