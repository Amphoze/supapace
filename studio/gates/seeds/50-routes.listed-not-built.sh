#!/usr/bin/env bash
# Seed of 50-routes: a served row of a route the build does not serve.
printf 'api\t/api/sp-seed\tGET\tserved\tn\t-\n' >>"$1/routes.tsv"
