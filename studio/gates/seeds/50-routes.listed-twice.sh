#!/usr/bin/env bash
# Seed of 50-routes: a served route listed a second time, as deleted.
printf 'api\t/api/get-utc-time\tGET\tdeleted\tn\tnever\n' >>"$1/routes.tsv"
