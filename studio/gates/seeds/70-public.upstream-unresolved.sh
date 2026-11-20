#!/usr/bin/env bash
# Seed of 70-public: an @upstream row that names nothing in the pinned tree.
printf '@upstream:apps/studio/.env:SP_SEED_NO_SUCH_NAME\tserver\ttext\n' >>"$1/origins.txt"
