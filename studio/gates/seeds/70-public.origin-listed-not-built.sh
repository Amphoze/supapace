#!/usr/bin/env bash
# Seed of 70-public: an origins.txt row of an origin the bundles do not hold.
printf 'https://seed.example\n' | perl -MDigest::SHA=sha256_hex -nle 'print substr(sha256_hex($_), 0, 16), "\tclient\ttext"' >>"$1/origins.txt"
