#!/usr/bin/env bash
# Seed of 70-public: an origins.txt row that is an origin, not its digest.
printf 'https://seed.example\tclient\ttext\n' >>"$1/origins.txt"
