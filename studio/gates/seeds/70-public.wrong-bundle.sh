#!/usr/bin/env bash
# Seed of 70-public: an origins.txt row that names the wrong bundle for its origin.
grep -qE '^[0-9a-f]{16}	client	' "$1/origins.txt"
sed -i -E '0,/^([0-9a-f]{16})\tclient\t/s//\1\tserver\t/' "$1/origins.txt"
