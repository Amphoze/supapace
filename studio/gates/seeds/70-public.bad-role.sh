#!/usr/bin/env bash
# Seed of 70-public: an origins.txt row with a role the table does not know.
grep -qE '^[0-9a-f]{16}	[a-z]+	text$' "$1/origins.txt"
sed -i -E '0,/^([0-9a-f]{16}\t[a-z]+)\ttext$/s//\1\tfetched/' "$1/origins.txt"
