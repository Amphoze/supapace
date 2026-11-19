#!/usr/bin/env bash
# Seed of 55-record: the member bypass of the build record changed.
sed -i 's|^ "bypass": .*$| "bypass": ["GET page"],|' "$1/build-record.json"
