#!/usr/bin/env bash
# Seed of 55-record: the member listener of the build record changed.
sed -i 's|^ "listener": .*$| "listener": [],|' "$1/build-record.json"
