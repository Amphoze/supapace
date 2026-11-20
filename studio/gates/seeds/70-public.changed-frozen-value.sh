#!/usr/bin/env bash
# Seed of 70-public: a frozen value that differs from its row.
grep -q '"process.env.NODE_ENV": "\\"production\\""' "$1/resolved-config.json"
sed -i 's|"process.env.NODE_ENV": "\\"production\\""|"process.env.NODE_ENV": "\\"development\\""|' "$1/resolved-config.json"
