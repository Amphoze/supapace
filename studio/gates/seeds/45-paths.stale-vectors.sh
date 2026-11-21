#!/usr/bin/env bash
# Seed of 45-paths: committed vectors that say otherwise than the build — one route of one
# vector changed.
set -euo pipefail
grep -q '"route":"/api/get-utc-time"' "$1/paths.json"
sed -i '0,/"route":"\/api\/get-utc-time"/s//"route":null/' "$1/paths.json"
