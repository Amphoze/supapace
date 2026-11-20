#!/usr/bin/env bash
# Seed of 50-routes: a route rule of the server's own router that is not a header rule (a proxy).
grep -q '^\t\t\tname: "headers",$' "$1/output/server/index.mjs"
sed -i '0,/^\t\t\tname: "headers",$/s//\t\t\tname: "proxy",/' "$1/output/server/index.mjs"
