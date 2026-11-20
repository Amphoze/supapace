#!/usr/bin/env bash
# Seed of 50-routes: an API route renamed in the route tree and the server bundle.
f=$(grep -l 'createFileRoute("/api/get-utc-time")' -r "$1/output/server" | head -1)
sed -i 's#createFileRoute("/api/get-utc-time")#createFileRoute("/api/get-utc-time2")#' "$f"
sed -i "s#'/api/get-utc-time'#'/api/get-utc-time2'#g" "$1/routeTree.gen.ts"
