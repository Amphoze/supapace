#!/usr/bin/env bash
# Seed of 50-routes: a global middleware of the server's own router that answers a path.
perl -0pi -e 's#var globalMiddleware = \[toEventHandler\(static_default\)\]#var globalMiddleware = [toEventHandler(static_default), (e) => { if (e.url.pathname === "/api/sp-seed") return new Response("seed") }]#' "$1/output/server/index.mjs"
grep -q 'sp-seed' "$1/output/server/index.mjs"
