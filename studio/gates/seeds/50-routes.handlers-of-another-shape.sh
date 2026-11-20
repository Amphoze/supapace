#!/usr/bin/env bash
# Seed of 50-routes: a route registration whose handlers the manifest cannot read.
echo 'var Route = createFileRoute("/api/sp-seed")({ server: { handlers: makeHandlers() } });' >"$1/output/server/_ssr/sp-seed.mjs"
