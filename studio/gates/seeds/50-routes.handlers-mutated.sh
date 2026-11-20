#!/usr/bin/env bash
# Seed of 50-routes: a method added to a route's handlers after its registration.
echo 'Route.options.server.handlers.DELETE = () => null;' >"$1/output/server/_ssr/sp-seed.mjs"
