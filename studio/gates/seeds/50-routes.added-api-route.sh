#!/usr/bin/env bash
# Seed of 50-routes: an API route nobody classified, in the route tree and the server bundle.
sed -i "/^export interface FileRoutesBy\(FullPath\|Id\) {$/a\\  '/api/sp-seed': typeof SpSeedRoute" "$1/routeTree.gen.ts"
echo 'var Route = createFileRoute("/api/sp-seed")({ server: { handlers: { GET: () => null } } });' >"$1/output/server/_ssr/sp-seed.mjs"
