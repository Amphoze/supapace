#!/usr/bin/env bash
# Seed of 50-routes: a page route nobody classified.
sed -i "/^export interface FileRoutesBy\(FullPath\|Id\) {$/a\\  '/sp-seed': typeof SpSeedRoute" "$1/routeTree.gen.ts"
