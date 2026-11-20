#!/usr/bin/env bash
# Seed of 50-routes: a page whose first segment the gateway reads as "api" (classified, so only
# that check can fail).
sed -i "/^export interface FileRoutesBy\(FullPath\|Id\) {$/a\\  '/Api/sp-seed': typeof SpSeedRoute" "$1/routeTree.gen.ts"
printf 'page\t/Api/sp-seed\t-\tserved\tn\t-\n' >>"$1/routes.tsv"
