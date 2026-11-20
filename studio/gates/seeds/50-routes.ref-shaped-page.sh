#!/usr/bin/env bash
# Seed of 50-routes: a page route with a static segment of the shape of a ref (classified, so
# only that check can fail).
sed -i "/^export interface FileRoutesBy\(FullPath\|Id\) {$/a\\  '/project/\$ref/abcdefghij0123456789': typeof SpSeedRoute" "$1/routeTree.gen.ts"
printf 'page\t/project/$ref/abcdefghij0123456789\t-\tserved\ty\t-\n' >>"$1/routes.tsv"
