#!/usr/bin/env bash
# Seed of 50-routes: a page whose $ref moved to another segment.
grep -q "^  '/project/\$ref/editor': " "$1/routeTree.gen.ts"
sed -i "s|^  '/project/\$ref/editor': |  '/project/editor/\$ref': |" "$1/routeTree.gen.ts"
