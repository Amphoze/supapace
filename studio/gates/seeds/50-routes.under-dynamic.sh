#!/usr/bin/env bash
# Seed of 50-routes: an API route moved under another dynamic segment (its ref column changes).
f=$(grep -l 'createFileRoute("/api/platform/projects/$ref/settings")' -r "$1/output/server" | head -1)
sed -i 's#createFileRoute("/api/platform/projects/\$ref/settings")#createFileRoute("/api/platform/projects/$slug/settings")#' "$f"
sed -i "s#'/api/platform/projects/\$ref/settings'#'/api/platform/projects/\$slug/settings'#g" "$1/routeTree.gen.ts"
