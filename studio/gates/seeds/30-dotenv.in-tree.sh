#!/usr/bin/env bash
# Seed of 30-dotenv: an .env.local in the build tree.
echo 'apps/studio/.env.local' >>"$1/tree-files.txt"
