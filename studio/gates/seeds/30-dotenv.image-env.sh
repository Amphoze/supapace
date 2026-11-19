#!/usr/bin/env bash
# Seed of 30-dotenv: the image declares an environment name beyond the Node base's own.
echo NODE_OPTIONS >>"$1/image-env.txt"
sort -o "$1/image-env.txt" "$1/image-env.txt"
