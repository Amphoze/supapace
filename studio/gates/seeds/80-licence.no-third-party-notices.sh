#!/usr/bin/env bash
# Seed of 80-licence: an image without the third-party notices.
sed -i '\|^app/THIRD-PARTY-NOTICES$|d' "$1/image-files.txt"
