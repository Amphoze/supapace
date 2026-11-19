#!/usr/bin/env bash
# Seed of 80-licence: an image without upstream's LICENSE.
sed -i '\|^app/LICENSE$|d' "$1/image-files.txt"
