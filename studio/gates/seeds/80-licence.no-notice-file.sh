#!/usr/bin/env bash
# Seed of 80-licence: an image without NOTICE.supapace.
sed -i '\|^app/NOTICE\.supapace$|d' "$1/image-files.txt"
rm -f "$1/image-notice.txt"
