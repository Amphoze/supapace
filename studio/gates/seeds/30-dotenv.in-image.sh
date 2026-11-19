#!/usr/bin/env bash
# Seed of 30-dotenv: an .env.local in the assembled image.
echo 'app/apps/studio/.env.local' >>"$1/image-files.txt"
