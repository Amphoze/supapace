#!/usr/bin/env bash
# Seed of 70-public: an origin with escaped slashes, as JSON text writes it (red until fixed).
printf '%s\n' 'fetch("https:\/\/seed.example/x")' > "$1/output/public/assets/sp-seed.js"
