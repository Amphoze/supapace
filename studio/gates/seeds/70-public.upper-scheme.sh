#!/usr/bin/env bash
# Seed of 70-public: an origin whose scheme is written in capitals (red until fixed).
printf '%s\n' 'fetch("HTTPS://seed.example/x")' > "$1/output/public/assets/sp-seed.js"
