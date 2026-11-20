#!/usr/bin/env bash
# Seed of 70-public: an origin outside origins.txt, in the client bundle.
echo 'fetch("https://seed.example/x")' >"$1/output/public/assets/sp-seed.js"
