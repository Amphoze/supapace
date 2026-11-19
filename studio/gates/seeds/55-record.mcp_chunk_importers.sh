#!/usr/bin/env bash
# Seed of 55-record: the member mcp_chunk_importers of the build record changed.
sed -i 's|^ "mcp_chunk_importers": .*$| "mcp_chunk_importers": ["_ssr/seeded.mjs"],|' "$1/build-record.json"
