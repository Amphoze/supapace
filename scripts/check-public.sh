#!/usr/bin/env bash
# check-public.sh --staged | --tree | --message FILE | --tag OBJECT | --range REVS...
# Runs the public-content gate, cmd/check-public (see its package comment). The gate
# checks the repository of the current directory; it is built from the source next
# to this script, so the hooks and make public-check keep a fixed path.
set -euo pipefail
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
mkdir -p "$src/bin"
(cd "$src" && CGO_ENABLED=0 go build -buildvcs=false -o "$src/bin/check-public" ./cmd/check-public)
exec "$src/bin/check-public" "$@"
