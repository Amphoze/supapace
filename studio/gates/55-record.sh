#!/usr/bin/env bash
# 55-record DIR — fails when a fact of the build the design rests on differs from its
# recorded value: the members bypass, mcp_chunk_importers, pages_with_project_data and
# listener of DIR/build-record.json against DIR/record.expect.json (both one member per
# line), or when a listener variable is outside the list DIR/names.json gives
# (`sp-dashstub limits --names`).
set -euo pipefail
d=$1
member() { grep -m1 "^ \"$1\": " "$2" | sed 's/,$//'; }
bad=0
for m in bypass mcp_chunk_importers pages_with_project_data listener; do
  got=$(member "$m" "$d/build-record.json")
  want=$(member "$m" "$d/record.expect.json")
  if [ -z "$got" ] || [ "$got" != "$want" ]; then
    echo "55-record: $m differs" >&2
    echo "  built:    ${got:-(absent)}" >&2
    echo "  recorded: ${want:-(absent)}" >&2
    bad=1
  fi
done
names=$(sed -n 's/.*"listener":\[\([^]]*\)\].*/\1/p' "$d/names.json" | tr -d '"' | tr ',' '\n')
[ -n "$names" ] || { echo "55-record: names.json lists no listener names" >&2; exit 1; }
for v in $(member listener "$d/build-record.json" | sed 's/^ "listener": \[\(.*\)\]$/\1/' | tr -d ' "' | tr ',' '\n'); do
  if ! grep -qxF -- "$v" <<<"$names"; then
    echo "55-record: the listener reads $v, which is not a listener name of dashcfg" >&2
    bad=1
  fi
done
exit $bad
