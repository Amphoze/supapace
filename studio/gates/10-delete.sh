#!/usr/bin/env bash
# 10-delete DIR — fails when a path of DIR/delete.txt does not exist at the pin. Tested
# against DIR/pin-files.txt (every file of the pinned tree, `git ls-tree -r --name-only`),
# before anything is removed. A line names a file, or a directory that holds files; blank
# lines and lines starting with # are skipped.
set -euo pipefail
d=$1
bad=0
while IFS= read -r p; do
  case $p in '' | '#'*) continue ;; esac
  if ! grep -qxF -- "$p" "$d/pin-files.txt" &&
    ! awk -v p="$p/" 'index($0, p) == 1 { f = 1; exit } END { exit !f }' "$d/pin-files.txt"; then
    echo "10-delete: \"$p\" does not exist at the pin" >&2
    bad=1
  fi
done <"$d/delete.txt"
exit $bad
