#!/usr/bin/env bash
# 30-dotenv DIR — fails when a file named .env* is in the build tree or in the image, or when
# the image declares an environment name beyond the Node base's own.
# DIR/tree-files.txt: the files of the build tree (the pruned workspace the bundler reads),
# before the build; never empty. Once the image is assembled, DIR/image-files.txt (the files
# of its exported file system) and DIR/image-env.txt (the names of its ENV, sorted), which
# must be exactly PATH, NODE_VERSION and YARN_VERSION: anything else reaches the server's
# process outside the agent's closed environment.
set -euo pipefail
d=$1
bad=0
[ -s "$d/tree-files.txt" ] || { echo "30-dotenv: no list of the build tree's files" >&2; exit 1; }
lists=tree-files.txt
if [ -e "$d/image-files.txt" ]; then
  [ -s "$d/image-files.txt" ] || { echo "30-dotenv: the list of the image's files is empty" >&2; exit 1; }
  lists="$lists image-files.txt"
  got=$(tr '\n' ' ' <"$d/image-env.txt")
  if [ "$got" != "NODE_VERSION PATH YARN_VERSION " ]; then
    echo "30-dotenv: the image's ENV names are \"$got\", not NODE_VERSION PATH YARN_VERSION" >&2
    bad=1
  fi
fi
for f in $lists; do
  hits=$(grep -E '(^|/)\.env[^/]*$' "$d/$f" || true)
  if [ -n "$hits" ]; then
    echo "30-dotenv: .env files in ${f%-files.txt}:" >&2
    echo "$hits" >&2
    bad=1
  fi
done
exit $bad
