#!/usr/bin/env bash
# 80-licence DIR — fails when the image lacks upstream's LICENSE, NOTICE.supapace or the
# third-party notices; when a package of the server bundle has no notice there; when a file
# the series modifies lacks its change notice; or when NOTICE.supapace does not list a
# modified, deleted or added file. No input may be empty.
#   DIR/image-files.txt   the files of the image's exported file system
#   DIR/image-notice.txt  NOTICE.supapace as the image holds it (absent if it holds none)
#   DIR/image-third-party-notices.txt  THIRD-PARTY-NOTICES as the image holds it
#   DIR/bundle-packages.txt  the packages of the built server bundle (its module comments and
#                         its traced node_modules), one name per line
#   DIR/name-status.txt   `git diff --name-status --no-renames` from the pin to the patched tree
#   DIR/modified/PATH     each modified file as built
# 80-licence --comment PATH TEXT prints TEXT as a one-line comment in PATH's language, or
# nothing for a format without comments (JSON and the like), whose notice is NOTICE.supapace.
set -euo pipefail
comment() {
  case $1 in
  *.ts | *.tsx | *.mts | *.cts | *.js | *.jsx | *.mjs | *.cjs) echo "// $2" ;;
  *.css | *.scss) echo "/* $2 */" ;;
  *.yaml | *.yml | *.sh | *.toml) echo "# $2" ;;
  *.md | *.mdx | *.html) echo "<!-- $2 -->" ;;
  esac
}
if [ "${1:-}" = --comment ]; then
  comment "$2" "$3"
  exit 0
fi
d=$1
bad=0
for f in image-files.txt name-status.txt bundle-packages.txt; do
  [ -s "$d/$f" ] || { echo "80-licence: $f is empty or missing" >&2; exit 1; }
done
for f in app/LICENSE app/NOTICE.supapace app/THIRD-PARTY-NOTICES; do
  grep -qxF "$f" "$d/image-files.txt" || { echo "80-licence: the image lacks /$f" >&2; bad=1; }
done
# a package's heading is the line after a rule of 72 "=": "name version — licence"
missing=$(awk 'NR == FNR { if (rule) h[$1] = 1; rule = ($0 ~ /^=+$/ && length($0) == 72); next }
  !($0 in h) { print }' "$d/image-third-party-notices.txt" "$d/bundle-packages.txt" 2>/dev/null || cat "$d/bundle-packages.txt")
if [ -n "$missing" ]; then
  echo "80-licence: packages of the server bundle without a notice: $(echo "$missing" | sed -n 1,5p | tr '\n' ' ')($(echo "$missing" | wc -l) in all)" >&2
  bad=1
fi
while IFS= read -r line; do
  [ -n "$line" ] || continue
  if [ ! -f "$d/image-notice.txt" ] || ! grep -qxF -- "$line" "$d/image-notice.txt"; then
    echo "80-licence: NOTICE.supapace does not list \"$line\"" >&2
    bad=1
  fi
  st=${line%%$'\t'*} path=${line#*$'\t'}
  if [ "$st" = M ] && [ -n "$(comment "$path" x)" ] &&
    ! awk 'NR <= 3 && index($0, "see NOTICE.supapace") { f = 1 } END { exit !f }' "$d/modified/$path" 2>/dev/null; then
    echo "80-licence: $path lacks its change notice" >&2
    bad=1
  fi
done <"$d/name-status.txt"
exit $bad
