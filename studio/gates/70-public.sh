#!/usr/bin/env bash
# 70-public DIR — fails when a value frozen into the bundles differs from DIR/public.tsv, when
# an origin in the bundles is not a row of DIR/origins.txt, or when a row of either table holds
# a value of upstream's .env.
# - Frozen values: the bundler's resolved replacement map as the build dumped it
#   (DIR/resolved-config.json: "define" and each environment's), every name with its
#   replacement text, against the plain rows of public.tsv (NAME<TAB>TEXT), both directions.
#   Upstream's hosted values found in the bundles (the build record's "frozen": a value of the
#   pinned apps/studio/.env, by bundle file) against its @upstream rows
#   (@upstream:apps/studio/.env:NAME<TAB>FILE, a bundler hash written [hash]), both directions.
# - Origins: every http, https, ws and wss origin literal in the text of both bundles
#   (DIR/output/public, the client, and DIR/output/server: .js .mjs .cjs .html .css .json .svg
#   .webmanifest), in any letter case and with escaped slashes (https:\/\/) read as slashes,
#   lower-cased, against origins.txt, both directions, each with the bundle it is found in.
#   The repository holds no host name, so a row is DIGEST<TAB>BUNDLE<TAB>ROLE: the first 16 hex
#   digits of the SHA-256 of the origin's text (or @upstream:FILE:NAME for the origin of a value
#   of FILE in the pinned tree); client, server or both; and the reviewed role, text (a link,
#   a default, a name) or request (a page or the server contacts it). The gate prints every
#   origin of the build beside its digest and bundle, every build: that list is what a review
#   of origins.txt reads. The role is not checked here; the recorded browser session holds it.
#   LIMIT: the method sees literals. An origin assembled at run time from pieces or a template
#   ("https://" + h, `https://${h}.x`), written with an escaped colon, or protocol-relative
#   (//host) is not a literal origin: it shows at most as a truncated row (https://,
#   https://$) and is the recorded browser session's to find.
# - No plain row of either table equals a non-empty value of the pinned apps/studio/.env (for
#   origins.txt: the digest of that value or of its origin); only an @upstream row may stand for
#   one. The pinned tree is read from the clone behind DIR/repo, at the parent of
#   DIR/base-commit.
# No input may be empty.
set -euo pipefail
d=$(cd "$1" && pwd)
fail() { echo "70-public: $*" >&2; bad=1; }
bad=0
for f in public.tsv origins.txt resolved-config.json build-record.json base-commit; do
  [ -s "$d/$f" ] || { echo "70-public: $f is empty or missing" >&2; exit 1; }
done
for f in output/server output/public; do
  [ -n "$(ls -A "$d/$f" 2>/dev/null)" ] || { echo "70-public: $f is empty or missing" >&2; exit 1; }
done
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
export LC_ALL=C
# origin — the http, https, ws and wss origins in stdin, of any letter case, lower-cased; an
# escaped slash (https:\/\/, as JSON text writes it) is read as a slash
origin() {
  sed 's#:\\/\\/#://#g' | { grep -oiE '(https?|wss?)://[^]/[:space:]"'"'"'`<>()\\,;|{}^*?#[]*' || true; } | tr 'A-Z' 'a-z'
}
pinned() { git -C "$d/repo" show "$(cat "$d/base-commit")^:$1"; }
# dotenv FILE NAME — the value NAME has in FILE of the pinned tree, unquoted
dotenv() { pinned "$1" | sed -n "s/^$2=//p" | sed -n '$p' | sed 's/^"\(.*\)"$/\1/'; }
pinned apps/studio/.env >"$t/env" 2>/dev/null || { echo "70-public: the pinned tree has no apps/studio/.env" >&2; exit 1; }
sed -n 's/^[A-Za-z_][A-Za-z0-9_]*=//p' "$t/env" | sed 's/^"\(.*\)"$/\1/' | grep -v '^$' | sort -u >"$t/envvalues"
[ -s "$t/envvalues" ] || { echo "70-public: no values in the pinned apps/studio/.env" >&2; exit 1; }
# digest — each line of stdin as "DIGEST<TAB>TEXT"
digest() { perl -MDigest::SHA=sha256_hex -nle 'print substr(sha256_hex($_), 0, 16), "\t", $_'; }
{ cat "$t/envvalues" && origin <"$t/envvalues"; } | digest | cut -f1 | sort -u >"$t/envdigests"

# frozen values: "KEY": "JSON text" lines of the define map and of each environment's
awk '/^ "(define|environments)": \{/ { on = 1; next } /^ "[a-z]+": / { on = 0 }
  on && /^ +"[^"]+": "/ {
    line = $0; sub(/^ +"/, "", line); k = line; sub(/": ".*$/, "", k)
    v = line; sub(/^[^"]*": "/, "", v); sub(/",?$/, "", v); gsub(/\\"/, "\"", v); gsub(/\\\\/, "\\", v)
    print k "\t" v }' "$d/resolved-config.json" | sort -u >"$t/frozen"
[ -s "$t/frozen" ] || { echo "70-public: no replacement map in resolved-config.json" >&2; exit 1; }
# hosted values, by file
grep -m1 '^ "frozen": ' "$d/build-record.json" | perl -ne '
  while (/"([A-Za-z0-9_]+)": \[((?:"[^"]*"(?:, )?)*)\]/g) { my ($n, $fs) = ($1, $2);
    while ($fs =~ /"([^"]+)"/g) { my $f = $1; $f =~ s/-([A-Za-z0-9_-]{8})\.mjs$/my $h = $1; $h =~ m|[A-Z0-9_]| ? "-[hash].mjs" : "-$h.mjs"/e;
      print "\@upstream:apps/studio/.env:$n\t$f\n" } }' | sort -u >"$t/hosted"

: >"$t/rows" && : >"$t/uprows"
while IFS=$'\t' read -r name value extra; do
  case $name in '' | '#'*) continue ;; esac
  [ -z "$extra" ] || { fail "public.tsv row \"$name\": more than two columns"; continue; }
  if [[ $name == @upstream:* ]]; then
    printf '%s\t%s\n' "$name" "$value" >>"$t/uprows"
  else
    printf '%s\t%s\n' "$name" "$value" >>"$t/rows"
    v=${value#\"} v=${v%\"}
    if [ -n "$v" ] && grep -qxF -- "$v" "$t/envvalues"; then fail "public.tsv row \"$name\" holds a value of upstream's .env"; fi
  fi
done <"$d/public.tsv"
s=$(sort "$t/rows" | comm -3 - "$t/frozen" | sed 's/^\t/  built: /; /^  built: /!s/^/  table: /')
[ -z "$s" ] || { fail "frozen values differ from public.tsv:"; echo "$s" >&2; }
s=$(sort "$t/uprows" | comm -3 - "$t/hosted" | sed 's/^\t/  built: /; /^  built: /!s/^/  table: /')
[ -z "$s" ] || { fail "upstream's hosted values in the bundles differ from public.tsv:"; echo "$s" >&2; }

# origins, by digest, with the bundle each is found in; the full list is printed, every build:
# it is what a review of origins.txt reads
scan() {
  (cd "$d/output/$1" && find . -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.html' -o -name '*.css' \
    -o -name '*.json' -o -name '*.svg' -o -name '*.webmanifest' \) -print0 | xargs -0 cat | origin | sort -u)
}
scan public >"$t/client"
scan server >"$t/server"
{
  comm -23 "$t/client" "$t/server" | sed 's/$/\tclient/'
  comm -13 "$t/client" "$t/server" | sed 's/$/\tserver/'
  comm -12 "$t/client" "$t/server" | sed 's/$/\tboth/'
} | perl -MDigest::SHA=sha256_hex -F'\t' -lane 'print substr(sha256_hex($F[0]), 0, 16), "\t$F[1]\t$F[0]"' | sort >"$t/origins"
[ -s "$t/origins" ] || { echo "70-public: no origin in the bundles at all" >&2; exit 1; }
echo "70-public: the origins of the bundles (digest, bundle, origin):"
sed 's/^/  /' "$t/origins"
: >"$t/table"
while IFS=$'\t' read -r row bundle role extra; do
  case $row in '' | '#'*) continue ;; esac
  [[ $bundle =~ ^(client|server|both)$ && $role =~ ^(text|request)$ && -z $extra ]] ||
    { fail "origins.txt row \"$row\": not DIGEST BUNDLE ROLE (client|server|both, text|request)"; continue; }
  if [[ $row == @upstream:* ]]; then
    IFS=: read -r _ file name <<<"$row"
    v=$(dotenv "$file" "$name" 2>/dev/null | origin)
    [ -n "$v" ] || { fail "origins.txt row \"$row\" names no origin in the pinned tree"; continue; }
    printf '%s\t%s\n' "$(echo "$v" | digest | cut -f1)" "$bundle" >>"$t/table"
  elif [[ $row =~ ^[0-9a-f]{16}$ ]]; then
    printf '%s\t%s\n' "$row" "$bundle" >>"$t/table"
    if grep -qxF -- "$row" "$t/envdigests"; then fail "origins.txt row $row is the digest of a value of upstream's .env"; fi
  else
    fail "origins.txt row \"$row\": neither a digest nor an @upstream row"
  fi
done <"$d/origins.txt"
s=$(sort -u "$t/table" | comm -3 - <(cut -f1,2 "$t/origins") |
  awk -F'\t' 'NF == 3 { print "  built: " $2 "  " $3 } NF == 2 { print "  table: " $1 "  " $2 }')
if [ -n "$s" ]; then
  fail "origins in the bundles differ from origins.txt (digest, bundle):"
  # the built side with its origin text
  echo "$s" | while IFS= read -r l; do
    case $l in "  built: "*) k=$(echo "$l" | awk '{print $2 "\t" $3}'); echo "  built: $(grep -m1 -F -- "$k" "$t/origins" | tr '\t' ' ')" ;; *) echo "$l" ;; esac
  done >&2
fi
exit $bad
