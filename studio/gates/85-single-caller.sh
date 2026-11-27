#!/usr/bin/env bash
# 85-single-caller DIR — fails when the address of postgres-meta could be read anywhere but in
# the one module that asks postgres-meta, the wrapper (apps/studio/lib/api/self-hosted/pg-meta.ts).
# It counts source files, not bundle files: a module the server's start check reaches is
# bundled twice, into the server entry and into the chunk of the request path.
#   1. Among the files of the build tree (DIR/tree-files.txt, read under DIR/repo) the setting's
#      name occurs in the wrapper and in no other file but a unit test (*.test.ts, *.test.tsx):
#      a text search, so a comment or a string naming it fails too.
#   2. The wrapper's exports are exactly the list below — read from its syntax tree with the
#      bundler's own parser (DIR/parser), in a container of the pinned Node base — so the
#      address leaves the module through no binding: only through what those functions do.
#   3. No file that is no unit test imports a module whose name ends in .test: the exception
#      of rule 1 is for tests, not for code a route could load under a test's name.
# It is a tripwire for the setting's name, not a proof: it does not hold an address written
# into the code, a name put together at run time (60-env stops what the bundler leaves
# computed), or what the wrapper's own functions are made to do. Patches are reviewed.
# The names upstream read the address from are held by 60-env: they are no rows of env.tsv.
# Inputs, none of which may be empty: DIR/tree-files.txt, DIR/repo, DIR/parser.
set -euo pipefail
d=$(cd "$1" && pwd)
g=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
node_base=$(awk '$1 == "node" { print $2 }' "$g/../PIN")
name=SUPAPACE_PGMETA
wrapper=apps/studio/lib/api/self-hosted/pg-meta.ts
exports='PgMetaAnswer PgMetaCall callPgMeta checkPgMetaSettings handOver parserSlot'
fail() { echo "85-single-caller: $*" >&2; bad=1; }
bad=0
[ -s "$d/tree-files.txt" ] || { echo "85-single-caller: tree-files.txt is empty or missing" >&2; exit 1; }
for f in repo parser; do
  [ -n "$(ls -A "$d/$f/" 2>/dev/null)" ] || { echo "85-single-caller: $f is empty or missing" >&2; exit 1; }
done
grep -qxF "$wrapper" "$d/tree-files.txt" && [ -f "$d/repo/$wrapper" ] ||
  { echo "85-single-caller: $wrapper is not in the build tree" >&2; exit 1; }
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT

# 1. who names the setting
(cd "$d/repo" && tr '\n' '\0' <"$d/tree-files.txt" | xargs -0 grep -lF -- "$name" 2>/dev/null || true) |
  grep -vE '\.test\.tsx?$' | LC_ALL=C sort >"$t/named" || true
grep -qxF "$wrapper" "$t/named" || fail "$wrapper does not read $name"
others=$(grep -vxF "$wrapper" "$t/named" | tr '\n' ' ' || true)
[ -z "$others" ] || fail "$name is named outside the wrapper, in: $others"

# 3. who imports a test module
importers=$(cd "$d/repo" && grep -E '\.(c|m)?(j|t)sx?$' "$d/tree-files.txt" | grep -vE '\.test\.tsx?$' | tr '\n' '\0' |
  xargs -0 grep -lE "(from|import|require)[[:space:]]*\(?[[:space:]]*['\"\`][^'\"\`]*\.test(\.[cm]?[jt]sx?)?['\"\`]" 2>/dev/null | tr '\n' ' ' || true)
[ -z "$importers" ] || fail "a module named as a test is imported by a file that is none: $importers"

# 2. what the wrapper exports
cat >"$t/exports.mjs" <<'JS'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
const { parseAst } = await import(pathToFileURL(createRequire('/p/x.js').resolve('rolldown/parseAst')).href)
const names = []
const bound = (p) =>
  !p ? [] : p.type === 'Identifier' ? [p.name]
  : p.type === 'ObjectPattern' ? p.properties.flatMap((q) => bound(q.value ?? q.argument))
  : p.type === 'ArrayPattern' ? p.elements.flatMap(bound)
  : bound(p.left ?? p.argument)
for (const n of parseAst(readFileSync('/w.ts', 'utf8'), { lang: 'ts', sourceType: 'module' }).body) {
  if (n.type === 'ExportAllDeclaration') names.push(n.exported ? (n.exported.name ?? n.exported.value) : '*')
  else if (n.type === 'ExportDefaultDeclaration' || n.type === 'TSExportAssignment') names.push('default')
  else if (n.type === 'ExportNamedDeclaration') {
    for (const s of n.specifiers) names.push(s.exported.name ?? s.exported.value)
    const decl = n.declaration
    if (decl?.declarations) for (const v of decl.declarations) names.push(...bound(v.id))
    else if (decl) names.push(decl.id?.name ?? '?')
  }
}
console.log(names.sort().join(' '))
JS
got=$(docker run --rm --label supapace.build=studio --network none --memory 1g \
  -v "$d/parser:/p:ro" -v "$(readlink -f "$d/repo/$wrapper"):/w.ts:ro" -v "$t/exports.mjs:/exports.mjs:ro" \
  "$node_base" node /exports.mjs) || { echo "85-single-caller: the wrapper could not be parsed" >&2; exit 1; }
[ "$got" = "$exports" ] || fail "the wrapper's exports are \"$got\", not \"$exports\""
exit $bad
