#!/usr/bin/env bash
# 90-selftest DIR — fails when a gate passes on its seeded violation, when a gate has no seed,
# or when a seed cannot be applied. For every other gate of this directory, each seed
# seeds/<gate>.<slug>.sh and DIR/seeds-gen/<gate>.<slug>.sh (the seeds the build generates
# from the pinned clone) is applied to a fresh copy of DIR and the gate is run on that copy; it
# must fail. A copy for 20-apply gets a work tree of its own at DIR/base-commit as its repo.
# A seed seeds/<gate>.<slug>.patch needs a build of its own: it is listed, not run.
# Writes DIR/gates.json: one entry per seed, {"gate", "seed", "result"}, result "refused",
# "passed", "not applied" or "needs a build".
set -euo pipefail
d=$(cd "$1" && pwd)
g=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
self=$(basename "${BASH_SOURCE[0]}" .sh)
t=$(mktemp -d)
copy=$t/copy
cleanup() {
  [ -L "$copy/repo" ] || [ ! -e "$copy/repo" ] || git -C "$d/repo" worktree remove --force "$copy/repo" >/dev/null 2>&1 || true
  rm -rf "$t"
}
trap cleanup EXIT
bad=0
entries=()
gates=0
for gate in "$g"/[0-9][0-9]-*.sh; do
  name=$(basename "$gate" .sh)
  [ "$name" != "$self" ] || continue
  gates=$((gates + 1))
  seeds=()
  for s in "$g/seeds/$name".*.sh "$g/seeds/$name".*.patch "$d/seeds-gen/$name".*.sh; do
    [ -f "$s" ] && seeds+=("$s")
  done
  if [ ${#seeds[@]} -eq 0 ]; then
    echo "90-selftest: gate $name has no seed" >&2
    bad=1
    continue
  fi
  for s in "${seeds[@]}"; do
    slug=$(basename "$s")
    slug=${slug%.sh}
    if [[ $s == *.patch ]]; then
      result="needs a build"
    else
      cleanup
      mkdir -p "$t" && cp -a "$d" "$copy"
      if [ "$name" = 20-apply ]; then
        rm -f "$copy/repo"
        git -C "$d/repo" worktree add -q --detach "$copy/repo" "$(cat "$d/base-commit")"
      fi
      if ! bash "$s" "$copy" >"$t/seed.log" 2>&1; then
        result="not applied"
        echo "90-selftest: seed $slug could not be applied:" >&2
        sed 's/^/  /' "$t/seed.log" >&2
        bad=1
      elif bash "$gate" "$copy" >"$t/gate.log" 2>&1; then
        result=passed
        echo "90-selftest: gate $name passes on its seed $slug" >&2
        bad=1
      else
        result=refused
        echo "90-selftest: $slug refused: $(grep -m1 "^$name: " "$t/gate.log" || sed -n 1p "$t/gate.log")" >&2
      fi
    fi
    entries+=("{\"gate\": \"$name\", \"seed\": \"$slug\", \"result\": \"$result\"}")
  done
done
[ $gates -gt 0 ] || { echo "90-selftest: no gate to test" >&2; exit 1; }
{
  echo '['
  for i in "${!entries[@]}"; do
    [ "$i" -eq $((${#entries[@]} - 1)) ] && echo "  ${entries[$i]}" || echo "  ${entries[$i]},"
  done
  echo ']'
} >"$d/gates.json"
exit $bad
