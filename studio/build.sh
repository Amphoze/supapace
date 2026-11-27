#!/usr/bin/env bash
# studio/build.sh — builds the dashboard image from the pinned upstream commit (PIN), the
# delete list and the patch series, runs the build's gates and measures the result.
#
#   build.sh image [--variant NAME] [--cpus N] [--memory SIZE]
#       the whole pipeline to supapace-studio:local and $IMAGE_CACHE/supapace-studio.tar, with
#       its build record beside the archive. With --variant NAME the series is the product's
#       plus studio/test-patches/NNNN-NAME.patch, and the image, archive and record are
#       supapace-studio:NAME, supapace-studio-NAME.tar and supapace-studio-NAME.build-record.json.
#   build.sh test             the series' unit tests (vitest files it adds), in the build container
#   build.sh prove [NAME]     studio/prove/*.sh (or NAME.sh alone), each run as `bash F IMAGE`
#                             against supapace-studio:local; results go into the record
#   build.sh paths            studio/prove/paths.json from paths.in, by `node paths.mjs SRV`
#                             on the last image build's output (stdin paths.in, stdout JSON)
#   build.sh export DIR       the series of the private clone DIR (PIN..HEAD) into studio/patches/
#
# Host needs: bash, git, docker, go, flock. The bundler only ever runs in a container of the
# pinned Node base with --memory (default 12g) and --cpus (default 4); only the dependency
# install has a network. One build.sh at a time per host (the lock $LOCK, whatever the
# cache), and none starts below its memory need (10 GiB available for image, prove and paths;
# 4 for test). Containers and images it makes carry the label supapace.build=studio.
# Cache: $IMAGE_CACHE/studio — upstream/ (the clone), deps-<hash>.tar (the installed
# workspace, keyed by the pin, the Node base, the lockfile and the series' manifest changes),
# work/ (the last product build's tree and output), work-NAME/ (a variant's), work-test/.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(dirname "$HERE")
IMAGE_CACHE=${IMAGE_CACHE:-$HOME/.cache/supapace/images}
CACHE=$IMAGE_CACHE/studio
W=$CACHE/work
G=$W/gate
UPSTREAM=https://github.com/supabase/supabase
NOTICE_LINE='Modified by the supapace project; see NOTICE.supapace.'
LABELS=(--label supapace.build=studio)
LOCK=/tmp/supapace-studio-build.lock

die() { echo "build.sh: $*" >&2; exit 1; }
say() { echo "build.sh: $*" >&2; }
pin() { awk -v k="$1" '$1 == k { print $2 }' "$HERE/PIN"; }
PIN=$(pin commit)
NODE_BASE=$(pin node)
[ -n "$PIN" ] && [ -n "$NODE_BASE" ] || die "studio/PIN lacks commit or node"

# Containers this run started; removed on exit, whatever the outcome.
CONTAINERS=()
cleanup() {
  local c
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  restore_product
  if [ -n "${CANDIDATE:-}" ]; then docker rmi "$CANDIDATE" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

# lock_and_check GiB — one build.sh at a time per host, and enough memory to start.
lock_and_check() {
  mkdir -p "$CACHE"
  if [ -z "${SUPAPACE_STUDIO_LOCKED:-}" ]; then
    exec 9>>"$LOCK"
    flock -n 9 || die "another build.sh is running on this host (lock $LOCK); wait for it"
    export SUPAPACE_STUDIO_LOCKED=1
  fi
  local kib
  kib=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
  [ "$kib" -ge $(($1 * 1048576)) ] ||
    die "needs $1 GiB of available memory; the host has $((kib / 1024)) MiB — wait, or free memory"
}

fresh_work() { # an empty $W; files a killed build container left as root go through a container
  rm -rf "$W" 2>/dev/null ||
    docker run --rm "${LABELS[@]}" --network none -v "$(dirname "$W"):/c" "$NODE_BASE" rm -rf "/c/$(basename "$W")"
  mkdir -p "$W" "$G"
}

run_gate() { # run_gate NAME — studio/gates/NAME.sh on the gate directory
  say "gate $1"
  bash "$HERE/gates/$1.sh" "$G" || die "gate $1 failed"
}

# JSON helpers for the record: jstr TEXT, jarr < lines.
jstr() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '"%s"' "$s"; }
jarr() {
  local l sep='' out='['
  while IFS= read -r l; do [ -n "$l" ] && out+="$sep$(jstr "$l")" && sep=', '; done
  printf '%s]' "$out"
}

# --- the tree ---------------------------------------------------------------------------

vectors() { # the Go side's vector files, before any stage
  rm -rf "$W/vectors" && mkdir -p "$W/vectors"
  cp "$ROOT/internal/dashcfg/testdata/dsn.json" "$W/vectors/dsn.json"
  cp "$ROOT/internal/dashtok/testdata/vectors.json" "$W/vectors/tokens.json"
  (cd "$ROOT" && go run -buildvcs=false ./cmd/sp-dashstub limits) >"$W/vectors/limits.json"
  (cd "$ROOT" && go run -buildvcs=false ./cmd/sp-dashstub limits --names) >"$G/names.json"
}

clone() { # the upstream commit, fetched once into the cache
  if ! git -C "$CACHE/upstream" cat-file -e "$PIN^{commit}" 2>/dev/null; then
    say "fetching $UPSTREAM at $PIN"
    rm -rf "$CACHE/upstream" && git init -q "$CACHE/upstream"
    git -C "$CACHE/upstream" fetch -q --depth 1 "$UPSTREAM" "$PIN"
  fi
}

# prepare_tree [VARIANT_PATCH] — $W/src: the pin less delete.txt, the series applied, the
# change notices inserted; $W/ctx/NOTICE.supapace generated from the result.
prepare_tree() {
  local variant_patch=${1:-}
  export GIT_AUTHOR_NAME=supapace-build GIT_AUTHOR_EMAIL=build@localhost
  export GIT_COMMITTER_NAME=supapace-build GIT_COMMITTER_EMAIL=build@localhost
  git -C "$CACHE/upstream" ls-tree -r --name-only "$PIN" >"$G/pin-files.txt"
  cp "$HERE/delete.txt" "$G/delete.txt"
  run_gate 10-delete

  rm -rf "$W/src"
  git -C "$CACHE/upstream" worktree prune
  git -C "$CACHE/upstream" worktree add -q --detach --force "$W/src" "$PIN"
  grep -v -e '^#' -e '^$' "$HERE/delete.txt" |
    GIT_LITERAL_PATHSPECS=1 git -C "$W/src" rm -q -r --pathspec-from-file=-
  git -C "$W/src" commit -q -m "Remove the paths of delete.txt"
  git -C "$W/src" rev-parse HEAD >"$G/base-commit"

  mkdir -p "$G/patches"
  cp "$HERE"/patches/*.patch "$G/patches/" 2>/dev/null || true
  [ -z "$variant_patch" ] || cp "$variant_patch" "$G/patches/9999-variant-$(basename "$variant_patch" .patch | cut -d- -f2-).patch"
  ln -sfn "$W/src" "$G/repo"
  run_gate 20-apply

  git -C "$W/src" diff --name-status --no-renames "$PIN" HEAD >"$G/name-status.txt"
  local st path c
  mkdir -p "$G/modified"
  while IFS=$'\t' read -r st path; do
    [ "$st" = M ] || continue
    c=$(bash "$HERE/gates/80-licence.sh" --comment "$path" "$NOTICE_LINE")
    if [ -n "$c" ]; then
      if [[ $(sed -n 1p "$W/src/$path") == '#!'* ]]; then
        sed -i "1a\\$c" "$W/src/$path"
      else
        sed -i "1i\\$c" "$W/src/$path"
      fi
    fi
    mkdir -p "$G/modified/$(dirname "$path")" && cp "$W/src/$path" "$G/modified/$path"
  done <"$G/name-status.txt"

  mkdir -p "$W/ctx"
  {
    echo "This image contains Supabase Studio, modified by the supapace project."
    echo
    echo "Upstream: $UPSTREAM, commit $PIN, licensed under the Apache License,"
    echo "Version 2.0 (LICENSE). The modifications are offered under the same licence."
    echo "Licence notices of the third-party packages: THIRD-PARTY-NOTICES."
    echo
    echo "Files changed against the upstream commit (M modified, D deleted, A added):"
    cat "$G/name-status.txt"
  } >"$W/ctx/NOTICE.supapace"
  cp "$W/src/LICENSE" "$W/ctx/LICENSE"
}

# deps — the installed workspace for this pin and lockfile, from the cache or (the one stage
# with a network) installed now. Sets DEPS to the archive.
deps() {
  local hash pnpm_v turbo_v c
  hash=$( {
    echo "$PIN"
    echo "$NODE_BASE"
    cat "$W/src/pnpm-lock.yaml"
    git -C "$W/src" diff "$PIN" HEAD -- ':(glob)**/package.json' pnpm-workspace.yaml .npmrc
  } | sha256sum | cut -c1-16)
  DEPS=$CACHE/deps-$hash
  if [ -f "$DEPS.tar" ] && [ -f "$DEPS.paths" ]; then
    say "dependencies: cached ($(basename "$DEPS").tar)"
    return
  fi
  pnpm_v=$(sed -n 's/.*npm install -g pnpm@\([0-9.]*\).*/\1/p' "$W/src/apps/studio/Dockerfile" | sed -n 1p)
  turbo_v=$(sed -n 's/.*pnpm dlx turbo@\([0-9.]*\) prune.*/\1/p' "$W/src/apps/studio/Dockerfile" | sed -n 1p)
  [ -n "$pnpm_v" ] && [ -n "$turbo_v" ] || die "the pin's apps/studio/Dockerfile names no pnpm or turbo version"
  say "dependencies: installing (pnpm $pnpm_v, turbo $turbo_v)"
  c=supapace-studio-deps-$$
  CONTAINERS+=("$c")
  docker run --name "$c" "${LABELS[@]}" --memory "$MEMORY" --memory-swap "$MEMORY" --cpus "$CPUS" \
    -e PNPM_V="$pnpm_v" -e TURBO_V="$turbo_v" -e OUT="$(basename "$DEPS")" -e UIDGID="$(id -u):$(id -g)" \
    -v "$W/src:/src:ro" -v "$CACHE:/cache" "$NODE_BASE" bash -c '
      set -euo pipefail
      npm install -g --silent "pnpm@$PNPM_V"
      cd /src && pnpm dlx "turbo@$TURBO_V" prune studio --docker --out-dir /p
      mkdir -p /w && cp -a /p/json/. /w/ && cp /p/pnpm-lock.yaml /w/
      if [ -d /src/patches ]; then cp -a /src/patches /w/; fi
      mkdir -p /w/.build-tools && npm install --silent --prefix /w/.build-tools "pnpm@$PNPM_V"
      cd /w && pnpm install --frozen-lockfile
      cd /p/full && { find . -mindepth 1 -maxdepth 1 -type f; find . -mindepth 2 -maxdepth 2 -type d; } |
        sed "s|^\./||" | sort >"/cache/$OUT.paths.tmp"
      tar -C /w -cf "/cache/$OUT.tar.tmp" .
      chown "$UIDGID" "/cache/$OUT.paths.tmp" "/cache/$OUT.tar.tmp"
      mv "/cache/$OUT.paths.tmp" "/cache/$OUT.paths" && mv "/cache/$OUT.tar.tmp" "/cache/$OUT.tar"' ||
    die "the dependency install failed"
}

# in_build SCRIPT — SCRIPT in a build container: the cached workspace unpacked, the tree's
# pruned paths copied over it, no network; /out is $W/out.
in_build() {
  local c=supapace-studio-build-$$
  CONTAINERS+=("$c")
  rm -rf "$W/out" && mkdir -p "$W/out"
  docker run --name "$c" "${LABELS[@]}" --network none --memory "$MEMORY" --memory-swap "$MEMORY" --cpus "$CPUS" \
    -e UIDGID="$(id -u):$(id -g)" \
    -v "$DEPS.tar:/deps.tar:ro" -v "$DEPS.paths:/deps.paths:ro" -v "$W/src:/src:ro" \
    -v "$W/vectors:/vectors:ro" -v "$HERE/image:/image:ro" -v "$W/out:/out" "$NODE_BASE" bash -c '
      set -uo pipefail
      export PATH=/w/.build-tools/node_modules/.bin:$PATH
      export pnpm_config_verify_deps_before_run=false # the install is the cached one; no network here
      (
        set -e
        mkdir -p /w && tar -C /w -xf /deps.tar
        # the package directories as patched; a root file only where the install has none
        # (its package.json, workspace file and lockfile are the pruned ones it installed)
        (cd /src && grep / /deps.paths | tar -cf - --exclude=.git -T -) | tar -C /w -xf -
        grep -v / /deps.paths | while IFS= read -r f; do [ -e "/w/$f" ] || cp -a "/src/$f" "/w/$f"; done
        cp -a /vectors /w/vectors
        cd /w
        '"$1"'
      )
      rc=$?
      chown -R "$UIDGID" /out
      exit $rc'
}

# --- sub-commands -----------------------------------------------------------------------

cmd_image() {
  local variant='' variant_patch='' t0=$SECONDS
  CPUS=4 MEMORY=12g
  while [ $# -gt 0 ]; do
    case $1 in
    --variant) variant=${2:-}; shift 2 ;;
    --cpus) CPUS=${2:-}; shift 2 ;;
    --memory) MEMORY=${2:-}; shift 2 ;;
    *) die "image: unknown argument $1" ;;
    esac
  done
  local tag=supapace-studio:local archive=$IMAGE_CACHE/supapace-studio
  if [ -n "$variant" ]; then
    [[ $variant =~ ^[a-z0-9][a-z0-9-]*$ && $variant != local ]] || die "variant name $variant: lower-case letters, digits and hyphens, not \"local\""
    local found=("$HERE"/test-patches/[0-9][0-9][0-9][0-9]-"$variant".patch)
    [ -f "${found[0]}" ] || die "no studio/test-patches/NNNN-$variant.patch for variant $variant"
    [ ${#found[@]} -eq 1 ] || die "more than one test patch for variant $variant"
    variant_patch=${found[0]}
    tag=supapace-studio:$variant archive=$IMAGE_CACHE/supapace-studio-$variant
    W=$CACHE/work-$variant G=$CACHE/work-$variant/gate # the product build's work/ stays for paths
  fi
  lock_and_check 10
  fresh_work
  vectors
  clone
  prepare_tree "$variant_patch"
  (cd "$W/src" && find . -path ./.git -prune -o -type f -print | sed 's|^\./||') >"$G/tree-all.txt"
  deps
  # the build tree is the pruned workspace the bundler reads
  awk 'NR == FNR { p[$0] = 1; next } { for (k in p) if ($0 == k || index($0, k "/") == 1) { print; next } }' \
    "$DEPS.paths" "$G/tree-all.txt" >"$G/tree-files.txt"
  rm -f "$G/image-files.txt"
  run_gate 30-dotenv

  say "build (--cpus $CPUS --memory $MEMORY)"
  local tb=$SECONDS
  in_build '
      s=$SECONDS rc=0
      NODE_OPTIONS=--max-old-space-size=4096 pnpm --filter studio run build >/out/build.log 2>&1 || rc=$?
      echo "compile_seconds $((SECONDS - s))" >/out/stats
      echo "peak_bytes $(cat /sys/fs/cgroup/memory.peak)" >>/out/stats
      cp apps/studio/.supapace/resolved-config.json apps/studio/routeTree.gen.ts /out/ 2>/dev/null || true
      [ $rc = 0 ] || exit $rc
      # the bundler'"'"'s own parser (the rolldown its vite resolves), for gates 50 and 60
      p=$(cd apps/studio && node -p "require(\"path\").dirname(require(\"module\").createRequire(require.resolve(\"vite/package.json\")).resolve(\"rolldown/package.json\"))")
      mkdir -p /out/parser/node_modules/@rolldown && cp -aL "$p" /out/parser/node_modules/rolldown
      cp -aL "$p"/../@rolldown/binding-* /out/parser/node_modules/@rolldown/
      mkdir -p /out/srv/apps/studio && cp -a apps/studio/.output /out/srv/apps/studio/
      find /out/srv -name "*.map" -delete
      # every package of studio and its workspace packages, dev ones included: the bundler
      # bundles some of those too
      pnpm --filter "studio..." list --depth Infinity --json | node /image/notices.mjs >/out/THIRD-PARTY-NOTICES' ||
    {
      tail -30 "$W/out/build.log" >&2 || true
      cp "$W/out/build.log" "$G/build.log" 2>/dev/null || true
      cp "$W/out/resolved-config.json" "$G/" 2>/dev/null || true
      run_gate 40-compat
      die "the build failed (log: $W/out/build.log)"
    }
  cp "$W/out/build.log" "$W/out/resolved-config.json" "$G/"
  cp -a "$W/out/routeTree.gen.ts" "$W/out/parser" "$G/"
  local build_wall=$((SECONDS - tb))

  # the runtime image, first with an empty record
  local studio_env features
  studio_env='{"PORT":"3000"'
  if [ -f "$HERE/features-off.txt" ]; then
    while IFS= read -r features; do
      case $features in '' | '#'*) continue ;; esac
      features=$(echo "$features" | tr 'a-z' 'A-Z' | tr -c 'A-Z0-9\n' '_')
      studio_env+=",\"ENABLED_FEATURES_$features\":\"false\""
    done <"$HERE/features-off.txt"
  fi
  studio_env+='}'
  mv "$W/out/srv" "$W/ctx/srv" && mv "$W/out/THIRD-PARTY-NOTICES" "$W/ctx/"
  echo '{}' >"$W/ctx/build-record.json"
  CANDIDATE=supapace-studio-candidate:$$
  local first
  first=$(image_build) || die "the image build failed"
  docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CANDIDATE" | sed -n 's/=.*//p' | sort >"$G/image-env.txt"
  bundle_packages "$W/ctx/srv/apps/studio/.output/server" >"$G/bundle-packages.txt"
  local image_bytes
  image_bytes=$(docker image inspect -f '{{.Size}}' "$CANDIDATE")
  local wall=$((SECONDS - t0))

  # the image's file system, for gates 30 and 80
  local c=supapace-studio-export-$$
  CONTAINERS+=("$c")
  docker create --name "$c" "${LABELS[@]}" "$CANDIDATE" >/dev/null
  docker export "$c" | tar -t >"$G/image-files.txt"
  local unpacked
  unpacked=$(docker export "$c" | wc -c)
  docker cp "$c:/app/NOTICE.supapace" - 2>/dev/null | tar -xO >"$G/image-notice.txt" || rm -f "$G/image-notice.txt"
  docker cp "$c:/app/THIRD-PARTY-NOTICES" - 2>/dev/null | tar -xO >"$G/image-third-party-notices.txt" ||
    rm -f "$G/image-third-party-notices.txt"
  docker rm -f "$c" >/dev/null

  measure
  write_record

  # the tables and a copy of the build output, for gates 50, 60 and 70 and their seeds
  cp "$HERE/routes.tsv" "$HERE/env.tsv" "$HERE/public.tsv" "$HERE/origins.txt" "$G/"
  cp "$HERE/prove/paths.in" "$HERE/prove/paths.json" "$G/"
  rm -rf "$G/output" && cp -a "$W/ctx/srv/apps/studio/.output" "$G/output"
  bash "$HERE/gates/seeds/gen.sh" "$CACHE/upstream" "$G/seeds-gen"
  local g
  for g in "$HERE"/gates/[0-9][0-9]-*.sh; do
    g=$(basename "$g" .sh)
    case $g in 10-delete | 20-apply) continue ;; esac
    run_gate "$g"
  done
  if [ -f "$G/gates.json" ]; then
    set_member gates "$(tr -d '\n' <"$G/gates.json")" "$W/ctx/build-record.json"
  fi

  # the final image (the record inside it), then the tag, the archive and the record beside it
  # replaced together: until both files are in place, a failure restores the previous tag
  local final
  final=$(image_build) || die "the image build failed"
  [ "$final" = "$first" ] || docker rmi "$first" >/dev/null 2>&1 || true
  cp "$W/ctx/build-record.json" "$archive.build-record.json.tmp"
  PREV_TAG=$tag PREV_ARCHIVE=$archive PREV_ID=$(docker image inspect -f '{{.Id}}' "$tag" 2>/dev/null || echo none)
  docker tag "$CANDIDATE" "$tag"
  docker save -o "$archive.tar.tmp" "$tag" || die "docker save failed; $tag restored"
  set_member total_seconds "$((SECONDS - t0))" "$archive.build-record.json.tmp"
  mv "$archive.tar.tmp" "$archive.tar" && mv "$archive.build-record.json.tmp" "$archive.build-record.json"
  [ "$PREV_ID" = none ] || [ "$PREV_ID" = "$(docker image inspect -f '{{.Id}}' "$tag")" ] ||
    docker rmi "$PREV_ID" >/dev/null 2>&1 || true
  PREV_TAG=''
  say "built $tag in ${wall}s (build ${build_wall}s, all $((SECONDS - t0))s); archive $archive.tar; record $archive.build-record.json"
}

# image_build — the runtime image from $W/ctx as $CANDIDATE; prints its id.
image_build() {
  docker build -q -t "$CANDIDATE" --label supapace.build=studio -f "$HERE/image/Dockerfile" \
    --build-arg NODE_BASE="$NODE_BASE" --build-arg STUDIO_ENV="$studio_env" "$W/ctx"
}

# restore_product — on a failure between the product tag's move and the files' rename, the
# tag goes back to the previous image (or away); the previous archive and record are untouched.
restore_product() {
  [ -n "${PREV_TAG:-}" ] || return 0
  if [ "$PREV_ID" = none ]; then docker rmi "$PREV_TAG" >/dev/null 2>&1 || true
  else docker tag "$PREV_ID" "$PREV_TAG" || true; fi
  rm -f "$PREV_ARCHIVE.tar.tmp" "$PREV_ARCHIVE.build-record.json.tmp"
  PREV_TAG=''
}

# set_member NAME JSON FILE — the line of member NAME in a record (one member per line).
set_member() {
  V=$2 awk -v m="$1" 'index($0, " \"" m "\": ") == 1 { c = sub(/,$/, ""); print " \"" m "\": " ENVIRON["V"] (c ? "," : ""); next } { print }' \
    "$3" >"$3.new" && mv "$3.new" "$3"
}

# bundle_packages SERVER — the packages in the built server bundle: those its module comments
# name and those traced into its node_modules.
bundle_packages() {
  {
    grep -rhoE '^// [^ ]*node_modules/\.pnpm/[^/]+/node_modules/(@[^/]+/)?[^/]+' --include='*.mjs' "$1" |
      sed -E 's|.*/node_modules/||'
    find "$1/node_modules" -name package.json | sed -nE 's|.*/node_modules/((@[^/]+/)?[^/]+)/package\.json$|\1|p'
  } | sort -u
}

# measure — the facts of the record, from containers of the candidate image (no network).
measure() {
  local srv=$W/ctx/srv/apps/studio/.output m=$W/measure c=supapace-studio-measure-$$
  rm -rf "$m" && mkdir -p "$m/keys"
  CONTAINERS+=("$c")
  # A node's settings: the server stops at start without them. The assertion key is the
  # vectors' public test key; nothing here signs, so every request is answered 401.
  sed -n 's/^ *"public_file": "\(.*\)",$/\1/p' "$W/vectors/tokens.json" >"$m/keys/assert.pub"
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' >"$m/keys/cache.key"
  head -c 48 /dev/urandom | base64 | tr '+/' '-_' >"$m/keys/crypto.key"
  local node=(-v "$m:/data:ro" -e SUPAPACE_NODE_ID=build -e SUPAPACE_DASH_SOCKET=/run/dash/dash.sock
    -e SUPAPACE_DASH_KEYS=/data/keys -e SUPAPACE_DASH_DATA=/tmp/dash -e SUPAPACE_PGCAP=10.212.0.6:20000:21023
    -e "SUPAPACE_LIMITS=$(cat "$W/vectors/limits.json")")
  start() { # start [docker args] — the candidate as $c, until it answers
    docker rm -f "$c" >/dev/null 2>&1 || true
    docker run -d --name "$c" "${LABELS[@]}" --network none --memory 2g --memory-swap 2g \
      -v "$HERE/image:/m:ro" "${node[@]}" "$@" "$CANDIDATE" >/dev/null
    docker exec "$c" node /m/measure.mjs wait 120 || die "the built server did not answer within 120 s"
  }

  say "measure: idle memory, precompressed files"
  start
  sleep 30 # idle after the first request
  M_IDLE=$(docker exec "$c" cat /sys/fs/cgroup/memory.current)
  local asset
  asset=$(cd "$srv/public" && find assets -name '*.js' -size +20k | sort | sed -n 1p)
  [ -f "$srv/public/$asset.br" ] || die "no precompressed copy of $asset"
  M_PRECOMP="{\"files\": $(cd "$srv/public" && find . -name '*.br' -o -name '*.gz' -o -name '*.zst' | wc -l), \"answer\": $(jstr "$(docker exec "$c" node /m/measure.mjs encoding "/$asset")")}"

  say "measure: listener variables"
  # read from the built listener path; a port or host name read there must move the listener
  docker run --rm "${LABELS[@]}" --network none --memory 1g -v "$HERE/image:/m:ro" -v "$srv/server:/s:ro" \
    "$NODE_BASE" node /m/measure.mjs listener /s >"$m/listener.txt" || die "the listener path could not be read"
  [ -s "$m/listener.txt" ] || die "the listener path reads no variable"
  local base got n v
  base=$(docker exec "$c" node /m/measure.mjs listen 30)
  for n in $(grep -E 'PORT$|HOST$' "$m/listener.txt"); do
    case $n in *PORT) v=3999 ;; *) v=127.0.0.2 ;; esac
    docker rm -f "$c" >/dev/null
    docker run -d --name "$c" "${LABELS[@]}" --network none --memory 2g --memory-swap 2g \
      -v "$HERE/image:/m:ro" "${node[@]}" -e "$n=$v" "$CANDIDATE" >/dev/null
    got=$(docker exec "$c" node /m/measure.mjs listen 60) || die "no listener with $n set"
    [ "$got" != "$base" ] || die "the listener path reads $n, but setting it does not move the listener"
  done
  M_LISTENER=$(jarr <"$m/listener.txt")

  say "measure: what bypasses the middleware chain"
  local fn file
  rm -rf "$m/server" && cp -a "$srv/server" "$m/server"
  docker run --rm "${LABELS[@]}" --network none --memory 1g --user "$(id -u):$(id -g)" \
    -v "$HERE/image:/m:ro" -v "$m/server:/s" "$NODE_BASE" node /m/measure.mjs mark /s >/dev/null ||
    die "could not place the measurement marker"
  fn=$(grep -rh -A1 'createServerRpc({' "$srv/server/_ssr" | grep -oE 'id: "[0-9a-f]{16,}"' | grep -oE '[0-9a-f]{16,}' | sort | sed -n 1p) ||
    die "no server function id in the server bundle"
  file=$(cd "$srv/public" && find . -type f ! -path './assets/*' ! -name '*.br' ! -name '*.gz' ! -name '*.zst' ! -name '_shell.html' | sed 's|^\.||' | sort | sed -n 1p)
  [ -n "$file" ] || die "no public file outside assets/"
  {
    printf 'public asset\t%s\t/%s\n' GET "$asset" HEAD "$asset" POST "$asset" OPTIONS "$asset" GET "$asset.br"
    printf 'public file\t%s\t%s\n' GET "$file" HEAD "$file" POST "$file"
    printf 'missing asset\tGET\t/assets/sp-missing.js\n'
    printf 'shell\tGET\t/_shell.html\n'
    printf 'root\tGET\t/\n'
    printf 'page\tGET\t/project/default\n'
    printf 'page\tGET\t/project/default/editor\n'
    printf 'page\tHEAD\t/project/default/editor\n'
    printf 'api route\tGET\t/api/platform/profile\n'
    printf 'api route\tPOST\t/api/platform/pg-meta/default/query\n'
    printf 'server function\tGET\t/_serverFn/%s\tx-tsr-serverfn:true\n' "$fn"
    printf 'server function\tPOST\t/_serverFn/%s\tx-tsr-serverfn:true\n' "$fn"
    printf 'not found\tGET\t/sp-no-such-path\n'
    printf 'not found\tGET\t/api/sp-no-such-route\n'
    printf 'function without id\tGET\t/_serverFn/\n'
    printf 'doubled slash\tGET\t//sp-no-such-path\n'
  } >"$m/matrix.txt"
  start -v "$m/server:/app/apps/studio/.output/server:ro"
  docker exec "$c" node /m/measure.mjs matrix /data/matrix.txt >"$m/matrix.out"
  docker logs "$c" >"$m/marker.log" 2>&1
  local kind method path
  M_BYPASS=$(while IFS=$'\t' read -r kind method path _; do
    grep -qxF "[sp-marker] $method $path" "$m/marker.log" || echo "$method $kind"
  done <"$m/matrix.out" | sort -u | jarr)
  docker rm -f "$c" >/dev/null

  say "measure: the importers of the MCP library's chunk, frozen values"
  M_MCP=$(docker run --rm "${LABELS[@]}" --network none --memory 1g -v "$HERE/image:/m:ro" -v "$srv/server:/s:ro" \
    "$NODE_BASE" node /m/measure.mjs importers /s /node_modules/@supabase/mcp-server-supabase/ | jarr) || die "no MCP library chunk"
  local name value sep='' files
  M_FROZEN='{'
  while IFS='=' read -r name value; do
    value=${value%\"}; value=${value#\"}
    case $name in '' | '#'*) continue ;; esac
    # a short value or plain words (a default name) would only match the interface's own text
    [ ${#value} -ge 8 ] || continue
    [[ ! $value =~ ^[A-Za-z\ ]+$ ]] || continue
    files=$(cd "$srv" && { grep -rlF --exclude='*.br' --exclude='*.gz' --exclude='*.zst' -- "$value" . || true; } | sed 's|^\./||' | sort | jarr)
    [ "$files" = '[]' ] || { M_FROZEN+="$sep$(jstr "$name"): $files"; sep=', '; }
  done < <(git -C "$CACHE/upstream" show "$PIN:apps/studio/.env")
  M_FROZEN+='}'
  M_OUTPUT=$(cd "$srv" && find . -type f ! -name nitro.json -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
  M_STUDIO_ENV=$studio_env M_IMAGE_BYTES=$image_bytes M_UNPACKED=$unpacked M_WALL=$wall M_VARIANT=$variant
}

# write_record — build-record.json, one member per line (gate 55 compares lines).
write_record() {
  local patches peak compile
  patches=$(ls "$G/patches" | jarr)
  peak=$(awk '$1 == "peak_bytes" { print $2 }' "$W/out/stats")
  compile=$(awk '$1 == "compile_seconds" { print $2 }' "$W/out/stats")
  {
    echo '{'
    echo " \"pin\": $(jstr "$PIN"),"
    echo " \"node_base\": $(jstr "$NODE_BASE"),"
    echo " \"patches\": $patches,"
    echo " \"variant\": $([ -n "$M_VARIANT" ] && jstr "$M_VARIANT" || echo null),"
    echo " \"cpus\": $(jstr "$CPUS"),"
    echo " \"memory\": $(jstr "$MEMORY"),"
    echo " \"build_peak_bytes\": $peak,"
    echo " \"build_seconds\": $M_WALL,"
    echo " \"compile_seconds\": $compile,"
    echo " \"image_bytes\": $M_IMAGE_BYTES,"
    echo " \"image_unpacked_bytes\": $M_UNPACKED,"
    echo " \"idle_memory_bytes\": $M_IDLE,"
    echo " \"listener\": $M_LISTENER,"
    echo " \"env_label\": $M_STUDIO_ENV,"
    echo " \"precompressed\": $M_PRECOMP,"
    echo " \"bypass\": $M_BYPASS,"
    echo " \"frozen\": $M_FROZEN,"
    echo " \"mcp_chunk_importers\": $M_MCP,"
    echo " \"output_sha256\": $(jstr "$M_OUTPUT"),"
    echo " \"total_seconds\": null,"
    echo " \"gates\": null,"
    echo " \"proofs\": null"
    echo '}'
  } >"$W/ctx/build-record.json"
  cp "$W/ctx/build-record.json" "$G/build-record.json"
  cp "$HERE/record.expect.json" "$G/record.expect.json"
  cat "$W/ctx/build-record.json" >&2
}

cmd_test() {
  CPUS=4 MEMORY=12g
  lock_and_check 4
  W=$CACHE/work-test G=$CACHE/work-test/gate # the image build's work/ stays for paths
  fresh_work
  vectors
  clone
  prepare_tree
  local tests
  # each path single-quoted for the build container's shell: a directory may be named $ref
  tests=$(awk -F'\t' '$1 != "D" && $2 ~ /^apps\/studio\/.*\.test\.tsx?$/ { sub(/^apps\/studio\//, "", $2); print "\047" $2 "\047" }' "$G/name-status.txt" | tr '\n' ' ')
  if [ -z "$tests" ]; then
    say "test: the series adds no unit tests"
    return
  fi
  deps
  in_build "cd apps/studio && pnpm exec vitest --run $tests" || die "unit tests failed"
}

cmd_prove() {
  local only=${1:-} f rc out=''
  lock_and_check 10
  local record=$IMAGE_CACHE/supapace-studio.build-record.json
  [ -f "$record" ] || die "no build record; run build.sh image first"
  # A build killed between moving the tag and renaming its files leaves the tag ahead of
  # the archive and record: proofs of that image must not land in the older record.
  local cid img_sha rec_sha
  cid=$(docker create "${LABELS[@]}" supapace-studio:local) || die "no product image; run build.sh image first"
  img_sha=$(docker cp "$cid:/opt/supapace/build-record.json" - 2>/dev/null | tar -xO 2>/dev/null |
    sed -n 's/^ *"output_sha256": *"\([^"]*\)".*/\1/p')
  docker rm -f "$cid" >/dev/null
  rec_sha=$(sed -n 's/^ *"output_sha256": *"\([^"]*\)".*/\1/p' "$record")
  [ -n "$img_sha" ] && [ "$img_sha" = "$rec_sha" ] ||
    die "the product tag and the archive disagree; run build.sh image"
  local sep='' ran=0
  for f in "$HERE"/prove/*.sh; do
    [ -f "$f" ] || continue
    [ -z "$only" ] || [ "$(basename "$f" .sh)" = "$only" ] || continue
    ran=1
    say "prove $(basename "$f" .sh)"
    rc=0
    (cd "$ROOT" && bash "$f" supapace-studio:local 9>&-) || rc=$?
    out+="$sep$(jstr "$(basename "$f" .sh)"): $([ $rc = 0 ] && echo '"pass"' || echo '"fail"')"
    sep=', '
  done
  [ $ran = 1 ] || die "no proof${only:+ named $only} under studio/prove/"
  sed -i "s|^ \"proofs\": .*| \"proofs\": {$out}|" "$record"
  case $out in *'"fail"'*) die "a proof failed: {$out}" ;; esac
}

cmd_paths() {
  lock_and_check 10
  [ -f "$HERE/prove/paths.mjs" ] || die "studio/prove/paths.mjs is missing"
  [ -d "$W/ctx/srv/apps/studio/.output" ] || die "no build output; run build.sh image first"
  docker run --rm -i "${LABELS[@]}" --network none --memory 2g \
    -v "$HERE/prove:/prove:ro" -v "$W/ctx/srv/apps/studio/.output:/srv:ro" "$NODE_BASE" \
    timeout 600 node /prove/paths.mjs /srv <"$HERE/prove/paths.in" >"$HERE/prove/paths.json.tmp" ||
    { rm -f "$HERE/prove/paths.json.tmp"; die "paths.mjs failed, or did not end within 600 s"; }
  mv "$HERE/prove/paths.json.tmp" "$HERE/prove/paths.json"
}

cmd_export() {
  local dir=${1:-}
  [ -d "$dir" ] || die "export: DIR is the private clone holding the series as commits after $PIN"
  rm -f "$HERE"/patches/*.patch
  git -C "$dir" format-patch -q --zero-commit --no-signature -o "$HERE/patches" "$PIN..HEAD"
  ls "$HERE/patches"
}

case ${1:-} in
image) shift; cmd_image "$@" ;;
test) shift; cmd_test "$@" ;;
prove) shift; cmd_prove "$@" ;;
paths) shift; cmd_paths "$@" ;;
export) shift; cmd_export "$@" ;;
*) sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
