#!/usr/bin/env bash
# cache-images.sh DIR — pull every upstream image of internal/nodecfg/images.lock by
# digest and docker-save it into DIR as <key>-<digest12>.tar; images already cached
# are skipped. The harness base image ("node") is built from, not loaded into, the
# node, so it is not cached.
set -euo pipefail
dir=${1:?usage: cache-images.sh DIR}
lock=$(dirname "$0")/../internal/nodecfg/images.lock
mkdir -p "$dir"

# images.lock keeps one entry per line: "key": {"tag": "…", "digest": "sha256:…", …}
entries=$(sed -n 's/^ *"\([a-z_]*\)": *{"tag": *"\([^"]*\)", *"digest": *"\(sha256:[0-9a-f]\{64\}\)".*/\1 \2 \3/p' "$lock" | grep -v '^node ' || true)
if [[ $(wc -l <<<"$entries") -lt 3 ]]; then
	echo "cache-images: cannot read the image entries of $lock" >&2
	exit 1
fi

while read -r key tag digest; do
	repo=$tag
	[[ ${tag##*/} == *:* ]] && repo=${tag%:*}
	ref=$repo@$digest
	tar=$dir/$key-${digest:7:12}.tar
	if [[ -s $tar ]]; then
		echo "cached   $ref"
		continue
	fi
	docker pull "$ref"
	docker save -o "$tar.tmp" "$ref"
	mv "$tar.tmp" "$tar"
	echo "saved    $ref"
done <<<"$entries"
