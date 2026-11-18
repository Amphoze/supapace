#!/usr/bin/env bash
# cache-images.sh DIR — pull every upstream image of internal/nodecfg/images.lock by
# digest and docker-save it into DIR as <key>-<digest12>.tar; images already cached
# are skipped. The harness base image ("node") is built from, not loaded into, the
# node, so it is not cached.
#
# A digest-only image is saved without a name and would load into the node
# untagged, unreachable by the reference the platform uses. So the fully qualified
# "<repository>@<digest>" is written into the archive's index.json as the
# annotation io.containerd.image.name, which docker load (containerd image store)
# takes as the image name; the archive is unpacked and packed again around that edit.
# That needs Docker's containerd image store on this machine too: the classic store
# saves a re-made manifest, whose digest is not the pinned one.
#
# cache-images.sh --pull-only — pull every image by digest and save nothing: enough
# where this machine's own Docker is the node's (a host install), with either store.
set -euo pipefail
pull_only=''
if [[ ${1:-} == --pull-only ]]; then
	pull_only=1
	shift
fi
dir=${1:-}
if [[ -z $pull_only ]]; then
	: "${dir:?usage: cache-images.sh [--pull-only] DIR}"
	if ! docker info -f '{{.DriverStatus}}' | grep -q io.containerd.snapshotter; then
		echo "cache-images: Docker's containerd image store is needed to save images by digest;" >&2
		echo "  set {\"features\": {\"containerd-snapshotter\": true}} in /etc/docker/daemon.json and restart Docker" >&2
		exit 1
	fi
fi
lock=$(dirname "$0")/../internal/nodecfg/images.lock
[[ -n $pull_only ]] || mkdir -p "$dir"
# A failed run leaves neither a partial archive nor its unpacked copy behind.
tar='' tmp=''
trap '[[ -z $tar ]] || rm -f "$tar.tmp"; [[ -z $tmp ]] || rm -rf "$tmp"' EXIT

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
	if [[ -n $pull_only ]]; then
		docker pull -q "$ref" >/dev/null
		echo "pulled   $ref"
		continue
	fi
	tar=$dir/$key-${digest:7:12}.tar
	if [[ -s $tar ]] && tar -xOf "$tar" index.json | grep -q "\"io.containerd.image.name\":\"[^\"]*@$digest\""; then
		echo "cached   $ref"
		continue
	fi
	# pull -q prints the reference fully qualified, as the image store keeps it.
	name=$(docker pull -q "$ref")
	annotation="\"io.containerd.image.name\":\"$name\""
	docker save -o "$tar.tmp" "$ref"
	tmp=$(mktemp -d)
	tar -xf "$tar.tmp" -C "$tmp"
	sed -i "s|\"annotations\":{|\"annotations\":{$annotation,|" "$tmp/index.json"
	if ! grep -qF "$annotation" "$tmp/index.json"; then
		echo "cache-images: cannot name $ref in its archive" >&2
		exit 1
	fi
	# shellcheck disable=SC2046 # docker save writes a few fixed top-level names
	tar -cf "$tar.tmp" -C "$tmp" $(ls -A "$tmp")
	rm -r "$tmp"
	mv "$tar.tmp" "$tar"
	echo "saved    $ref"
done <<<"$entries"
