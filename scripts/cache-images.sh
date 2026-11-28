#!/usr/bin/env bash
# cache-images.sh DIR — pull every upstream image of internal/nodecfg/images.lock by
# digest and docker-save it into DIR as <key>-<digest12>.tar; images already cached
# are skipped. Never loaded into a node, so not cached: the harness base image
# ("node", built from), the object-store stand-in ("s3_standin", run beside the
# node) and the worker image's base and source ("worker_base", "worker_source",
# built from).
#
# SP_DASH=1 (make images DASH=1): also the images of the lock that only a node with
# a studio domain runs ("pgmeta"), in both modes; saved under DIR/dash, which only
# such a node loads. Without it they are neither pulled nor saved.
#
# SP_POOLER=1 (make images POOLER=1): likewise the connection pooler's image
# ("supavisor"), saved under DIR/pool, which only a node with a pooler label
# loads; pulled by its index digest in the pull-only mode.
#
# An archive is cached when its index.json names the lock's index digest as the
# digest of its manifest entry and as the image's name: one saved for a single
# platform names that platform's manifest instead, resolves by that digest only,
# and is removed and saved again.
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
#
# cache-images.sh --save IMAGE NAME ARCHIVE — docker-save a locally built IMAGE into
# ARCHIVE named NAME (a local name such as supapace-worker:local), whatever IMAGE's
# own tag: the node loads it under the name the platform uses.
set -euo pipefail
pull_only='' save=''
if [[ ${1:-} == --pull-only ]]; then
	pull_only=1
	shift
elif [[ ${1:-} == --save ]]; then
	[[ $# == 4 && $3 != */* ]] || { echo "usage: cache-images.sh --save IMAGE NAME ARCHIVE" >&2; exit 2; }
	save=1
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
# A failed run leaves neither a partial archive nor its unpacked copy behind.
tar='' tmp=''
trap '[[ -z $tar ]] || rm -f "$tar.tmp"; [[ -z $tmp ]] || rm -rf "$tmp"' EXIT

# name_archive ANNOTATION [TAG]: unpack $tar.tmp, set the image's io.containerd.image.name
# annotation (replaced, or added when absent) and its reference name to TAG when given,
# pack it again and move it into place.
name_archive() {
	tmp=$(mktemp -d)
	tar -xf "$tar.tmp" -C "$tmp"
	[[ -z ${2:-} ]] || sed -i "s|\"org.opencontainers.image.ref.name\":\"[^\"]*\"|\"org.opencontainers.image.ref.name\":\"$2\"|" "$tmp/index.json"
	if grep -q '"io.containerd.image.name":' "$tmp/index.json"; then
		sed -i "s|\"io.containerd.image.name\":\"[^\"]*\"|$1|" "$tmp/index.json"
	else
		sed -i "s|\"annotations\":{|\"annotations\":{$1,|" "$tmp/index.json"
	fi
	if ! grep -qF "$1" "$tmp/index.json"; then
		echo "cache-images: cannot name the image in $tar" >&2
		exit 1
	fi
	# shellcheck disable=SC2046 # docker save writes a few fixed top-level names
	tar -cf "$tar.tmp" -C "$tmp" $(ls -A "$tmp")
	rm -r "$tmp"
	tmp=''
	mv "$tar.tmp" "$tar"
}

if [[ -n $save ]]; then
	tar=$4
	docker save -o "$tar.tmp" "$2"
	# NAME qualified as Docker qualified IMAGE's own name: the same repository prefix.
	prefix=$(tar -xOf "$tar.tmp" index.json | sed -n 's|.*"io.containerd.image.name":"\([^"]*/\)[^"/]*".*|\1|p')
	[[ -n $prefix ]] || { echo "cache-images: the archive of $2 names no image" >&2; exit 1; }
	name_archive "\"io.containerd.image.name\":\"$prefix$3\"" "${3##*:}"
	echo "saved    $2 as $3"
	exit 0
fi

lock=$(dirname "$0")/../internal/nodecfg/images.lock
[[ -n $pull_only ]] || mkdir -p "$dir"

# images.lock keeps one entry per line: "key": {"tag": "…", "digest": "sha256:…", …}
entries=$(sed -n 's/^ *"\([a-z_]*\)": *{"tag": *"\([^"]*\)", *"digest": *"\(sha256:[0-9a-f]\{64\}\)".*/\1 \2 \3/p' "$lock" |
	grep -Ev '^(node|s3_standin|worker_base|worker_source) ' || true)
[[ ${SP_DASH:-} == 1 ]] || entries=$(grep -Ev '^pgmeta ' <<<"$entries" || true)
[[ ${SP_POOLER:-} == 1 ]] || entries=$(grep -Ev '^supavisor ' <<<"$entries" || true)
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
	sub=$dir
	case $key in
	pgmeta) sub=$dir/dash ;;
	supavisor) sub=$dir/pool ;;
	esac
	mkdir -p "$sub"
	tar=$sub/$key-${digest:7:12}.tar
	if [[ -s $tar ]] && idx=$(tar -xOf "$tar" index.json) && grep -q "\"digest\":\"$digest\"" <<<"$idx" &&
		grep -q "\"io.containerd.image.name\":\"[^\"]*@$digest\"" <<<"$idx"; then
		echo "cached   $ref"
		continue
	fi
	rm -f "$tar"
	# pull -q prints the reference fully qualified, as the image store keeps it.
	name=$(docker pull -q "$ref")
	docker save -o "$tar.tmp" "$ref"
	name_archive "\"io.containerd.image.name\":\"$name\""
	echo "saved    $ref"
done <<<"$entries"
