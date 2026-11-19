#!/bin/sh
# setup.sh — the object-store stand-in beside a running test node (make node-up and
# node-bare call it unless SP_OFFSITE=0; make node-down removes what it made).
#
#   NODE=… NODE_IMAGE=… S3_IMAGE=name@digest S3_SLOT=… S3_NET1=… S3_NET2=… \
#   S3_ADDR1=… S3_ADDR2=… S3_NODE1=… S3_NODE2=… test/harness/s3/setup.sh
#
# The lab's subnets and addresses are the node's lab slot's (the Makefile derives
# them, `make lab` prints them); this script takes them from its environment only.
#
# Like a provider's endpoint, the stand-in is reached by routing: two internal lab
# networks $NODE-net and $NODE-net2 (no route out, no address of this machine on
# them, labelled as test objects),
# the stand-in $NODE-s3 on both at fixed addresses — one endpoint name with two
# addresses — and the node joined to both. Its data is on a tmpfs.
# TLS comes from a harness CA made in a throw-away container of the node image;
# the certificate is for the endpoint name only. Then, with the admin keys, the
# buckets sp-projects and sp-cp: created with the object-lock header,
# versioning enabled, a compliance lock of 1 day, and the lifecycle rule
# (incomplete uploads aborted after 1 day, noncurrent versions expired 1 day
# after they became noncurrent). Last, the node's /var/lib/sp/s3/ (root, read
# only): endpoint, addrs (the stand-in's two addresses, one per line), ca.pem and
# the keys of each identity of identities.json.tmpl
# (admin, projects-write, projects-read, cp-write, cp-read); a full node then
# declares the stand-in (node-init.sh declare-offsite).
set -eu
: "${NODE:?}" "${NODE_IMAGE:?}" "${S3_IMAGE:?}" "${S3_SLOT:?}" "${S3_NET1:?}" "${S3_NET2:?}"
: "${S3_ADDR1:?}" "${S3_ADDR2:?}" "${S3_NODE1:?}" "${S3_NODE2:?}"
here=$(dirname "$0")
. "$here/lab.env"
die() {
	echo "s3 setup: $*" >&2
	exit 1
}
case $S3_SLOT in
0 | [1-9] | [1-9][0-9] | 1[0-9][0-9] | 2[0-4][0-9] | 25[0-5]) ;;
*) die "S3_SLOT=$S3_SLOT: a lab slot is a number from 0 to 255" ;;
esac
docker image inspect "$S3_IMAGE" >/dev/null 2>&1 || die "$S3_IMAGE is not in this machine's Docker; run make images"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/tls" "$tmp/node"

docker run --rm --label supapace.test=1 --network none --entrypoint sh "$NODE_IMAGE" -c '
	set -e
	cd "$(mktemp -d)"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=supapace harness CA" \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout ca.key -out ca.pem 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout key.pem -out req.pem 2>/dev/null
	printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n" "$1" >ext
	openssl x509 -req -in req.pem -CA ca.pem -CAkey ca.key -days 3650 -extfile ext -out cert.pem 2>/dev/null
	tar -cf - ca.pem cert.pem key.pem' sh "$S3_NAME" | tar -xf - -C "$tmp/tls"
cp "$tmp/tls/ca.pem" "$tmp/node/ca.pem"
printf 'https://%s:%s\n' "$S3_NAME" "$S3_PORT" >"$tmp/node/endpoint"
printf '%s\n%s\n' "$S3_ADDR1" "$S3_ADDR2" >"$tmp/node/addrs"

# One random key pair per identity: the stand-in's configuration and the node's keys files.
rnd() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
sub=''
for r in admin projects-write projects-read cp-write cp-read; do
	ak=$(rnd 10) sk=$(rnd 20)
	printf '%s\n%s\n' "$ak" "$sk" >"$tmp/node/$r.keys"
	sub="$sub -e s/@${r}_access@/$ak/ -e s/@${r}_secret@/$sk/"
done
# shellcheck disable=SC2086 # $sub is a list of sed arguments without spaces
sed $sub "$here/identities.json.tmpl" >"$tmp/tls/s3.json"
! grep -q @ "$tmp/tls/s3.json" || die "identities.json.tmpl has a placeholder without a key"
chmod 0644 "$tmp/tls/"*

L="--label supapace.test=1"
# No address of this machine on the lab networks either: only their members reach the stand-in.
N="--internal -o com.docker.network.bridge.inhibit_ipv4=true"
for net in "$NODE-net $S3_NET1" "$NODE-net2 $S3_NET2"; do
	# shellcheck disable=SC2086 # $net is a name and a subnet
	docker network create $L $N --subnet ${net#* } ${net%% *} >/dev/null ||
		die "cannot create ${net%% *} on ${net#* }: the lab slot S3_SLOT=$S3_SLOT is in use by another network; pass another S3_SLOT=<n> (0..255) or SP_OFFSITE=0 (make node-down NODE=$NODE first)"
done
docker create $L --name "$NODE-s3" --network "$NODE-net" --ip "$S3_ADDR1" --memory 1g --tmpfs /data:size=512m \
	--entrypoint weed "$S3_IMAGE" mini -dir=/data -ip=127.0.0.1 -ip.bind=0.0.0.0 -s3.port.https="$S3_PORT" \
	-s3.cert.file=/tls/cert.pem -s3.key.file=/tls/key.pem -s3.config=/tls/s3.json >/dev/null
docker cp "$tmp/tls/." "$NODE-s3:/tls"
docker network connect --ip "$S3_ADDR2" "$NODE-net2" "$NODE-s3"
docker start "$NODE-s3" >/dev/null
docker network connect --ip "$S3_NODE1" "$NODE-net" "$NODE"
docker network connect --ip "$S3_NODE2" "$NODE-net2" "$NODE"

S3=/var/lib/sp/s3
tar -C "$tmp/node" -cf - . | docker exec -i "$NODE" sh -c "rm -rf $S3 && mkdir -m 0700 $S3 && tar -xof - -C $S3 &&
	chmod 0400 $S3/* && chmod 0500 $S3"

# s3 BUCKET SUBCOMMAND [ARG]…: sp-probe s3 in the node with the admin keys; the verdict line.
s3() {
	b=$1
	shift
	docker exec "$NODE" /opt/supapace/bin/sp-probe s3 "$@" --endpoint "https://$S3_NAME:$S3_PORT" \
		--keys $S3/admin.keys --bucket "$b" --ca $S3/ca.pem --timeout 10s
}
# Ready when it answers a signed request (a missing bucket is an answer).
i=0
until s3 sp-projects head >/dev/null 2>&1 || [ $? = 1 ]; do
	i=$((i + 1))
	[ "$i" -le 120 ] || die "the stand-in did not answer within 120 s: $(docker logs --tail 20 "$NODE-s3" 2>&1)"
	sleep 1
done
for b in sp-projects sp-cp; do
	for step in "mkbucket|created" "versioning enable|versioning Enabled" "lock 1|lock COMPLIANCE 1" \
		"lifecycle 1 1|lifecycle sp 1 1"; do
		# shellcheck disable=SC2086 # the step's words are the arguments
		got=$(s3 $b ${step%|*} 2>&1) || :
		[ "$got" = "${step#*|}" ] || die "$b: ${step%|*}: $got"
	done
done
docker exec "$NODE" /usr/local/bin/node-init.sh declare-offsite
echo "s3 setup: $NODE-s3 at $S3_ADDR1 and $S3_ADDR2, port $S3_PORT ($S3_NAME)"
