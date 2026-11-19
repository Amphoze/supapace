# shellcheck shell=sh disable=SC2154 # run after lib-pool.sh, which sets the lab's variables
# e40.sh — what source address does the pooler see? Supavisor published with
# an explicit IPv4 bind (0.0.0.0:5432 and 0.0.0.0:6543) on the ingress
# address, under the node's tables; three clients:
#   remote      the outside client on the lab bridge, to the node's address there;
#   node-local  a client on the node's own network, to 127.0.0.1;
#   hairpinned  the same client, to the node's own lab-bridge address;
# and, recorded, a container on a bridge of the node to the node's address.
# The address is read from the pooler's own refusal: a tenant whose allow_list
# admits only a documentation address answers EADDRNOTALLOWED naming the peer it
# saw. Pass: the remote client shows its own address, the node-local and the
# hairpinned client a node-internal one. Then the restriction itself: an
# allow_list of the remote client's address alone admits it and refuses the
# node-local client (control: both admitted with the open list).
#
# Run by the wrapper: test/harness/experiments/pool-lab.sh <node> e40.sh

lab_up
R=$(ref_of 0)
NOWHERE='"203.0.113.250/32"'

# internal ADDRESS: a node-internal address (the node's private blocks, loopback).
internal() {
	case $1 in 10.21[2-5].* | 127.*) return 0 ;; *) return 1 ;; esac
}

step "addresses seen by the pooler (allow_list admits only 203.0.113.250)"
st=$(register 0 "$NOWHERE")
[ "$st" = 200 ] || [ "$st" = 201 ] || die "update with a closed list answered $st"
for port in 5432 6543; do
	pq_out 0 postgres "$port" 'select 1' || :
	seen=$(peer_of "$PQ")
	if [ "$seen" = "$OUT_CLIENT_IP" ]; then
		res PASS "remote client, port $port, shows its own address" "seen $seen, client $OUT_CLIENT_IP"
	else
		res FAIL "remote client, port $port, shows its own address" "seen '${seen:-none}', client $OUT_CLIENT_IP: $PQ"
	fi
	pq 0 postgres "$port" 127.0.0.1 'select 1' || :
	seen=$(peer_of "$PQ")
	if [ -n "$seen" ] && internal "$seen"; then
		res PASS "node-local client (127.0.0.1), port $port, shows a node-internal address" "seen $seen"
	else
		res FAIL "node-local client (127.0.0.1), port $port, shows a node-internal address" "seen '${seen:-none}': $PQ"
	fi
	pq 0 postgres "$port" "$OUT_NODE_IP" 'select 1' || :
	seen=$(peer_of "$PQ")
	if [ -n "$seen" ] && internal "$seen"; then
		res PASS "hairpinned client (node to its own $OUT_NODE_IP), port $port, shows a node-internal address" "seen $seen"
	else
		res FAIL "hairpinned client (node to its own $OUT_NODE_IP), port $port, shows a node-internal address" "seen '${seen:-none}': $PQ"
	fi
done

# A member of a bridge of the node, to the node's lab-bridge address: what the
# node's tables do with a hairpin from a container (input from a bridge: I2).
docker run -d --name "$P-hairpin" --label supapace.test=1 --network "$P-ing" --memory 128m \
	-v "$KIT/ca.pem:/ca.pem:ro" --entrypoint sleep "$CP_IMAGE" infinity >/dev/null
s=0
out=$(PGPASSWORD=$(password 0 postgres) docker exec -e PGPASSWORD "$P-hairpin" timeout 40 \
	psql "host=$OUT_NODE_IP port=6543 user=postgres.$R dbname=postgres sslmode=require connect_timeout=15" -X -At -c 'select 1' 2>&1) || s=$?
out=$(printf '%s' "$out" | tr '\n' ' ')
res RECORDED "container on the ingress bridge to the node's $OUT_NODE_IP:6543" "status $s, seen '$(peer_of "$out")': $out"
docker rm -f "$P-hairpin" >/dev/null

step "the restriction: allow_list = the remote client's address alone"
st=$(register 0 "\"$OUT_CLIENT_IP/32\"")
[ "$st" = 200 ] || [ "$st" = 201 ] || die "update with the client's list answered $st"
if pq_out 0 postgres 6543 'select 1'; then
	res PASS "restriction admits the listed remote client" "answer: $PQ"
else
	res FAIL "restriction admits the listed remote client" "$PQ"
fi
if pq 0 postgres 6543 127.0.0.1 'select 1'; then
	res FAIL "restriction refuses the node-local client" "admitted: $PQ"
else
	case $PQ in
	*EADDRNOTALLOWED*) res PASS "restriction refuses the node-local client (address not allowed)" "$PQ" ;;
	*) res FAIL "restriction refuses the node-local client (address not allowed)" "refused for another reason: $PQ" ;;
	esac
fi
st=$(register 0)
[ "$st" = 200 ] || [ "$st" = 201 ] || die "update with the open list answered $st"
ok=0
pq 0 postgres 6543 127.0.0.1 'select 1' && pq_out 0 postgres 6543 'select 1' && ok=1
control "open allow_list admits both clients" "$ok" "last answer: $PQ"

"$SP_BIN/supapaced" nft check >/dev/null && t=verified || t="NOT verified"
res RECORDED "node tables after the run" "$t"
scan_result
if [ "$FAILS" = 0 ]; then
	say "VERDICT E40: PASS — a remote IPv4 client is seen with its own address; node-local and hairpinned clients with a node-internal one; the restriction holds on the address-preserving path"
else
	say "VERDICT E40: FAIL — see the lines above; fallback: network restrictions are not offered"
fi
finish e40
