# shellcheck shell=sh disable=SC2154 # run after lib-pool.sh, which sets the lab's variables
# e41.sh — does a per-source connection-count limit hold in front of the
# pooler, and does it fail closed? The limit table (inet supapace_limit, its
# own table, hooked at priority filter - 11 ahead of the node's tables) is
# loaded by hand beside the node's two as-built tables:
#   L1  a new connection to the pooler's two ports from a source with more
#       than 64 tracked connections is reset;
#   L2  (the companion) a new connection whose source is not in the set after
#       L1's add is dropped — so a full set refuses new sources;
#   L3  a new flow of any protocol from an opted-in cluster's bridge (spe0)
#       beyond its count is dropped; L4 its companion.
# Sources are distinct addresses of the outside client: each extra address
# reaches the pooler through an extra address of the node (a host route per
# destination with that source), so every flow enters the node's forward path
# from outside, as a remote client's does.
#
# Criteria: the main ruleset stays static; a source at its limit is refused
# while another connects; `supapaced nft load` under 200 open connections
# neither resets the counts nor passes a connection; the content check of the
# limit table (listed without set elements) is stable while the set changes;
# with the set full (size lowered to 8, eight sources in it) a ninth source is
# refused and a source in it still connects — run with the companion rule and
# with the large-set alternative (no companion; the set is meant to be sized at
# nf_conntrack_max); a member of spe0 at its count (lowered to 8) opens no
# further flow while another member does.
#
# The table needs the kernel module nft_connlimit. When the wrapper finds it
# absent (CONNLIMIT=absent) nothing that names a count is ever handed to nft —
# that would make the kernel load the module — and only the control lines that
# need no limit rule run; every criterion is then UNRUN and the script exits 4.
#
# Run by the wrapper: test/harness/experiments/pool-lab.sh <node> e41.sh

case ${CONNLIMIT:-} in
present | absent) ;;
*) die "CONNLIMIT must be present or absent (set by pool-lab.sh)" ;;
esac
LIMIT=64 FULL_SIZE=8 EGRESS_RUN=8
lab_up
R=$(ref_of 0)
# More than 200 clients of one login and mode: the pool's client cap (100 by
# default) is raised for the run, so that only the limit under test refuses.
st=$(MAXC=300 register 0)
[ "$st" = 200 ] || die "raising the client cap answered $st"
EGR=$P-egr EGR_SUB=10.212.16.0/24

# --- sources ----------------------------------------------------------------
# Source 0 is the outside client's own address, to the node's own address;
# source k (1..8) is 192.0.2.(base+17+k) to the node's 192.0.2.(base+9+k).
base=${OUT_SUBNET%/*}
pre=${base%.*} o4=${base##*.}
src_ip() { if [ "$1" = 0 ]; then echo "$OUT_CLIENT_IP"; else echo "$pre.$((o4 + 17 + $1))"; fi; }
dst_ip() { if [ "$1" = 0 ]; then echo "$OUT_NODE_IP"; else echo "$pre.$((o4 + 9 + $1))"; fi; }
out_if=$(ip -o -4 addr show to "$OUT_NODE_IP/32" | awk '{print $2; exit}')
[ -n "$out_if" ] || die "no interface of the node holds $OUT_NODE_IP"
e41_cleanup() {
	for k in 1 2 3 4 5 6 7 8; do ip addr del "$(dst_ip "$k")/32" dev "$out_if" 2>/dev/null || :; done
	# The outside client is the wrapper's, and goes with it.
	if [ "$CONNLIMIT" = present ]; then nft delete table inet supapace_limit 2>/dev/null || :; fi
	"$SP_BIN/supapaced" nft load >/dev/null 2>&1 || :
}
trap 'trap "" PIPE; e41_cleanup; lab_down' EXIT
for k in 1 2 3 4 5 6 7 8; do
	ip addr add "$(dst_ip "$k")/32" dev "$out_if"
	outside "ip addr add $(src_ip "$k")/32 dev eth0 && ip route replace $(dst_ip "$k")/32 dev eth0 src $(src_ip "$k")" ||
		die "source $k: $OUT"
done
outside "printf 'select 1;\\n\\\\sleep 2 s\\n' > /tmp/idle.sql" || die "idle script: $OUT"

# hold_src K N: N authenticated connections from source K (pgbench, one
# process), each sending `select 1` every 2 s, so that a cut connection aborts
# its client (counted by hold_errors); established K: those of source K the
# client sees established.
hold_src() {
	outside "PGPASSWORD='$(password 0 postgres)' PGSSLMODE=require nohup pgbench -n -c $2 -j 1 -T 600 -f /tmp/idle.sql -h $(dst_ip "$1") -p 6543 -U postgres.$R postgres </dev/null >/tmp/hold-$1.out 2>&1 &" ||
		die "hold from source $1: $OUT"
}
established() {
	outside "netstat -tn | awk '\$4 ~ /^$(src_ip "$1"):/ && \$5 == \"$(dst_ip "$1"):6543\" && \$6 == \"ESTABLISHED\"' | wc -l" || :
	echo "$OUT" | tr -d ' '
}
# hold_errors: the error lines the holders of sources 0..8 have written so far
# (a client whose connection was cut or refused aborts with one).
hold_errors() {
	outside "cat /tmp/hold-[0-8].out 2>/dev/null | grep -c -i -E 'error|abort' || true" || :
	echo "$OUT" | tr -d ' '
}
# reload_watch K: across the next 20 s, source K tries new logins in a loop;
# every one that gets through is counted in /tmp/reload-pass. reload_passes
# waits (40 s at most) for the loop to end and prints that count.
reload_watch() {
	outside "rm -f /tmp/reload-pass /tmp/reload-done; (PGPASSWORD='$(password 0 postgres)' timeout 20 sh -c 'while :; do psql \"host=$(dst_ip "$1") port=6543 user=postgres.$R dbname=postgres sslmode=require connect_timeout=5\" -X -At -c \"select 1\" >/dev/null 2>&1 && echo ok >>/tmp/reload-pass; done'; touch /tmp/reload-done) </dev/null >/dev/null 2>&1 &" ||
		die "reload watch: $OUT"
}
reload_passes() {
	_rp=0
	until outside "test -e /tmp/reload-done"; do
		_rp=$((_rp + 1))
		[ "$_rp" -le 40 ] || die "the reload watch did not end"
		sleep 1
	done
	outside "cat /tmp/reload-pass 2>/dev/null | wc -l" || :
	echo "$OUT" | tr -d ' '
}
# wait_established K N: up to 120 s for N connections of source K.
wait_established() {
	_we=0
	until [ "$(established "$1")" -ge "$2" ]; do
		_we=$((_we + 2))
		[ "$_we" -le 120 ] || break
		sleep 2
	done
	established "$1"
}
# try_src K: one login from source K; status returned, answer in PQ.
try_src() {
	_s=0
	outside "PGPASSWORD='$(password 0 postgres)' timeout 40 psql 'host=$(dst_ip "$1") port=6543 user=postgres.$R dbname=postgres sslmode=require connect_timeout=15' -X -At -c 'select 1' 2>&1" || _s=$?
	PQ=$(printf '%s' "$OUT" | tr '\n' ' ')
	[ "$_s" != 0 ] || [ "$PQ" = 1 ] || _s=1
	return "$_s"
}
stop_holds() {
	outside "pkill pgbench; true" || :
	for k in 0 1 2 3 4 5 6 7 8; do
		_sh=0
		until [ "$(established "$k")" = 0 ]; do
			_sh=$((_sh + 1))
			[ "$_sh" -le 60 ] || break
			sleep 1
		done
	done
}
main_digest() { nft -s list table inet supapace | sha256sum | cut -c1-16; nft -s list table bridge supapace | sha256sum | cut -c1-16; }

# limit_table FORM SIZE EGRESS: the limit table's text; FORM companion adds
# L2 and L4, FORM large leaves them out.
limit_table() {
	cat <<-EOF
		table inet supapace_limit
		delete table inet supapace_limit
		table inet supapace_limit {
		    set pool_src4   { type ipv4_addr; flags dynamic; size $2; }
		    set egress_src4 { type ipv4_addr; flags dynamic; size 4096; }
		    chain forward {
		        type filter hook forward priority filter - 11; policy accept;
		        oifname "spi0" ip daddr $POOLER_ING_IP tcp dport { 5432, 6543 } ct state new add @pool_src4 { ip saddr ct count over $LIMIT } reject with tcp reset comment "L1"
	EOF
	[ "$1" != companion ] || echo "        oifname \"spi0\" ip daddr $POOLER_ING_IP tcp dport { 5432, 6543 } ct state new ip saddr != @pool_src4 drop comment \"L2\""
	echo "        iifname \"spe0\" ct state new add @egress_src4 { ip saddr ct count over $3 } drop comment \"L3\""
	[ "$1" != companion ] || echo "        iifname \"spe0\" ct state new ip saddr != @egress_src4 drop comment \"L4\""
	printf '    }\n}\n'
}
# load_limit FORM SIZE EGRESS: only with the module loaded.
load_limit() {
	[ "$CONNLIMIT" = present ] || die "refusing to hand a count to nft without nft_connlimit"
	limit_table "$@" | nft -f - || die "the limit table did not load"
}

D0=$(main_digest)
say "nf_conntrack_max $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo unknown); limit $LIMIT; module nft_connlimit $CONNLIMIT"

step "controls without a limit rule"
hold_src 0 $((LIMIT + 1))
n=$(wait_established 0 $((LIMIT + 1)))
ok=0
[ "$n" -ge $((LIMIT + 1)) ] && ok=1
control "L1 without the table: source 0 holds $((LIMIT + 1)) connections" "$ok" "$n established"
stop_holds
for k in 0 1 2 3; do hold_src "$k" 50; done
for k in 0 1 2 3; do wait_established "$k" 50 >/dev/null; done
before=$(for k in 0 1 2 3; do established "$k"; done | awk '{s += $1} END {print s}')
e0=$(hold_errors)
"$SP_BIN/supapaced" nft load >/dev/null || die "reload failed"
# Three of the sessions' 2-second query rounds: a session the reload cut has
# failed its query and its client has aborted by then.
sleep 6
after=$(for k in 0 1 2 3; do established "$k"; done | awk '{s += $1} END {print s}')
e1=$(hold_errors)
ok=0
[ "$before" -ge 200 ] && [ "$after" = "$before" ] && [ "$e0" = 0 ] && [ "$e1" = 0 ] && "$SP_BIN/supapaced" nft check >/dev/null && ok=1
control "reload of the two main tables under $before active connections, without the table: none cut, tables verified" "$ok" "$before before, $after 6 s after; holder errors $e0 before, $e1 after"
stop_holds
ok=0
[ "$(main_digest)" = "$D0" ] && ok=1
control "the main tables' listing is unchanged by the reload" "$ok" "$(main_digest | tr '\n' ' ')"
# The spe0 pair: an egress bridge with two members, the node's tables told to
# route their new flows out (lab rules, removed by the next load).
docker network create --label supapace.test=1 --ipv6=false --subnet "$EGR_SUB" -o com.docker.network.bridge.name=spe0 "$EGR" >/dev/null
for m in a b; do
	docker run -d --name "$P-egr-$m" --label supapace.test=1 --network "$EGR" --memory 64m --cap-drop ALL \
		--entrypoint sleep "$CP_IMAGE" infinity >/dev/null
done
nft insert rule inet supapace forward oifname "spe0" ct state established,related accept
nft insert rule inet supapace forward iifname "spe0" ct state new accept
outside "nohup nc -lk -p 7000 -e cat </dev/null >/dev/null 2>&1 &" || die "listener: $OUT"
# flows M N: N connections held from member M to the outside listener; prints
# how many are established.
flows() {
	docker exec -d "$P-egr-$1" sh -c "for i in \$(seq $2); do (sleep 600 | nc $OUT_CLIENT_IP 7000 >/dev/null 2>&1 &); done"
	_fw=0
	until [ "$(docker exec "$P-egr-$1" sh -c "netstat -tn | grep -c '$OUT_CLIENT_IP:7000 *ESTABLISHED'")" -ge "$2" ]; do
		_fw=$((_fw + 1))
		[ "$_fw" -le 60 ] || break
		sleep 1
	done
	docker exec "$P-egr-$1" sh -c "netstat -tn | grep -c '$OUT_CLIENT_IP:7000 *ESTABLISHED'" || :
}
n=$(flows a $((EGRESS_RUN + 1)))
ok=0
[ "$n" -ge $((EGRESS_RUN + 1)) ] && ok=1
control "L3 without the table: member a holds $((EGRESS_RUN + 1)) flows" "$ok" "$n established"
docker exec "$P-egr-a" sh -c 'pkill nc; pkill sleep; true'
"$SP_BIN/supapaced" nft load >/dev/null || die "reload failed"

if [ "$CONNLIMIT" = absent ]; then
	for c in "L the main ruleset stays static with the limit table beside it" \
		"L1 a source at its limit is refused while another connects" \
		"L1 a reload of the main tables under 200 open connections neither resets the counts nor passes a connection" \
		"L the content check (no set elements) is stable while the set changes" \
		"L2 with the set full a further source is refused (dropped)" \
		"L2 with the set full a source already in it still connects" \
		"large-set alternative with the set full" \
		"L3 a member of spe0 at its count opens no further flow while another member does"; do
		res UNRUN "$c" "module nft_connlimit absent"
	done
	say "VERDICT E41: UNRUN — module nft_connlimit absent"
	finish e41 || exit 1
	exit 4
fi

step "the limit table, companion form, set size 65536"
load_limit companion 65536 4096
T0=$(nft -s -t list table inet supapace_limit | sha256sum | cut -c1-16)
if [ "$(main_digest)" = "$D0" ] && "$SP_BIN/supapaced" nft check >/dev/null; then
	res PASS "L the main ruleset stays static with the limit table beside it" "main tables $(main_digest | tr '\n' ' '), verified"
else
	res FAIL "L the main ruleset stays static with the limit table beside it" "main tables $(main_digest | tr '\n' ' ')"
fi
# The source the full-set run tries last must be able to connect while the set
# has room, or its refusal there would prove nothing.
ok=0
try_src "$FULL_SIZE" && ok=1
control "L2 source $FULL_SIZE connects while the set has room" "$ok" "$PQ"
hold_src 0 "$LIMIT"
n0=$(wait_established 0 "$LIMIT")
s0=0
try_src 0 || s0=$?
a0=$PQ
s1=0
try_src 1 || s1=$?
reset=0
case $a0 in *"Connection refused"*) reset=1 ;; esac
if [ "$n0" = "$LIMIT" ] && [ "$s0" != 0 ] && [ "$reset" = 1 ] && [ "$s1" = 0 ]; then
	res PASS "L1 a source at its limit is refused while another connects" "source 0: $n0 held, one more reset ($a0); source 1 served"
else
	res FAIL "L1 a source at its limit is refused while another connects" "source 0: $n0 held, one more status $s0 ($a0); source 1 status $s1 ($PQ)"
fi
T1=$(nft -s -t list table inet supapace_limit | sha256sum | cut -c1-16)
elements=$(nft list set inet supapace_limit pool_src4 | grep -c 'ct count' || :)
if [ "$T0" = "$T1" ] && [ "$elements" -ge 1 ]; then
	res PASS "L the content check (no set elements) is stable while the set changes" "terse listing $T0 empty and populated; $elements element line(s) in the full listing"
else
	res FAIL "L the content check (no set elements) is stable while the set changes" "terse $T0 -> $T1; element lines $elements"
fi
for k in 1 2 3; do hold_src "$k" 50; done
for k in 1 2 3; do wait_established "$k" 50 >/dev/null; done
before=$(for k in 0 1 2 3; do established "$k"; done | awk '{s += $1} END {print s}')
e0=$(hold_errors)
# Source 0, at its limit, keeps trying new logins across the reload.
reload_watch 0
"$SP_BIN/supapaced" nft load >/dev/null || die "reload failed"
passed=$(reload_passes)
# Three query rounds after the reload: a cut session has aborted by then.
sleep 6
after=$(for k in 0 1 2 3; do established "$k"; done | awk '{s += $1} END {print s}')
e1=$(hold_errors)
n0=$(established 0)
s0=0
try_src 0 || s0=$?
reset=0
case $PQ in *"Connection refused"*) reset=1 ;; esac
if [ "$before" -ge 200 ] && [ "$after" = "$before" ] && [ "$e0" = 0 ] && [ "$e1" = 0 ] && [ "$passed" = 0 ] &&
	[ "$n0" = "$LIMIT" ] && [ "$reset" = 1 ] &&
	[ "$(nft -s -t list table inet supapace_limit | sha256sum | cut -c1-16)" = "$T0" ]; then
	res PASS "L1 a reload of the main tables under 200 open connections neither resets the counts nor passes a connection" "$before active before, $after after, holder errors $e0/$e1; 0 logins of source 0 got through across the reload; source 0 still $n0 and reset"
else
	res FAIL "L1 a reload of the main tables under 200 open connections neither resets the counts nor passes a connection" "$before before, $after after, holder errors $e0/$e1; $passed logins of source 0 got through; source 0 $n0, one more status $s0 ($PQ)"
fi
stop_holds

# full FORM: the set at its size with sources 0..SIZE-1, one session each; the
# run stops unless every one of them is established (else the set is not full).
full() {
	load_limit "$1" "$FULL_SIZE" 4096
	for k in $(seq 0 $((FULL_SIZE - 1))); do hold_src "$k" 1; done
	_in=0
	for k in $(seq 0 $((FULL_SIZE - 1))); do _in=$((_in + $(wait_established "$k" 1))); done
	[ "$_in" = "$FULL_SIZE" ] || die "the set is not full: $_in of $FULL_SIZE sources hold a session"
	FS=0
	try_src "$FULL_SIZE" || FS=$?
	FA=$PQ
	MS=0
	try_src 0 || MS=$?
	MA=$PQ
	stop_holds
}
step "the set full (size $FULL_SIZE), companion form"
full companion
case $FA in *timeout*) dropped=1 ;; *) dropped=0 ;; esac
if [ "$FS" != 0 ] && [ "$dropped" = 1 ]; then
	res PASS "L2 with the set full a further source is refused (dropped)" "source $FULL_SIZE: status $FS ($FA)"
else
	res FAIL "L2 with the set full a further source is refused (dropped)" "source $FULL_SIZE: status $FS ($FA)"
fi
if [ "$MS" = 0 ]; then
	res PASS "L2 with the set full a source already in it still connects" "source 0 served"
else
	res FAIL "L2 with the set full a source already in it still connects" "status $MS ($MA)"
fi
companion_ok=$([ "$FS" != 0 ] && [ "$dropped" = 1 ] && [ "$MS" = 0 ] && echo 1 || echo 0)
step "the set full (size $FULL_SIZE), large-set alternative (no companion)"
full large
res RECORDED "large-set alternative with the set full" "a further source: status $FS ($FA); a source in it: status $MS ($MA)"

step "the spe0 count, companion form, count $EGRESS_RUN"
# Only the count is exercised: egress_src4 holds one element per opted-in
# cluster and is not filled here. TCP flows only; the rule matches any protocol.
load_limit companion 65536 "$EGRESS_RUN"
nft insert rule inet supapace forward oifname "spe0" ct state established,related accept
nft insert rule inet supapace forward iifname "spe0" ct state new accept
na=$(flows a $((EGRESS_RUN + 1)))
nb=$(flows b 1)
if [ "$na" = "$EGRESS_RUN" ] && [ "$nb" = 1 ]; then
	res PASS "L3 a member of spe0 at its count opens no further flow while another member does" "member a: $na of $((EGRESS_RUN + 1)); member b: $nb"
else
	res FAIL "L3 a member of spe0 at its count opens no further flow while another member does" "member a: $na of $((EGRESS_RUN + 1)); member b: $nb"
fi
"$SP_BIN/supapaced" nft load >/dev/null || die "reload failed"

scan_result
if [ "$FAILS" = 0 ]; then
	say "VERDICT E41: PASS — form: the companion rule L2 beside L1 (L3 by count; L4 not filled)"
elif [ "$companion_ok" = 1 ]; then
	say "VERDICT E41: FAIL — the full set fails closed with the companion form, but see the lines above"
else
	say "VERDICT E41: FAIL — see the lines above; fallback: MAX_CONNECTIONS as a node-wide last resort and the flood before authentication named as a residual"
fi
finish e41
