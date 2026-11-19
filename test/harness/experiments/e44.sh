#!/bin/sh
# e44.sh - a dial from inside a container's network namespace (internal/nsdial).
# Does a dial reach the target container's own listener and no other
# namespace's; is no other goroutine's connection ever made from the
# namespace while 64 goroutines dial from the host; is a container restarted
# between inspection and entry detected? Also: the context's deadline inside
# the namespace, and the process's thread count after 1,000 dials.
#
# The package's reach-tagged tests do the work; this script runs them as root
# and prints one line per criterion. Build the test binary on the host first
# (static, into the directory the node mounts at /opt/supapace/bin):
#   CGO_ENABLED=0 go test -c -tags reach -o bin/nsdial.test ./internal/nsdial
# Run on the bare test node: docker exec -i <node> sh -s < e44.sh
set -eu

BIN=/opt/supapace/bin/nsdial.test
# The control_plane image of images.lock: only its root filesystem is used.
IMG=postgres@sha256:a77aa70e641402a21411b92b721c58d10f23b50ae5fdd2333efd22d166e1e5f7
LOG=/tmp/e44.log

say() { echo "e44: $*"; }
cleanup() {
	ids=$(docker ps -aq --filter label=supapace.test=1 --filter name=sp-test-nsdial-)
	[ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || :
	rm -f "$LOG"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

[ "$(id -u)" = 0 ] || { say "needs root"; exit 2; }
[ -x "$BIN" ] || { say "$BIN absent: build it on the host (see the header)"; exit 2; }
docker image inspect "$IMG" >/dev/null || { say "image $IMG not loaded"; exit 2; }
cleanup

say "kernel $(uname -r), $(nproc) CPUs"
s=0
NSDIAL_IMAGE=$IMG "$BIN" -test.v -test.count=1 -test.timeout 15m -test.run 'TestDialTCP_|TestTarget_|TestTargetOf_|TestDialer_|TestStartTicks_' >"$LOG" 2>&1 || s=$?
grep -E '^(=== RUN|--- |    nsdial_)' "$LOG" | grep -v '^=== RUN' || :

verdict() { # criterion test
	if grep -q -- "--- PASS: $2 " "$LOG"; then echo "PASS $1 ($2)"
	else echo "FAIL $1 ($2)"; s=1; fi
}
verdict "a dial reaches the target's own listener and no other namespace's" TestDialTCP_ReachesOnlyTheTargetNamespace
verdict "no other goroutine's connection is made from the namespace" TestDialTCP_NoOtherConnectionFromTheNamespace
verdict "a restart between inspection and entry is detected" TestDialTCP_RestartBetweenInspectionAndEntryDetected
verdict "the context's deadline holds inside the namespace" TestDialTCP_DeadlineInsideTheNamespace
verdict "threads do not accumulate" TestDialTCP_ThreadsDoNotAccumulate
if [ "$s" = 0 ]; then echo "VERDICT E44: confirmed — the in-process entry holds all three criteria."
else echo "VERDICT E44: failed — see the lines above."; fi
exit "$s"
