# shellcheck shell=sh disable=SC2034 # the variables are used by the scripts that run after this file
# lib-agent.sh — after lib-backup.sh, in a bare test node: the experiments that
# drive the platform's own code. Not run by itself: ag/lab.sh builds the daemon
# with its `exp` command, copies both libraries, that binary and one script
# into the node and runs them there as root:
#
#   test/harness/experiments/ag/lab.sh NODE SCRIPT
#
# Where lib-backup.sh stands a project up by hand and runs shell stand-ins of
# the job programs, these functions call internal/agent through `supapaced exp`
# (ag/exp.go): a layout-2 project as the agent creates it, every job by
# agent.RunJob with the daemon's own job programs, the recovery start and the
# re-key of internal/agent, the control-plane database of internal/agent, the
# node ruleset of internal/nft. lib-backup.sh's verdict lines (res, check,
# control), s3 and worker (for pgBackRest commands no platform job runs, such
# as verify and expire) are used as they are.
#
# Functions (REF a 20-character ref; the project's uid is also its gid):
#   ag ARGS…                      supapaced exp ARGS…
#   ag_lab ID                     lab_up, the node's platform objects, the ruleset
#                                 with the stand-in's addresses; ID names the
#                                 VERDICT line; a fresh store prefix in $PFX
#   ag_project REF UID SLICE DISKMB REPOMB   a layout-2 project, running
#   asql REF SQL / atsql REF SQL  superuser session: SCRAM / trust (recovery start)
#   ajob REF KIND [OPTIONS]       one job; its output in $JOUT, the summary in $JSUM,
#                                 the result line in $JRES; the job's status
#   serve_bg REF / serve_end      a serve job in the background / stopped (its summary
#                                 in $JSUM)
#   arecover REF [OPTIONS]        serve job, recovery start until promoted, serve
#                                 stopped; the promotion line in $RLINE
#   restore_set REF LABEL         stop, wipe, restore job of LABEL
#   stage TEXT                    a step's heading; named by an unexpected exit
#   verdict ID SENTENCE           the VERDICT line: confirmed when every line
#                                 passed, else unknown; the exit status
# AG_CLEAN: shell commands a script adds for what it made itself (run first).
# The EXIT trap removes everything the lab made (ag downall, then lab_down) and,
# when no VERDICT line was printed, prints one naming the step that stopped.

EXPB=$KIT/bin/supapaced
export SUPAPACE_EXP_DIR="$KIT/a"
ag() { "$EXPB" exp "$@"; }

STAGE=start DONE='' VID=E2x
stage() {
	STAGE=$*
	step "$*"
}

serve_end() {
	[ -s "$KIT/serve.pid" ] || return 0
	kill -TERM "$(cat "$KIT/serve.pid")" 2>/dev/null || :
	wait "$(cat "$KIT/serve.pid")" 2>/dev/null || :
	rm -f "$KIT/serve.pid"
	JSUM=$(sed -n 's/^summary //p' "$KIT/serve.out")
	say "serve: ${JSUM:-no result}"
}
serve_bg() {
	# The binary itself in the background (not the shell function), so that the TERM reaches it.
	# SERVE_TL: the timelines the serve job admits (the record's recorded, pending and abandoned
	# ones; the scripts here never hold more than three).
	"$EXPB" exp job "$1" serve -tl "${SERVE_TL:-1,2,3}" >"$KIT/serve.out" 2>&1 &
	echo $! >"$KIT/serve.pid"
}

ag_exit() {
	_rc=$?
	trap '' INT TERM
	set +e
	serve_end >/dev/null 2>&1
	eval "${AG_CLEAN:-}" >/dev/null 2>&1
	[ -n "$DONE" ] || say "VERDICT $VID: unknown — the run stopped (exit $_rc) at step: $STAGE"
	ag downall >/dev/null 2>"$KIT/down.err" || { say "cleanup: $(head -c 400 "$KIT/down.err")"; _rc=3; }
	lab_down
	exit "$_rc"
}
trap ag_exit EXIT

ag_lab() {
	VID=$1
	lab_up
	ag downall >/dev/null 2>&1 || :
	ag node -offsite || die "the node's platform objects"
	# A fresh store prefix per run: the stand-in keeps what earlier runs on this node wrote.
	PFX=lab-$LAB_T0-$(rand_hex 3)
	say "lab: store prefix $PFX; daemon $(sha256sum "$EXPB" | cut -c1-16) (with the exp command)"
}

ag_project() {
	ag up "$@" || die "project $1"
	printf '%s\n' "$2" >"$KIT/p/$1" # for lib-backup.sh's worker and lab_down
	echo 0 >"$KIT/p/$1.gen"
	ag pass "$1" "$S/$1.pass"
}

asql() { ag sql "$1" "$2"; }
atsql() { ag sql -trust "$1" "$2"; }

# ajob REF KIND [OPTIONS]: $JOUT the whole output, $JRES the result line, $JSUM its summary.
ajob() {
	_s=0
	JOUT=$(ag job "$@" 2>&1) || _s=$?
	JRES=$(printf '%s\n' "$JOUT" | sed -n 's/^result //p')
	JSUM=$(printf '%s\n' "$JOUT" | sed -n 's/^summary //p')
	return $_s
}
# jsay: the job's summary, its failure line if any, trimmed.
jsay() { say "  $2 $1: ${JSUM:-$(printf '%s\n' "$JOUT" | tail -2 | tr '\n' ' ' | cut -c1-300)}"; }

restore_set() {
	_r=$1 _l=$2
	shift 2
	{ ag stop "$_r" && ag wipe "$_r"; } || die "stop and wipe $_r"
	ajob "$_r" restore -set "$_l" "$@" || {
		jsay "$_r" restore
		return 1
	}
}

# arecover REF [OPTIONS]: $RLINE the promotion line; the recovery start keeps running when promoted.
arecover() {
	_r=$1
	shift
	serve_bg "$_r"
	_s=0
	RLINE=$(ag recover "$_r" "$@" 2>&1) || _s=$?
	serve_end
	say "recovery start of $_r: $RLINE"
	return $_s
}

verdict() {
	DONE=1
	_t=$(($(date +%s) - LAB_T0))
	say ""
	say "run time: $_t s"
	if [ "$FAILS" = 0 ] && [ "$UNRUNS" = 0 ]; then
		say "VERDICT $1: confirmed — $2"
		return 0
	fi
	say "VERDICT $1: unknown — $FAILS criterion line(s) failed, $UNRUNS not run; expected: confirmed — $2"
	return 1
}
