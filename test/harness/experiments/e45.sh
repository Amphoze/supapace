#!/bin/sh
# e45.sh - can the pinned upstream supabase CLI be pointed at another Management
# API host, and what does it send there? Fetches the CLI of pins-cli.env by
# checksum into the image cache, then runs `projects list` against the
# stand-in `sp-probe mgmt` in these tries, each with one PASS or FAIL line:
#
#   how the host is chosen: SUPABASE_API_URL alone; the built-in profile
#     supabase-local; a profile file by --profile, by SUPABASE_PROFILE and by
#     $HOME/.supabase/profile; a profile name in that file; a profile whose host
#     is dead (the control of every precedence try);
#   precedence: --profile over SUPABASE_PROFILE over $HOME/.supabase/profile,
#     both orders each; SUPABASE_API_URL beside a profile;
#   a path in api_url; profile files with an extra key, a non-http URL and a
#     missing member;
#   a token the stand-in refuses (401, the error document); the sbp_oauth_ and
#     sbp_v0_ forms; tokens refused before sending: not of the form, upper-case
#     hex, 39 and 41 digits, sbp_v1_, a trailing line end.
#
# The CLI is a third-party binary: it runs only inside a throw-away container
# without a network (loopback alone, where the stand-in listens), as the
# invoking user, with a scratch HOME, a made-up token and no mount but the CLI
# binary and the scratch directory. The CLI links against the GNU C library, so
# its image is built here from scratch and holds only this machine's copies of
# the interpreter and the shared libraries the binary names (read with readelf,
# never by running it); image and container are removed at the end. Nothing is
# sent anywhere but to the stand-in; the fetch is a plain HTTPS GET of the
# release archive.
#
# Run from the repository root on a glibc machine with Docker, Go and readelf:
#   sh test/harness/experiments/e45.sh
# IMAGE_CACHE as in the Makefile; E45_NAME names the container (labelled
# supapace.test=1). Prints "cli PATH" for the verified binary, a block and a
# PASS or FAIL line per try, a RESULT line and one VERDICT line; exits 1 when a
# try failed.
set -eu

here=$(dirname "$0")
# shellcheck source=test/harness/experiments/pins-cli.env
. "$here/pins-cli.env"
case $(uname -m) in
x86_64) arch=amd64 archive=$CLI_ARCHIVE_AMD64 sum=$CLI_SHA256_AMD64 ;;
aarch64 | arm64) arch=arm64 archive=$CLI_ARCHIVE_ARM64 sum=$CLI_SHA256_ARM64 ;;
*) echo "e45: unsupported machine $(uname -m)" >&2; exit 2 ;;
esac
cache=${IMAGE_CACHE:-$HOME/.cache/supapace/images}
name=${E45_NAME:-sp-test-e45}
img=$name-run:local
port=8080
dead=8081 # nothing listens here
cli=$cache/supabase-cli-$CLI_VERSION-$arch
W=

say() { echo "e45: $*"; }
cleanup() {
	trap '' INT TERM
	set +e
	docker rm -f "$name" >/dev/null 2>&1
	docker image rm "$img" >/dev/null 2>&1
	rm -f "$cache/$archive.tmp" "$cli.tmp"
	[ -z "$W" ] || rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Fetch by checksum: the archive is used only when its SHA-256 is the pinned one.
mkdir -p "$cache"
if ! echo "$sum  $cache/$archive" | sha256sum -c --status 2>/dev/null; then
	curl -q -fsSL -o "$cache/$archive.tmp" "$CLI_URL/$archive"
	echo "$sum  $cache/$archive.tmp" | sha256sum -c --status || {
		rm -f "$cache/$archive.tmp"
		say "checksum mismatch for $archive"
		exit 1
	}
	mv "$cache/$archive.tmp" "$cache/$archive"
fi
# Extracted from the verified archive on every run, never trusted for existing.
tar -xzf "$cache/$archive" -O supabase >"$cli.tmp"
chmod 0755 "$cli.tmp"
mv "$cli.tmp" "$cli"
echo "cli $cli"
echo "archive $archive sha256 $sum"

W=$(mktemp -d)
# The run image: the interpreter and every library the binary needs, at the
# paths this machine keeps them, resolved through the loader cache.
mkdir -p "$W/img/root"
interp=$(readelf -l "$cli" | sed -n 's/.*interpreter: \(.*\)\]/\1/p')
files=$interp
for lib in $(readelf -d "$cli" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'); do
	f=$(ldconfig -p | awk -v l="$lib" '$1 == l && /x86-64|AArch64/ { print $NF; exit }')
	[ -n "$f" ] || { say "cannot resolve $lib, a library of the CLI"; exit 2; }
	files="$files $f"
done
case $interp in /*) ;; *) say "the CLI names no interpreter"; exit 2 ;; esac
for f in $files; do
	mkdir -p "$W/img/root$(dirname "$f")"
	cp -L "$f" "$W/img/root$f"
done
printf 'FROM scratch\nCOPY root/ /\n' >"$W/img/Dockerfile"
docker build -q --label supapace.test=1 -t "$img" "$W/img" >/dev/null
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o "$W/sp-probe" ./cmd/sp-probe
hex=$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf 'sbp_%s\n' "$hex" >"$W/token"
cat >"$W/standin.yaml" <<EOF
name: standin
api_url: http://127.0.0.1:$port
dashboard_url: http://127.0.0.1:$port
project_host: localhost
EOF

docker rm -f "$name" >/dev/null 2>&1 || :
docker run -d --name "$name" --label supapace.test=1 --network none \
	--user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
	--read-only --tmpfs /tmp --memory 1g --pids-limit 256 \
	-v "$cli:/cli/supabase:ro" -v "$W:/w" --entrypoint /w/sp-probe "$img" \
	mgmt --listen 127.0.0.1:$port --log /w/log --token /w/token >/dev/null
i=0
until docker logs "$name" 2>&1 | grep -q '^listening'; do
	i=$((i + 1))
	[ $i -le 50 ] || { say "stand-in did not start"; docker logs "$name"; exit 1; }
	sleep 0.1
done

echo "== version"
# A CLI that does not run at all must not read as "not redirected".
mkdir -p "$W/version/homedir"
if ver=$(timeout 60 docker exec -e HOME=/w/version/homedir -e SUPABASE_TELEMETRY_DISABLED=1 -e DO_NOT_TRACK=1 \
	-e SUPABASE_NO_UPDATE_NOTIFIER=1 "$name" /cli/supabase --version 2>&1); then
	echo "$ver"
else
	printf '%s\n' "$ver" | tail -n 20
	echo "VERDICT E45: unknown — the CLI does not run in its container"
	exit 1
fi

# try NAME CONTROL TOKEN EXIT ANSWER TARGET TEXT [ENV=V…] -- [ARG…]: one
# projects list in a fresh home and work directory. It passes when the CLI exits
# EXIT, its output holds TEXT (when not empty), and the stand-in got at least one
# request, each to TARGET with the Bearer scheme, answered ANSWER — or, with
# ANSWER "-", got none. HOMEPROFILE=V in place of an ENV writes V into
# $HOME/.supabase/profile. CONTROL names the earlier try that is this one's
# control (the same path, accepted); a try whose control failed fails too.
# Prints the CLI's output, the stand-in's records and one PASS or FAIL line.
passed='' failed=0 reached=''
try() {
	t=$1 ctl=$2 tok=$3 xexit=$4 xanswer=$5 xtarget=$6 xtext=$7
	shift 7
	mkdir -p "$W/$t/homedir" "$W/$t/work"
	envs=''
	while [ "$1" != -- ]; do
		case $1 in
		HOMEPROFILE=*)
			mkdir -p "$W/$t/homedir/.supabase"
			echo "${1#HOMEPROFILE=}" >"$W/$t/homedir/.supabase/profile"
			;;
		*) envs="$envs -e $1" ;;
		esac
		shift
	done
	shift
	before=$(wc -l <"$W/log")
	set +e
	# shellcheck disable=SC2086 # envs is a list of -e options
	out=$(timeout 150 docker exec -w "/w/$t/work" -e HOME="/w/$t/homedir" -e PATH=/usr/bin:/bin \
		-e SUPABASE_ACCESS_TOKEN="$tok" -e SUPABASE_NO_KEYRING=1 -e SUPABASE_TELEMETRY_DISABLED=1 \
		-e DO_NOT_TRACK=1 -e SUPABASE_NO_UPDATE_NOTIFIER=1 $envs \
		"$name" /cli/supabase projects list --output-format json "$@" 2>&1)
	rc=$?
	set -e
	recs=$(tail -n +$((before + 1)) "$W/log")
	n=$(printf '%s\n' "$recs" | grep -c '^request' || :)
	echo "== try $t: exit $rc, requests $n"
	printf '%s\n' "$out" | sed 's/^/   cli: /' | head -n 20
	[ -z "$recs" ] || printf '%s\n' "$recs" | sed 's/^/   standin: /'
	why=''
	[ "$rc" = "$xexit" ] || why="$why exit $rc, want $xexit;"
	[ -z "$xtext" ] || printf '%s\n' "$out" | grep -qF -- "$xtext" || why="$why output lacks \"$xtext\";"
	if [ "$xanswer" = - ]; then
		[ "$n" = 0 ] || why="$why $n requests, want none;"
	else
		[ "$n" = 1 ] || why="$why $n requests, want one;"
		hdrs=$(printf '%s\n' "$recs" | sed -n 's/^header //p' | tr '\n' ' ')
		[ "$hdrs" = "Accept Accept-Encoding Authorization Connection User-Agent " ] || why="$why headers $hdrs;"
		bad=$(printf '%s\n' "$recs" | awk -v t="$xtarget" -v a="$xanswer" '
			$1 == "request" && $3 != t { print "target " $3 }
			$1 == "auth" && $2 != "Bearer" { print "scheme " $2 }
			$1 == "answer" && $2 != a { print "answer " $2 }' | tr '\n' ' ')
		[ -z "$bad" ] || why="$why $bad;"
	fi
	if [ "$ctl" != - ]; then
		case " $passed " in *" $ctl "*) ;; *) why="$why control $ctl did not pass;" ;; esac
	fi
	if [ -z "$why" ]; then
		passed="$passed $t"
		echo "PASS $t (control: $ctl)"
		[ "$xanswer" != 200 ] || reached="$reached $t"
	else
		failed=$((failed + 1))
		echo "FAIL $t (control: $ctl):$why"
	fi
}

good=$(cat "$W/token")
rnd40() { head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
other=sbp_$(rnd40)
h=$(rnd40)
upper=sbp_ABCDEF$(echo "$h" | cut -c7- | tr a-f A-F)
profile() { # profile FILE API_URL [EXTRA-LINE] [DROP-KEY]
	{
		printf 'name: p\napi_url: %s\ndashboard_url: http://127.0.0.1:%s\nproject_host: localhost\n' "$2" "$port"
		[ -z "${3:-}" ] || echo "$3"
	} | { if [ -n "${4:-}" ]; then grep -v "^$4:"; else cat; fi; } >"$W/$1"
}
profile dead.yaml http://127.0.0.1:$dead
profile prefix.yaml http://127.0.0.1:$port/prefix
profile extra-key.yaml http://127.0.0.1:$port 'colour: blue'
profile not-http.yaml ftp://127.0.0.1:$port
profile no-host.yaml http://127.0.0.1:$port '' project_host
L=/v1/projects S=/w/standin.yaml D=/w/dead.yaml

# How the host is chosen.
try env - "$good" 1 - - "GET https://api.supabase.com$L" SUPABASE_API_URL=http://127.0.0.1:$port --
try builtin - "$good" 0 200 $L '' -- --profile supabase-local
try flag - "$good" 0 200 $L '"linked":false}],"message":""}' -- --profile $S
try profile-env - "$good" 0 200 $L '' SUPABASE_PROFILE=$S --
try profile-file - "$good" 0 200 $L '' HOMEPROFILE=$S --
try profile-file-name profile-file "$good" 0 200 $L '' HOMEPROFILE=supabase-local --
try dead flag "$good" 1 - - "127.0.0.1:$dead" -- --profile $D
# Precedence, both orders each: --profile over SUPABASE_PROFILE over the file.
try flag-over-env flag "$good" 0 200 $L '' SUPABASE_PROFILE=$D -- --profile $S
try flag-over-env-dead dead "$good" 1 - - "127.0.0.1:$dead" SUPABASE_PROFILE=$S -- --profile $D
try env-over-file profile-env "$good" 0 200 $L '' SUPABASE_PROFILE=$S HOMEPROFILE=$D --
try env-over-file-dead dead "$good" 1 - - "127.0.0.1:$dead" SUPABASE_PROFILE=$D HOMEPROFILE=$S --
try api-url-beside-profile flag "$good" 0 200 $L '' SUPABASE_API_URL=http://127.0.0.1:$dead -- --profile $S
# A path in api_url; profile files the CLI refuses.
try prefix flag "$good" 1 404 /prefix$L '{\"message\":\"Not Found\"}' -- --profile /w/prefix.yaml
try extra-key flag "$good" 1 - - 'unknown keys: colour' -- --profile /w/extra-key.yaml
try not-http flag "$good" 1 - - 'api_url must be an http(s) URL' -- --profile /w/not-http.yaml
try no-project-host flag "$good" 1 - - 'project_host is required' -- --profile /w/no-host.yaml
# The error document; token forms sent and refused.
try refused flag "$other" 1 401 $L '{\"message\":\"Unauthorized\"}' -- --profile $S
try token-oauth refused "sbp_oauth_$(rnd40)" 1 401 $L '' -- --profile $S
try token-v0 refused "sbp_v0_$(rnd40)" 1 401 $L '' -- --profile $S
I=InvalidAccessTokenError
try malformed refused "not-a-token" 1 - - $I -- --profile $S
try token-upper-hex refused "$upper" 1 - - $I -- --profile $S
try token-39 refused "sbp_$(echo "$h" | cut -c2-)" 1 - - $I -- --profile $S
try token-41 refused "sbp_${h}0" 1 - - $I -- --profile $S
try token-v1 refused "sbp_v1_$h" 1 - - $I -- --profile $S
try token-line-end refused "sbp_$h
" 1 - - $I -- --profile $S

echo "RESULT E45: $(echo "$passed" | wc -w) passed, $failed failed"
if [ -n "$reached" ]; then
	echo "VERDICT E45: redirected — the CLI $CLI_VERSION listed projects from the stand-in by:$reached"
else
	echo "VERDICT E45: not redirected — no way tried listed projects from the stand-in"
fi
[ "$failed" = 0 ]
