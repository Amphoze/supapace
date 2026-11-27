#!/usr/bin/env bash
# config.sh IMAGE — what the dashboard answers about a project is that project's own: its name,
# its public URL, its Data API settings, its version and its state, as the control plane
# answered them for the request — never one of the process. Two projects with different
# settings and names, their requests interleaved, through the built image; and a server whose
# header key file is missing or malformed does not start. Prints one row per case; exits 1 when
# a row fails.
. "$(dirname "${BASH_SOURCE[0]}")/stand-ins.bash"
standins_up "${1:?usage: config.sh IMAGE}" || { echo "config.sh: the image or a stand-in did not start" >&2; exit 1; }

# B gets Data API settings, a version and a state of its own; A keeps the stand-ins' ones.
perl -i -pe 'if (/"resolve": \{"ref": "'$B'"/) {
  s/"state": "active"/"state": "restoring"/;
  s/"db_version": "17\.6\.1"/"db_version": "15.8.1"/;
  s/"data_api": \{[^}]*\}/"data_api": {"schemas": ["api", "reporting"], "extra_search_path": ["extensions"], "max_rows": 250}/ }' "$T/table.json"
socket && studio || { echo "config.sh: the stand-ins did not restart" >&2; exit 1; }

# What each route must answer, per project: JSON members as the server writes them.
want() { # want ROUTE PROJECT — one member a line
  local r=$1 p=$2 name ver state schema extra rows port
  if [ "$p" = "$A" ]; then
    name=spmark-alpha ver=17.6.1 state=ACTIVE_HEALTHY schema=public extra=public,extensions rows=null port=$PA
  else
    name=spmark-bravo ver=15.8.1 state=RESTORING schema=api,reporting extra=extensions rows=250 port=$PB
  fi
  case $r in
  project) printf '%s\n' "\"ref\":\"$p\"" "\"name\":\"$name\"" "\"status\":\"$state\"" "\"dbVersion\":\"$ver\"" "\"restUrl\":\"https://$p.spmark.example/rest/v1/\"" ;;
  projects) printf '%s\n' "\"ref\":\"$p\"" "\"name\":\"$name\"" "\"dbVersion\":\"$ver\"" ;;
  props) printf '%s\n' "\"ref\":\"$p\"" "\"name\":\"$name\"" ;;
  api) printf '%s\n' "\"db_host\":\"$p.spmark.example\"" "\"endpoint\":\"$p.spmark.example\"" "\"protocol\":\"https\"" "\"restUrl\":\"https://$p.spmark.example/rest/v1/\"" "\"project\":{\"ref\":\"$p\"}" ;;
  databases) printf '%s\n' "\"identifier\":\"$p\"" "\"db_host\":\"$p.spmark.example\"" "\"status\":\"$state\"" ;;
  settings) printf '%s\n' "\"ref\":\"$p\"" "\"name\":\"$name\"" "\"endpoint\":\"$p.spmark.example\"" "\"db_host\":\"$p.spmark.example\"" "\"status\":\"$state\"" ;;
  postgrest) printf '%s\n' "\"db_schema\":\"$schema\"" "\"db_extra_search_path\":\"$extra\"" "\"max_rows\":$rows" ;;
  organizations) printf '%s\n' "\"name\":\"$name\"" ;;
  profile) printf '%s\n' "\"ref\":\"$p\"" "\"name\":\"$name\"" ;;
  types) printf '%s\n' "\"port\":$port" ;;
  esac
}
path() { # path ROUTE REF
  case $1 in
  project) echo "/api/platform/projects/$2/" ;;
  projects) echo /api/platform/projects/ ;;
  props) echo "/api/platform/props/project/$2/" ;;
  api) echo "/api/platform/props/project/$2/api" ;;
  databases) echo "/api/platform/projects/$2/databases" ;;
  settings) echo "/api/platform/projects/$2/settings" ;;
  postgrest) echo "/api/platform/projects/$2/config/postgrest" ;;
  organizations) echo /api/platform/organizations/ ;;
  profile) echo /api/platform/profile/ ;;
  types) echo "/api/v1/projects/$2/types/typescript" ;;
  esac
}
ROUTES='project projects props api databases settings postgrest organizations profile types'
ROUNDS=5

echo '| # | case | answer | |'
echo '|---|---|---|---|'

# --- 1. every route, both projects, all requests in flight together
mkdir -p "$T/got"
TA=$(tok $A oa owner) TB=$(tok $B ob owner)
for i in $(seq $ROUNDS); do
  for r in $ROUTES; do
    curl -s -m 60 -o "$T/got/$r.$A.$i" -w '%{http_code}' "$U$(path $r $A)" -H "X-Supapace-Assertion: $TA" >"$T/got/$r.$A.$i.status" &
    curl -s -m 60 -o "$T/got/$r.$B.$i" -w '%{http_code}' "$U$(path $r $B)" -H "X-Supapace-Assertion: $TB" >"$T/got/$r.$B.$i.status" &
  done
done
wait
n=0
for r in $ROUTES; do
  for p in $A $B; do
    o=$B oname=spmark-bravo
    [ "$p" = "$A" ] || o=$A oname=spmark-alpha
    n=$((n + 1)) bad=''
    for i in $(seq $ROUNDS); do
      f=$T/got/$r.$p.$i
      [ "$(cat "$f.status")" = 200 ] || { bad="$bad status $(cat "$f.status");"; continue; }
      while IFS= read -r m; do grep -qF -- "$m" "$f" || bad="$bad no $m;"; done < <(want $r $p)
      grep -qF -e "$o" -e "$oname" "$f" && bad="$bad the other project's ref or name;"
      grep -qE '"default"|Default (Project|Organization)|localhost:|spmark[A-Za-z]' "$f" && bad="$bad a value of the process;"
    done
    check 1.$n "$r for $([ "$p" = "$A" ] && echo A || echo B), $ROUNDS requests among $((ROUNDS * 20)) interleaved" "${bad:-own values only}" "own values only"
  done
done

# --- 2. the version is the control plane's, not the database's: no project answer asks postgres-meta
n0=$(seen)
for r in project projects props api databases settings postgrest organizations profile; do
  curl -s -o /dev/null -m 30 "$U$(path $r $A)" -H "X-Supapace-Assertion: $(tok $A oa owner)"
done
check 2.1 "postgres-meta's requests during every project answer" "$(($(seen) - n0))" 0
check 2.2 "... and a statement is seen (the control)" "$(ask GET "$(path types $A)" "$(tok $A oa owner)" >/dev/null; echo $(($(seen) - n0)))" 1

# --- 3. the header key is the node's file and nothing else
stops() { # stops WHAT KEYS-DIR [docker args] — the server is gone within 5 s, unasked
  local what=$1 keys=$2 i
  shift 2
  docker rm -f "$PREFIX-studio" >/dev/null 2>&1
  docker run -d --name "$PREFIX-studio" "${L[@]}" --network "$PREFIX-net" --user 65527:65527 --read-only --tmpfs /tmp \
    --memory 1g --cap-drop ALL --security-opt no-new-privileges \
    -v "$T/sock:/run/dash:ro" -v "$keys:/etc/dash:ro" -v "$T/data:/var/lib/dash" "${STUDIO_ENV[@]}" "$@" "$IMAGE" >/dev/null
  for i in $(seq 10); do
    [ "$(docker inspect -f '{{.State.Running}}' "$PREFIX-studio")" = false ] && break
    sleep 0.5
  done
  printf '%s; last line: %s' "$(docker inspect -f 'running {{.State.Running}}, exit {{.State.ExitCode}}' "$PREFIX-studio")" \
    "$(docker logs "$PREFIX-studio" 2>&1 | grep '^supapace: ' | tail -1 | sed "s/ .*$what.*/ ...$what.../")"
}
keys() { # keys NAME — a copy of the keys directory; prints its path
  mkdir -p "$T/$1" && cp "$T/keys/assert.pub" "$T/keys/cache.key" "$T/$1/" && echo "$T/$1"
}
k=$(keys nokey)
check 3.1 "no crypto.key" "$(stops 'header key file' "$k")" "running false, exit 1; last line: supapace: ...header key file..."
check 3.2 "no crypto.key, the key given as upstream's setting" "$(stops 'header key file' "$k" -e "PG_META_CRYPTO_KEY=$CRYPTO")" "running false, exit 1; last line: supapace: ...header key file..."
k=$(keys short) && printf '%s' "${CRYPTO:1}" >"$k/crypto.key" && chmod 0644 "$k/crypto.key"
check 3.3 "a crypto.key one character short" "$(stops 'header key file' "$k")" "running false, exit 1; last line: supapace: ...header key file..."
check 3.4 "... and its log names no part of the key" "$(docker logs "$PREFIX-studio" 2>&1 | grep -c "${CRYPTO:8:32}")" 0
# The same key with a line end, in place: the server reads it at start, postgres-meta's stand-in
# keeps the one it read (none). A line end is part of the key, so the two no longer agree.
printf '%s\n' "$CRYPTO" >"$T/keys/crypto.key"
studio || { echo "config.sh: the server did not start with a line end in the key file" >&2; exit 1; }
got=$(ask GET "$(path types $A)" "$(tok $A oa owner)")
check 3.5 "the key file with a line end: the server serves; postgres-meta, handed the key without one, cannot read the header" "$([ "${got%% *}" = 200 ] && echo "$got" || echo refused)" refused
printf '%s' "$CRYPTO" >"$T/keys/crypto.key"
studio || { echo "config.sh: the server did not restart" >&2; exit 1; }
check 3.6 "the same key on both sides (the control)" "$(ask GET "$(path types $A)" "$(tok $A oa owner)")" "200 postgres:$PA"

finish
