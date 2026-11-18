#!/bin/sh
# e07.sh - supautils privileged_extensions template on the pinned supabase/postgres
# image: with the five network-capable extensions (pg_net, http, dblink,
# postgres_fdw, wrappers) removed from supautils.privileged_extensions, the
# non-superuser role postgres cannot create them while pg_trgm still works; with
# the image's unmodified supautils.conf (control) it can create all five.
#
# The cluster runs at a project uid under the cluster container's hardening flags
# (--network none, image pg_hba; the tenant connects by peer over the socket).
#
# Run on the bare test node: docker exec -i <node> sh -s < e07.sh
set -eu

IMG=supabase/postgres@sha256:b3bfedb107413abb3b8cb0d0874b0414a1dceb3d55bc0c778de6ad22d1f7dc86
REF=e07exp00000000000000
PUID=700607
PROJ=/var/lib/supapace/projects/$REF
REND=/var/lib/supapace/platform/projects/$REF
PG=pg-$REF
NETEXT="pg_net http dblink postgres_fdw wrappers"

say() { echo "e07: $*"; }
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

cleanup() {
	docker rm -f "$PG" >/dev/null 2>&1 || :
	rm -rf "$PROJ" "$REND"
}
# A step that fails under set -e still ends with a VERDICT line.
STEP=start
step() { STEP=$*; }
on_exit() {
	rc=$?
	cleanup
	[ "$rc" = 0 ] || [ -n "${DONE:-}" ] || echo "VERDICT E07: unknown — step '$STEP' failed (exit $rc)"
}
trap on_exit EXIT
# A killed run still ends with its VERDICT line and cleans up.
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
cleanup

docker image inspect "$IMG" >/dev/null || { say "image $IMG not loaded"; exit 2; }
mountpoint -q /var/lib/supapace/projects || { say "projects mount absent"; exit 2; }

step "render"
mkdir -p "$PROJ/data" "$PROJ/sock" "$REND/image"
chown "$PUID:$PUID" "$PROJ" "$PROJ/data" "$PROJ/sock"
chmod 0700 "$PROJ" "$PROJ/data" "$PROJ/sock"
chmod 0755 /var/lib/supapace/platform /var/lib/supapace/platform/projects "$REND"
cid=$(docker create --network none "$IMG")
for f in /etc/passwd /etc/group /etc/postgresql-custom/supautils.conf /etc/postgresql/postgresql.conf; do
	docker cp -q "$cid:$f" "$REND/image/"
done
docker rm "$cid" >/dev/null
sed "s/^postgres:x:[0-9]*:[0-9]*:/postgres:x:$PUID:$PUID:/" "$REND/image/passwd" >"$REND/passwd"
sed "s/^postgres:x:[0-9]*:/postgres:x:$PUID:/" "$REND/image/group" >"$REND/group"
sed -E "/^supautils.privileged_extensions = /{s/(['[:space:]])(pg_net|http|dblink|postgres_fdw|wrappers), /\\1/g;s/, wrappers'\$/'/}" \
	"$REND/image/supautils.conf" >"$REND/supautils-template.conf"
cp "$REND/image/supautils.conf" "$REND/supautils-image.conf"
rnd 32 >"$REND/pgsodium_root.key"
chown "$PUID:$PUID" "$REND/pgsodium_root.key"
chmod 0400 "$REND/pgsodium_root.key"
chmod 0444 "$REND/passwd" "$REND/group" "$REND/supautils-template.conf" "$REND/supautils-image.conf"

lst() { sed -n "s/^supautils.privileged_extensions = '\\(.*\\)'\$/\\1/p" "$1" | tr ',' '\n' | sed 's/^ *//'; }
lst "$REND/image/supautils.conf" >"$REND/list-image"
lst "$REND/supautils-template.conf" >"$REND/list-template"
say "template: $(wc -l <"$REND/list-image") -> $(wc -l <"$REND/list-template") privileged extensions; removed: $(grep -vxFf "$REND/list-template" "$REND/list-image" | tr '\n' ' ')"
say "template: lines only in the image's file: $(grep -cvxFf "$REND/supautils-template.conf" "$REND/image/supautils.conf" || :), only in the template: $(grep -cvxFf "$REND/image/supautils.conf" "$REND/supautils-template.conf" || :)"

run_cluster() { # supautils file
	docker run -d --name "$PG" --hostname "$PG" --network none --user "$PUID:$PUID" \
		--cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
		--memory 512m --memory-swap 512m --cpus 1 --pids-limit 512 --shm-size 64m --ulimit core=0 \
		-e POSTGRES_PASSWORD="$(rnd 32)" \
		-v "$PROJ/data:/var/lib/postgresql/data" -v "$PROJ/sock:/var/run/postgresql" \
		-v "$REND/passwd:/etc/passwd:ro" -v "$REND/group:/etc/group:ro" \
		-v "$REND/pgsodium_root.key:/etc/postgresql-custom/pgsodium_root.key:ro" \
		-v "$1:/etc/postgresql-custom/supautils.conf:ro" \
		--label supapace.role=cluster --label supapace.ref=$REF --label supapace.test=1 "$IMG" >/dev/null
	i=0
	until docker logs "$PG" 2>&1 | grep -qE 'init process complete|Skipping initialization' &&
		docker exec "$PG" pg_isready -q -h /var/run/postgresql; do
		[ "$(docker inspect -f '{{.State.Running}}' "$PG")" = true ] || { docker logs --tail 30 "$PG"; exit 1; }
		i=$((i + 1))
		[ "$i" -lt 600 ] || { say "not ready"; exit 1; }
		sleep 0.5
	done
}
# Tenant role postgres: peer over the socket (the uid is named postgres in the mounted passwd).
# Prints the command tag, or the ERROR line (with its DETAIL) when the statement fails.
tsql() { docker exec "$PG" psql -X -At -h /var/run/postgresql -U postgres -d postgres -c "$1" 2>&1 |
	grep -E '^(ERROR|DETAIL|[A-Z]+ [A-Z]+$|[a-z_]+ super=)' | tr '\n' ' ' | sed 's/ *$//'; }
asql() { docker exec "$PG" psql -X -At -h /var/run/postgresql -U supabase_admin -d postgres -c "$1"; }
schema_for() { case $1 in pg_net) echo "" ;; *) echo " with schema extensions" ;; esac; }

step "template"
# --- template ---
run_cluster "$REND/supautils-template.conf"
say "tenant: $(tsql "select current_user||' super='||rolsuper from pg_roles where rolname=current_user")"
pl=$(asql "show supautils.privileged_extensions")
for e in $NETEXT pg_trgm; do
	case ", $pl," in *", $e,"*) say "  privileged_extensions lists $e" ;; *) say "  privileged_extensions omits $e" ;; esac
done
say "control files (default version): $(asql "select string_agg(name||' superuser='||superuser||' trusted='||trusted, ', ' order by name) from (select distinct on (name) name, superuser, trusted from pg_available_extension_versions v0 where name in ('pg_net','http','dblink','postgres_fdw','wrappers','pg_trgm') order by name, version = (select default_version from pg_available_extensions a where a.name = v0.name) desc) v")"
refused=0
for e in $NETEXT; do
	r=$(tsql "create extension $e$(schema_for "$e")")
	say "template: create extension $e -> $r"
	# Refused = the statement failed and the extension does not exist afterwards.
	case $r in ERROR*) [ "$(asql "select count(*) from pg_extension where extname='$e'")" = 0 ] && refused=$((refused + 1)) ;; esac
done
r=$(tsql "create extension pg_trgm with schema extensions")
say "template: create extension pg_trgm -> $r"
trgm=0
[ "$r" = "CREATE EXTENSION" ] && trgm=1
say "template: installed now: $(asql "select coalesce(string_agg(extname, ' ' order by extname),'-') from pg_extension where extname in ('pg_net','http','dblink','postgres_fdw','wrappers','pg_trgm')")"
tsql "drop extension if exists pg_trgm" >/dev/null
docker rm -f "$PG" >/dev/null

step "control with the image file"
# --- control: the image's own supautils.conf ---
run_cluster "$REND/supautils-image.conf"
allowed=0
for e in $NETEXT; do
	r=$(tsql "create extension $e$(schema_for "$e")")
	say "image file: create extension $e -> $r"
	[ "$r" = "CREATE EXTENSION" ] && allowed=$((allowed + 1))
done
say "image file: installed now: $(asql "select string_agg(extname||' owner='||pg_get_userbyid(extowner), ', ' order by extname) from pg_extension where extname in ('pg_net','http','dblink','postgres_fdw','wrappers')")"
for e in $NETEXT; do tsql "drop extension if exists $e cascade" >/dev/null; done
docker rm -f "$PG" >/dev/null

say "template: $refused/5 refused, pg_trgm allowed=$trgm; image file: $allowed/5 allowed"
DONE=1
if [ "$refused" = 5 ] && [ "$trgm" = 1 ] && [ "$allowed" = 5 ]; then
	echo "VERDICT E07: confirmed — with the templated privileged_extensions the tenant role is refused all five network extensions and still creates pg_trgm; the image's file allows all five."
elif [ "$allowed" = 5 ] && [ "$trgm" = 1 ]; then
	echo "VERDICT E07: fallback — the template does not refuse all five network extensions ($refused/5 refused); the extension list cannot be part of the boundary."
else
	echo "VERDICT E07: unknown — the control did not behave as expected (image file allowed $allowed/5, pg_trgm=$trgm)."
	exit 1
fi
