#!/bin/sh
# e12.sh - first boot of the control-plane database: the pinned postgres:17-alpine
# image on an empty data directory with --read-only, --user 70:70, --network none,
# all capabilities dropped, POSTGRES_USER=supapaced and our own hba_file and
# ident_file (peer only, no password, no TCP). Root on the node then connects by
# peer through the mounted socket directory; other local users are refused. A
# second start over the initialised directory must skip initialisation.
#
# Run on the bare test node: docker exec -i <node> sh -s < e12.sh
set -eu

IMG=postgres@sha256:a77aa70e641402a21411b92b721c58d10f23b50ae5fdd2333efd22d166e1e5f7
CP=/var/lib/supapace/e12/cp
DB=sp-cp-db-e12

say() { echo "e12: $*"; }
now() { cut -d' ' -f1 /proc/uptime; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b-a}'; }
rnd() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

cleanup() {
	docker rm -f "$DB" "$DB-init" >/dev/null 2>&1 || :
	rm -rf /var/lib/supapace/e12
}
# A step that fails under set -e still ends with a VERDICT line.
STEP=start
step() { STEP=$*; }
on_exit() {
	rc=$?
	cleanup
	[ "$rc" = 0 ] || [ -n "${DONE:-}" ] || echo "VERDICT E12: unknown — step '$STEP' failed (exit $rc)"
}
trap on_exit EXIT
# A killed run still ends with its VERDICT line and cleans up.
trap 'exit 143' TERM
trap 'exit 130' INT
trap 'exit 129' HUP
cleanup

docker image inspect "$IMG" >/dev/null || { say "image $IMG not loaded"; exit 2; }

step "prepare directories"
mkdir -p "$CP/data" "$CP/sock" "$CP/etc"
chmod 0700 /var/lib/supapace/e12 "$CP"
chown 70:70 "$CP/data" "$CP/sock"
chmod 0700 "$CP/data" "$CP/sock"
printf 'local all supapaced peer map=cp\nlocal all all reject\n' >"$CP/etc/pg_hba.conf"
printf 'cp root supapaced\ncp postgres supapaced\n' >"$CP/etc/pg_ident.conf"
chmod 0755 "$CP/etc"
chmod 0444 "$CP/etc/pg_hba.conf" "$CP/etc/pg_ident.conf"
say "image user 70 is: $(docker run --rm --network none --entrypoint sh "$IMG" -c 'getent passwd 70')"

# $1 = name, $2 = "ro" for --read-only; further args go to docker run before the image.
run_db() {
	name=$1 ro=$2
	shift 2
	set -- --network none --user 70:70 --cap-drop ALL --security-opt no-new-privileges \
		--tmpfs /tmp --memory 256m --pids-limit 128 --ulimit core=0 --restart unless-stopped \
		-e POSTGRES_USER=supapaced -e POSTGRES_DB=supapaced -e POSTGRES_PASSWORD="$(rnd 32)" \
		-v "$CP/data:/var/lib/postgresql/data" -v "$CP/sock:/var/run/postgresql" -v "$CP/etc:/etc/sp:ro" \
		--label supapace.test=1 "$@"
	[ "$ro" = ro ] && set -- --read-only "$@"
	docker run -d --name "$name" "$@" "$IMG" \
		postgres -c listen_addresses='' -c hba_file=/etc/sp/pg_hba.conf -c ident_file=/etc/sp/pg_ident.conf >/dev/null
}
wait_ready() { # name, marker; returns 1 if the container stops
	i=0
	until docker logs "$1" 2>&1 | grep -q "$2" && docker exec "$1" pg_isready -q -h /var/run/postgresql; do
		if [ "$(docker inspect -f '{{.State.Running}} {{.State.Restarting}}' "$1")" != "true false" ] || [ "$i" -ge 240 ]; then
			say "$1 did not come up:"
			docker logs --tail 15 "$1" 2>&1 | sed 's/^/  | /'
			return 1
		fi
		i=$((i + 1))
		sleep 0.5
	done
}
# psql as a given uid in a throw-away container that sees only the socket directory.
# uid 0 there is root of the node: no user namespace, so the server sees uid 0 on the socket.
peer() { # uid role
	docker run --rm --network none --user "$1" -v "$CP/sock:/var/run/postgresql" --entrypoint psql "$IMG" \
		-X -At -h /var/run/postgresql -U "$2" -d supapaced \
		-c "select current_user||' via '||coalesce((select auth_method from pg_hba_file_rules where rule_number=1),'?')" 2>&1 | tail -1
}

step "first boot"
t=$(now)
mode=ro
run_db "$DB" ro
if ! wait_ready "$DB" 'PostgreSQL init process complete'; then
	# Fallback split: initialise without --read-only (same uid, same directory), then read-only.
	mode="split"
	docker rm -f "$DB" >/dev/null
	find "$CP/data" "$CP/sock" -mindepth 1 -delete
	run_db "$DB-init" rw
	wait_ready "$DB-init" 'PostgreSQL init process complete'
	docker stop "$DB-init" >/dev/null
	docker rm "$DB-init" >/dev/null
	run_db "$DB" ro
	wait_ready "$DB" 'Skipping initialization'
fi
TFIRST=$(since "$t")
say "first boot ($mode) ready in ${TFIRST}s"
say "hardening: $(docker inspect -f 'user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} capdrop={{.HostConfig.CapDrop}} secopt={{.HostConfig.SecurityOpt}} net={{.HostConfig.NetworkMode}} tmpfs={{.HostConfig.Tmpfs}} mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}} restart={{.HostConfig.RestartPolicy.Name}}' "$DB")"
say "root filesystem write: $(docker exec "$DB" touch /etc/e12 2>&1 || :)"
docker logs "$DB" 2>&1 | grep -iE 'error|fatal|permission|read-only' | sed 's/^/  log | /' | head -10 || :

step "peer checks"
ok=1
r0=$(peer 0 supapaced)
r1=$(peer 70 supapaced)
r2=$(peer 1000 supapaced)
r3=$(peer 0 postgres)
say "root (uid 0) as supapaced: $r0"
say "uid 70 (the image's postgres) as supapaced: $r1"
say "uid 1000 as supapaced: $r2"
say "root as role postgres: $r3"
case $r0 in "supapaced via peer") ;; *) ok=0 ;; esac
case $r1 in "supapaced via peer") ;; *) ok=0 ;; esac
case $r2 in *FATAL*) ;; *) ok=0 ;; esac
case $r3 in *FATAL*) ;; *) ok=0 ;; esac
q() { docker run --rm --network none --user 0 -v "$CP/sock:/var/run/postgresql" --entrypoint psql "$IMG" \
	-X -At -h /var/run/postgresql -U supapaced -d supapaced -c "$1"; }
say "server: $(q "select current_setting('server_version')||' listen_addresses='''||current_setting('listen_addresses')||''' hba_file='||current_setting('hba_file')||' ident_file='||current_setting('ident_file')||' superuser='||(select rolsuper from pg_roles where rolname=current_user)")"
say "databases: $(q "select string_agg(datname, ' ' order by datname) from pg_database")"
say "hba rules: $(q "select string_agg(rule_number||':'||type||' '||array_to_string(user_name,',')||' '||auth_method||coalesce(' '||array_to_string(options,','),'')||coalesce(' ERROR '||error,''), '; ') from pg_hba_file_rules")"
say "socket: $(stat -c '%A %u:%g %n' "$CP/sock/.s.PGSQL.5432")"
say "listening TCP sockets in the container: $(docker exec "$DB" sh -c 'cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk "\$4==\"0A\"" | wc -l')"
q "create table e12(x int); insert into e12 values (1)" >/dev/null

step "second start"
# Second start over the initialised directory, read-only.
docker stop "$DB" >/dev/null
docker rm "$DB" >/dev/null
t=$(now)
run_db "$DB" ro
wait_ready "$DB" 'Skipping initialization' || ok=0
say "second start ready in $(since "$t")s; $(docker logs "$DB" 2>&1 | grep -m1 -o 'Skipping initialization'); row kept: $(q 'select count(*) from e12')"
case $(peer 0 supapaced) in "supapaced via peer") ;; *) ok=0 ;; esac
docker stop "$DB" >/dev/null

DONE=1
if [ "$ok" = 1 ] && [ "$mode" = ro ]; then
	echo "VERDICT E12: confirmed — the control-plane database initialises and restarts under --read-only, uid 70:70, no network and no capabilities; root reaches it by peer through the mounted socket and nobody else does."
elif [ "$ok" = 1 ]; then
	echo "VERDICT E12: fallback — first boot needs a writable root filesystem; initialising without --read-only and starting read-only afterwards works."
else
	echo "VERDICT E12: fallback — peer access or restart did not behave as designed; see above."
fi
