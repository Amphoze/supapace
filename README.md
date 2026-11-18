# supapace

An open-source platform for self-hosting many isolated Postgres projects on one node, each served
through PostgREST in the style of Supabase's REST API (`/rest/v1/`, `apikey`, anon and
service_role keys). Each project gets its own hardened Postgres cluster container and its own
PostgREST container; one shared gateway in front of them checks every request's keys and
tokens. A root daemon, `supapaced`, owns the node; operators drive it with the `supapace` CLI.

> **Status: first release (path and containment).** Do not host real data yet: **there are no
> backups.** A deleted project is kept for the retention period (7 days), then purged for good;
> a lost node loses every project on it.

## What it is today

- **One node, many projects.** A project is a cluster container (the
  `supabase/postgres` image, unmodified) and a PostgREST container, created, restarted,
  deleted and purged through an operation queue that survives daemon restarts.
- **The cluster container is the isolation boundary.** The platform treats the database
  server of a project as untrusted; a project's database credentials should be treated as
  full control of that project's database server. Each cluster runs at its own uid with no
  capabilities, a read-only root, its own internal network and an XFS disk quota; a static
  nftables ruleset keeps project networks apart and is checked every 10 seconds.
- **A gateway that checks before it forwards.** `https://<ref>.<domain>/rest/v1/` requires the
  project's anon or service_role key as `apikey`; user tokens are RS256 tokens signed by an
  issuer key you register at create (there is no shared JWT secret and no built-in auth
  server). `auth.uid()`, `auth.role()` and `auth.jwt()` work, so row-level security works.
- **An operator CLI with a stable contract:** one JSON document on stdout, progress on
  stderr, exit codes 0 / 1 / 2 / 130.

## What it is not yet

Later phases, not in this release: **backups** and point-in-time recovery, a connection
pooler, a dashboard, Storage, Realtime, Edge Functions, several nodes, and published database ports
(schema changes go through `docker exec` on the node, see below). There is no built-in auth
server: user tokens come from an external issuer. Security model in one page: the
isolation boundary is the project's container; what is not claimed is listed in
[docs/architecture.md](docs/architecture.md#what-is-not-claimed).

## Architecture in one paragraph

A node runs the daemon (`supapaced serve`, root, systemd), a control-plane Postgres
(`sp-cp-db`, no network, its socket only), the gateway (`sp-gateway`, ports 443 and 80) and,
per project, `pg-<ref>` and `postgrest-<ref>` on the project's own internal network
`proj-<ref>`. PostgREST containers also sit on the internal `platform` network, where only the
gateway may open connections. The daemon's operation worker is the only writer of a project's
lifecycle; every tenant container start passes a start gate that re-reads the firewall,
networks and container configuration first. If the firewall check fails and a reload does not
fix it, or a blocking node-check row fails at daemon start, the node turns `containment_failed`:
every route drains, every tenant container is stopped and every mutation is refused until the
checks pass again ([operations](docs/operations.md#containment_failed)).

```
 client ─TLS :443─▶ sp-gateway ─platform─▶ postgrest-<ref> ─proj-<ref>─▶ pg-<ref> :5432
                    keys, tokens,          one pair per project; both networks internal,
                    route table            only the gateway opens connections on platform

 supapace CLI ─admin.sock─▶ supapaced ─▶ docker, nftables, XFS quota
                                     └─▶ sp-cp-db (unix socket only)
```

## Quick start (disposable test node)

The test node is a privileged Docker-in-Docker container with loop-backed XFS; it runs the
real daemon in development mode (domain `sp.test`, its own CA). You need Linux, Docker,
Go 1.25, GNU make, and for the requests below `openssl`, `xxd`, `basenc` (coreutils), `curl`
and `jq`. The node loads the `xfs` kernel module on the host and uses one loop device.
Docker on the workstation must use the containerd image store (`make images` says how to
switch it on): the pinned images are saved by digest and loaded into the node.

```sh
make setup                   # commit hooks (needed only to commit)
make images                  # build binaries, cache the pinned images, build the gateway image
make node-up                 # start the node container sp-node (NODE=name for another)
S='docker exec sp-node /opt/supapace/bin/supapace'
$S node check                # every row "ok": true (make node-up waits for the daemon)
```

A project needs the public key set of the issuer that will sign your users' tokens. For a
first try, make one key pair:

```sh
openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out issuer.key
n=$(openssl rsa -in issuer.key -noout -modulus | cut -d= -f2 | xxd -r -p |
    basenc --base64url | tr -d '=\n')
printf '{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"issuer-1","n":"%s","e":"AQAB"}]}\n' \
    "$n" >issuer.jwks
docker cp issuer.jwks sp-node:/root/issuer.jwks

$S project create --name demo --issuer-jwks /root/issuer.jwks
```

The create takes about 15 seconds; stderr shows its steps, stdout the finished operation
(stderr and stdout interleave in a terminal):

```
operation 1: running, after step 2
…
supapace: project qg6zivyo8iazv6bzkb5r: its url, keys and CA: 'supapace project keys qg6zivyo8iazv6bzkb5r'
{"id":1,"ref":"qg6zivyo8iazv6bzkb5r","kind":"create","state":"done","step":"12","attempts":1,…}
```

Where to connect: `project keys` prints the URL, the CA that signed the gateway's
certificate, and the credentials.

```sh
REF=qg6zivyo8iazv6bzkb5r     # yours
$S project keys $REF >keys.json
docker cp sp-node:/etc/supapace/ca/ca.pem ca.pem
NODE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' sp-node)
api() { curl -sS --cacert ca.pem --resolve "$REF.sp.test:443:$NODE_IP" "$@"; echo; }
ANON=$(jq -r .anon_key keys.json); SERVICE=$(jq -r .service_role_key keys.json)
```

Create a table as the database role `postgres` (no database port is published; this runs
psql inside the cluster container and asks for `postgres_password` from `keys.json`):

```sh
docker exec -it sp-node docker exec -it -e PSQL_HISTORY=/dev/null pg-$REF \
  psql -h 127.0.0.1 -U postgres
```

```sql
create table public.notes (
  id bigint generated always as identity primary key,
  body text not null
);
alter table public.notes enable row level security;
create policy "anyone can read" on public.notes for select to anon using (true);
create policy "signed-in users can write" on public.notes
  for insert to authenticated with check (true);
notify pgrst, 'reload schema';
```

Then one request with each key, and one with a user token:

```sh
api "https://$REF.sp.test/rest/v1/notes" -H "apikey: $SERVICE" \
    -H 'Content-Type: application/json' -H 'Prefer: return=representation' -d '{"body":"hello"}'
# [{"id":1,"body":"hello"}]            the service_role key bypasses row-level security
api "https://$REF.sp.test/rest/v1/notes" -H "apikey: $ANON" \
    -H 'Content-Type: application/json' -d '{"body":"from anon"}'
# {"code":"42501",…"new row violates row-level security policy for table \"notes\""}
api "https://$REF.sp.test/rest/v1/notes?select=body" -H "apikey: $ANON"
# [{"body":"hello"}]
api "https://$REF.sp.test/rest/v1/notes"
# {"code":"no_apikey"}                 refused by the gateway

b64url() { basenc --base64url | tr -d '=\n'; }
header=$(printf '{"alg":"RS256","typ":"JWT","kid":"issuer-1"}' | b64url)
claims=$(printf '{"role":"authenticated","sub":"user-1","exp":%d}' $(($(date +%s) + 3600)) | b64url)
sig=$(printf '%s.%s' "$header" "$claims" | openssl dgst -sha256 -sign issuer.key | b64url)
api "https://$REF.sp.test/rest/v1/notes" -H "apikey: $ANON" \
    -H "Authorization: Bearer $header.$claims.$sig" \
    -H 'Content-Type: application/json' -d '{"body":"from a user"}' -w '%{http_code}'
# 201
```

Clean up:

```sh
$S project delete $REF       # stops and removes the containers; data kept for the retention
$S project purge $REF        # removes the data and the keys now
make node-down               # removes the node container and its two volumes
```

## Documentation

- [docs/architecture.md](docs/architecture.md) — components, trust boundaries, the operation
  worker, routes and keys, start-up, repair and containment.
- [docs/node-install.md](docs/node-install.md) — preparing and installing a real node: kernel,
  Docker, XFS quota, the units, `supapaced init`, TLS and DNS.
- [docs/operations.md](docs/operations.md) — every CLI command with its JSON, states, checks,
  runbooks and known limits.
- [docs/measurements.md](docs/measurements.md) — what is measured and how.
- `AGENTS.md` — change log with each package's rules and limits as built.

## Tests

| Command | What runs |
|---|---|
| `make unit` | the content gate's own tests, `go vet ./...`, `go test -race ./...` |
| `make reach` | the end-to-end suite as root on the node (about 20 minutes) |
| `make reach-reboot` | after one `make reach`: restarts the node, checks boot order |
| `make reach-host` | as root, the suite on a host installed with `scripts/install-node.sh` |
| `make measure` | `test/measure/cluster_mem.sh` on the node (`REF`, `IDLE`, `LOAD`, `CLIENTS`) |
| `make public-check` | the content gate over the tree (needs a deny-list file) |

`make build` precedes `make reach`; `make images` must have run before `make node-up`. Unit
tests that need Docker start throw-away containers labelled `supapace.test=1` and skip without
Docker. `REACH_ARGS='-test.run TestReach01'` selects suite tests. Re-run
`go vet -tags reach ./...` when you touch a `reach`-tagged file.

## Contributing

The repository is public and every commit passes a content gate (`cmd/check-public`, run by the
hooks `make setup` installs and by CI): no host names, home paths, or addresses outside the
platform and documentation ranges. Commits must carry
a GitHub noreply address and the time zone +0000 (`TZ=UTC git commit`): an address or a local
time zone in a public history tells who and where the author is. Merge by pushing a
fast-forward from a local checkout: GitHub's merge buttons commit as GitHub's own address,
which the gate refuses.

## Repository layout

    cmd/supapaced      node daemon: init, nft, serve, rmtree
    cmd/supapace       operator CLI
    cmd/gateway        the gateway
    cmd/sp-probe       network and sandbox probe used by the tests
    cmd/check-public   the public-content gate
    internal/          implementation packages (agent, saga, adminapi, gateway, nft, ...)
    deploy/gateway     gateway image
    scripts/           install-node.sh, image cache, content gate wrappers
    test/harness       test node and the network and image experiments
    test/reach         end-to-end suite (build tag reach)
    test/measure       measurement scripts
    docs/              operator documentation

## Licence

Apache-2.0. See [LICENSE](LICENSE).
