# Architecture

This describes the system as built in the first release: one node, many projects, the path
from a client to a project's database and the containment around it. `AGENTS.md` holds the
per-package detail (bounds, caller rules, known limits); this page is the overview.

## Trust model

- **The isolation boundary is the project's cluster container.** The database server of a
  project is treated as untrusted by the platform: nothing it answers may set or clear a
  platform decision (containment, placement, routing, another project's state). A project's
  database credentials should be treated as full control of that project's database server.
- **The gateway** is the only public entry point. It checks keys and tokens itself, before
  anything reaches a project's PostgREST.
- **The node daemon** runs as root and is trusted. It acts only on host-side facts: Docker's
  record of container configuration, network membership, interfaces, the firewall state and
  its own files. A tenant process or a database reply never decides whether a container may
  start.
- **The operator** is whoever can reach the root-only admin socket.

## Components

Shared per node:

- `supapaced serve` — the daemon (root, systemd unit `supapaced.service`): admin API on
  `/run/supapace/admin.sock`, the operation worker, the drift timer, the repair round.
- `sp-cp-db` — the control-plane Postgres (`postgres:17-alpine`): no network at all, uid 70,
  read-only root, peer authentication over its mounted socket. It holds projects, operations,
  placement, wrapped data keys, sealed secrets and project keys.
- `sp-gateway` — the gateway (static Go binary on `scratch`, uid 65531, 768 MiB, 256 pids),
  publishing `0.0.0.0:443` (TLS) and `0.0.0.0:80` (a redirect to HTTPS).
- The nftables tables `inet supapace` and `bridge supapace`, loaded by
  `supapace-nft.service` before Docker starts.
- The Docker networks `platform` (bridge `spl0`, `10.212.0.0/21`, internal) and `ingress`
  (bridge `spi0`, `10.212.8.0/24`, where the published ports land), IPv6 off on both.

Per project (`ref` = 20 characters of `a-z0-9`, never reused):

- `pg-<ref>` — the cluster container: `supabase/postgres` (pinned by digest, unmodified).
- `postgrest-<ref>` — PostgREST 16.5 (pinned by digest).
- `proj-<ref>` — an internal network on bridge `spp<i>` with the project's `/26` slice of
  `10.213.0.0/16` (the cluster at base + 2, PostgREST at base + 3).
- `/var/lib/supapace/projects/<ref>/` — `data/` and `sock/`, owned by the project's uid; the
  XFS user quota on that uid is the project's disk limit.
- `/var/lib/supapace/platform/projects/<ref>/` — root-owned rendered files (configuration,
  `pg_hba.conf`, the PostgREST key set and configuration) and `state.json`.

Every container image is pinned by digest in `internal/nodecfg/images.lock`.

## The cluster container

Started by the daemon only, with: its own uid and gid (from `700000` up, never reused),
`--cap-drop ALL`, `no-new-privileges`, the platform's seccomp profile (Docker's default
profile for the pinned release, written by the daemon), a read-only root with a `/tmp`
tmpfs, 512 MiB memory and no swap, 1 CPU, 512 pids, no core files, a private IPC
namespace, no health check, no restart policy, IPv6 and ping disabled by sysctl, and a
45-second stop timeout. Its configuration files (`passwd`, `group`, `conf.d`, `pg_hba.conf`,
the supautils file) are rendered by the platform and mounted read-only; the access files
(`hba_file`, `ident_file`) and the preload lists are pinned on the command line. The daemon
reaches the server only through the project's Unix socket, after checking that the peer is
the container's init process it recorded (pid and start time), and authenticates with
SCRAM-SHA-256 only, under fixed time and byte budgets.

At its first boot (a create) the cluster starts once with no network; the daemon sets the
platform roles' passwords as SCRAM verifiers, creates its two roles, defines the
`auth.*` helper functions, and checks the catalog against a baseline of the pinned image.
Only then does the networked start happen. PostgREST connects as `authenticator` over the
project network; database roles connect only from loopback inside the container or from the
project's slice.

PostgREST runs at uid 65532 with the same hardening, 256 MiB, 64 pids and
`GHCRTS=-N2`; its key set file holds only validated RSA public keys, replaced by rename.

## Networks and the static ruleset

- `proj-<ref>`: internal, isolated gateway mode (the bridge has no IPv4 address), IPv6 off.
  Members: `pg-<ref>` and `postgrest-<ref>`.
- `platform`: internal, isolated, Docker allocating dynamic addresses only from
  `10.212.6.0/23`. Members: the gateway at `10.212.0.2` and each project's PostgREST at
  `10.212.0.16 + i` (a pure function of the slice index, assigned explicitly).
- `ingress`: the gateway at `10.212.8.2`; the published ports land here.

The ruleset (`supapaced nft load`, rendered from `internal/nft/ruleset.tmpl`; its only input
is the gateway's address) is static: it names bridge classes, not projects, so creating a
project never changes it. Every rule carries a label:

- `inet` input — I1: replies to the host from the ingress bridge; I2: drop everything any
  bridge member sends to the host.
- `inet` forward — F1: the gateway's replies; F2: nothing is routed out of a bridge; F3:
  clients to the gateway's published ports; F4: nothing is routed into another bridge.
- `bridge` forward, policy drop — B1–B3 on project bridges: ARP, replies, and new
  connections only to port 5432 of the slice's cluster address; B4 ARP on the platform
  bridge; B8 on the platform bridge only the gateway opens connections; B6 the rest of the
  platform bridge; B9 a final explicit drop. Frames on any other bridge (Docker's default
  bridge, other software's) are dropped: their members cannot reach each other.

A cluster therefore cannot reach the internet, the host, another project or the platform
network; PostgREST cannot open connections on the platform network. Docker keeps its
userland proxy on and `br_netfilter` must never be loaded (it would divert bridged frames
into the routed chains); the daemon keeps the bridge-netfilter switches off.

## The start gate

Immediately before every `docker start` of a tenant container, with no Docker call in
between, the daemon checks, refusing on any error:

1. the bridge-netfilter switches are off and the tables match what was loaded;
2. `proj-<ref>` is internal, IPv6 off, on bridge `spp<i>` with the slice as subnet and
   isolated mode, and the interface is a bridge with no address but IPv6 link-local ones;
3. `platform` is likewise correct, and no running container but `postgrest-<ref>` holds the
   project's platform address;
4. neither tenant container has a restart policy or shares the host's or another
   container's network namespace;
5. the node is not `containment_failed`;
6. every member of the project, platform and ingress networks, both tenant containers and
   every container sharing a network namespace with them or with the host is unprivileged,
   drops every capability and adds none.

A start that fails with Docker's "Address already in use" is a containment refusal. Adopting
an already running container is gated by conditions 2–6.

## Operations

The admin API inserts a create; `restart` and `delete` are queued by the operation worker,
which is the only writer of a project's lifecycle. It runs one operation at a time, each
under the project's lock, through fixed steps; `step` is the last step completed:

- create: `1` (the API), `2` secrets, `3` placement (uid, slice, admission), `4a` and `4`
  first boot and first networked start, `6` keys, `7` tokens, `9` PostgREST, `11` route
  published and probed, `12` active;
- restart: `R0` merge-base check, `R1` the new configuration validated in a throw-away
  container, `R2` generation bumped and route drained (the gateway confirms), `R3` stop,
  quota, start, `R4` health, `R5` route active again;
- delete: `D1` route removed, `D2` PostgREST and `D3` cluster stopped and removed, `D4`
  network removed, `D5` `deleted` with the purge queued at now + retention (168 h);
- purge: `P1` leftovers stopped, `P2` keys destroyed, `P3` rendered files removed, `P4` the
  project tree removed by descriptor at the project's uid, `P5` `purged` and the slice freed;
- abort of a create: compensation `C1`–`C7` (route, PostgREST, cluster, keys, rendered files,
  network and tree, then the slice).

Operation states: `pending`, `running`, `aborting`, then `done`, `failed` or `aborted`. A
failed step is retried after 2, 5, 15 and 30 s; the fifth failure ends the operation `failed`
at its step with nothing undone (`op retry` continues it). Some failures end at once
(`conflict`, `assertion`, `epoch_divergence`, `bad_request`); `node_full` goes straight to
compensation; a containment refusal is requeued without counting while the node is
`containment_failed`. Each step has 300 s, each attempt 900 s.

A restart whose health check fails rolls forward once to generation g+2 with the previous
configuration and ends `aborted` with `last_error` `rolled_back: …`. If that rollback fails
too, the operation ends `failed` and the project stays `restarting` with its route draining.
A restart whose new cluster does not start fails at R3 after five attempts with no rollback:
the project stays `restarting` with its route draining until `op retry` succeeds.

## Routes, keys and tokens

- The route file `/var/lib/supapace/platform/gateway/routes.json` maps each project host to
  its PostgREST upstream (`http://<platform address>:3000`) and its keys, with a state
  `active` or `draining` and a generation that increases at every write. The gateway re-reads
  it when it changes, keeps the last good table on a bad file, and answers `503` for a
  draining route (`project_restarting`) and for an empty or draining table. Writers wait until
  the gateway's `/-/health` reports the generation they wrote.
- Each project has two platform signing keys (RSA, `kid` = RFC 7638 thumbprint) and two
  long-lived tokens signed with them: the anon key (`role: anon`) and the service_role key
  (`role: service_role`). User tokens are verified against the issuer key set given at
  create.
- The gateway verifies the `apikey` with the project's anon or service key, verifies an
  optional bearer token (RS256 only; `kid`, `exp` and `role` required; `nbf` may lie up to
  30 s ahead), binds the key class to the claimed role (the anon key may claim only `anon`,
  the service key only `service_role`, an issuer key only a role of the project's
  `user_roles` (`authenticated` unless roles were listed at create)), applies connection,
  in-flight and size limits, and forwards with exactly one `Authorization` header it sets
  itself. Responses are filtered (no `Server`, no domain cookies, no
  `Clear-Site-Data`) and carry `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: sandbox`, so nothing one project answers can act on another
  project's host in a browser.
- **Envelope encryption.** A node key-encryption key (KEK, `/etc/supapace/kek`, 0400) wraps
  one data key per project, bound to the ref; each project secret (the three platform
  passwords, the signing keys, the pgsodium root key) is sealed under the data key, bound to
  the ref and the secret's name (AES-256-GCM). The KEK is shown once at `supapaced init` for
  offline escrow and never replaced.

## Daemon start and adoption

`supapaced serve` at start:

1. checks its environment, loads `node.json` and the KEK;
2. takes `/run/supapace/serve.lock` (a second daemon exits 1) and the socket path;
3. removes the drift hold, re-renders the ruleset and loads it when the installed file
   differs, turns the bridge-netfilter switches off and checks the tables;
4. ensures the platform networks, writes the boot record `/run/supapace/boot.json` once per
   boot (before any tenant starts), runs the node check;
5. ensures the image files, `sp-cp-db` and the store (retried for up to 3 minutes);
6. drains every route, marks every `active` project pending adoption;
7. ensures the gateway, resumes open operations, opens the admin socket, starts the drift
   timer, the worker and the repair round.

The first failure of the firewall check, the platform networks, the drain or a blocking node
check row makes the node `containment_failed` at once (flag, drain, stop every tenant).

**Adoption** brings a pending project back without restarting it: a running container whose
labels (including a hash of its arguments and rendered files), recorded init pid and start
time all match is kept after the gate's adoption check; anything else is re-created. Then the
route goes back to `active`. Only host-side facts restore a route; the cluster check that
follows is advisory and only logged. A restart or upgrade of the daemon therefore leaves
running projects running; an upgrade that changes a container's arguments, rendered files or
seccomp profile restarts that container once, cleanly. A project still pending adoption
refuses `restart` and `delete` with "not yet adopted".

## The repair round

Once at start, 60 s after each round ends, and at once when the drift timer clears
`containment_failed` (never two at once, never while `containment_failed`), the daemon:

1. ensures `sp-cp-db` and `sp-gateway` (untouched while running with this daemon's
   configuration label; re-created otherwise, which cuts the gateway's in-flight requests);
2. adopts the pending projects;
3. repairs every other `active` project whose cluster or PostgREST container is not running
   or absent, or whose route a failed repair drained.

At most 4 projects at a time, each within 180 s, under a lock that is only tried (a project
busy with an operation is skipped). A failed repair drains the route once (clients get `503
project_restarting`) and is retried next round; the first successful repair restores the
route; a repair whose ref lock was lost writes no route. A drift hold younger than 15 minutes
pauses step 3 only.

## The drift check and containment failure

The drift timer runs every 10 s on its own: bridge-netfilter switches, then the tables. A
wrong state is reloaded once and checked again (a check that cannot run at all acts on the
third time in a row). If it still fails, the node becomes **`containment_failed`**: the flag is
set, every route drains, every tenant is stopped — all network connections cut first, then
clusters stopped with their grace period (a clean shutdown, no crash recovery) and PostgREST
containers killed — and every mutation of the admin API answers `503 containment_failed`.
Reads, `project check` and `node check` keep working. While flagged, each tick stops tenants
again and re-runs the node check; the first tick on which the tables and every blocking
node-check row pass clears the flag and starts the repair round, which brings every project
back. `docs/operations.md` has the operator's side.

## What is not claimed

- The checks a project's database server answers (the drift list of `project check`) are
  advisory: they describe that project, never the node's safety.
- The extension and role defaults inside a cluster (for example network-capable extensions
  being off) are product behaviour, not part of the boundary.
- No backups, no high availability, one node.
- Upstream response bodies, errors included, pass through the gateway unchanged and can show
  the project's private addresses.
- `docker logs pg-<ref>` prints raw bytes a tenant controls (terminal escape sequences
  included); a project that raises its own statement logging can put its users' tokens there.
- Not studied in this release: a custom allow-list seccomp profile, a sandboxing runtime,
  user-namespace remapping, mandatory access control labels.
