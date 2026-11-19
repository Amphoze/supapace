# Operations

The operator's day on one node: the CLI, project and operation states, the checks, and what to
do when something is wrong. Every example below was taken from a test node (`make node-up`,
domain `sp.test`); refs, ids and times are that node's. On a host installed with
`scripts/install-node.sh` the CLI is `/usr/local/bin/supapace`; in the test node run it as
`docker exec sp-node /opt/supapace/bin/supapace …`.

## The CLI contract

- Run it as root on the node: it talks to `/run/supapace/admin.sock` (root only, 0600).
- **stdout holds exactly one JSON document** — the body of the last API response, byte for
  byte — or nothing. Progress, summaries and hints go to stderr. Scripts read stdout only.
- A mutation (`create`, `restart`, `delete`, `purge`, `abort`, `op retry`) is accepted with
  `{"ref","operation_id"}`, then the CLI polls the operation every 500 ms until it is `done`,
  `failed` or `aborted` and prints the operation. `--no-wait` prints the acceptance at once.
- Polling tolerates an unreachable daemon for 2 minutes, then prints the last body and says
  the operation continues on the node. An interrupt (SIGINT, SIGTERM) while waiting prints the
  newest body and exits 130; before the answer arrives it says the request may already have
  been accepted.
- Flags may come before or after the ref or id. `supapace <command> --help` prints that
  command alone; a usage error prints the error and a pointer to `--help`.
- Times are RFC 3339 UTC to the second; lists are `[]`, never `null`.

Exit status:

- `0` success;
- `1` an API error, an operation that ended `failed` or `aborted` (for `project abort`,
  `aborted` is the success), a check with `"ok": false`, or the daemon could not be reached
  (`cannot reach /run/supapace/admin.sock: … (is supapaced running?)` or `(run as root)`);
- `2` usage, or an argument that cannot be read;
- `130` interrupted while waiting (the operation continues on the node).

API errors are `{"code":…,"message":…}`:

- `bad_request` (400; 413 for a body over 128 KiB) — a field or setting refused, with the
  accepted form in the message;
- `bad_ref` (400) — a ref is 20 characters of `a-z` and `0-9`;
- `ref_exists` (409) — a ref is never reused;
- `node_full` (409) — the admission ceiling, with the figures;
- `not_found` (404) — no such project, operation, or keys destroyed or not yet issued;
- `conflict` (409) — the project's state or an open operation does not allow it; the message
  names the open operation;
- `containment_failed` (503) — every mutation while the node is not contained;
- `internal` (500) — always the message `internal error`; the daemon logs the cause.

## Commands

### `project create`

```
supapace project create --name NAME --issuer-jwks FILE [--ref REF] [--user-role ROLE]...
                        [--disk-quota SIZE] [--no-wait]
```

- `--name`: 1 to 64 letters, digits, spaces, `.`, `_` or `-`, starting with a letter or digit.
- `--issuer-jwks`: the public key set of the issuer that signs your users' tokens: 1 to 16
  RSA signing keys of 2048 to 4096 bits, each with a `kid`. No private key material.
- `--ref`: 20 characters of `a-z0-9`; generated when omitted; never reused.
- `--user-role`: a role user tokens may claim (repeatable, at most 16; reserved and platform
  roles are refused). The list replaces the default `authenticated`: add
  `--user-role authenticated` if tokens with that role must keep working. The platform does
  not create the roles: create each in the project's database and grant it to `authenticator`.
- `--disk-quota`: MiB, or a number with suffix `m`, `g` or `t`; default `8g`, from `1g` to
  `16t`. The cluster's memory is fixed at 512 MiB.

```
$ supapace project create --name demo --issuer-jwks /root/issuer.jwks
operation 1: running, after step 2
operation 1: running, after step 3
operation 1: running, after step 4a
operation 1: running, after step 7
operation 1: running, after step 9
supapace: project qg6zivyo8iazv6bzkb5r: its url, keys and CA: 'supapace project keys qg6zivyo8iazv6bzkb5r'
{"id":1,"ref":"qg6zivyo8iazv6bzkb5r","kind":"create","state":"done","step":"12","attempts":1,
 "epoch":1,"generation":1,"last_error":"","created_at":"2026-11-18T19:37:26Z",
 "updated_at":"2026-11-18T19:37:40Z"}
```

(JSON wrapped here for reading; the CLI prints one line.) Admission is checked before any row
is written: a refused create (`node_full`) burns no ref. With `--no-wait`:

```
$ supapace project create --name scratch --issuer-jwks /root/issuer.jwks --no-wait
supapace: project ff28roktc6kx72erl1lb is being created; follow it with 'supapace op show 7'; …
{"ref":"ff28roktc6kx72erl1lb","operation_id":7}
```

### `project list [--state STATE]...`, `project show REF`

```
$ supapace project show qg6zivyo8iazv6bzkb5r
{"ref":"qg6zivyo8iazv6bzkb5r","name":"demo","state":"active","generation":1,"applied_gen":1,
 "uid":700000,"subnet_index":0,"config":{"disk_quota_mb":8192,"mem_mb":512,"guc":{}},
 "user_roles":["authenticated"],"created_at":"2026-11-18T19:37:26Z","deleted_at":null,
 "purge_after":null,"url":"https://qg6zivyo8iazv6bzkb5r.sp.test","ca_cert":"/etc/supapace/ca/ca.pem"}
```

`project list` prints `{"projects":[…]}` with the same objects, tombstones (`purged`,
`aborted`) included unless `--state` filters (repeatable; an unknown state is refused).
`state` is the lifecycle state, not health: use `project check`. `ca_cert` is the path of the
node CA's certificate when that CA signed the gateway's certificate (a development node),
otherwise `null`.

### `project keys REF`

```
$ supapace project keys qg6zivyo8iazv6bzkb5r
{"ref":"qg6zivyo8iazv6bzkb5r","anon_key":"eyJhbGciOiJS…","service_role_key":"eyJhbGciOiJS…",
 "postgres_password":"…","url":"https://qg6zivyo8iazv6bzkb5r.sp.test","ca_cert":"/etc/supapace/ca/ca.pem"}
```

- `anon_key` — for client applications, sent as the `apikey` header (or query parameter) on
  every request; row-level security applies.
- `service_role_key` — for trusted servers only; it bypasses row-level security.
- `postgres_password` — the database role `postgres`, for schema changes. No database port is
  published; open psql inside the cluster container (it prompts for the password):
  `docker exec -it -e PSQL_HISTORY=/dev/null pg-REF psql -h 127.0.0.1 -U postgres`.
- User tokens: RS256, signed with a key of the issuer set; header `kid` of that key; claims
  `role` (one of the project's `user_roles`: `authenticated` unless `--user-role` was
  given), integer `exp` in the future, optional `sub`
  and `nbf`; at most 8 KiB; sent as `Authorization: Bearer TOKEN` together with the anon key.

`not_found` "the project's credentials are not issued yet" before step 7 of the create;
"… destroyed when it was purged or aborted" afterwards.

### `project check REF`

Served for `active` and `restarting` projects only (otherwise `conflict`). It reads the
project's host-side facts, then opens one session to its cluster (within 75 s):

```
$ supapace project check qg6zivyo8iazv6bzkb5r
{"ok":true,"drift":[]}

$ supapace project check qg6zivyo8iazv6bzkb5r         # PostgREST container killed
{"ok":false,"code":"internal","message":"host-side: rest-container: postgrest-qg6zivyo8iazv6bzkb5r not running",
 "drift":[{"name":"rest-container","detail":"postgrest-qg6zivyo8iazv6bzkb5r not running"}]}
```

See [project check rows](#project-check-rows) for codes and names.

### `project restart REF [--set KEY=VALUE]... [--no-wait]`

Applies a new configuration and restarts the project's containers (about 8 s; clients get
`503 project_restarting` meanwhile). Settings: `disk_quota_mb=MIB` (1024 to 16777216),
`max_connections` (16–400), `shared_buffers` (16 MB to 40 % of 512 MB),
`effective_cache_size`, `work_mem`, `maintenance_work_mem`, `archive_timeout` (30–3600 s),
`cron.max_running_jobs` (1–32). Without `--set` it restarts with the current configuration.

Scheduled jobs (`pg_cron`) run in background workers, as the role that scheduled them and
with that role's rights; they need no connection or password. `cron.max_running_jobs` is the
number of jobs that run at once (default 2); a job due while that many run waits for one to
end. Parallel queries draw on the same pool of background workers; a job that finds none
free is recorded as failed and runs again at its next scheduled time. A project running
before this release takes this up at its next restart.

```
$ supapace project restart qg6zivyo8iazv6bzkb5r --set max_connections=120 --set disk_quota_mb=4096
operation 2: pending, before its first step
operation 2: running, after step R0
…
operation 2: running, after step R4
{"id":2,"ref":"qg6zivyo8iazv6bzkb5r","kind":"restart","state":"done","step":"R5","attempts":1,
 "epoch":1,"generation":2,"last_error":"","created_at":"2026-11-18T19:38:41Z","updated_at":"2026-11-18T19:38:49Z"}

$ supapace project restart qg6zivyo8iazv6bzkb5r --set shared_buffers=9GB
{"code":"bad_request","message":"shared_buffers = \"9GB\": want kB/MB/GB, 16MB to 40% of 512MB"}
$ supapace project restart qg6zivyo8iazv6bzkb5r --set fsync=off
{"code":"bad_request","message":"setting \"fsync\" cannot be set; see 'supapace project restart --help' for those that can"}
```

A value starting with `0` followed by a digit or letter is refused (the server would read it
as octal or hex). The merged configuration is checked against the generation it was read
from: two restarts merged from the same base cannot drop each other's settings (the second is
a `conflict`). A restart whose health check (R4) fails is rolled back; one whose new cluster
does not start at all (R3) is not, see [restart outcomes](#restart-outcomes).

### `project delete REF [--no-wait]`, `project purge REF [--no-wait]`

```
$ supapace project delete qg6zivyo8iazv6bzkb5r
…
{"id":5,"ref":"qg6zivyo8iazv6bzkb5r","kind":"delete","state":"done","step":"D5",…}
$ supapace project show qg6zivyo8iazv6bzkb5r      # excerpt
{…"state":"deleted",…"deleted_at":"2026-11-18T19:47:02Z","purge_after":"2026-11-25T19:47:02Z",…}
$ supapace project purge qg6zivyo8iazv6bzkb5r
…
{"id":6,"ref":"qg6zivyo8iazv6bzkb5r","kind":"purge","state":"done","step":"P5",…}
```

Delete removes the route and both containers and keeps the data, the keys and the uid; the
purge is queued at `purge_after` (now + the node's retention, 168 h). There is no restore
command in this release: during the retention the data is on disk under
`/var/lib/supapace/projects/<ref>/` and `project keys` still answers. `project purge` runs the
queued purge now: keys destroyed first, then the rendered files and the data; the row stays
as a `purged` tombstone and the uid is never reused.

### `project abort REF [--no-wait]`

Gives up a create that has not completed (project `provisioning`) and undoes what it did:

```
$ supapace project abort ff28roktc6kx72erl1lb
{"id":7,"ref":"ff28roktc6kx72erl1lb","kind":"create","state":"aborted","step":"1","attempts":0,…}
$ supapace project abort qg6zivyo8iazv6bzkb5r
{"code":"conflict","message":"project is active; abort applies only to a create in progress; an active project is removed with delete"}
```

### `op list [REF]`, `op show ID`, `op retry ID [--no-wait]`

```
$ supapace op list qg6zivyo8iazv6bzkb5r
{"operations":[{"id":1,"ref":"qg6zivyo8iazv6bzkb5r","kind":"create","state":"done","step":"12",
 "attempts":1,"epoch":1,"generation":1,"last_error":"","created_at":"2026-11-18T19:37:26Z",
 "updated_at":"2026-11-18T19:37:40Z"}]}
$ supapace op retry 1
{"code":"conflict","message":"operation is done; only a failed operation can be retried"}
```

`op list` is newest first. `op show` prints one operation; `step` is the last step completed
(`""` before the first). `op retry` puts a `failed` operation back in the queue; it continues
from its step.

### `node check`

```
$ supapace node check
{"ok":true,"containment_failed":false,"checks":[{"name":"nft","ok":true,"detail":""},
 {"name":"docker-version","ok":true,"detail":""},…,
 {"name":"core_pattern","ok":true,"detail":"informational (dev-mode): kernel.core_pattern pipes core dumps to a helper"},
 …,{"name":"docker-firewall-backend","ok":true,"detail":"iptables"},
 {"name":"control-plane-db","ok":true,"detail":""},{"name":"gateway","ok":true,"detail":""}]}
```

Exit 1 when any row fails. See [node check rows](#node-check-rows).

## Project states

| State | Allows |
|---|---|
| `provisioning` | `show`; `keys` once issued; `abort` |
| `active` | `show`, `keys`, `check`, `restart`, `delete` |
| `restarting` | `show`, `keys`, `check`; `op retry` of its failed restart |
| `deleting` | `show`, `keys`; `op retry` of its failed delete |
| `deleted` | `show`, `keys`, `purge` (also runs by itself at `purge_after`) |
| `purged`, `aborted` | `show` (tombstone; keys destroyed, ref never reused) |

`restart` and `delete` also need no open operation on the project, and a project still pending
adoption after a daemon start refuses them with `conflict` "not yet adopted" (for up to one
repair round).

## Operation states

- `pending` — queued; `running` — the worker has it; `aborting` — a create being undone.
- `done`; `failed` — stopped at `step` after five failed attempts, nothing undone; `aborted` —
  a create undone, or a restart rolled back.

A step that fails is retried after 2, 5, 15 and 30 s; the fifth failure ends the operation
`failed`. The CLI then prints `supapace: operation N failed after step S: <last_error>` and
the ways on: `op retry N`, and for a create also `project abort REF`. `last_error` is
`<code>: <message>`; codes: `internal`, `timeout`, `peer`, `conflict`, `bad_request`,
`node_full`, `containment_failed`, `assertion`, `epoch_divergence`, `stale_generation`, and
`rolled_back` on an aborted restart. `conflict`, `bad_request`, `assertion` and
`epoch_divergence` end an operation at once; `node_full` sends a create straight to its
compensation; a containment refusal waits (requeued every 10 s, not counted) while the node
is `containment_failed`. A daemon restart in the middle of an operation counts as an attempt;
the worker resumes it after the restart.

### Restart outcomes

- `done` — the new configuration runs at the new generation.
- `failed` after step R2 — the new cluster did not start (`… is not running after docker start`)
  in five attempts. Nothing is rolled back: the project stays `restarting` with its route
  draining (clients get `503 project_restarting`) and neither a new restart nor a delete is
  accepted. Read `docker logs pg-REF` on the node, remove the cause, then `supapace op retry ID`
  (R3 stops and starts the cluster again).
- `aborted`, `last_error` `rolled_back: the project runs its previous configuration at
  generation N; the restart to generation M was rolled back because its health check failed:
  …` — the health check (R4) failed, the restart rolled forward to generation N = M + 1 with
  the previous configuration (disk quota included). The CLI exits 1. The project is `active`;
  fix the cause and restart again. `generation` of the operation stays M.
- **The two-failure state:** the rollback's health check fails too. The operation ends
  `failed`, the project stays `restarting` with its route draining (clients get `503
  project_restarting`), and neither a new restart nor a delete is accepted. Read
  `last_error` (`… rollback to generation N: …`) and the cluster's log (`docker logs pg-REF` on
  the node, raw tenant output), remove the cause, then `supapace op retry ID`: it continues the
  rollback (R3 stops and starts the cluster again, R4 checks it). Each R4 attempt waits up to
  120 s for the server to accept a login.

## Node check rows

`node check` (and every daemon start, and every drift tick while the node is flagged) reports
one row per condition. A **blocking** row that fails at daemon start makes the node
`containment_failed`, and while the node is flagged every blocking row must pass before the flag
clears. A row that starts failing while the node runs normally is only reported (`ok: false`,
exit 1): fix it before the next daemon start, which would otherwise flag the node.

- `nft` — our two tables present and as last loaded, bridge-netfilter switches off. See
  [drift after an nftables upgrade](node-install.md#drift-after-an-nftables-upgrade); run
  `supapaced nft check` for its exit code.
- `docker-version` — Docker 26.1.3 or later. Upgrade Docker.
- `daemon.json` — our address pool, `ipv6: false`, the `local` log driver with `max-size` and
  `max-file`, no `userland-proxy` or `icc` key, and no network with inter-container traffic
  off. Restore the file (`supapaced init` rewrites it) and restart Docker.
- `live-restore` — Docker's live-restore off.
- `docker-seccomp` — Docker's seccomp on with a profile other than `unconfined`.
- `docker-networks` — only the platform's networks and Docker's defaults, drivers `bridge`,
  `host` or `null`, no macvlan or ipvlan interface besides the uplinks. Remove the foreign
  network or interface (a node is dedicated).
- `uplinks` — the recorded and default-route interfaces exist and are not bridges.
- `quota-accounting`, `quota-enforcement` — the projects mount is XFS with user and project
  accounting and user-quota enforcement. Remount with `usrquota,prjquota`.
- `ptrace_scope` — `kernel.yama.ptrace_scope` at least 1.
- `kek` — `/etc/supapace/kek` is a root-owned regular file, 0400, 32 bytes. Restore it from
  the escrow ([install](node-install.md#supapaced-init)).
- `platform-members` — on the `platform` network only the gateway at its address and each
  project's PostgREST at its own address, each dropping every capability. Remove the foreign
  member (`docker network disconnect`).
- `core_pattern`, `br_netfilter`, `file-max` — host-global settings
  ([prerequisites](node-install.md#prerequisites)); informational on a development node.
- `docker-firewall-backend`, `drift-hold` — informational, never failing. `drift-hold`
  appears only while the file exists: `present, age Ns: drift check and project repairs
  paused`, or `stale, ignored: age Ns, honoured below 900s`.
- `control-plane-db`, `gateway` — the platform containers run with this daemon's
  configuration (and the gateway at its addresses). They **fail without blocking**: `ok` is
  false and the exit code 1, but the node stays contained; the repair round re-creates them
  within 60 s. While `sp-cp-db` is down, every CLI call but `node check` answers
  `internal error` (`node check` shows `control-plane-db`: `sp-cp-db not running`); running
  projects keep serving.

The top-level `containment_failed` is the daemon's flag, which the drift timer clears (see
below), not a re-evaluation of these rows.

## Project check rows

Host-side rows, read first, from Docker, `state.json` and the route file:

- `cluster-container` — `pg-<ref>` exists, runs, and is the container `state.json` records
  (labels, init pid and start time, network and address);
- `rest-container` — `postgrest-<ref>` exists, runs, with the desired labels on exactly its
  two networks at its addresses;
- `route` — the project's route is `active` (`no route: requests answer 404`, or `route
  draining: requests answer 503`).

Then one session to the cluster. The `code` of a failed check: `peer` (the socket's peer is
not the recorded process), `timeout` (a bound was hit), `internal` (anything else, including a
failing host-side row with a passing session: message `host-side: <row>: <detail>`). The
remaining drift rows compare the cluster with what the platform expects: `presence`,
`superuser`, `attributes`, `memberships-reserved`, `memberships-dangerous`,
`role-settings`, `schema-acl`, `event-triggers`, `auth-functions`, `configuration`,
`source-file`, `hba`, `service-passwords`. **The drift list is advisory**: it describes that
project only, it is not a security signal, and nothing on the node acts on it after the
create. Failing host-side rows are repaired by the next repair round (within 60 s).

## Runbooks

### A project at its disk quota

Symptoms: writes fail with `Disk quota exceeded`. When the server cannot write its WAL it
restarts its own processes and runs crash recovery inside the container; for those seconds
REST answers `503` with `PGRST000` ("the database system is not accepting connections") and
`project check` answers `ok: false`. In a test it served again after about 8 s with the data
consistent.

Look at the usage (uid from `project show`; excerpt):

```
$ xfs_quota -x -c 'report -u -n -h' /var/lib/supapace/projects
User ID      Used   Soft   Hard Warn/Grace
#700000     988.9M      0     1G  00 [------]
```

Then either free space (the developer drops data; space is returned at once:
`drop table` took the example from 1005 MiB to 503 MiB) or raise the limit:

```sh
supapace project restart REF --set disk_quota_mb=2048
```

The new quota is applied with the cluster stopped (R3), so it also helps a cluster whose
crash recovery itself needs more space and exits at every start (the repair round starts it
again once per round until then).

**Never set a quota below the current usage.** It is not refused, but the cluster then cannot
start (`could not create lock file "postmaster.pid": Disk quota exceeded` in `docker logs`), the
restart ends `failed` after step R2 and the project stays `restarting` with its route draining;
`op retry` applies the same quota again, and this release has no command that leaves that state.

### The daemon restarts or is upgraded

Restarting or upgrading the daemon does not restart projects. At start it drains every route
for a moment (clients may see `503 project_restarting` for one to two seconds), adopts every
running tenant container whose configuration still matches, and re-activates the routes; an
upgrade that changes a container's arguments, rendered files or seccomp profile restarts that
container once, cleanly. In a test, `kill -TERM` of the daemon left the cluster's start time
unchanged; the new daemon served after about 2 s and logged `adopted ref=… generation=4`.
Operations in progress resume after the restart.

### `containment_failed`

Meaning: the node could not show that its containment holds — the firewall tables are wrong
and a reload did not fix them, the check could not run three times in a row, a platform
network is wrong, or a blocking node-check row fails (at daemon start, or while flagged).

What the node does, at once: every route drains, every tenant is cut off from its networks
and stopped (clusters with their 45 s grace period, a clean shutdown; PostgREST containers
killed), every mutation answers `503 containment_failed`, the worker takes nothing. Reads,
`project check`, `node check` and the admin socket keep working; `project show` still says
`active` (the lifecycle state). The log says, for example:

```
level=ERROR msg="drift: firewall tables wrong; reloading" err="nft: supapace table absent: table inet supapace"
level=ERROR msg="drift: reload" err="nft: load: …"
level=ERROR msg="drift: containment failed; draining every route and stopping every tenant" err="…"
```

```
$ supapace node check            # excerpt
{"ok":false,"containment_failed":true,"checks":[{"name":"nft","ok":false,
 "detail":"nft: supapace table absent: table inet supapace"},…]}
$ supapace project create --name x --issuer-jwks /root/issuer.jwks
{"code":"containment_failed","message":"the node's containment is not verified; mutations are refused until it is (see 'supapace node check')"}
```

How the node leaves it: fix what the failing rows name (`supapaced nft check` and its exit
code for the tables). The drift timer re-runs the checks every 10 s while flagged; the first
tick on which the tables and every blocking row pass clears the flag (`drift: containment
shown again; adopting the pending projects`), and the repair round starts every project
again. In a test with a broken rules file: flag set within 10 s of the fault; after the file
was restored, the flag cleared within 4 s and the project served again 3 s later. A daemon
restart re-evaluates everything at start.

### The drift hold (a test hook)

`/run/supapace/drift-hold` is how the end-to-end suite keeps the drift timer from acting while
it builds scratch networks on purpose. While the file is younger than 15 minutes the drift
timer skips its ticks (`drift check skipped: hold file present, age Ns`) and the repair round
skips project repairs (`repair: drift hold present (age Ns); project repairs paused this
round`); adoptions and the platform containers' repair go on. An older file, or one dated in
the future, is ignored, and every daemon start removes it. The node-check row reads
`present, age Ns: drift check and project repairs paused`. Outside the suite, take the hold
only to stop or replace a tenant container on purpose while the daemon runs (otherwise the next
round starts it again). It also suspends the firewall drift check: keep it as short as the
work, refresh it within 15 minutes only if needed, and remove it afterwards.

## Logs

- The daemon: one text line per event on stderr, which systemd puts in the journal
  (`journalctl -u supapaced`; bounded by the journal's own settings). In the test node it also
  goes to `/var/log/supapaced.log`, emptied at node start and cut to its last 4 MiB above
  8 MiB before each daemon start. Text from Docker or a cluster is sanitised and capped at
  1 KiB; no key, password or secret is logged.
- Operation lines: `step done`, `step failed` (with `final`, and `retry_in` when retried),
  one `operation finished` per ending (outcome `done|failed|aborted|rolled_back`, step,
  attempts, duration). Repair lines: `repair: started`, `repair failed; route draining,
  retried at the next round`, `repair failed; retried at the next round` (the ref lock was lost; no
  route written), `adopted`, `advisory cluster check …`, `cluster drift`.
- Containers: Docker's `local` log driver, 10 MiB × 3 files per container (`daemon.json`).
  `docker logs pg-<ref>` prints raw bytes the tenant controls, terminal escape sequences
  included (pipe it through `cat -v`); a project that raises its own statement logging can put
  its users' tokens there.

## Known limits

- No backups, no restore of a deleted project, one node.
- Ports and address ranges are fixed; the admission ceiling counts 768 MiB per project.
- The repair round does not re-check running containers: an unadoptable or disconnected
  running container is handled at the next daemon start or containment clear. A route left
  draining by a failed operation of an active project is not restored by the round. A cluster
  that exits at every start is re-created once per round. While the store is unreachable a
  dead container's route stays active.
- A restart to a disk quota below the project's current usage leaves the project `restarting`
  and unserved, with no command to recover it. Check the usage (`xfs_quota`) first.
- A restart whose new cluster does not start is not rolled back: the project stays
  `restarting` and unserved until `op retry` succeeds.
- `--user-role` replaces the default role `authenticated` instead of adding to it.
- A blocking node-check row that starts failing while the daemon runs is reported, not acted
  on, until the next daemon start.
- A database-level setting a project makes on itself can lock out its own sessions and its
  PostgREST (for example a preload library that does not exist, or read-only transactions by
  default). The platform's own sessions override those settings and keep working, but this
  release has no operator command to reset them.
- A configuration include of a FIFO or a very large file in a project makes that project's
  checks end in a timeout or an error (only that project); restarts then fail at R4.
- `node.json` or a key that does not load makes the daemon exit before any containment step;
  running tenants and routes stay as they were while systemd restarts it every second.
- Upstream response bodies pass through the gateway unchanged: PostgREST's connection errors
  can show the project's private cluster address. An oversized request header block gets a
  plain-text `431` (HTTP/1.1) or a stream reset (HTTP/2).
- A purge whose task fails leaves the project's uid without quota limits until the purge
  completes (no tenant container exists by then); a completely full projects filesystem needs
  the operator to free space.
