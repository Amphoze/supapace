# supapace — agent notes

## Overview

Control plane, gateway and provisioning model for running many isolated Supabase-compatible
projects on one shared stack, across multiple instances and clouds. Upstream Supabase
components are consumed as containers and are not vendored, except for a patch series
against Studio. GoTrue is deliberately absent; identity comes from an external OIDC issuer.

## Conventions

- Go for the control plane, node agent, gateway and CLI. No Python anywhere in the runtime.
  Rust only where a measured hot path justifies it.
- `master` is the production branch. Feature work happens on short-lived branches and is
  deleted after merge. Releases are tagged.
- Containers use minimal base images. Upstream images are pinned by digest, never `latest`.
- Shared services are shared **per node**, not globally: no single global point of failure,
  and a project's shared services sit next to its database.
- This repository is public. No hostnames, IP addresses, credentials, customer names or
  other operator-identifying detail may be committed. Deployment specifics live in the
  operator's private spec tree, not here.
- Design specs, plans and runbooks live outside this repository; this repo carries product
  documentation only.

## Change log

### 2026-11-17 — repository created

Skeleton only: licence, readme, agent notes, Go module. Architecture under design; the
decisions that gate it (shared Realtime/Storage/pg-meta/edge-runtime viability, Studio
patch surface, backup model) were verified against upstream source first.

### 2026-11-17 — scaffolding, shared types, public gate

- Public-content gate: `cmd/check-public` (Go, stdlib only), run through
  `scripts/check-public.sh`. Modes: `--staged`, `--tree`, `--message FILE`,
  `--range <rev-list args>`, `--tag OBJECT`. It refuses e-mail addresses, home-directory
  paths, addresses outside the platform and documentation ranges, non-test host names and
  every pattern of the operator's deny-list (`SUPAPACE_DENYLIST`, kept outside the
  repository). It scans blobs as bytes (binary files, invalid UTF-8, UTF-16, CRLF and
  symlink targets included), path names, whole commit messages and commit identities, and
  fails closed on a missing, unreadable, empty or non-compiling deny-list and on any git
  error. Findings show file, line and rule only. Exact exceptions live in
  `scripts/public-allow.txt`, each with a reason; the file is read from the index.
  What a pattern gate cannot catch is listed in the package comment.
- `make setup` installs the hooks: `pre-commit`, `commit-msg`, `pre-merge-commit` and
  `pre-push` (the last scans exactly what is being pushed: every commit's identities,
  headers, message and introduced blobs, tags and ref names). Commits are made with
  `TZ=UTC` under a noreply identity; anything else is refused at commit (cherry-pick and
  rebase run no commit hook) and at push.
- `scripts/test-check-public.sh` runs the gate's end-to-end cases (`make gate-test`, part
  of `make unit`).
- `internal/nodecfg`: `node.json` type, fixed defaults and validation (overlapping networks,
  uid range, domain), slice and platform-address arithmetic, every on-disk path (`Paths`,
  rootable for tests), and `images.lock` (upstream images pinned by multi-platform digest,
  embedded).
- `internal/routes`: the gateway route-file type with strict parse and marshal. Unknown
  fields, trailing data, an empty domain and a generation below 1 are rejected. Case-variant
  and duplicate JSON keys stay accepted (the file is written by a trusted local component).
- `go.mod` pins `github.com/jackc/pgx/v5`, the only dependency; `internal/store/doc.go` keeps
  the requirement until the store package lands.
- `Makefile`: `setup build images unit gate-test node-up node-bare node-down reach
  reach-reboot reach-host measure public-check`; reach runs are bracketed by a suite reset
  whose failure fails the target.

### 2026-11-17 — `internal/dockerx`

- Drives the `docker` CLI by argv only (no shell): `Run`, `RunInput`, `InspectContainer`,
  `InspectNetwork`, `ListContainers`, `ServerVersion`. 60 s default timeout (an earlier
  caller deadline wins); on timeout or cancel the whole process group is killed.
- An inspect returns `nil, nil` only when docker itself reports the object as absent, in its
  own wording at the start of stderr. An unreachable daemon, a missing binary or any other
  failure is an error: "does not exist" and "could not ask" are never confused.
- Object names are passed after `--`. Errors name only the docker verb and carry at most
  64 KiB of stderr, never later arguments or environment values.

### 2026-11-17 — `internal/secrets`

- Envelope encryption: a node key-encryption key (KEK) in a 0400 file, one data key per
  project wrapped by the KEK with the project ref bound, project secrets sealed under the data
  key with `(ref, name)` bound. AES-256-GCM, random 12-byte nonces. Every authentication
  failure returns the same error; no error carries key, plaintext or ciphertext bytes.
- `ref` must be 20 lower-case alphanumerics and `name` non-empty in all four seal/wrap calls.
- `GenerateKEK` writes a temporary file, syncs it and hard-links it into place: an existing
  file is never modified. If the directory sync fails, the new key is removed again so a
  retry starts clean. `LoadKEK` refuses anything but a regular 0400 file of the right size
  and owner, opened without following a final symlink and without blocking.
- The key directory must be root-owned; the caller removes `.<name>.tmp-*` leftovers of a
  crashed run before generating.

### 2026-11-17 — `internal/jwtx`

- RS256 tokens only; the verifier fixes the algorithm. `Verify(token, keys, now)` checks, in
  order: size (8 KiB) and alphabet, three unpadded base64url segments, strict JSON with
  duplicate members refused at any depth (depth limit 64), `alg`, no `crit`, exactly one
  supplied key with the token's `kid`, the signature, then `exp`, `nbf` (30 s leeway), `role`
  and `sub`. Numeric dates are integers. It reads no clock and starts no goroutine.
- `CheckRole` binds the verifying key's class to the claimed role: the anon key may claim
  only `anon`, the service key only `service_role`, an issuer key only `authenticated` or a
  role the project lists — never a reserved or platform role, even if listed. Callers must
  call it after every `Verify`.
- `ParseJWKS` (64 KiB cap) keeps RSA signature keys of 2048–4096 bits with `e = 65537` and
  skips other entries; it refuses the set when no usable key remains, when a usable key is
  malformed or shares a kid, or when any entry carries private or symmetric key material.
  Key ids are RFC 7638 thumbprints.

### 2026-11-17 — `internal/store`

- Control-plane database layer on pgx over a unix socket: schema and one-shot migration
  (serialised by an advisory lock), node row, projects, placement, the operation queue,
  per-ref advisory locks, wrapped data keys, sealed secrets and project keys.
- Placement: a per-node monotonic uid counter (a uid is never reused), the lowest free
  network slice (released only at purge or abort), admission against the node's memory and
  pids ceilings counting `provisioning`, `active`, `restarting` and `deleting` projects.
  `EnsureNode` refuses changed address or uid ranges and applies changed ceilings.
- Operations: `restart` and `delete` are accepted only for an `active` project with no open
  operation; `RetryOperation` has the same guard. Step, failure and finish writes succeed
  only in the states that allow them, so a worker that lost a race with an abort gets
  `ErrConflict`. `MarkAborted` works from `provisioning`, and from `active` while the create
  is aborting. A project ref is never reused.
- `SetProjectState` has no transition rules: reaching `purged` or `aborted` goes through
  `MarkPurged` / `MarkAborted`, which release the slice. Each held or waiting `LockRef` pins
  one of the pool's 8 connections.
- Tests run against a throw-away `postgres` container (`--network none`, unix socket,
  removed by a detached watchdog) and are skipped without Docker.

### 2026-11-18 — `internal/nodefs`

- Root-side filesystem work of a node: `CreateProjectDir` (project directory with `data/`
  and `sock/`, owned by the project's uid and gid, outer chown last so an interrupted
  creation is resumed, a finished one is never touched again), `SetQuota`,
  `RemoveEmptyProjectDir` (one non-recursive `unlinkat`), `WriteFile` (atomic rendering of
  root-owned files below the render roots only) and `CheckRange` (the platform's id range
  against passwd, group, subuid and subgid).
- Everything below a project directory is reached by descriptor (`O_NOFOLLOW`, `fstat`
  before acting) and only while the directory is still root-owned; root makes no path-based
  call on a name a tenant can replace.
- The disk limit is the XFS **user quota** on the project's uid: a block limit and an inode
  limit of `max(65536, 256 × MiB)`. The project id and inherit flag are set for usage
  accounting only and **no project limit is set** — a file's owner can tag files with any
  project id, so a project limit could be spent by another tenant. `SetQuota` refuses to set
  a limit unless user-quota accounting and enforcement are on, runs `xfs_quota` with
  `LC_ALL=C`, treats any stderr output as failure (the tool exits 0 on errors) and reads the
  limits back. `SetQuota(p, uid, 0)` clears.
- Project ids must lie in [65536, 2^31−1]. `WriteFile` creates no directories, always
  replaces its target and may leave `.<name>.tmp-*` after a crash. The ioctl constants are
  for amd64 and arm64; the package does not build elsewhere.
- Tests that need root and XFS skip on a workstation and run as root on the node; the
  `reach`-tagged file holds the quota tests.

### 2026-11-18 — node harness and `sp-probe`

- `make node-up` / `node-bare` run the node as a privileged Docker-in-Docker container
  (`NODE ?= sp-node`, 4 GiB, stop timeout 60 s): loop-backed XFS with user and project
  quotas, then init → rules load → dockerd → cached image archives → supervisor loop; `bare`
  stops after the filesystem and a bare dockerd. Set `NODE` to run several side by side.
  A corrupt image archive fails the boot; the node reclaims its own cgroup's file cache and
  never touches host-wide settings. Host side effects: the `xfs` module, one loop device
  per running node, the shared node image tag and the image cache directory.
- Image archives are re-tagged in their `index.json`, so digest references resolve after
  `docker load` (containerd image store).
- `sp-probe tcp|udp|dns` prints one verdict line — `connected`, `answered`,
  `refused <errno>`, `unreachable <errno>`, `timeout`, `negative <rcode>`, `error …` — and
  exits 0 / 1 / 2 / 3 for reached / refused or negative / timeout / usage or internal
  error. An internal failure is never 1. **A caller must require the line and the exit code
  to agree**: through `nsenter`, a bad namespace path also exits 1 and a missing binary 127.
  UDP probes carry a nonce; a unicast target must answer from the probed address, multicast
  and broadcast targets from any. `dns` exits 0 only for NOERROR with an address of the
  queried type.
- `sp-probe listen` binds exactly one address family and echoes UDP from the address the
  datagram was sent to. `sp-probe fakepg` logs every byte a client sends as records
  `conn N LEN` + LEN bytes, prints `listening` once bound and logging, and leaves no
  record for a connection that sends nothing (clients need their own timeout). Its modes
  and socket rule are in the `sp-probe sys` entry below.

### 2026-11-18 — reach suite: helpers and path tests

- `test/reach` is the end-to-end suite that runs as root on a node (`make reach`). It is
  written ahead of the system under test: until the daemon and CLI exist the tagged binary
  stops in `TestMain` naming what is missing. `helpers_test.go` is untagged, so
  `go test ./...` runs the golden JSON-shape test and the helper self-tests
  (`helpers_self_test.go`, `!reach`); the suite itself is in files tagged `reach`.
- Rules the helpers enforce, which later tests must keep:
  - a refusal by the gateway is asserted by its error body (`invalid_apikey`,
    `invalid_token`, `no_apikey`, `body_too_large`) and fails on any `PGRST` code — the
    upstream refuses the same tokens, so a status code alone proves nothing about the
    gateway;
  - every refusal is preceded by an accepted twin on the same path; "not reached" from
    `postgrestDirect` or a failed dial is never a refusal without a control that reaches;
  - `probe` requires the verdict line and the exit code of `sp-probe` to agree and fails
    the test on a bad namespace, a missing binary or an `error` verdict;
  - failure text is redacted (no query, token, key or password in test output);
  - every created object carries `supapace.test=1`; every external command has a
    deadline and is killed with its process group; cleanups are idempotent.
- Fixture projects A and B persist between runs (so a reboot test has tenants that existed
  before it) and are rebuilt when the daemon binary changes; `fixtureScratch` holds one
  extra project at a time and removes it whatever state it is in.
- The suite reset (in `TestMain` and in the Makefile, before and after the binary) removes
  the drift hold and the failpoint file, reloads the rules and removes labelled objects.
- Tests so far: signature and project separation (01), key class and role, including the
  bearer defects only the gateway refuses (02), `auth.uid()` (08), gateway headers (12),
  GraphQL (15), gateway limits (17). The defective bearers come from one helper,
  `gatewayOnlyBearers`, checked by a self-test to carry exactly one defect each.
- The suite needs from the system: the CLI's JSON documents, the admin socket, the dev CA,
  the rendered key-set file of each project's PostgREST, and a unique nft `comment` on
  every rule a control deletes.

### 2026-11-18 — network experiments (`test/harness/experiments/e01, e02, e03, e10, e11`)

- Scripts that reproduce, inside a bare node, the kernel and Docker facts the network design
  rests on. Each prints `VERDICT ENN: confirmed|fallback|unknown — …`; run with
  `docker exec -i <node> sh -s < test/harness/experiments/eNN.sh`. Re-run them when the
  kernel, nftables or the node's Docker version changes. Every "blocked" result in them has
  a control that connects when one rule is removed.
- Facts established (Docker 29.10 in the node, nftables 1.1):
  - bridge-family conntrack, the bridge-name wildcard and the masked address match work in
    a nested network namespace; open connections survive a conntrack flush or table reload;
  - `iifkind`/`oifkind "bridge"` match named and unnamed bridges; a macvlan child or a plain
    veth is treated like an uplink;
  - Docker's isolated gateway mode keeps the embedded resolver, gives the bridge no IPv4
    address, and the bridge still has an IPv6 link-local address; `network inspect` reports
    the gateway as an invalid address;
  - with the **userland proxy on** (the default) dockerd never loads `br_netfilter` and
    never touches the bridge-nf switches; with the proxy off it loads the module and turns
    `bridge-nf-call-iptables` back on at every network create, which diverts bridged frames
    into the routed chains. Published ports need an explicit IPv4 bind
    (`-p 0.0.0.0:443:8443`), otherwise the proxy also serves IPv6 clients and the container
    sees them all with the bridge address;
  - a static address outside the network's `--ip-range` is accepted and stable; dynamic
    members never leave the range; Docker does not reserve a stopped member's address, and
    `network connect --ip` succeeds even while a running container holds the address (only
    the start fails);
  - a bridge member with Docker's default capabilities can take over a neighbour's address
    with one ARP frame; with all capabilities dropped it cannot.
- `e10.sh` loads no kernel module in its default run; the proxy-off demonstration needs
  `E10_LOAD_MODULE=1` and leaves `br_netfilter` loaded until reboot.

### 2026-11-18 — cluster-image experiments, fixtures and baseline

- `test/harness/experiments/e06, e07, e12, e13, e15`: scripts for a bare node about the
  pinned Postgres images. Facts established:
  - the two-phase first boot of the cluster image works at an arbitrary project uid under
    the full hardening (read-only root, no capabilities, no-new-privileges): phase A with the
    platform's `conf.d`, phase B with the platform's `pg_hba`; the entrypoint neither
    re-initialises nor rewrites mounted files; the image needs a rendered `passwd` entry for
    the uid;
  - the control-plane database starts read-only at uid 70 with no network, peer
    authentication over the mounted socket for root and uid 70 only;
  - `postgres -C <setting>` in a throw-away container validates a candidate configuration
    without touching the running cluster, but checks syntax and range only — it does not
    validate settings of preloaded libraries, nor cross-setting rules;
  - the database-level session defaults of a project database apply to every role's
    sessions. `e15.sh` holds the list of settings a platform session sends as startup
    parameters, shows for each entry that it wins over a database-level value, and prints
    the **residual** — the settings a database owner can still change for such a session.
    Re-run it when the image pin changes. `event_triggers=off` is accepted only from a
    superuser session.
- `internal/bootstrap/baseline_17.6.1.166.json`: roles, memberships, role settings, schemas
  and event triggers of a fresh, un-bootstrapped cluster of the pinned image.
- `internal/pgconf/testdata/image/`: `passwd`, `group`, `supautils.conf` and `conf.d/*`
  copied unmodified out of the pinned image (the allow file carries four exact tokens for
  the `passwd` fixture).

### 2026-11-18 — PostgREST, socket and quota experiments (`e04, e05, e08, e09, e14`)

- Scripts for a bare node (`cat lib-rest.sh eNN.sh | docker exec -i <node> sh -s`; `e14.sh`
  runs on the workstation with the node name); `e08` and `e09` need their Go helpers built
  into `bin/`. Facts established:
  - **PostgREST 16.5** starts one runtime worker per CPU and dies at a pids limit of 64 on a
    many-core host; with `GHCRTS=-N2` it idles at about 9 threads and peaks near 23. It
    selects the key by `kid` from a multi-key set and re-reads its whole configuration on
    `SIGUSR2` **and on `NOTIFY pgrst, 'reload config'` from any database session**; only
    `SIGUSR1` / `'reload schema'` rebuild the schema cache. `db-config = false` makes it
    ignore `pgrst.*` role settings. Without an admin port there is no readiness endpoint
    (`GET /` answers). It logs no token and no database password.
  - **A key file that is not a valid key set is used as a shared HS256 secret**, and a set
    containing a symmetric key enables HS256: whatever renders that file must build it only
    from validated public keys and replace it atomically.
  - Token strictness is the gateway's job, not the upstream's: a token with no `kid`, no
    `exp`, no `role`, an unknown `crit` header, `role = authenticator` or a duplicate
    `role` must be refused before it is forwarded.
  - `SO_PEERCRED` on a cluster's socket reports the process that called `listen()` — the
    container's init — stably across forks, reloads and crash recovery; a listener planted
    at the same path by another process of the same uid reports its own pid, so the pid and
    start time are the check, not the uid.
  - a Unix socket can be dialled as `/proc/self/fd/<n>` for an `O_PATH` descriptor of the
    checked socket inode, which keeps working when the name is swapped afterwards; dialling
    by name follows the swap.
  - XFS: the user quota (blocks and inodes) holds wherever the uid writes; a file's owner
    can move it to any project id.
  - a node restart re-attaches exactly one loop device, keeps quota limits and loads no
    image again.

### 2026-11-18 — image fixture: `postgresql.conf`

- `internal/pgconf/testdata/image/postgresql.conf` is the pinned cluster image's main
  configuration file, unmodified (its preload lists and `include` lines are what the
  command-line pins and the restart check are built from).

### 2026-11-18 — gateway (`internal/gateway`, `cmd/gateway`, `deploy/gateway`)

- The node's public entry point. Per request: health (`/-/health`, any host) → route table →
  host → TLS server name must equal the host → draining → upgrade refusal → `apikey` (header
  or query, they must agree) verified with the project's anon or service key → optional
  bearer verified with the project's keys → key class bound to the claimed role
  (`jwtx.CheckRole` after every `Verify`) → in-flight caps → body cap → proxy to the
  project's PostgREST with exactly one `Authorization` header set by the gateway and
  client-supplied forwarding headers replaced.
- Refusals are JSON `{"code": …}`: `no_apikey`, `invalid_apikey`, `invalid_token` (401),
  `not_found` (404), `body_too_large` (413), `misdirected` (421), `too_many_requests` (429,
  per project), `unavailable` (503, gateway-wide or an empty table), `project_restarting` (503,
  a draining project), `bad_request` and `upgrade_not_supported` (400), `upstream_unavailable` (502),
  `upstream_timeout` (504), `http_version_not_supported` (505). The gateway refuses tokens
  without `kid`,
  `exp` or `role`, with an unknown `crit`, a duplicate `role`, or `role = authenticator`.
- Limits (constants next to each other in `server.go` / `limit.go`, pinned by tests):
  2,048 connections and 64 per source (an IPv6 /64 is one source); 2,048 proxied requests in
  flight and 128 per project (also the upstream connections per project); request headers
  32 KiB, body 8 MiB; upstream response headers 32 KiB; HTTP/2: 8 streams per connection,
  16 KiB frames, 128 KiB receive windows; kernel socket buffers fixed at 32 KiB on client
  and upstream sockets; timeouts header 10 s, read 60 s, write 60 s, idle 120 s, upstream
  dial 5 s and response header 30 s; at most 8 informational responses relayed per request.
  The request header is released when the handler returns.
- Memory: the image sets `GOMEMLIMIT=460MiB` and is sized for a **768 MiB** container; at
  the limits above the measured peak is about 630 MiB. Socket buffers are outside the Go
  heap, which is why they are fixed in code. With 32 KiB buffers an 8 MiB upload takes about
  20 s at 100 ms round trip and about 45 s at 200 ms.
- Upstream responses are filtered on the final header, on 1xx responses and on trailers:
  `Server`, `Set-Cookie2`, `Clear-Site-Data` and every `Set-Cookie` with a `Domain`
  attribute are dropped; `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: sandbox` are set on every upstream response and on the
  gateway's own refusals. Projects are sibling hosts under one parent domain: nothing one
  project answers may act on another project's host in a browser.
- The route file is re-read on a changed inode, size or mtime; a bad file keeps the last
  good table; an empty or draining table answers 503, never another project's upstream. It
  must be replaced by rename and must hold only keys the token package accepts.
- The image is `scratch` with the static binary, numeric user 65531; without TLS files the
  process exits 1; a second termination signal ends the 10 s grace period at once. Publish
  its ports with an explicit IPv4 bind.
- The health answer and the plain-HTTP redirect carry the two sandbox headers as well.

### 2026-11-18 — `internal/dockerx`: bounded output

- Captured stdout is capped at 4 MiB while the child writes: a call that would exceed it
  kills the child's process group and returns an error matching `ErrOutputTooLarge`, with no
  partial output. Captured stderr keeps its **first** 64 KiB (the "absent" detection reads the
  start) and never fails the call by itself. Once the cap is hit that error wins over a
  time-out. The default time-out is still 60 s and a longer caller deadline does not extend
  it: long-running containers are started detached and polled.
- Known limit, unchanged: when a child exits while a descendant still holds its output pipe
  open, the call returns an error after the 2 s wait delay and the descendant is left running.

### 2026-11-18 — `internal/pgconf`

- Pure functions (no filesystem, network or process access; a test checks the imports)
  that render what a project's cluster and PostgREST containers start with:
  - `Overrides(gucs, memMB)` — the platform's override file: defaults merged with settings
    from `GUCAllowList` (`max_connections` 16–400, `shared_buffers` 16 MB to 40 % of
    `memMB`, `effective_cache_size` between `shared_buffers` and `memMB`,
    `cron.max_running_jobs` 1–32, `archive_timeout` 30–3600 s, `work_mem`,
    `maintenance_work_mem`). `memMB` is the cluster container's memory limit; the defaults
    need at least 384. Values are 1–64 bytes of `[A-Za-z0-9.]`; **a number starting with
    `0` followed by a digit or letter is refused** — the server reads such values as octal
    or hex. Names are case-sensitive.
  - `OverrideFile` (`zz-supapace.conf`) is the name the override file is written under: the
    server reads the image's include directory in byte order and a later file wins, so the
    platform's file must sort last. **Call `SortsLast` on the directory's file names before
    rendering.**
  - `CommandLine(imageConf)` — the `-c name=value` pairs that pin `hba_file`, `ident_file`
    and the three preload lists on the command line, read from the image's main file; a
    file in the include directory cannot move them. (`pg_settings.source` shows `override`
    for the two files and `command line` for the lists.)
  - `HBA(slice)`, `Ident()` — no `trust` line; the platform's roles cannot connect over
    TCP; the one `peer` line is the socket-only backup role.
  - `Supautils(image, outbound)` — the image's file with the backup role added to the
    reserved roles and, unless outbound access is enabled, the network-capable extensions
    removed from the privileged list. This is a product default, not a boundary. A test
    pins the image's full extension list so that an image bump forces a look.
  - `Passwd`, `Group` — the image's files with the `postgres` entry moved to the project's
    ids (the image needs an entry for the uid it runs as).
  - `PostgREST(c)` — its configuration; the password is percent-encoded byte by byte (the
    pinned PostgREST's parser treats `$` specially) and the connection string carries
    `require_auth=scram-sha-256`, which the pinned version honours: it sends no password
    to a server that asks for cleartext.
- Checked on the pinned images: every accepted boundary value passes `postgres -C`; a start
  with only rendered files takes all settings from the platform's file even with
  conflicting values planted in an image file. `postgres -C` validates one setting per run
  (several `-C` flags print nothing and still exit 0) and does not validate settings of
  preloaded libraries.
- The PostgREST container's command is `/bin/postgrest <config file>` (the image has no
  entrypoint).

### 2026-11-18 — `internal/nft`

- Renders, loads and checks the node's two nftables tables, keeps the bridge-netfilter
  switches off, and carries the systemd units.
  - `Render(cfg)` — the ruleset file; its only input is the gateway's platform address.
  - `Load(ctx, paths)` — one `nft -f` transaction that replaces only `inet supapace` and
    `bridge supapace`, then writes the checksum file, then turns the bridge-netfilter
    switches off (an error there is returned after the tables are in).
  - `Check(ctx, paths)` — `ErrAbsent` (a table is missing), `ErrDrift` (file or loaded
    tables differ from what was loaded), `ErrBridgeNF` (a switch is on), `ErrUnverified`
    (`nft` could not be run, failed or timed out). **Any non-nil error means the node is
    not verified.**
  - `EnsureBridgeNF()`, `Units()`.
- Rules, each findable by its comment (the label):
  - `inet` input: I1 replies to the host from the ingress bridge; I2 drop everything a
    bridge member sends to the host.
  - `inet` forward: F1 gateway replies; F2 drop everything routed out of a bridge; F3
    clients to the gateway's published ports; F4 drop everything routed into a bridge.
  - `bridge` forward (policy drop): B1, B2, B3 project bridges (ARP, replies, new
    connections to the cluster's port only); B4 platform ARP; B8 on the platform bridge
    only the gateway opens connections; B6 the rest of the platform bridge; **B9 a final
    explicit `drop`**.
  - B9 is not redundant with the policy: while a reload installs the chain, a few packets
    were seen to pass on the policy alone (1–4 of 50,000 connects under continuous
    reloads; none with B9). The `inet` table has no such window (its denials are rules).
  - There is no B5 or B7.
- The bridge chain drops on **every** bridge in the network namespace, also ones the
  ruleset does not name (other software's, Docker's default bridge): their members cannot
  reach each other while the tables are loaded.
- I2 alone keeps a bridge member off the host: a socket bound to the member's interface
  needs no route. Tests of host-input drops set `rp_filter` to 0 for their duration.
- Units: the tables unit runs before Docker, is reloaded with the distribution's nftables
  service and has no stop action (stopping leaves the tables); the daemon unit is tied to
  Docker's lifecycle and runs with `UMask=0077`, so **every file the daemon creates for a
  container needs an explicit mode**. The binary path `/usr/local/bin/supapaced` is fixed.
  The units are checked statically here; a node with systemd exercises them later.
- `internal/nft` tests tagged `reach` need a bare node and root
  (`go test -c -tags reach ./internal/nft`, copy the binary into the node). They take about
  6 minutes. **A killed run leaves the node dirty** (tables, scratch containers and
  networks, `rp_filter`); recreate the node rather than rerun.
- A caller that restarts with a newer binary must render again and compare with the
  installed file: `Load` loads the file as it is.

### 2026-11-18 — `internal/pgsock`

- The only way the daemon talks to a project's database server: the cluster container's
  Unix socket, opened by descriptor without following links, after checking that the peer
  is the container's init process the platform recorded (uid, pid and start time).
  **The database server is treated as untrusted.**
- API: `Dial(ctx, Target) (*pgx.Conn, error)`; `Target` (project directory, ref, uid,
  recorded process, role, password, `ScramSalt`, `AllowTrust`, `Superuser`, `Budget`);
  `Budget`/`DefaultBudget` (connect 5 s, statement 10 s, session 60 s, 4 MiB read in total,
  1 MiB per message, 64 parameter-status and 256 notice messages); `Stmt(ctx, budget)`;
  `IsBudget(err)`; `Clean(err)` and `*ServerError{Code, Message}`; `Sanitize`;
  `CheckEnv()`; `StartupParams(superuser)`; `ProcStart(pid)`; `ScramSalt(dek, ref, role)`
  and `ScramVerifier(password, salt)`. Sentinels: `ErrNotSocket`, `ErrPeer`,
  `ErrCleartextRequested`, `ErrNotScram`, `ErrScramParams`, `ErrBudget`, `ErrEnvironment`.
- Authentication: only SCRAM-SHA-256 with the salt and iteration count the platform fixed
  for that role (`ScramSalt` derives the salt; roles are created with `ScramVerifier`).
  A server that asks for a cleartext or MD5 password, or presents other SCRAM parameters,
  receives nothing derived from the password. `AllowTrust` is for the first boot only.
- Every session sends the fixed startup parameters of `StartupParams` (search path, role,
  timeouts, encodings and so on) — the single definition of that list.
- Bounds are enforced below the client library, on the 5-byte message header: a message
  over the cap is refused before its body is read. A statement is bounded in pipeline
  mode too.
- **Callers must**
  - build every `Target` with the role's salt from `ScramSalt` and handle its error;
  - start the daemon with no `PG*` variable in its environment and call `CheckEnv()` at
    start-up — `Dial` refuses to run while any is set;
  - run each statement under a context from `Stmt`, and test errors with `IsBudget`; after
    a budget error the session is finished: close it and retry the step with a new `Dial`;
  - pass every error from a statement, a rows iteration or a scan through `Clean` before
    logging, storing or returning it; the text of a `*ServerError` (`errors.As`) is the
    only server text available;
  - close the connection when the step ends, and after any error;
  - send plain, schema-qualified SQL, pass values as parameters, and treat every result
    (values, column names, command tags) as untrusted input.
- **Callers must not**
  - log, format or encode `conn.Config()` — it holds the password;
  - encode a `Target` with `encoding/gob` or `encoding/xml`, read its `Password` or
    `ScramSalt` in a template or log line, embed it in another struct, or hold it in an
    unexported field of a value that is formatted or logged (only fmt, slog and
    `encoding/json` are redacted);
  - keep, pool or reuse a connection across steps, share it between goroutines, hold it
    past the session budget, or rely on `IsClosed()` (it can stay false after a budget
    error);
  - use COPY, replication, function calls or `WaitForNotification`;
  - open any other connection to the cluster (`pgconn.Connect`, a pool,
    `pgx.ConnectConfig(conn.Config())`, a cancel request) or write through
    `PgConn().Conn()`;
  - take a successful `Exec` as proof that the statement ran: confirm effects with a typed
    read where it matters.
- Tests: `go test ./internal/pgsock/` runs without root; two tests need root and two need
  Docker (they start the pinned cluster image) and skip otherwise. A full pass takes about
  16 s, about 55 s with `-race`.

### 2026-11-18 — `sp-probe sys`, `--device`, hostile `fakepg` modes

- **`sp-probe sys`** prints `seccomp 0|1|2`, `nonewprivs 0|1`, `capeff <16 hex>`,
  `capbnd <16 hex>` (this process's status), then one line per call in a fixed order:
  getpid, unshare-user, keyctl, add_key, request_key, mount, bpf, perf_event_open,
  userfaultfd, io_uring_setup, kexec_load, init_module, open_by_handle_at, clock_settime,
  syslog, socket-icmp, socket-raw. Each call runs in its own short-lived, non-dumpable
  child with arguments that change nothing when allowed. Each line is `sys NAME VERDICT`:
  - `ok` — the call succeeded, or failed only in its own argument checks: it passed any
    seccomp filter and the capability checks made before those. For mount, bpf,
    perf_event_open, userfaultfd, io_uring_setup, open_by_handle_at and clock_settime this
    means "passed the filter", not "would succeed".
  - `errno 1 EPERM` — refused by a seccomp errno action or a missing capability;
    `errno 13 EACCES` for socket-icmp (`net.ipv4.ping_group_range`). An LSM refusal also
    reads as its errno.
  - `signal 31 SIGSYS` — refused by a seccomp kill-process action.
  - `unknown host SWITCH` — EPERM that a host-wide setting alone explains:
    `io_uring_disabled`; `unprivileged_bpf_disabled` (kernels before 6.5);
    `unprivileged_userfaultfd` (before 5.11); `unprivileged_userns_clone` — each counts when
    set and not overridden by a capability held, and as not set when unreadable. Only while
    CAP_SYS_BOOT or CAP_SYS_MODULE is held: `kexec_load_disabled`,
    `kexec_load_limit_reboot`, `lockdown`, `modules_disabled` — these count as set when
    unreadable (a container never sees the lockdown state).
  - `unknown …` — anything else: another errno, another signal, a child failure, or no
    answer within 2 s. A seccomp kill-thread action (`SCMP_ACT_KILL` in a Docker profile)
    reads `unknown timeout`.
  - A verdict holds for the probed arguments only; unshare-user probes
    `clone(CLONE_NEWUSER)`. Exit 0 once every line is printed; exit 3 with one `error …`
    line on a usage error or an unreadable status file.
- **Consumers of `sys`:**
  - "nothing but getpid succeeds" means every other line is not `ok`;
  - "refused by the sandbox" may be claimed only for `errno …` and `signal 31 SIGSYS`;
    `unknown host …` says nothing about the sandbox;
  - lines required to differ between a confined run and its unconfined control must read
    `errno 1 EPERM` or `signal 31 SIGSYS` confined and `ok` in the control; any `unknown …`
    there fails the test, with the line as the diagnosis.
- **`sp-probe tcp|udp HOST:PORT --device IFACE`** binds the socket to IFACE
  (`SO_BINDTODEVICE`) before it connects or sends, also for multicast and broadcast
  targets, so the probe leaves by that interface whatever the routes say. Usage error
  (exit 3) when the name is empty or longer than 15 bytes, or with any other subcommand.
  A failing setsockopt (no such device; a missing CAP_NET_RAW only before Linux 5.7) reads
  `error … SO_BINDTODEVICE IFACE: setsockopt: …`, exit 3. From a member of a bridge the
  node has no route back to, a bound probe to a node address times out whatever the
  firewall does: such a probe needs a control on the same path to mean anything.
- **`sp-probe fakepg --socket PATH --log FILE [--mode MODE] [--password-file F --salt HEX]`**
  — a fake, untrusted Postgres backend on a Unix socket.
  - Before it binds: a stale socket at PATH (a connect to it is refused) is removed. A live
    socket (a connect succeeds; that server sees one connection that sends nothing), any
    other file, or a socket that cannot be tried makes it fail with exit 3. **Start one
    fake per path at a time.**
  - `conn N` numbers accepted connections, and a connection that sends nothing leaves no
    record: count connections by records and read the log by `LEN`.
  - On SIGTERM or SIGINT it exits 0 and removes its socket only if PATH still holds the
    socket it bound. It reaps nothing, so it can run as a container's init.
  - It declines SSL and GSS encryption requests and never closes a connection first. What a
    mode streams stops after 1 GiB per connection; the connection is then held.
  - Modes before authentication (a client never authenticates): `sasl` (default, the
    request then nothing), `cleartext`, `md5`, `authok` (AuthenticationOk without any
    exchange; queries get no answer), `sasl-iter` (a server-first message with the `--salt`
    salt, which it requires, and ten million iterations), `huge` (a header announcing 1 GiB,
    then its body),
    `flood` (ParameterStatus and NoticeResponse without end), `stall` (nothing), `trickle`
    (the SASL request, one byte per second).
  - Post-authentication modes need `--password-file` and `--salt`; `sasl-iter` needs `--salt`
    alone; both flags are refused for every other mode. The post-authentication modes
    complete a real SCRAM-SHA-256 exchange with that password, that salt and
    4096 iterations, then answer a simple Query, or the Sync of an extended batch:
    `row-huge` (a DataRow announcing 64 MiB), `rows-endless` (1 KiB DataRows without end),
    `stall-auth` (no reply), `escapes` (notices and an error whose message, detail and hint
    carry terminal escape sequences, control bytes and invalid UTF-8; every such field
    starts with `fake-marker`).
  - Put the fake's log on a size-limited tmpfs in tests that run the endless modes.
- A plain client library, pointed at these modes without the bounds of `internal/pgsock`,
  sends the password on `cleartext`, logs in on `authok`, allocates the announced size on
  `huge` and `row-huge`, and otherwise waits for its own timeout.
- `go test ./cmd/sp-probe/` installs seccomp filters in its own children; one case uses a
  kill-process action. The test first checks that the child is non-dumpable and stops
  before installing any filter if it is not, so a regression cannot run the host's crash
  handler. One `--device` test row needs IPv6 on the host.

### 2026-11-18 — reach suite: containment tests

- New tests in `test/reach` (tagged `reach`): cluster egress (03), unknown bridges (04),
  boot, restart and reload (05, with `TestReach05_AfterReboot`), container posture and the
  search for secrets (06), the platform bridge (16) and upstream responses (17). The
  gateway-limits test (17) now expects the gateway's 60 s read timeout.
- Helpers that need no daemon are in the untagged `imagectr_test.go` with self-tests, so
  `go test ./...` covers them.
- Running: `make build`, then `make reach` on a node from `make node-up`
  (`REACH_ARGS='-test.run …'` to select); `make reach-reboot` after the node has run the
  suite once, so that the fixture projects predate the boot — it passes
  `SUPAPACE_REBOOT=1`, under which the after-reboot test fails instead of skipping;
  `make reach-host` on a host prepared by `scripts/install-node.sh`. `node_reach` in the
  Makefile takes extra `docker exec` options as its second parameter.
- **Every negative has a control on the same path:**
  - a rule is shown to be the barrier by deleting it by its comment (`withRuleDeleted`) on
    a scratch bridge of the same class that has the route or host address the real one
    lacks; routed paths need both forward drops deleted before anything connects;
  - unknown bridges: the tables are deleted, with a receive counter in the routed
    neighbour's namespace, so a one-way leak fails;
  - the platform bridge: its one drop rule deleted;
  - posture: scratch containers of the real image with the real flags minus one (seccomp
    unconfined; uid 0 with default capabilities; no ping sysctl; health check kept; host
    IPC).
- Topology is asserted before any sweep: each container's networks and addresses must be
  exactly the expected set, and the sweep's expected verdicts come from that set.
- The search for secrets covers every bind and tmpfs mount resolved through the
  container's own links (each root must yield a file; a walk error fails), the environment
  and command line of every process in the container, and the configured command,
  environment and labels — for the cluster and the PostgREST container. Its control is
  finding the project's own key.
- Posture by `sp-probe sys`: getpid must be `ok`; every other call refused or
  `unknown host …`, never another `unknown`; in the unconfined control the compared calls
  must flip to `ok`. IPv6 must be disabled in the cluster and PostgREST containers.
- **Drift hold:** every section that creates a scratch network, a bridge member or a
  foreign member of the platform bridge takes the hold before the first object exists and
  releases it after the last is removed. No test writes `rp_filter`.
- **Reset** (Makefile, before and after every run, and `TestMain`): removes the failpoint,
  reloads the tables, removes labelled containers with their volumes and labelled
  networks, kills left-over listeners started from the suite's binary directory, deletes
  the neighbour link and the second source address, and drops the drift hold **last**.
  It is safe to run twice and on a clean node. After a timeout or a kill, the hold stays
  until this reset.
- Checked so far only against a stand-in (a bare node with the real ruleset, images and
  container flags): tests 03, 04 (the half without the daemon), 06 and 16. Everything that
  needs the daemon, the CLI, the gateway or a real project is unexercised until those
  exist.

### 2026-11-18 — `supapaced init`, `supapaced nft`, `scripts/install-node.sh`

- CLI: `supapaced init --domain D [--dev] [--no-systemd] [--ack-escrow]
  [--tls-cert F --tls-key F]`; `supapaced nft load|check`. `cmd/supapaced/main.go` holds
  only the command map and the dispatcher; each subcommand registers itself from its own
  file, so a new subcommand is a new file.
- Exit codes: 0 success, 1 failure, 2 usage; `nft load|check` also 3 (a table is absent),
  4 (drift: the file or the installed tables differ from the last load), 5 (a
  bridge-netfilter switch is on), 6 (not verified: `nft` could not run, failed or timed
  out). Errors are one line on stderr.
- `init` runs as root and offline (no Docker, no database). It checks every input before
  writing, writes atomically and skips unchanged files: a second run changes nothing. It
  refuses an invalid domain; a `node.json` that does not load or names another domain; ids
  of the reserved range in passwd, group, subuid or subgid; a `daemon.json` holding any
  other key or value (it prints the merged document to apply by hand); a link at a unit
  path (a masked unit); an `/etc/supapace`, `tls/` or `ca/` that is not a root-owned 0700
  directory; an operator certificate that does not match its key, does not cover a project
  host of the domain, has expired, is not yet valid, or has an extended key usage without
  serverAuth. An empty or subset `daemon.json`, or one not root 0644, is rewritten with
  exactly init's settings.
- Files: `/etc/supapace` (0700) with `node.json`, `nftables.nft`, `nft.sha256` (written by
  `nft load`), `kek.escrowed`, `dev-mode` (all 0600) and `kek` (0400); `tls/cert.pem`,
  `tls/key.pem` (0600); with `--dev`, `ca/ca.key` (0400) and `ca/ca.pem` (0644);
  `/etc/docker/daemon.json` (address pool, `ipv6: false`, the `local` log driver; **no**
  `userland-proxy`, `icc` or `live-restore` key); unless `--no-systemd`, the three unit
  files of `internal/nft`. Temporary files left by an interrupted write are removed at the
  start of the next run, by exact name pattern; a link is unlinked, never followed.
- **Escrow rule.** The key-encryption key is generated once and never replaced. Its text is
  shown on every run until the marker `kek.escrowed` exists — decided by the marker, never
  by the key file. The marker is written only after the text was written to standard
  output and acknowledged, by the typed word or by `--ack-escrow`. `--ack-escrow` is
  refused when standard output is the null device (a closed standard output counts). A
  failed write ends with exit 1 and no marker; the next run shows the same key. With the
  marker present the key file must be a regular file, 0400, 32 bytes, root-owned;
  otherwise init refuses and never makes a new key.
- **Development mode** is fixed at the first init, like the domain: `--dev` on a node set
  up without it, and a run without `--dev` on a development node, are refused before any
  write. `--dev` refuses the TLS flags and issues a CA that is name-constrained (critical)
  to the node's domain and the gateway's ingress address, plus a server certificate for
  `*.<domain>` and that address, valid 825 days and issued again from the same CA whenever
  the pair cannot be loaded or expires within 30 days. The `dev-mode` marker makes
  host-global node checks informational.
- `scripts/install-node.sh --domain D (--dev | --tls-cert F --tls-key F) [--ack-escrow]`,
  as root: requires systemd, Docker and `nft`, and the projects filesystem mounted (the
  topmost mount) at `/var/lib/supapace/projects` as XFS with user-quota enforcement
  (`usrquota` in `/proc/mounts`) and project accounting (`prjquota` or `pqnoenforce`). It
  writes the modprobe block that keeps `br_netfilter` from loading and
  `kernel.core_pattern = core`, installs the binaries to `/usr/local/bin`, runs `init`,
  enables the units, restarts Docker and ends with `supapaced nft check`. It is safe to
  rerun and refuses the no-systemd flag. **Do not run it on a host before the daemon binary
  provides `serve`**: the daemon unit is pulled in by Docker's drop-in.
- Not verified until a host with systemd: unit ordering on boot and on a Docker restart,
  reload propagation from the distribution's nftables service, the modprobe block and
  `core_pattern` across a reboot, socket activation of Docker, the typed acknowledgement
  from a terminal, and exit code 5 end to end. The script's tests run it against a scratch
  root with stand-ins for `supapaced`, `systemctl`, `sysctl`, `dockerd` and `nft`.

### 2026-11-18 — `internal/adminapi` and `cmd/supapace`

- The node's admin API: JSON over HTTP, to be served by the daemon on its root-only Unix
  socket. `New(st *store.Store, kek secrets.KEK, ops Ops) http.Handler`; `NewRef()` returns
  20 characters of `[a-z0-9]` from `crypto/rand`. **This package owns ref generation and
  the output contract.**
- Routes: `POST /v1/projects` (the API inserts the project and its `create` operation
  itself), `GET /v1/projects`, `GET /v1/projects/{ref}`, `GET /v1/projects/{ref}/keys`,
  `POST /v1/projects/{ref}/check`, `POST /v1/projects/{ref}/restart`,
  `DELETE /v1/projects/{ref}`, `POST /v1/projects/{ref}/purge`,
  `POST /v1/projects/{ref}/abort`, `GET /v1/operations[?ref=REF]`,
  `GET /v1/operations/{id}`, `POST /v1/operations/{id}/retry`, `GET /v1/node/check`. Any
  other path, or a path that is not clean, answers a JSON `not_found`.
- A mutation answers 202 `{"ref","operation_id"}`; reads answer 200. Every body is one JSON
  document and a newline; timestamps are RFC 3339 UTC to the second; lists are `[]`, never
  `null`. While `Ops.ContainmentOK()` is false every mutation answers 503
  `containment_failed`; reads, `check` included, are served.
- Codes: `bad_request` (400; 413 for an oversized body), `bad_ref` (400), `ref_exists`
  (409), `not_found` (404), `conflict` (409, with the reason), `containment_failed` (503),
  `internal` (500, always the fixed message `internal error`; the error itself is logged
  once with `log/slog`, sanitised and capped — the daemon must set the default handler).
- Requests: at most 128 KiB, decoded strictly (one JSON object, no unknown members, no
  trailing data); routes that take no body refuse one.
- Limits: name `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`; issuer key set parsed by
  `jwtx.ParseJWKS`, 1 to 16 usable keys; user roles at most 16, not
  `jwtx.ForbiddenUserRole`, default `authenticated`; `disk_quota_mb` 1024 to 16777216,
  default 8192; cluster memory fixed at 512 MiB. Text from elsewhere is sanitised with
  `pgsock.Sanitize`: `message` and `last_error` at most 1 KiB, drift and node-check
  `detail` 256 bytes, at most 64 drift rows.
- `check` is served only for `active` or `restarting` projects (`conflict` otherwise) and
  answers `{"ok":true,"drift":[]}` or `{"ok":false,"code":"peer|timeout|internal",
  "message":…,"drift":[{"name","detail"}]}`.
- **Operation parameters the worker must honour:**
  - `create`: `{"issuer_jwks":{"keys":[…]}}` in `jwtx.MarshalJWKS` form, already validated;
    the project row carries the configuration and the user roles.
  - `restart`: `{"base_generation": N, "config": {"disk_quota_mb","mem_mb","guc"}}` —
    `config` is the complete target configuration, validated with `pgconf.Overrides`, and
    N is the project generation it was merged onto. A restart whose `base_generation` is
    no longer the project's generation when it is admitted must be refused with a
    conflict, so two restarts merged from the same base cannot drop each other's settings.
  - `delete`: no parameters. Purge: the API calls `store.SetPurgeNow` and answers with the
    id of the ref's single purge operation.
- `Ops` (implemented by the daemon; a fake in the tests): `Submit(ctx, kind, ref, params)`
  for `restart` and `delete` — a wrapped `store.ErrConflict` is shown as `conflict` with
  its reason, anything unexpected as `internal`, so its errors must carry no secrets;
  `Abort(ctx, ref)` returns the create operation's id and is idempotent while aborting;
  `VerifyProject(ctx, ref)` returns a code (`""`, `peer`, `timeout`, `internal`), a message
  and the findings; `NodeCheck(ctx)`; `ContainmentOK()`.
- `supapace` (the operator's client) parses arguments, makes one call on the admin socket
  and, for a mutation, polls its operation every 500 ms until it is `done`, `failed` or
  `aborted`, unless `--no-wait`. Commands: `project create|list|show|keys|check|restart|
  delete|purge|abort`, `op list|show|retry`, `node check`; flags may come before or after
  the positional argument; `help`, `-h`, `--help` print the usage (stdout, exit 0).
  - **stdout holds exactly one JSON document — the body of the last API response received,
    byte for byte — or nothing.** Progress, summaries and hints go to stderr.
  - Exit status: 0 success; 1 an API error, an operation that ended `failed` or `aborted`
    (for `project abort`, `aborted` is the success), a check with `"ok": false`, or an
    unreachable daemon; 2 usage; 130 interrupted.
  - Polling tolerates an unreachable daemon for 2 minutes, then prints the last body and
    says that the operation continues. Mutations handle SIGINT and SIGTERM from their
    first request on: before the answer, stdout is empty and stderr says the request may
    already have been accepted; while polling, the newest body is printed. Reads keep the
    default signal behaviour.
- Tests in both packages start a throw-away control-plane database with Docker and skip
  without it. The limits quoted in the usage text and in the API's messages are pinned by
  tests against `jwtx` and `pgconf`.

### 2026-11-18 — `internal/bootstrap`

- Prepares a project's cluster once, at its first boot, and later reports where a running
  cluster differs from what the platform expects. **The database server is treated as
  untrusted**: what the checks report is drift for that project, never a guarantee, and every
  value read from the server is bounded and sanitised before it reaches a finding.
- API: `LoadBaseline() (Baseline, error)` (the embedded, strictly parsed baseline of the pinned
  image); `Run(ctx, conn, Secrets) error`; `Assert(ctx, conn, Baseline, renderedConf []byte)
  ([]nodecfg.CheckResult, error)`; `AssertHBA(ctx, conn, renderedHBA []byte)
  ([]nodecfg.CheckResult, error)`; `ErrAssertion`. `Secrets` holds the three platform passwords,
  the pgsodium root key and `ScramSalts` (role → salt from `pgsock.ScramSalt`).
- `Run`, in order, each step idempotent (a run cut short is repeated on a new session):
  1. the passwords of `supabase_admin`, `postgres` and `authenticator` (three distinct values)
     are set as SCRAM-SHA-256 verifiers computed here with the role's salt and 4096
     iterations — no password reaches the server;
  2. `supabase_realtime_admin` (NOLOGIN NOINHERIT) and `supapace_backup` (LOGIN, no other
     attribute, NOINHERIT) are created if absent; `supapace_backup` gets
     `pg_read_all_settings` and EXECUTE on the four backup functions;
  3. as `supabase_auth_admin`, `auth.uid()`, `auth.role()`, `auth.email()` and `auth.jwt()`
     are defined: plain SQL, stable, no SET clause, not security definer, every function,
     type and operator written `pg_catalog.`-qualified and no construct that looks an operator
     up by name, so a caller's search path cannot change the result and the planner still
     inlines them. Each reads the per-claim setting first, then the JSON claims. The session
     role is reset afterwards, also after an error.
- `Assert` and `AssertHBA` read with plain, schema-qualified SQL only. Each returns one
  `OK:false` row per difference — `Name` from a frozen set, `Detail` sanitised and at most 256
  bytes, at most 32 rows per check plus one "further findings omitted" — and nothing when the
  cluster matches. The error is reserved for a failed session or query.

  - `presence`: a required role or one of the schemas `auth`, `extensions`, `realtime`,
    `storage` is absent
  - `superuser`: the set of roles with the superuser attribute differs from the baseline
  - `attributes`: one of the seven compared attributes of a baseline role (except `postgres`)
    or of a platform role differs
  - `memberships-reserved`: a membership held by a platform role differs from the baseline
    (plus the one bootstrap grants)
  - `memberships-dangerous`: a membership in a platform role or a server-file role is not
    in the baseline
  - `role-settings`: the settings of a platform role differ from the baseline (compared as
    sets), or one has per-database settings
  - `schema-acl`: `auth`, `storage` or `realtime`: absent, other owner, a baseline entry
    missing or changed, or an extra entry granted by the baseline owner or a platform role
  - `event-triggers`: the event triggers owned by a superuser, other than extension members,
    differ from the baseline
  - `auth-functions`: an auth helper function is absent, has another owner or body, is
    security definer, or `authenticated` may not execute it
  - `configuration`: a setting of the platform's override file is not in force from that
    file at its line, is not a setting of the cluster, or a line of the file is not a setting
  - `source-file`: a setting is in force from, or written in, a file outside the image's and
    the platform's files (one finding per setting and file), or the command-line settings
    or the pinned `hba_file`/`ident_file` differ
  - `hba`: the rules in force differ from the rendered `pg_hba.conf`, or a rule has an error
  - `service-passwords`: one of the six service roles has a password

- Not reported, by design: access entries on those schemas granted by any other role (a
  role holding a grant option); event triggers owned by a role without the superuser
  attribute; per-database and per-role setting values; the project's own roles, schemas and
  extensions.
- The grantor of an access entry is read by parsing the entry from its start as the server
  writes it (quoted names, doubled quotes, an empty grantee for PUBLIC); text not in that form
  has no grantor.
- **Callers must**
  - call `Run` only in the first-boot phase, before any project credential exists, on a
    session from `pgsock.Dial` as `supabase_admin`, and close the session afterwards;
  - treat findings as blocking only at create; afterwards they are a drift list;
  - pass the platform's rendered override file and `pg_hba.conf` bytes exactly as written;
  - follow the caller rules of `internal/pgsock` (one session per step, close after any
    error, every error through `pgsock.Clean`, `IsBudget` for bounds).
- **Callers must not** rely on any finding — or on its absence — as a security property of
  the project.
- Every statement is a constant run under `pgsock.Stmt`; values travel as parameters. The one
  exception, a password statement completed with a checked verifier, is enforced by
  `verifierStatement` (only the package's three password statements, only a well-formed
  verifier) and a static test.
- Known limits: a check reads every line of every configuration file through
  `pg_file_settings`. An include of a FIFO makes the check end in the budget error and leaves
  one server process of that project waiting for each check. An include of a very large file
  can exhaust that project's server memory and end the check in a session error. Both affect
  only the project whose files they are; run the drift check at a bounded rate.
- Tests: the Docker-backed tests start the pinned cluster image (skipped without Docker or the
  image); about 50 s with `-race`. As root they run the server at an unprivileged project uid.
  `TestAssert_NamesAreFrozen` fixes the check names; `TestAssert_AllowListMatchesImageFixture`
  ties the source-file allow-list to the image fixture.

### 2026-11-18 — reach suite: cluster and saga tests

- New tests in `test/reach/cluster_test.go` (tagged `reach`): the image's own refusals and
  the platform's drift report (07, `7a_image_parity`, `7b_bootstrap`); socket and loopback
  rules, a planted link, a fake backend in the container and a container whose init is a
  fake backend (09, `socket_replaced`), and per-project secrets (09); outbound extensions
  off by default (10); refs (11); disk and inode quota with a log flood (13); resumable
  creates, queueing, retention, identity release, purge of a hostile tree and a restart
  against an include of a FIFO (14); the route and adoption half of test 16.
- Helpers that need no daemon are in the untagged `clusterhelp_test.go` (self-tests in
  `clusterhelp_self_test.go`, `!reach`): the check document and drift names, the fake
  backend's log read by its LEN fields, the messages a client sent it, the expected
  verdict of each fake mode, the user quota report, the agent's state file, a log bound
  and tail, a tree count by descriptor, and background steps (`repeatWhile`,
  `inBackground`). `sqlAs` reaches the administrative role over the socket (its loopback
  line rejects).
- Rules for later tests:
  - Results are read as the CLI's JSON documents and codes, and drift by its check name.
  - Quota verdicts come from `xfs_quota`'s report, never from shell text. Fills run in a
    separate container of the cluster image at the project's uid.
  - A log bound is checked as configured (under 31 MiB) as well as stored. Rotated files
    are compressed. Docker's data root is read from `docker info`.
  - The fake backend is started one per socket path, and the test waits for `listening`.
    "No connection" means "received no bytes".
  - Anything placed in a project (fake, password file, canaries, fills) is removed in
    cleanup. Every command has a deadline.
  - A step run beside the test (`inBackground`) is waited for on every exit path, within
    a bound longer than its own deadline.
  - A container of A or B that a test stops is brought back with `project restart`, never
    `docker start`, in cleanup and at the start of test 16.
  - A's settings that a test changes are reset at the start as well as in cleanup.
- Fixture setup: before removing a scratch project an earlier run left `restarting`, the
  setup removes the include of a FIFO from its `postgresql.auto.conf`, through a
  container of the cluster image at the project's uid (`dropFifoInclude`). The restart can
  then be retried and the project deleted and purged. The suite reset is unchanged.
- Exercised so far only against stand-ins in a bare node (a cluster container of the
  pinned image with the platform's flags and rendered files, quota on the node's XFS, a
  check made with `pgsock` and `bootstrap`): 07, 09 (socket rules and the three fakes'
  verdicts), 10, 13 (fills and flood) and the hostile tree of 14. Everything that needs
  the daemon is unexercised until it exists: creates, restarts, purge, failpoints, the
  gateway, and tests 11 and 16. The log-line half of 14's control-character check waits
  for the harness to keep the daemon's output.
- Found while proving the hostile tree of 14: the shell tools of the cluster image walk by
  path and cannot remove a tree nested deeper than a path can name. The purge and wipe
  tasks therefore must not rely on them; the test stays red until they remove by
  descriptor.

### 2026-11-18 — `internal/agent`: core, start gate, platform objects, node check

- `Spec` is a project's desired state as the agent applies it: ref, epoch, generation, uid/gid,
  subnet index, quota, memory, pids, settings, user roles, secrets, keys and `HealthWait` (zero:
  120 s; negative: do not wait). Its `String` prints no secrets.
- `State` is `state.json`: root 0600, written atomically. It must be exactly one state with
  phase `A-done` or `B` in at most 4096 bytes; null, an unknown field or phase, trailing data, a
  larger file or a link is an error, and an unknown phase is refused on write. `checkState`
  returns `ErrEpochDivergence` for another epoch and `ErrStaleGeneration` for an older
  generation in the same epoch.
- `Agent`: `New`, `SetContainmentFailed`/`ContainmentFailed`, `EnsureImageFiles`,
  `EnsurePlatformNetworks`, `EnsureControlPlaneDB`, `EnsureGateway`, `NodeCheck`, `EnsureDir`,
  `SetQuota`, `EnsureNetwork`, `RemoveNetwork`, `RemoveRender`, `CheckContainment`,
  `CheckAdopted`, `StopAllTenants`. Errors: `ErrContainment`, `ErrStaleGeneration`,
  `ErrEpochDivergence`. All idempotent.
- Every Docker, `ip`, nft and root-side file call goes through a package-level function value in
  `agent.go`: `dockerRun`, `dockerRunInput`, `dockerInspectContainer`, `dockerInspectNetwork`,
  `dockerListContainers`, `dockerServerVersion`, `nftCheck`, `ensureBridgeNF`, `runIP`,
  `createProjectDir`, `setQuota`, `writeFile`, `chown`.
  - `agent_test.go` replaces them all with the recording fake `fakeDocker(t)`. It logs every
    call and keeps a small model of containers (network mode included, `container:<x>` recorded
    by full id), networks (IPv6 flag included) and images.
  - Like Docker, it resolves a full id before a name and refuses: removing a running container
    without `-f`, removing a network with running members, connecting twice or to an absent
    network, killing a stopped container, starting a second running holder of an address.
  - Unmodelled verbs and formats are test errors; script them with `onRun`. Fail a call with
    `failVerb`/`failInspect`; read the log with `calls`/`argv`/`mutations`.
  - Fixtures: `newTestAgent`, `healthy`, `tenants`, `gateRefuses`, `goodNode`, `rows`,
    `writeTLS`, `writeSeccomp`.
  - `TestMain` (umask 0077) lives there; no other test file may define one.
- **Start gate** (`CheckContainment`, called immediately before every run or start of a tenant
  container). It refuses with `ErrContainment` unless:
  1. the bridge-nf switches are off and `nft.Check` passes;
  2. `proj-<ref>` is internal, has IPv6 off, sits on bridge `spp<i>` with the slice as subnet
     and isolated gateway mode, and the interface itself is a bridge holding no address but IPv6
     link-local ones;
  3. `platform` is internal, has IPv6 off, sits on `spl0`, isolated, with its interface as in 2;
     and no running container but `postgrest-<ref>` holds `PlatformAddr(i)`, which that
     container, if attached, holds exactly;
  4. neither tenant container has a restart policy or uses the host's or another container's
     network namespace;
  5. the node is not containment-failed;
  6. every member of the project, platform and ingress networks, both tenant containers, and
     every container sharing the network namespace of one of them (in turn) or of the host is
     unprivileged, drops every capability and adds none.

  Members are read by their endpoint ids and every configuration by id, never by name. Only
  host-side facts are read: Docker's record of container configuration (`docker container
  inspect --format`, bounded and strictly parsed), network membership, interfaces and the
  firewall state; never a tenant process or a database answer. Every error is a refusal. A
  member that disappears between listing and reading is skipped. `CheckAdopted` is conditions 2
  to 6, for a running container being adopted.
- A container start that fails with "Address already in use" is a containment refusal, never a
  transient error. Docker frees a stopped holder's address and refuses a second running holder,
  so the gate judges running holders.
- **Node requirements:**
  - no container on the node runs in host network mode, or shares another container's network
    namespace, unless it drops every capability and adds none; otherwise every tenant start is
    refused, even while that container is stopped;
  - the projects file system is XFS with user-quota enforcement and project-quota accounting;
  - `br_netfilter` is blocked from loading.
- **Node check rows** (blocking unless marked):
  - `nft`;
  - `docker-version` ≥ 26.1.3;
  - `daemon.json`: our address pool, `ipv6:false`, the `local` log driver with size limits, no
    `userland-proxy` or `icc` key, no network with inter-container traffic off;
  - `live-restore` off;
  - `docker-seccomp`;
  - `docker-networks`: only the platform's networks and Docker's defaults; drivers bridge, host
    or null; no macvlan or ipvlan interface besides the uplinks;
  - `uplinks`: exist and are not bridges;
  - `quota-accounting`;
  - `quota-enforcement`: live XFS state of the projects mount;
  - `ptrace_scope` ≥ 1;
  - `kek`: root, 0400, 32 bytes;
  - `platform-members`: members read by id; only the gateway at its address and each project's
    PostgREST at its own platform address, each dropping every capability and adding none;
  - `core_pattern`, `br_netfilter`, `file-max` ≥ 2^30: informational on a node carrying the
    development marker;
  - informational always: `docker-firewall-backend` and `drift-hold` (with its age).
- **Platform objects:**
  - `platform` (internal, isolated, Docker allocating only from the platform range) and
    `ingress`, both with IPv6 off; an existing network with other options is a refusal;
  - `sp-cp-db`: no network, uid 70, read-only, peer authentication over the mounted socket,
    access files rendered root 0444 through the shared atomic writer;
  - `sp-gateway`: uid 65531, read-only, 768 MiB, 256 pids, explicit IPv4 publications, fixed
    addresses on both networks, TLS key copy 0400 owned by 65531, the development CA never
    copied;
  - both run with `--cap-drop ALL`, no-new-privileges, `core=0` and the embedded seccomp profile
    (Docker's default profile for the pinned release, with its NOTICE; written 0444 at every
    `EnsureImageFiles`, which must run first);
  - **configuration label.** Each carries `supapace.config`, a SHA-256 over its arguments and
    what it takes at create or start, as now on disk or in the image store: the seccomp profile
    (both), the control-plane access files, and the gateway's certificate (never the key) and
    the image id its tag names. No secret is included.
    - A missing or different label means re-creation: a running control-plane database is first
      stopped with the server's grace period, and its data stays in the mounted directory.
    - An unreadable input is an error, never an adoption;
  - the cluster image's `passwd`, `group`, `supautils.conf`, `conf.d` and `postgresql.conf` are
    taken once per image digest, through a container that is created, never started: regular
    files only, 1 MiB each, no duplicates.
- `StopAllTenants` disconnects every running cluster and PostgREST container from its networks
  and kills it, all in parallel, waiting on no tenant.
- `ip` output is bounded (16 MiB; a larger answer is killed and refused).
- **Caller rules:**
  - no Docker call between the gate and the start it guards;
  - map "Address already in use" at start to a containment refusal;
  - run `EnsureImageFiles` before `EnsureControlPlaneDB` and `EnsureGateway`.

- Known limits: a platform container that is found stopped is removed with `rm -f`, and the
  gateway is re-created with `rm -f` (in-flight requests are cut); a re-creation that fails
  leaves the platform container absent until the next ensure, with the control-plane data
  intact.

### 2026-11-18 — `internal/agent`: PostgREST container and route file

- PostgREST and the route file (`postgrest.go`, `route.go`):
  - API: `EnsurePostgREST(ctx, spec)`, `StopPostgREST(ctx, ref)` (stop -t 10, rm; nil when
    absent), `RouteFor(spec, state)`, `SetRoute(ctx, ref, *routes.Project) (generation)` (nil
    removes), `DrainAllRoutes(ctx) (generation)`, `GatewayGeneration(ctx)`,
    `ProbeREST(ctx, ref, anonToken)`.
  - Rendered files in `platform/projects/<ref>/postgrest/` (root 0755): `jwks.json` (root 0444;
    only keys `jwtx.KeyFromJWK` accepts, a nil key or modulus refused; serialised with
    `MarshalJWKS`, parsed back and compared key by key and byte for byte before the rename) and
    `postgrest.conf` (0400, uid 65532; the only place the authenticator password is written).
    Both are replaced by rename inside a directory mount, so a running container sees each new
    file at its next reload; every file is valid the instant it is renamed.
  - Container: `docker create --name postgrest-<ref> --user 65532:65532 --cap-drop ALL
    --security-opt no-new-privileges --security-opt seccomp=<platform>/seccomp.json --read-only
    --memory 256m --memory-swap 256m --pids-limit 64 --ulimit core=0 --ulimit nofile=65536:65536
    --no-healthcheck --ipc private --sysctl net.ipv4.ping_group_range="1 0"
    --sysctl net.ipv6.conf.all.disable_ipv6=1 -e GHCRTS=-N2 --network proj-<ref>
    --ip <slice base+3> -v <render>/postgrest:/etc/postgrest:ro <labels> -- <image>
    /bin/postgrest /etc/postgrest/postgrest.conf`, then `docker network connect --ip
    <PlatformAddr(index)> -- platform postgrest-<ref>`, the start gate, `docker start`. No restart
    policy; nothing secret in argv or environment. The pids limit must stay at least `db-pool` + 15.
  - When the gate refuses after create and connect, or the start fails with Docker's `Address
    already in use` (`ErrContainment`, never a transient error), the created container is removed
    with `rm -f` on a fresh bounded context; a removal error is joined to the refusal, which stays
    matchable.
  - Labels: `supapace.role=postgrest`, `.ref`, `.generation`, `.epoch`, `.image` (the configured
    image reference, `name@sha256:<digest>`) and `supapace.config`: the platform containers' hash
    over the create arguments (without this label), `--`, image and command, then
    `postgrest.conf sha256=<hash of postgrest.conf as written>` and the digest of the seccomp
    profile as on disk. `jwks.json` is not covered. An unreadable profile is an error before any
    Docker change.
  - Adoption: a running container whose labels all equal the desired values, attached to exactly
    two networks, at `PlatformAddr(index)` on `platform` and base+3 on its project network, is
    adopted after `CheckAdopted`; when that fails it is stopped and removed. Anything else under
    the name (stopped, created only, other labels, arguments, configuration, profile, addresses,
    networks, or another generation older or newer) is removed with `rm -f` and created again.
  - Addresses are computed from the subnet index (`nodecfg.PlatformAddr`), never read from Docker.
  - Route file `platform/gateway/routes.json` (root 0444), written by `nodefs.WriteFile` under an
    in-process lock shared by `SetRoute` and `DrainAllRoutes`. Every write increments the
    generation. When there is no parsable previous file the counter starts from the larger of the
    wall clock in milliseconds and the last generation this process wrote, so it stays above
    values handed out before a loss, also when the clock stepped back or the file was lost twice
    within a millisecond. `SetRoute` refuses a state other than active/draining, an upstream that
    is not `http://<a platform address>:3000` or that another entry already uses, a key
    `KeyFromJWK` refuses or whose kty is not RSA, a duplicate kid within the entry, and anything
    `routes.Marshal` refuses; a refused call leaves the file as it was. A file that does not parse
    is never overwritten by `SetRoute`; `DrainAllRoutes` replaces such a file with an empty table
    (every entry is rebuilt from the store). A route file that exists but cannot be read for
    another reason (not a regular file, an I/O error) fails both.
  - Activation: before taking the lock, `SetRoute` with state `active` reads `proj-<ref>` from
    Docker, takes the slice index from its bridge name, checks the network's options and subnet,
    and requires `rest` to be exactly `http://<PlatformAddr(index)>:3000`; a failed read or a
    mismatch is a plain error. Draining and removal read nothing. Under the lock, an `active`
    entry is refused with `ErrContainment` while the node is containment_failed; the flag is read
    under the same lock as the drain, so "set the flag, then drain" cannot be undone by a
    concurrent activation.
  - Probes dial only `gateway_ingress_ip:8443` and trust exactly the leaf certificate in
    `gateway/tls/cert.pem` (byte comparison, no chain check); the gateway is re-created when that
    certificate changes, so the pinned file and the served certificate agree. No redirects,
    response headers at most 64 KiB, 10 s per probe, no connection reuse. `ProbeREST` sends
    `GET /rest/v1/` with host and TLS server name `<ref>.<domain>` and the token as `apikey`, and
    reads the status line only (200 is success). `GatewayGeneration` reads `/-/health` (200, at
    most 4 KiB, strict JSON with a generation).
  - Caller rules: give `SetRoute` `RouteFor(spec, state)`; set the containment flag before
    `DrainAllRoutes`; run `EnsureCluster` (which refuses a stale generation) before
    `EnsurePostgREST`; never run two ensures for the same ref at once (the worker is single and
    boot try-locks each ref); after a write, wait until `GatewayGeneration` reaches the returned
    value.
  - Known limits: after a daemon restart the generation seed is the wall clock alone, so a clock
    stepped back across a restart and a file loss can make it go down; a crash can leave
    `.<name>.tmp-*` files behind; a stopped container keeps its configured platform address but is
    invisible to another project's gate (two projects never share a slice: Docker refuses a second
    network with the same bridge name or an overlapping subnet); the lock and the last generation
    are per process and the flag per `Agent` (one `Agent` per daemon); a key change within one
    generation is not signalled to a running PostgREST.

### 2026-11-18 — `internal/rmtree` and `supapaced rmtree`

- `rmtree.Remove(root string) error` removes a directory tree; `rmtree.Empty(root string) error`
  removes everything below root and keeps root (inode, owner, attributes; a mode without owner
  rwx is left 0700). root must be absolute, clean and not `/`; uid 0 is refused. An absent root
  is success for `Remove` and an error for `Empty`; a root that is not a directory (a symbolic
  link to one included) or that is a mount point is refused.
- Only descriptor-relative calls below the root's parent. Entries are classified with
  `fstatat(AT_SYMLINK_NOFOLLOW)`; only directories are opened (`O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK`)
  and checked by device and inode; everything else is unlinked. Links are never followed and
  another file system inside the tree is an error. A directory without owner access is opened
  `O_PATH|O_NOFOLLOW`, checked, and given 0700 through `/proc/self/fd/N`, so the helper needs
  procfs at `/proc` (always present under Docker).
- The walk keeps a stack of the directories it is in (descriptor, name, read position, 8 KiB
  buffer) and never opens `..`: it acts only in directories it opened from the root downwards.
  It enters at most 8 levels below the root (at most 2303 bytes of path below it), because
  Docker's default AppArmor profile refuses full paths near 8 KiB even for descriptor-relative
  calls. A deeper directory is renamed into the root as `.rmtree-N` (`renameat2`
  `RENAME_NOREPLACE`; taken names are skipped and removed like any entry), and the root is read
  again until a whole read lists nothing. At most 11 descriptors and 72 KiB of buffers, whatever
  the shape; cost is linear in the number of entries on XFS.
- Precondition: nothing else changes the tree while it runs (the project's processes are
  stopped). If something does, the removal may fail (for example a directory that gained an
  entry after it was read), but it does not act outside the directories it opened.
- Callers: clear the owner's quota limits before running it. Each move into the root may need a
  free directory block, so at a full block quota (or a full file system) a tree deeper than 8
  levels fails on every attempt. A directory the caller cannot regain access to (not its own) or
  an entry under a sticky bit makes the removal fail. Moves need `RENAME_NOREPLACE` (XFS, ext4,
  tmpfs).
- `supapaced rmtree [--keep-root] PATH...`: each PATH in order with `Remove`, or `Empty` under
  `--keep-root`; reads no configuration (it runs as the only platform file inside a task
  container at the project's uid). Every PATH is checked (absolute, clean, not `/`) before the
  first is touched. Exit 0 with no output; 1 on the first failure or as uid 0; 2 on a usage
  error. Errors are one line on stderr, names quoted and shortened.

### 2026-11-18 — gateway tests: the raw HTTP/2 client has one writer

- `h2open` (`internal/gateway/wire_test.go`) reads the server's first SETTINGS and
  acknowledges them before it returns; its reader goroutine never writes. A frame written
  from a second goroutine could land between HEADERS and its CONTINUATION, which the server
  rightly answers with GOAWAY PROTOCOL_ERROR; under CPU load that made
  `TestHTTP2_HeaderBlockAcrossContinuation` fail about once in a few hundred runs and could
  let its over-limit steps pass for the wrong reason. The gateway is unchanged.
- Rule for tests that drive a connection frame by frame: one goroutine writes.

### 2026-11-18 — `internal/agent`: cluster and task containers

- API: `EnsureCluster(ctx, Spec)`, `CheckCluster(ctx, Spec) ([]nodecfg.CheckResult, error)`,
  `VerifyCluster(ctx, Spec)`, `StopCluster(ctx, ref)`, `Prevalidate(ctx, Spec)`,
  `PromoteCandidate(ctx, ref)`, `PurgeDir(ctx, Spec)`; all idempotent. `Spec.FirstBoot`
  marks a create; `Spec.HealthWait` bounds health waits.
- **State file** `<platform>/projects/<ref>/state.json` (root 0600): `epoch`,
  `generation`, `phase` (`A-done` or `B`), `pm_pid`, `pm_start` (the container init's
  pid and start time); listener fields 0. Only the agent writes it; a file that is not
  exactly one such record is an error.
- **One phase per `EnsureCluster` call:**
  - no state file and `FirstBoot`: first boot. Any `pg-<ref>` is removed, the platform
    files are rendered, `data/` is emptied at the project's uid, and the cluster starts
    with `--network none`, the image's own `pg_hba` and a random throwaway
    `POSTGRES_PASSWORD`. A trust session over the socket (peer = the container's init)
    runs bootstrap and the blocking catalog check; the container is stopped and removed;
    only then is `A-done` written.
  - no state file without `FirstBoot`: an error; nothing is touched (no first boot
    outside a create, so a lost state file never empties a database).
  - `A-done`: any `pg-<ref>` is removed (never adopted); the first networked start
    always waits for a SCRAM login (120 s when `HealthWait` ≤ 0) and runs the blocking
    check including `pg_hba`; then `B` with the init's pid and start time.
  - `B`: adoption, or re-creation without bootstrap or check.
- **Every start** is `docker create`, the start gate, `docker start`, with no Docker call
  between the gate and the start. A refused start (the gate, or the cluster's address
  held by another container: a containment error) removes the created container on a
  fresh bounded context, with the error joined. Any other failed start keeps the
  container for its logs until the next ensure.
- **Cluster container:** `--user uid:gid --cap-drop ALL --security-opt no-new-privileges
  --security-opt seccomp=<platform>/seccomp.json --read-only --tmpfs /tmp
  --memory/--memory-swap <MemMB>m --cpus 1 --pids-limit <Pids> --shm-size 64m
  --ulimit core=0 --ulimit nofile=65536:65536 --no-healthcheck --ipc private
  --stop-timeout 45`, no restart policy.
  - Mounts: `data/` and `sock/` read-write; passwd, group, pgsodium key, `conf.d`,
    supautils and tools read-only.
  - Networked starts add `--network proj-<ref> --ip <slice base+2>`, the IPv6-off and
    no-ping sysctls, and read-only `pg_hba`/`pg_ident`.
  - Command: `postgres -D /etc/postgresql` plus the image's pinned `-c` settings.
  - Logs are bounded by the daemon-wide `local` log driver.
- **Labels:** `supapace.role=cluster`, `.ref`, `.generation`, `.epoch`, `.phase`
  (`A`/`B`). Networked starts add `.image` (the configured reference) and `.config`:
  SHA-256 over the create arguments (options, image and command; no secret), the
  rendered files (`zz-supapace.conf`, supautils, `pg_hba`, `pg_ident`, passwd, group),
  the image's `postgresql.conf` and the seccomp profile, as on disk.
- **Adoption:** a running container is adopted only when every label equals the desired
  one (`.config` recomputed now), `state.json` records phase `B` at the desired epoch
  and generation, and its init's pid and start time equal `pm_pid`/`pm_start`.
  - It is then gated by `CheckAdopted`; on failure it is removed at once (no grace
    period) and the containment error returned.
  - A running networked container that is not adoptable is stopped (45 s grace) and
    re-created; anything else is removed at once.
  - A restart of the same daemon binary adopts every healthy cluster. An upgrade that
    changes the cluster's arguments, rendered files or seccomp profile restarts every
    cluster once, cleanly, at its next ensure.
- `HealthWait`: 0 means wait up to 120 s for a SCRAM login after a networked start or
  adoption; negative means no wait and no session (except the first networked start).
- `CheckCluster`: one session to the recorded process; returns at once after a failed
  statement. Its error is the operational verdict (login within the bounds,
  `pg_stat_archiver.failed_count = 0`); its rows are drift. `VerifyCluster` logs the
  drift at WARN and fails on the operational facts only.
- `StopCluster`: `docker stop -t 45`, then `docker rm -v`; nil when absent.
- **Task containers** `task-<ref>-wipe|prevalidate|purge`: the cluster image at the
  project's uid, `--network none`, the same hardening, `--memory 128m --memory-swap 128m
  --pids-limit 64`. They are not gated and have no restart policy or healthcheck.
  - Lifecycle: run detached after removing a leftover of the same name, polled every
    second, bounded at 300 s or the caller's earlier deadline, removed by name on a
    fresh context.
  - Output: stdout and stderr (read with `dockerx.RunOutput`), each sanitised and
    capped at 64 KiB.
  - Wipe: `supapaced rmtree --keep-root /p/data`. Purge: `supapaced rmtree /p/data
    /p/sock`. Both mount the daemon's own executable read-only and `<projects>/<ref>`
    at `/p`; the helper works by descriptor and refuses uid 0. The wipe needs the
    project directory and launches nothing without it.
  - Purge refuses while `pg-<ref>` or `postgrest-<ref>` exists in any state (a failed
    read is an error). It then clears the uid's quota limits, runs the task, and the
    daemon removes the empty project directory (non-recursive). An absent directory
    launches nothing.
  - Prevalidate: `postgres -C max_connections` against `<render>/candidate/conf.d`, with
    an empty tmpfs at the data path and no tenant data or key. The value must appear on
    stdout; a refusal reports stderr. `PromoteCandidate` removes the live `conf.d` and
    renames the candidate over it; it can be resumed.
- `dockerx.RunOutput(ctx, args...) (stdout, stderr string, err error)`: `Run`'s bounds
  (60 s, 4 MiB stdout, first 64 KiB of stderr), with stderr returned on success too.
- **Callers must:**
  - run one `EnsureCluster` per project at a time (hold the project's lock);
  - set `FirstBoot` only in a create's cluster steps;
  - expect a resumed first-boot step to perform the first networked start, the next
    call then adopting;
  - stop the cluster before `PromoteCandidate`;
  - stop and remove both tenant containers before `PurgeDir` (`StopCluster`,
    `StopPostgREST`); `PurgeDir` checks this and refuses otherwise;
  - install `supapaced` as a static binary executable by every uid (task containers
    run it);
  - treat an adoption's `ErrContainment` as "container removed";
  - never edit `state.json`.
- **Known limits:**
  - The log bound depends on the node's Docker configuration.
  - `PromoteCandidate` is a remove plus rename, not one atomic step.
  - A purge task that fails leaves the uid without quota limits until the purge
    completes (no tenant container exists by then).
  - A failed first boot leaves its network-less container until the next attempt.

### 2026-11-18 — `internal/saga` and store changes

`internal/saga` is the node's operation worker and the only writer of a project's lifecycle. It
carries create, restart, delete and purge operations through fixed step tables against `store`
and the node agent, one operation at a time, under the project's ref lock.

API
- `saga.New(st, ag, kek, cfg, paths)`. `Run(ctx)` is the worker; a second `Run` on the same
  runner waits for the first.
- `Submit(ctx, kind, ref, params)` queues a `restart` or `delete` of an `active` project. Creates
  are inserted by the admin API (`store.CreateProject`) and picked up by `Run`.
- `Abort(ctx, ref)` marks the ref's create `aborting` and returns its id (the same id while it is
  aborting). Only a `provisioning` project can be aborted.
- `ResumeAll(ctx)` logs the operations a previous worker left `running` or `aborting`; it changes
  nothing (`Run` takes them like pending ones).
- `SpecFor(ctx, ref)` is the desired state at `project.generation`, secrets and SCRAM salts
  unwrapped; it never sets `FirstBoot`.
- `saga.Agent` is the subset of `*agent.Agent` the steps call.

Step ids (`operation.step` is the last step completed)
- Create: `1` (admin API), then `2 3 4a 4 6 7 9 11 12`. Only steps 4a and 4 set `Spec.FirstBoot`.
  Step 12 is one store transaction (`FinishCreate`).
- Restart: `R0` (merge-base check), `R1` pre-validation, `R2` bump and drain, `R3` stop, quota,
  start, `R4` health, `R5` resume.
- Delete: `D1`-`D5`; `D5` queues the purge at now + retention. Purge: `P1`-`P5`.
- Compensation of an aborted create: `C1`-`C7` (route, PostgREST, cluster, keys, render tree,
  network and project tree, then the slice). Never written to `operation.step`.
- Keys are destroyed before any tree is removed; the slice is freed last; uids are never reused.

Parameters
- Restart input: `{"base_generation": N, "config": {...}}`. Stored: `base_generation`, `prev`,
  `next`, plus `rollback_gen` and `rollback_error` after a failed health check.
- Create: `{"issuer_jwks": ...}`.
- Added by the worker: `requeued` (attempts given back for containment refusals) and
  `compensating: true` once a create's compensation has started. Such a create never runs a
  forward step again; any pick of it, also after `op retry`, resumes the compensation from `C1`.

Failure policy
- A failed step is retried with back-off 2 s, 5 s, 15 s, 30 s; the fifth failure ends the
  operation `failed` at its step, nothing undone (`op retry` continues it; `project abort`
  compensates a create). Attempts are also counted when started: an operation interrupted five
  times before finishing a step is failed.
- Not retried: `node_full` (straight to compensation); `containment_failed` (requeued after 10 s
  and not counted while the agent's containment flag is set; `Run` takes nothing while it is set);
  `assertion`; `epoch_divergence`; `bad_request` (issuer kid equal to a platform kid);
  `conflict`.
- Restart conflicts: on every pick the project must still be at the merge base, or carry this
  operation's own bump (target generation, `restarting`, the target configuration; from R5 on
  also `active` at the target). Anything else - another restart's bump or a newer generation -
  is `conflict`, before any agent call.
- The disk quota is applied at R3 with the cluster stopped. A failed health check at R4 rolls
  forward once to generation g+2 with `prev` (its quota included); a second failure leaves the
  project `restarting` with its route draining.
- A probe that fails at 11 or R5 sets the route back to draining.
- A failing compensation backs off and is parked `failed` after 8 runs; `project abort` re-arms
  it. A transient error while resuming a compensation backs off.
- Deadlines: 300 s per step, 900 s per attempt (a roll-forward included); store bookkeeping runs
  outside them, `FinishCreate` under the step deadline.
- `last_error` is "<code>: <message>" through `pgsock.Sanitize`, at most 1 KiB. Log lines carry
  ref and operation id, never secrets or specs.

What `serve` must do
- At start: `pgsock.CheckEnv()`, `EnsureImageFiles` (the cluster steps need the image files),
  store `Migrate` and `EnsureNode`, then `ResumeAll` and exactly one `Run` per node, on one
  runner.
- `Ops.Submit` and `Ops.Abort` go to the runner. The admin API validates a restart's merged
  configuration before `Submit` (the runner does not) and passes the generation it read as
  `base_generation`.
- Failpoint, for crash tests only: `/run/supapace/failpoint` holding `<kind>:<step>` (compensation
  entries `create:C<n>`) is honoured only when the `dev-mode` marker is a regular file beside
  `node.json`. Neither file is followed through a link; on a match the file is removed, then the
  process exits with status 137.

Store additions
- `SubmitOperation(ctx, ref, kind, params, base, notBefore)` refuses (`ErrConflict`) unless the
  project is still at generation `base`.
- `NextOperation` orders ready operations by `updated_at, id` (least recently run first).
- `FailAttempt` on an aborting create counts the run. `ParkAbort` ends an aborting create
  `failed` after 8 runs.
- `RequestAbort` accepts only a `provisioning` project, resets `attempts` on every move to
  aborting and re-arms a parked create. `MarkAborted` only from `provisioning`.
- `FinishCreate(ctx, id)`: the operation `done` at step 12 and the project `active` at its
  generation in one transaction, only for a running create of a provisioning project; it locks
  the project row before the operation row, as `RequestAbort` does.
- `BeginRestart(ctx, ref, target, cfg)`: generation, configuration and `restarting` in one
  statement, from `active` or `restarting`; repeating it is a no-op only with the same
  configuration.
- `TryLockRef`: the ref lock without waiting.
- `LockRefChecked`: the ref lock plus `held`, one round trip on the lock's connection. The worker
  calls it before every record and ends an attempt with nothing recorded when the lock is gone.

Known limits
- Between the lock check and the write it guards there is one round trip in which a dying
  connection goes unnoticed.

### 2026-11-18 — `supapaced serve`

- `supapaced serve` takes no arguments. It runs until SIGTERM or SIGINT; a second signal during
  the bounded shutdown ends the process. Exit 0 after a signal (also during start-up), 1 when
  start-up fails (the supervisor starts it again after 1 s), 2 on usage.
- Start-up order:
  1. `pgsock.CheckEnv`, `node.json`, the key-encryption key.
  2. The run directory `/run/supapace` (created 0700 when absent; must be a real directory
     owned by the daemon's uid, no group or other bits), an exclusive `flock` on
     `serve.lock` there for the life of the process, and the admin socket path (anything but
     a socket there is refused). A second daemon, or a bad path, exits 1 here, before
     anything on the node is touched.
  3. Remove the drift hold. Render the ruleset; when the installed file differs, write it
     (0600) and load it. Bridge-nf switches off, `nft.Check`, on failure one load and a
     second check.
  4. `EnsurePlatformNetworks`, `EnsureImageFiles`, `EnsureControlPlaneDB`, then the store
     (open, migrate, node row), retried for up to 3 minutes.
  5. `DrainAllRoutes`; the boot record (`boot.json`, once per boot, before any tenant is
     started); `NodeCheck`.
  6. The pending-adoption set is marked for a refill and filled with every `active`
     project (a failed listing is retried by the adoption loop).
  7. `EnsureGateway`, `Runner.ResumeAll`, the admin socket, the drift timer and
     `Runner.Run`; then the adoption loop in the background.
- Containment at start: the first failure of the firewall check (any error, an
  unverifiable result included), of the platform networks, of the drain or of a node-check
  row sets the flag, drains every route and stops every tenant at once, before any step
  that can fail or wait. A signal during start-up is not a finding.
- Adoption (one round at start, on each signal of the drift timer, every 60 s; never two
  rounds at once; none while the flag is set):
  - projects in ref order, at most 4 at a time, each within 180 s, the ref lock only tried
    (`TryLockRefChecked`): a held lock defers the project and frees its slot at once;
  - under the lock the row is read again: a project no longer `active` leaves the set; one
    with a pending, running or aborting operation is left to that operation;
  - `SpecFor`, `EnsureCluster` with a negative health wait (no cluster session, never a
    first boot), `EnsurePostgREST`, a check that the lock is still held, then the route
    `active`. Only host-side facts restore a route;
  - then an advisory `CheckCluster` with no slot and no lock (repeated every 2 s for up to
    90 s while the cluster does not answer yet); its result is only logged;
  - a failure is logged with its ref, leaves the route draining and the project pending.
- Pending set: filled at start and at every containment failure. Until a listing has
  succeeded every project counts as pending. A project leaves the set when its adoption
  succeeds, unless a refill happened meanwhile. `restart` and `delete` of a pending
  project answer `conflict` "not yet adopted". A project created after start never enters
  it; one whose own operation re-activates its route leaves it at the next round.
- Drift timer (10 s, own goroutine, waits on no adoption and no cluster):
  - a hold file younger than 15 minutes skips the tick with a WARN carrying its age; an
    older one, or one dated in the future, is ignored;
  - bridge-nf switches, `nft.Check`; an unverifiable result acts on the third in a row,
    anything else at once; one reload and a second check;
  - still failing and not yet flagged: flag, drain every route, stop every tenant, refill
    the pending set (bounded to 5 s, retried by the adoption loop);
  - while flagged, every tick that does not clear the flag stops the tenants again; the
    first tick on which the firewall check and every blocking node-check row pass clears
    the flag and signals the adoption loop without waiting for it.
- Admin API operations: `Submit` (restart, delete) through the worker, refused for pending
  projects; `Abort` through the worker; `VerifyProject` = `SpecFor` + `CheckCluster` within
  75 s, codes `peer` (`pgsock.ErrPeer`), `timeout` (`pgsock.IsBudget` or a deadline),
  `internal` otherwise, message sanitised to 1 KiB; `NodeCheck` within 75 s;
  `ContainmentOK` is the flag cleared.
- Socket `/run/supapace/admin.sock`, 0600; a stale socket is removed, a live one refused.
  HTTP limits: header read 5 s, read 30 s, write 90 s, idle 60 s, headers 64 KiB. At
  shutdown requests get 10 s and are then cut; the worker, the drift timer and the
  adoption loop are stopped and waited for; the store is closed last. Tenant and platform
  containers are left running.
- Logs: one text handler on stderr; text from Docker or a cluster is sanitised (control
  characters removed) and capped at 1 KiB; no spec, key or session target is logged.
- Related changes:
  - `internal/agent`: when a fact of a running cluster's adoption check cannot be read,
    the check is read once more after 1 s; a refusal, a second failure or a node already
    marked not contained still removes the cluster at once.
  - `internal/store`: `TryLockRefChecked(ctx, ref) (unlock, held, ok, err)`; `TryLockRef`
    wraps it.
  - `supapaced.service`: `RuntimeDirectory=supapace`, mode 0700, kept across daemon
    restarts (the boot record is once per boot; a reboot empties `/run`).
  - Test node: the daemon's output also goes to `/var/log/supapaced.log`, emptied at node
    start and cut to its last 4 MiB above 8 MiB before each daemon start.
- Known limits:
  - a `node.json` or key that does not load exits 1 before any containment step: running
    tenants and active routes stay as they were while the daemon restarts every second,
    as with the daemon stopped;
  - the node check at start runs after the store is reachable, and the drift timer runs it
    only while the flag is set;
  - an adoption that ends after the flag was set can leave a started container for at most
    one tick;
  - in the test node a killed log pipe ends the daemon at its next log line (it is started
    again after 1 s).

### 2026-11-18 — operator surface: where to connect, early admission, clearer messages

- `project show`, each element of `project list` and `project keys` carry `url`
  (`https://<ref>.<domain>`, the domain the daemon loaded at start) and `ca_cert` (the path
  of the node CA's certificate when that CA signed the gateway's certificate, else null;
  checked at each request). No field was renamed or removed.
- `adminapi.New(st, kek, ops, domain, paths)`: the daemon passes its node domain and paths;
  the API reads no node configuration itself.
- `POST /v1/projects` checks, in this order: request fields, a chosen ref's form
  (400 `bad_ref`), a chosen ref that exists or existed (409 `ref_exists`), then admission:
  409 `node_full` "admission ceiling reached: N projects hold X of the node's Y MiB; a
  project needs Z MiB" (or the process ceiling, likewise) before any row is written, so a
  refused create burns no ref. Creates through the API pass these checks and the insert
  one at a time; a create waiting its turn gives up when its request ends.
- `store.CheckAdmission` applies `Place`'s rule but also counts projects not placed yet;
  it is advisory and `Place` stays the authority (its `node_full` last_error now carries the
  same figures). Without a node row it refuses with a conflict: the node is not initialised.
- `GET /v1/projects?state=S` (repeatable; an unknown state or any other parameter is 400);
  `supapace project list --state S`. The default listing still includes tombstones.
- Conflicts name the open operation: "operation N (KIND) of the project is STATE; wait for
  it to end" (submit and retry). Abort on a project that is not provisioning says abort
  applies only to a create in progress, pointing at delete (active) or purge (deleted).
  A setting refused for its form names the accepted form; one that cannot be set points at
  `project restart --help`. A reserved user role says which names are reserved and why.
- Outside text (check messages, last_error, error bodies) passes the sanitiser and cap,
  then `tidy`: whole ": "-separated parts that are platform package names, and a part that
  repeats the one before it, are dropped. It only removes parts, keeps their order, never
  removes the leading code of last_error, and keeps the stored last_error unchanged.
- CLI: `<command> --help` prints that command alone; a usage error prints the error, that
  command's usage and a pointer to `--help`. Help says what each key is for, how user
  tokens are signed (RS256 with an issuer key; header `kid`; claims `role`, integer `exp`,
  optional `sub` and `nbf`; at most 8 KiB) and how to open psql as postgres
  (`docker exec -it pg-REF psql -h 127.0.0.1 -U postgres`, which prompts). A create adds
  stderr notes (where to find url, keys and CA; with --no-wait, the operation to follow;
  the --user-role roles the developer must create and grant to authenticator). stdout is
  still exactly one JSON document. An operation with no step reads "before its first step".
- Limits: the create serialisation is in-process (one daemon per node); the pre-check is
  advisory and counts creates not placed yet, so it can refuse slightly earlier than `Place`.

### 2026-11-18 — gateway: slow or broken client bodies; refusal messages

- A request body that fails to arrive (the 60 s read timeout, broken chunked framing, a
  reset) or a client that goes away now ends the request without a response: HTTP/1.1
  closes the connection, HTTP/2 resets the stream. Nothing is logged and the upstream is
  not blamed. Before: `502 upstream_unavailable` when the upstream had given up on the
  slow body first, otherwise `400 bad_request` written after the write deadline (over TLS
  a broken record). `bad_request` no longer covers request bodies.
- When the upstream round trip fails after the upstream began receiving the body (it
  closed or reset mid-upload), the gateway reads the rest of the body, within the read
  timeout and the 8 MiB cap and keeping the request's slots, then answers `502`
  or `504`: a body that ends in time makes it the upstream's fault. A client that gives
  up during that read ends it at once. When the upstream was never reached (connection
  refused, dial timeout), the gateway answers at once without reading the body, so an
  `Expect: 100-continue` client gets no `100 Continue` and uploads nothing.
- `invalid_apikey` and `invalid_token` refusals (401) now carry a fixed message:
  `{"code":…,"message":…}`. This supersedes "Refusals are JSON `{"code": …}`" in the
  gateway entry for those two codes; `no_apikey` and every other refusal stay `{"code":…}`.
  The closed list:
  - `token is malformed`
  - `token has a duplicate member name`
  - `token algorithm is not RS256`
  - `token has no kid`
  - `token kid is not a key of this project`
  - `token signature is invalid`
  - `token is expired or has no exp`
  - `token is not yet valid`
  - `token has no role`
  - `token role is not allowed for its key`
  - `token is invalid` (any other token error)
  - `more than one apikey`
  - `apikey header and query parameter differ`
  - `apikey is not an anon or service_role key`
  - `Authorization is not "Bearer <token>"`
  - `more than one Authorization header`
  Nothing of the token, the keys or the upstream is echoed. Before the signature check a
  caller learns only whether its kid is one of the project's (key ids are public in every
  key and token); the claim messages need a validly signed token.
- Callers: assert gateway refusals by `code`; message texts may change.
- Known limits:
  - an oversized request header block gets the standard library's plain-text `431`
    (HTTP/1.1) or a stream reset (HTTP/2); there is no hook short of a custom parser;
  - a body declared over 8 MiB is refused `413` unread and the connection closed; a client
    still sending may see a reset instead, and `Expect: 100-continue` gets the 413
    reliably;
  - upstream response bodies, 5xx included, pass through byte for byte, so the upstream's
    connection-error details can show the project cluster's private address;
  - an upstream that answers before reading the body while the client stalls its body
    cannot be relayed before the read timeout; the client then sees the connection close.

### 2026-11-18 — Operation worker: restart retries, drain wait, rolled-back outcome, logs

- Restart resumed after R3 (a daemon restart, a back-off, `op retry`, also in the
  roll-forward): R3 runs again (stop, quota, promote, start) before R4, so R4 only
  waits on a cluster this attempt started. A server that never answered is no
  longer adopted again; a healthy one gets one extra clean stop and start. The
  ownership check still runs first, before any agent call.
- R2 waits for the gateway to serve the draining route file (same helper and step
  deadline as create 11 and D1) before PostgREST is stopped, in both passes.
  Clients see `503 project_restarting`, not 502. A gateway that does not catch up
  fails R2; after five attempts the restart is `failed` with the project
  `restarting` and PostgREST running; `op retry` continues it.
- A restart rolled back after a failed health check ends `aborted` (was `done`),
  step R5, `last_error` "rolled_back: the project runs its previous
  configuration at generation N; the restart to generation M was rolled back
  because its health check failed: <code>: <message>" (sanitised, 1 KiB).
  `generation` stays M. The CLI exits 1 with no retry hint; `op retry` answers
  409 conflict "operation is aborted; only a failed operation can be retried".
  It is not open: the next restart or delete is accepted. A `done` operation
  never carries `last_error`. `rollback_gen`/`rollback_error` stay in params.
- Store: `FinishOperation` also moves a running restart to `aborted`; every other
  kind reaches `aborted` only from `aborting`. `RetryOperation` refusal text now
  ends "; only a failed operation can be retried".
- Logs: `step failed` carries `final` (and `retry_in` when retried); a final
  failure is logged once recorded. One `operation finished` line per ending (op,
  ref, kind, outcome done|failed|aborted|rolled_back, step, attempts, duration
  since created_at); no error text, no parameters. The old `aborted` line is gone.
- Known limits: a parked abort that is re-armed logs two summary lines; duration
  includes back-off and a purge's retention; with the gateway slow in both passes
  an attempt can reach its 900 s deadline and resume on the next one.

### 2026-11-18 — `supapaced serve`: repair round, graceful containment stop, truthful checks

- Supersedes, in the entry "`supapaced serve`": start-up step order 4-5, "Adoption" (now the
  round below), the drift-timer hold rule (now shared with the round) and the known limit "the
  node check at start runs after the store is reachable". In the agent core entry: the
  `StopAllTenants` line and the node-check row list. In the PostgREST entry: `postgrest.conf`
  gains one key.
- Start-up: the boot record and `NodeCheck` now run right after `EnsurePlatformNetworks`,
  before `EnsureImageFiles`, `EnsureControlPlaneDB` and the store wait, so a failing blocking
  row stops tenants even when the store never comes up. `DrainAllRoutes` stays before any
  tenant is started.
- The round (at start, on each drift-timer signal, every 60 s; never two at once; none while
  `containment_failed`): `EnsureControlPlaneDB` and `EnsureGateway` first, then the pending
  adoptions, then a repair of every other `active` project whose cluster or PostgREST
  container is not running or absent, or whose route a failed repair drained. Same 4 slots,
  180 s budget per project, ref lock only tried, row re-read under the lock, no repair while
  the project has a pending, running or aborting operation. A repair never enters the pending
  set, so restart and delete stay accepted. A repair is the adoption's host-side ensure
  (`EnsureCluster` with no health wait, `EnsurePostgREST`, lock still held); it never stops a
  running container and never re-checks a running one (pid, labels, networks).
- Cost: a healthy round is two container listings plus the platform ensures' inspects, none
  per healthy project; a healthy container is never bounced.
- Routes: a failed repair drains the route once (503 `project_restarting` instead of gateway
  timeouts); the next successful repair restores it. A repair whose ref lock was lost writes
  no route. A repair that succeeds without a prior drain leaves the route as it is.
- Drift hold (`/run/supapace/drift-hold`, root only; removed at every daemon start): honoured
  when present, not dated in the future and younger than 15 minutes. It skips the drift tick
  (WARN each tick) and pauses the round's project repairs (INFO `repair: drift hold present
  (age Ns); project repairs paused this round`); the platform ensures and pending adoptions
  still run, and no route is drained or restored for a paused repair.
- Logs: INFO `repair: started` with `ref` and `containers`, or `container=sp-gateway|sp-cp-db`;
  WARN `repair failed; route draining, retried at the next round` (ref, step, err), at most
  once per round per ref (`repair failed; retried at the next round` when the ref lock was
  lost: no route is written then); WARN `repair: ensure failed; retried at the next round` with
  `container` for a platform container; INFO
  `re-creating sp-gateway: its configuration changed|its addresses changed` or `re-creating
  sp-cp-db: its configuration changed` with `was=running|stopped`, before a platform
  container is re-created (a gateway re-creation cuts its in-flight requests).
- Advisory check after an adoption, or after a repair that started the cluster: repeated every
  2 s for up to 90 s while the cluster is not ready (`pgsock.ErrPeer`, `ErrNotSocket`,
  `ErrConnect`, SQLSTATE 57P03); a cluster container that is no longer running ends the wait
  at once with a WARN and is started again by the next round. Its result changes no route.
- `node check`: rows `control-plane-db` and `gateway` (running, configuration label, the
  gateway's two addresses) fail without blocking (`agent.Blocking` is false for them): the
  document reads `ok:false`, `containment_failed:false`, and the CLI exits 1; no tenant is
  stopped. `drift-hold` (informational) reads `present, age Ns: drift check and project
  repairs paused`, or `stale, ignored: age Ns, honoured below 900s`.
- `project check`: rows `cluster-container`, `rest-container` and `route` (`agent.CheckHost`:
  exists, running, adoptable, expected networks; route active) are read before and
  independent of the cluster session. Failing rows come first in `drift`; when the session
  passes, a failing row gives code `internal` with message `host-side: <name>: <detail>`.
  Existing check names and codes are unchanged.
- `StopAllTenants` (containment failure only): every network disconnect of every running
  cluster and PostgREST container first, in parallel, all returned before any stop; then, in
  parallel, clusters `docker stop -t 45` (clean shutdown, no crash recovery at the next start)
  and PostgREST containers `docker kill`; a container whose disconnect failed is killed too.
  Each kill has its own 10 s bound that survives the caller's cancellation; the call is
  bounded at 60 s plus that. Callers' flag → drain → stop order is unchanged; a drift tick
  that finds nothing running stays fast.
- PostgREST: `postgrest.conf` sets `openapi-server-proxy-uri = "https://<ref>.<domain>/rest/v1"`,
  so the OpenAPI root advertises the public URL. The configuration hash changes: every
  PostgREST container is re-created once at its next ensure after an upgrade (503 for 1-2 s).
- `internal/pgsock`: `ErrConnect` marks a failed connect to the checked socket (before any
  byte from the server); a connect that ran out of budget is `ErrBudget`, not `ErrConnect`.
  The error text is unchanged; `Clean` keeps the sentinel.
- `internal/saga` worker: while the operation queue cannot be read, ERROR `operation queue`
  is logged at the first failure, then at most every 30 s with `failures` and `since`; INFO
  `operation queue readable again` with `down_for` on recovery.
- Test node (`node-init.sh`): the supervisor loop says `supapaced serve ended (status N|signal
  N)` instead of a bare `Killed`; `supapaced init`'s output (it shows the key escrow) goes to
  `/var/lib/sp/init.out`, root 0600, not to the node's log; shutdown matches the daemon by its
  full command line.
- Caller rules: a test or operator that stops or replaces a tenant container on purpose while
  the daemon runs takes the drift hold first and refreshes it within 15 minutes; otherwise the
  next round starts the container again.
- Known limits: a running container that is not adoptable or is off its network is handled
  only at the next daemon start or containment clear (`project check` shows it); a route left
  draining by a failed operation of an `active` project is not restored by the round; a
  cluster that exits at every start is re-created once per round (one INFO and one WARN per
  minute); when the store is unreachable a dead container's route stays active; a hold that is
  refreshed forever pauses project repairs forever; a daemon stopped during the disconnect
  phase of `StopAllTenants` kills every tenant (crash recovery at the next start).

### 2026-11-19 — Documentation, CI workflow, measurement script, Makefile entry points

- README.md (what exists and what does not yet: no backups; quick start on the test node;
  contributing rules), docs/architecture.md, docs/node-install.md, docs/operations.md and
  docs/measurements.md describe the system as built. They document today's behaviour where it
  is a known limit: a restart to a disk quota below usage, or whose new cluster does not start,
  leaves the project `restarting` (the former with no command out); `--user-role` replaces
  `authenticated`; a blocking node-check row that fails while the daemon runs is acted on only
  at the next start. Change those passages together with the code.
- .github/workflows/ci.yml: push to master and tags, pull requests. `public` (content gate over
  the tree, the pushed or proposed range — whole history for a new ref or force push — and the
  tag object on a tag push; deny-list from the secret SUPAPACE_DENYLIST, written to
  $RUNNER_TEMP and never printed, or a stand-in that matches nothing), `unit` (gofmt, vet with
  and without the reach tag, pinned images pulled, go test -race with the skipped tests listed),
  `reach` (make images, node-up, reach) and `reach-host` (install-node.sh on the runner VM).
  Actions pinned by major tag. Job-level concurrency on the two reach jobs only.
- test/measure/cluster_mem.sh (test nodes only): memory of one cluster idle and under pgbench
  load; samples memory.current and anon every second per phase (max_cur, max_anon); memory.peak
  is printed since container start only. The client shares the cluster's network namespace, not
  its cgroup.
- Makefile: `node-up` (full mode) waits up to 60 s until `supapace node check` answers, else
  prints the daemon log tail and fails; `reach-host` installs bin/* to /opt/supapace/bin first;
  `measure` takes REF, IDLE, LOAD, CLIENTS and on Ctrl-C stops the script through
  /run/sp-measure.pid.
- Known limits: no gateway capacity script yet (docs/measurements.md lists the method). Merge by
  local fast-forward push: GitHub's merge buttons commit as an address the gate refuses.

### 2026-11-19 — Image cache: store check and pull-only mode; CI on a hosted runner

- `scripts/cache-images.sh DIR` refuses to run unless Docker on this machine uses the
  containerd image store, and says how to enable it: the classic store saves a re-made
  manifest whose digest is not the pinned one, so the archive could not be named by digest.
- `scripts/cache-images.sh --pull-only` (`make images PULL_ONLY=1`) pulls every pinned image
  by digest and saves no archive: for a host install, where this machine's Docker is the
  node's; it works with either store. `make images` creates the cache directory itself.
- CI: the `reach` job switches the runner's Docker to the containerd image store before
  `make images`; the `reach-host` job uses `PULL_ONLY=1`.
- `internal/pgsock` test `TestBudget_EndlessRows`: the byte budget ends the session; its time
  bound is now 30 s, wide enough for the race detector on a slow machine.

### 2026-11-19 — reach suite: deterministic overlaps, drift holds around stops, exact answers

- A test that stops, kills, removes or replaces a tenant container (`pg-<ref>`,
  `postgrest-<ref>`) on purpose takes `driftHold(t)` before the stop and keeps it until the
  container is back or gone; the daemon's repair round then leaves the project alone. A hold
  is honoured for 15 minutes from its last write: a long section refreshes it (the
  hostile-init test calls `driftHold` again at the top of every mode). Every daemon start
  removes the hold. Platform containers are not covered: the round always repairs them.
- Never hold across a section that needs the drift check or the repair round to act;
  release first (cleanups run last-in, first-out, so register the hold before the cleanup
  that restores the container).
- After a node boot the daemon serves its socket before its first round has started the
  tenants: the fixture setup waits until a kept project is served (`waitServed`) before
  running SQL in it.
- A control that must overlap a load runs while the load is held open, not beside it on a
  timer: the log flood marks its start with a sequence and ends only after its counted lines
  and a `setval` the test issues once the control-plane and B writes have finished. Its
  fail-safe is a bound in time (30 s), not in lines.
- Windows shorter than the gateway's 5 s upstream dial timeout are sampled by several
  pollers (`pollHost(..., workers)`); every request in flight is collected. Answers from a
  host whose PostgREST is stopped must be the gateway's own 502 `upstream_unavailable`,
  503 `project_restarting` or 504 `upstream_timeout`; the other host is polled as well.
- A request the gateway refuses by its declared length is sent with
  `Expect: 100-continue` (no body before the answer, so no reset can hide the 413); the
  control is a body exactly at the 8 MiB cap answered by whoami(). A stalled body gets no
  response at all within 60–70 s, measured from before the connection is made.
- In a project without pg_graphql, `/graphql/v1` answers 200 with exactly one error
  "pg_graphql extension is not enabled." and no data (the image's stub); a project with the
  extension is the control.
- The retry of a restart that rolled back ends `aborted`, `last_error` starting
  `rolled_back:`, CLI exit 1; the project is `active` on its previous setting at a newer
  generation than before the restart.
- A create on a full node is refused at once: exit 1, `code` `node_full`, no new row in
  `project list` (which lists tombstones).
- Known sensitivity until the agent fix is merged: while a container on the platform network
  is starting, Docker can list it under an `ep-…` key; the agent's membership check refuses
  that and removes a healthy PostgREST being adopted. Test 14's failpoints then report a
  replaced or missing PostgREST of A or B (seen in about one full run in three on a reused
  node).
- Host tests: `recoverHost` clears the Docker unit's start counter (`systemctl reset-failed`)
  before it starts Docker, so that several Docker starts within a minute do not run into the
  unit's start rate limit.

### 2026-11-19 — `internal/agent`: transient endpoint keys; incomplete adoption checks

- Before: while a container's endpoint is not yet joined to it (a start, a restart, a
  `network connect` of a running container, rarely a stop), `docker network inspect` lists it
  under `ep-<endpoint id>` instead of the container id, and the member read refused that key.
  A container starting on `platform` then failed every concurrent start gate and adoption
  check and the blocking `platform-members` row: at boot the node was marked
  containment-failed and every tenant stopped; an adoption stopped a healthy PostgREST or
  removed a healthy cluster; an operation failed as final.
- After: a member read that holds `ep-<64 hex>` keys reads the listing again, at most 5 times
  200 ms apart, until every such key of its first read is gone, and judges the container ids
  of all its reads. A key of the first read still listed after the 5th re-read is refused as
  an unidentified member (`... member key "ep-..." (endpoint name "...") is an endpoint
  without a container, still listed after 5 re-reads 200ms apart: unidentified member`); any
  other key that is not a full container id is refused at once, without a re-read. The
  decision rests on Docker's keys alone; the endpoint name is printed, never used to accept or
  resolve. A healthy listing costs one read, as before. Added per network only while keys are
  listed: at most 1 s of waiting plus 5 reads (3 networks per project check).
- `ErrCheckIncomplete` (new): a refusal whose cause is a fact that could not be read (a failed
  Docker or `ip` read, an answer that does not parse, a context that ended during the
  re-reads). It still matches `ErrContainment`: the start gate refuses on it as before. A
  completed check's findings (absent or mismatched network, foreign or capable member,
  persistent endpoint key, the node flag) never match it.
- Adoption: `EnsurePostgREST` stops and removes a running PostgREST on a refusal, and returns
  an incomplete check leaving it running. `EnsureCluster` repeats an incomplete check once
  after 1 s; still incomplete, it returns the error and leaves the cluster running; a refusal,
  or a node marked containment-failed, still removes it at once (no grace period).
- Supersedes, in the entries above:
  - core, start gate: "Members are read by their endpoint ids" -> members are read by
    Docker's member keys (full container ids), `ep-` keys re-read as above; every
    configuration by id, never by name. "Every error is a refusal" holds; a refusal from a
    fact not read also matches `ErrCheckIncomplete`.
  - PostgREST, Adoption: "when that fails it is stopped and removed" -> a refusal stops and
    removes it; an incomplete check is returned and leaves it running.
  - cluster, Adoption: "on failure it is removed at once" -> a refusal removes it at once; a
    check still incomplete after its one repeat is returned and leaves it running.
  - cluster, caller rules: "treat an adoption's `ErrContainment` as 'container removed'" ->
    ... unless it also matches `ErrCheckIncomplete` (container left as it was).
  - `supapaced serve`, related changes: "a refusal, a second failure or a node already marked
    not contained still removes the cluster at once" -> a refusal or a node already marked
    not contained removes it at once; a second failure to read leaves it running, its route
    draining, retried at the next round.
- Callers: boot adoption and the repair round log an incomplete check as a failed step; the
  route stays draining and the project is retried at the next round. No route is activated
  without a completed check. The node check's `platform-members` row still fails (and blocks
  at boot) on any error, a read failure included.
- `internal/saga`: an operation step that fails with `agent.ErrCheckIncomplete` is retried
  with the worker's usual backoff and attempt bound; only a completed containment refusal ends
  the operation as final with code `containment_failed`.
- Known limits: a persistent
  `ep-` key on `platform` blocks the node until an operator removes the endpoint
  (`docker network disconnect -f platform <endpoint name>`). A read that fails on every round
  keeps a running project unverified and unrouted, logged at each round.

### 2026-11-19 — pgconf: pinned settings and recovery settings
Provides (internal/pgconf/pins.go; Overrides and CommandLine are unchanged, so a layout-1
project is not affected in argv, files or label):
- ArchiveCommand, RestoreCommand: the archive and restore commands of every project cluster
  (the archive command keeps its trailing "# pgbackrest" marker word, which is part of the value).
- OverridesPinned(gucs, memMB): Overrides without archive_mode, archive_command, max_connections,
  superuser_reserved_connections, reserved_connections; same checks as Overrides.
- Pins(gucs): -c flags for those names plus restore_command, in this order: archive_mode,
  archive_command, restore_command, max_connections (default merged with gucs), the two
  reserved settings. Each "-c" and each "name=value" is its own element. Checks are those of
  Overrides that do not depend on memory; OverridesPinned checks the memory bounds, so render
  OverridesPinned (not Overrides) in the same start.
- PinnedNames(layout): layout 1 the two preload names, layout 2 those plus the six names of Pins;
  any other layout nil.
- RecoveryTarget{Time, LSN, Timeline} and RecoveryPins(t): flags of a recovery start.
- RecoveryExtensionPins(): pgtle.enable_clientauth=off, pgtle.enable_password_check=off,
  cron.launch_active_jobs=off, for the project recovery start only.
Order contract for the recovery start: CommandLine, Pins, RecoveryExtensionPins, RecoveryPins,
with nothing appended after RecoveryPins. The server refuses a start in which any recovery
target setting, an empty one too, follows a set one. RecoveryPins therefore empties every unused
target first, then sets inclusive=on, action=promote, the timeline, min_apply_delay=0 and empty
end and cleanup commands, and puts the chosen target last. Call RecoveryPins before any step that
destroys data: a refusal after it would leave a project without its data.
Target rules: at most one of Time and LSN; no target needs timeline "latest"; a target needs
"current" or a decimal id 1 to 4294967295 (no sign, no leading zero); Time is rendered in UTC,
truncated to microseconds, and its UTC year must be 1 to 9999; LSN is 1 to 8 hex digits, a slash,
1 to 8 hex digits, not all zero, passed through as given.
Errors: every refusal wraps ErrGUCValue (errors.Is); the text quotes each field and cuts it to
40 characters, so operator input cannot forge log lines. The package stays pure: it reads no
clock, zone database or environment (the time import is for the type only; a test enforces it).
Known limits: Pins cannot check memory-relative bounds; the end-of-archive restore takes no target;
the order contract is enforced by the callers, not by this package.

### 2026-11-19 — WAL names and the archive binary
internal/walname (standard library only): the one definition of names.
- Kind: None, Segment, History, Label (spool and archive names); Info, SetManifest,
  SetManifestCopy, SetFile, HistoryManifest (repository paths only).
- Spool(name) (Kind, tli, ok): admits <24HEX> (Segment), <8HEX>.history (History) and
  <24HEX>.<8HEX>.backup (Label); upper-case hex only, anchored at both ends, so a trailing
  newline, white space, a leading "-" or any separator is refused. tli = first 8 digits.
- Request(name): Segment or History only - what recovery may ask for.
- SegmentOf(name): the 24 digits of a Segment or Label name, else "".
- Admitted(tli, list): list == nil admits every timeline (the control plane); an empty list
  admits none. Project callers must pass a non-nil slice: zero rows read into a nil slice, or a
  JSON null, would admit everything.
- Partial(name): exactly <24HEX>.partial. Spool, Request and RepoPath refuse it.
- RepoPath(stanza, rel) (Kind, tli, label, ok) admits only, with S = stanza (exact component),
  A = [0-9]{2}-[0-9]{1,3}, L = [0-9]{8}-[0-9]{6}F:
    archive/S/archive.info[.copy], backup/S/backup.info[.copy]          Info
    archive/S/A/<8HEX>.history                                         History
    archive/S/A/<16HEX>/<24HEX>-<40 hex>.zst                           Segment
    archive/S/A/<16HEX>/<24HEX>.<8HEX>.backup                          Label
    backup/S/backup.history/<yyyy>/L.manifest.gz  (yyyy = L's year)    HistoryManifest
    backup/S/L/backup.manifest, backup/S/L/backup.manifest.copy        SetManifest(Copy)
    backup/S/L/pg_data/<p>                                             SetFile
  The 16-digit directory must equal the name's first 16 digits; <p> is 1-512 bytes of
  [A-Za-z0-9_.+/-] with no empty, "." or ".." component. tli is 0 for kinds without one;
  label is set for the set kinds and HistoryManifest. latest, .partial, differential and
  incremental sets and tablespaces are refused. The stanza must be non-empty, not "." or "..",
  without "/" or NUL.

internal/arch exports Main(args, stderr) int and GetTimeout (120 s). cmd/supapace-arch is
os.Exit(arch.Main(os.Args, os.Stderr)); it imports nothing of the platform but walname (a test
checks the dependency list) and reads no environment. Fixed paths inside the cluster: spool
/opt/supapace/spool, restore spool /opt/supapace/rspool. Built static (CGO_ENABLED=0) by
make build as bin/supapace-arch, installed read-only, run by the server as
archive_command "…/supapace-arch push %p %f" and restore_command "…/supapace-arch get %f %p".

push <path> <name> - exit 0 archived or discarded, 1 refused or failed (one stderr line), 2 usage.
- Partial(name): exit 0 before anything is opened or written. The server archives such a file
  when a recovery ends inside a segment with no archive status yet (a cluster that promotes
  itself); no restore uses it, and refusing it would stop that cluster's archiving for good.
  Nothing is kept, so the spool never shows it; the discard is silent like a success.
- Otherwise the name must pass Spool. The source is opened non-blocking and must be a regular
  file. Copy to .tmp-<name>-<16 hex> (O_CREAT|O_EXCL|O_NOFOLLOW, 0600; a taken name draws
  again, at most 8 draws), fsync, hard-link to <name> (never replaces), unlink the temporary,
  fsync the directory. If <name> exists: opened without following or blocking; a regular file
  with identical bytes is fsynced through that descriptor and is success; anything else exits 1.
  A failed write or fsync (a full quota) leaves no final name and no temporary.

get <name> <dest> - exit 0 served, 1 not in the archive, 200 timeout, 201 any other error.
- The name must pass Request, else 201. Creates req/<name> exclusively without following a link
  (an existing entry is fine), then polls every 100 ms:
  out/<name>.none present -> remove the request and the marker, exit 1;
  out/<name> a regular file (not a link, opened non-blocking, at most 16 MiB + 1 KiB) -> copy to
  .<dest>.tmp-<16 hex> beside dest, fsync, rename onto dest, remove the request then the answer,
  exit 0 (a failed removal still exits 0). A link, FIFO or directory at out/<name> is not an
  answer. After GetTimeout exit 200; a usage error, an oversize answer and every other failure
  exit 201.
- Only the explicit marker gives an exit at or below 125: the server reads such an exit as the
  end of the archive and may end recovery and promote; above 125 it stops instead.

Never: follows a link at a name it creates or answers from, blocks on a FIFO, replaces an existing
spool entry, writes outside the spool or dest's directory, reads the environment.

Known limits: temporaries left by a killed process stay in the spool and beside dest (the spool's
consumer must ignore and expire .tmp-* entries); a Go runtime fatal error, or a shell that cannot
fork, exits 2, which the server reads as "not in the archive"; whatever the cluster writes to the
spool or the restore spool is its own and is checked again by the platform's jobs.

### 2026-11-19 — internal/s3x: minimal object-store client; sp-probe s3

internal/s3x is the only client of the S3-compatible object store: signature version 4, one
bucket per client, only the calls the off-site copy needs.

- Config{Endpoint, Region, Bucket, PathStyle, AccessKey, SecretKey, CAPEM, Addrs, Timeout}.
- New(Config) (*Client, error): checks only, sends nothing. Refuses an endpoint that is not
  https://name[:port], an invalid bucket name, an empty region, access key or secret, a
  timeout <= 0, an invalid address and a CA bundle without a certificate.
- Put(ctx, key, body, meta, ifAbsent) (versionID, error): one request; ifAbsent sends
  If-None-Match: * (the conditional create).
- Head(ctx, key, versionID) (Object, error); Get(ctx, key, versionID, w, max) (Object, error):
  a body over max is an error (nothing written when the length is known, else cut at max).
- List(ctx, prefix, token): one page of current objects; next is "" on the last page.
- ListVersions(ctx, prefix, keyMarker, versionMarker): one page of versions and delete
  markers in the store's order (by key, a key's versions newest first). Never re-sort by
  Modified: some stores keep whole seconds.
- CreateMultipart, UploadPart (part 1..10000), CompleteMultipart(..., etags, ifAbsent): the
  write-once condition is evaluated at completion, never at create.
- AbortMultipart(ctx, key, uploadID): refuses an empty upload id.
- Sign(r, payloadSHA256, accessKey, secretKey, region, now): signs every header r carries and
  sets r's escaped path and query to their canonical forms.
- (*Client).HTTPClient(): a copy of the client's own HTTP client, for a request the caller
  builds and signs with Sign (a probe's delete, a wrong-digest probe).
- ErrExists (412, also a completion answered 200 with a PreconditionFailed document),
  ErrNotFound (404), ErrDenied (any 403: a refused right, a wrong signature, an unknown key
  and clock skew alike), ErrChecksum (400 BadDigest or XAmzContentSHA256Mismatch). Match
  them with errors.Is.

Callers' rules:
- A sentinel means refused, nothing created. Any other error (a 5xx, a reset, a cut answer,
  a timeout) is an unknown outcome: the object may exist. Retry the conditional create; an
  ErrExists then is settled by Head and the stored sha256 metadata, never by overwriting.
- A negative check satisfied by ErrDenied needs a positive control with the same credential.
- Put and CompleteMultipart fail (not a sentinel) when the answer has no version id or
  "null" (versioning off or suspended). Every write returns a version id to record.
- A refused or failed completion leaves the upload open: abort it. A failed abort is left to
  the bucket's abort-incomplete lifecycle rule.
- Timeout bounds one call from the dial to the last body byte. Size it from the transfer
  (a large Get needs a large Timeout), or pass a ctx.

Key rule: a key is 1-1024 bytes with no leading or trailing "/" and no empty, "." or ".."
segment; a listing prefix the same, but it may be empty or end in "/". Anything else is
refused before a request: stores rewrite such names (a//b is stored as a/b, a trailing "/"
makes a directory entry without a version), so two names could be one object.

Connection rules: TLS 1.2 or later; CAPEM replaces the system roots; the certificate must
match the endpoint name. With Addrs set, each connection tries the addresses in order and the
name is never resolved (it is the TLS server name and Host only). No proxy, whatever the
environment says. No redirect is followed; a 3xx is an error. No compressed answer is decoded.

Bounds: response headers 64 KiB; an XML document 4 MiB (read no further); an error document
64 KiB; error codes in messages are letters and digits only, at most 64. A listing entry
outside the requested prefix, a truncated page without a new token, and a version page that
hands back the markers it was asked with are errors. Paging that never ends with fresh
markers is bounded only by the caller: cap pages or pass a ctx. Every request body carries
Content-MD5 and its signed SHA-256: stores verify both when sent but need not require them.

Never: no call deletes an object or a version. The one DELETE request is AbortMultipart's,
which needs an upload id (TestNoObjectDeleteInPackage). Nothing of the keys, a signature or
an Authorization header appears in an error.

sp-probe s3 SUBCOMMAND (mkbucket, versioning, lock, lifecycle, put, get, head, rm, versions)
drives a store for the harness, path style. The grammar is the comment at the top of
cmd/sp-probe/s3.go: options, one verdict line per call, exits 0 ok, 1 refused (denied,
not-found, exists, bad-digest), 2 timeout, 3 error. rm is the only destructive verb, for
harness set-up keys; the product never runs sp-probe.

Stand-in tests: TestStandin_* start the pinned stand-in image by digest, with a certificate
made in the test, and run only with SUPAPACE_STANDIN_TEST=1. The image must already be in
the local store. A detached watchdog removes the container (sp-test-s3x-standin-*) however
the test process ends. Not to be confused with the suite's SUPAPACE_STANDIN and its
needStandin(t).

Known limits: the pinned stand-in accepts any region, refuses a key segment over 255 bytes
(500), answers a.b/./c and ../ names with 400, and its write right includes delete.

### 2026-11-19 — bootstrap: inheriting backup grant, re-key session, image-settings check

internal/bootstrap gains the re-key of a cluster started from a restored data directory, a
drift check that takes the expected command-line names, and a check of the image's settings
at first boot.

- Rekey(ctx, conn, s): one session as supabase_admin. Computes the three verifiers before it
  sends anything, then sends exactly: the password statements of supabase_admin, postgres,
  authenticator (in that order, the session's first statements, each one simple-query
  message), the backup role's existence read, its creation when absent, its two grants.
  Idempotent. A later identity is added by appending to the list verifiers() returns.
- Password statement (first boot and re-key): alter role <role> with login connection limit -1
  valid until 'infinity' password '<verifier>'. On a fresh cluster this changes nothing in
  effect; rolvaliduntil reads infinity instead of NULL afterwards.
- GrantBackup(ctx, conn): grant pg_read_all_settings to supapace_backup with inherit true; also
  turns an existing plain grant into an inheriting one.
- InRecovery(ctx, conn) (bool, error): pg_is_in_recovery(); exactly one row. The answer is the
  cluster's: use it for the recovery poll only, in a session of its own.
- ReadTimeline(ctx, conn) (int, error): first 8 hex digits of the current WAL file's name;
  exactly one row of 8 upper-case hex digits, not zero, else an error.
- ResetStatementStats(ctx, conn) (reset bool, err error): clears the statement statistics of
  supabase_admin only, through extensions.pg_stat_statements_reset. SQLSTATE 42883 or 3F000
  (function or schema not there) is reset=false, nil. Other errors expose *pgsock.ServerError
  through errors.As. The function is the cluster's: send it last, treat errors as best effort.
- AssertPins(ctx, conn, bl, conf, cmdline): Assert with the names expected to read source
  "command line" (pass pgconf.PinnedNames(layout)); an extra or missing name is a source-file
  finding. Assert is AssertPins with the two preload names, unchanged for its callers.
- The drift check reports supapace_backup's membership in pg_read_all_settings without the
  inherit option under memberships-reserved. servicePasswordRoles is the one list of service
  roles without a password: remove a role from it when the platform gives it one.
- Run's order: verifiers computed, image settings compared, passwords, realtime admin role,
  backup role, auth functions. ErrImageSettings (match with errors.Is): the preloaded
  libraries (in order) or the setting names differ from the baseline; the text names up to
  eight sanitised names, then "and N more". Nothing is changed before the comparison.
- Baseline gains "preload" (shared_preload_libraries in the file's order) and
  "session_settings" (byte-sorted names: every name with a prefix, and log_*, debug_print_*,
  track_*). The names of a library loaded only through session_preload_libraries are left out,
  so the comparison is the same whether or not a session loads that library.
- Bounds: at most 1,024 settings read (more is an error); membership reads limited to 256 rows.
- Image bump: regenerate both members with readImageSettings on a fresh cluster of the new
  image (byte-sorted), after the recovery experiments have been re-run against it.
- Known limits: a library added only to session_preload_libraries is not detected (sessions that
  send it empty do not load it). The statements after the password statements may call
  functions of the restored database (the reset's function, those the reads use); nothing
  secret is sent after the password statements.
- Tests: about 95 s with -race; the cluster tests need the pinned image and skip without it.

### 2026-11-19 — Backup paths, limits and job formats (nodecfg, bklimit, jobio, agent types)
Provides
- nodecfg constants: ReplicatorUID 65530 and ControlPlaneUID 70 (each also the gid),
  BackupBridge "spb0", BackupNetwork "backup", WorkerImage "supapace-worker:local",
  ControlPlaneSubject "cp".
- Config.BackupSubnet (default 10.212.9.0/24; Validate refuses an overlap with the other
  four networks), CPDiskQuotaMB/CPRepoQuotaMB (omitempty; 0 = unset; negative refused),
  Images.Worker (must equal WorkerImage). Load fills BackupSubnet and Images.Worker when
  absent, so a node.json written before them loads; init rewrites it with both.
- CPQuotas(c, p): a set quota as it is, else 32,768 MiB, or 2,048 when the dev-mode marker
  (a regular file beside node.json) exists. Read the quotas only through it.
- Defaults(): Default without a domain and without Validate.
- Paths: RepoRoot, RepoDir(subject), CPProjectDir, CPRestoring, ToolsDir, JobsDir,
  IndexFile(subject), OffsiteSealed, OffsiteAddrs, NftLock, CPStanzaSealed, EscrowAcked,
  OffsiteCheck. Subject is a project ref or "cp"; nothing checks it.
- bklimit: every figure that sizes a backup job, loop, budget or lag. Deadline(kind, diskMB,
  repoMB) errors on an unknown kind or a negative quota; serve has the recover deadline;
  every division rounds up. PushLoopMax, ReplLoopMax, ReplMemMB, Budgets (objects follow
  the effective byte budget, floor 7,500), FetchMargin (negative extra = 0; above 3 it
  returns WholeArchive). ResultMax 1 MiB.
- jobio, standard library only: Input/ReplInput (/job/input.json); one result type per
  kind (CheckJobResult for check and stanza-create; ReplResult for replicate and probe,
  its wire "rows" is Rows or ProbeRows by mode); RecoverResult (the runner's own, never
  parsed); Failure; IndexRow and PlanRow lines with their readers and writers.
- agent: Spec gains Layout, RepoQuotaMB, Stanza, StanzaPass (json "-"). types_backup.go
  holds JobSpec, JobResult, QuotaUse, HostState. JobSpec's String, GoString and Format
  print only ID, Subject and Kind; SecretEnv and Cred are json "-". Do not redeclare them.
Contracts and refusals
- Every JSON document is decoded strictly: member names exactly as declared and unique
  (encoding/json alone would fold case and keep the last duplicate), nesting <= 16, no
  unknown member, nothing after it. Null or missing timelines only for subject "cp" or
  kind probe; an empty list admits none.
- MarshalResult: one line plus "\n", at most ResultMax bytes before it. ParseResult(kind,
  line) takes the line with or without its newline and returns the kind's value or a
  *Failure; err means unusable: record the job crashed. Store the value re-encoded with
  MarshalResult, never the raw line. A stored document (a fetch with histories, a
  replication with counts) is not ParseResult input. There is no kind recover.
- A failure is exactly {ok,code,message}: code [a-z0-9_-]{1,64}, message <= 256 bytes,
  unsanitised (sanitise before storing). Replicate takes modes copy and rebuild, probe
  takes probe; a copy has no rows; a fetch result with histories is refused.
- Count bounds: quarantined <= 56 and newest <= 64 (also a push nested in check,
  stanza-create and backup), serve none <= 64, rebuild rows <= 4,000.
- Rows (uploaded, adopted, rows): key 1-1,024 bytes, no control byte in key or version
  id, numbers not negative, hash empty or lower-case hex. AppendIndexRow returns an error
  and dst unchanged for a row that would not read back; ParseResult rows always fit.
- Index line: key, size, ino, ctime_ns, sha256 or "-". Plan line: key, version id or "-",
  sha256 or "-", size. Tab-separated, fields non-empty, no control byte, numbers 1-19
  digits. ParseIndexRow refuses a key over 1,024 bytes; ReadPlan a line over 4 KiB and an
  unterminated last line; WritePlan a row that would not read back.
Known limits
- Not bounded by count beyond the 1 MiB line: probe rows, uploaded, adopted, notices,
  info versions. newest's keys and values, labels and segment names are not shape-checked.
- Parsing a 1 MiB replication result costs about 125 ms and 25 MB.
- A JobSpec or Spec held in an unexported field of a printed struct prints raw. Spec's
  Secrets still print under %d and in JSON; no code does either today.
- A node.json hand-edited so another network covers 10.212.9.0/24 no longer loads; set
  backup_subnet explicitly.

### 2026-11-20 — `internal/dashtok` and `jwtx.VerifyID`: dashboard tokens

- `internal/dashtok` signs and verifies three Ed25519 token formats: the principal
  assertion (`Assertion`: node, iss, sub, name, ref, role, purpose, iat, exp), the session
  token (`Session`: iss, sub, name, ref or `_`, iat, exp) and the log-out ticket (`Ticket`:
  iss, sub, refs, iat, exp). `SignAssertion`/`VerifyAssertion(k, token, node, now)`,
  `SignSession`/`VerifySession(k, token, maxSeconds, now)`, `SignTicket`/`VerifyTicket`.
- Envelope `v1.<P>.<S>`: P is the unpadded base64url of the payload JSON, S of the 64-byte
  signature over `<label><P>`. Labels `supapace-assertion-v1.`, `supapace-session-v1.`,
  `supapace-logout-v1.`, so no token verifies as another kind (`ErrSignature`).
- Verification order: size (at most 4096 bytes); envelope (prefix `v1.`, two dots, non-empty
  P, S of exactly 86 characters, base64url alphabet only, strict decoding with zero unused
  bits); signature (RFC 8032, S < L); then the payload, which must be byte for byte the
  canonical encoding of what it decodes to: listed members in order, no white space, no
  escape but `\"` and `\\`, integers in plain decimal. Then member rules, times, node.
- Member rules (signers and verifiers): iss and sub 1 to 255 bytes of printable ASCII; name
  at most 128 bytes and node 1 to 255 bytes of UTF-8 without a control character, U+2028 or
  U+2029; ref `^[a-z0-9]{20}$`; role owner, developer or read_only; purpose "" or "reveal";
  a ticket holds 1 to 16 refs, never `_`.
- Times: exp <= now is `ErrExpired`; iat > now + 5 is `ErrNotYet`; exp <= iat, or exp - iat
  above the bound, is `ErrLifetime` (60 s for assertions and tickets, maxSeconds for
  sessions; a bound <= 0 accepts nothing). Another node is `ErrNode`.
- Errors, matched with `errors.Is`: `ErrMalformed` (size, envelope, JSON syntax, white
  space), `ErrSignature` (also a public key not of 32 bytes), `ErrField` (members or
  values; signers return it too), `ErrExpired`, `ErrNotYet`, `ErrLifetime`, `ErrNode`. A
  refused verification returns the zero value.
- Key files (`GenerateKey`, `ParsePrivate`, `ParsePublic`): the 32-byte seed or public key
  as 43 base64url characters and one line end; a parser also accepts the 43 characters
  alone. Signing with a private key of the wrong size returns an error, never panics.
- `testdata/vectors.json` is shared with a second implementation: the public test key (seed
  00..1f, never a node's key), three fixed accepted tokens, the login nonce vector and the
  refused cases with the Go error name of each. Another verifier must refuse every refused
  case; the error name is informational there. Regenerate the refused cases with
  `go test ./internal/dashtok -run TestVectors_UpdateRefused -update`; the accepted tokens
  are never regenerated.
- A verifier in another language must not use a lenient base64 decoder (trailing bits,
  skipped characters, the standard alphabet) and must compare the UTF-8 bytes of its
  re-serialised payload with the payload bytes, never strings.
- `jwtx.ClassDashboard` ("dashboard") is a fourth key class. `CheckRole` refuses it for
  every role; `KeyFromJWK` and `ParseJWKS` still refuse it. Dashboard keys come only from
  `DashboardKeyFromJWK(kid, n, e)` and `ParseDashboardJWKS`, with every check of those two;
  `DashboardKeyFromJWK` takes no kty, so the caller checks it is "RSA".
- `jwtx.VerifyID(token, keys, IDCheck{Issuer, ClientID, Nonce}, now)` checks an OpenID
  Connect ID token with Verify's parser and signature code, then: key class dashboard
  (`ErrKey`); iss exact, aud the client id or an array holding it with azp, a present azp
  equal to the client id, sub 1 to 255 bytes of printable ASCII (`ErrClaim`); exp later
  than now - 60 and iat no older than 600 s, both required (`ErrExpired`); iat and nbf at
  most 60 s ahead (`ErrNotYetValid`); nonce equal, compared in constant time (`ErrNonce`);
  name a string when present. A claim of the wrong type is `ErrMalformed`. An IDCheck with
  an empty member accepts nothing. `IDClaims.Name` is untrusted and unbounded: clean and
  cut it before it goes into a session.

### 2026-11-20 — pgconf: scheduled jobs run in background workers
- Every project cluster's override file now sets `cron.use_background_workers = on` and
  `max_worker_processes = 38`; both are platform-set (not in `GUCAllowList`, refused by
  `Overrides` and `OverridesPinned`; postmaster context, so no session, role or database
  setting changes them). pg_cron jobs run in a background worker as the job's role, with
  that role's rights and no connection or password; `pg_hba.conf` is unchanged.
- Worker pool: 3 idle image workers (pg_cron launcher, pg_net worker, logical replication
  launcher) + up to 32 running jobs (`cron.max_running_jobs`, still 1-32; pg_cron refuses
  more than `max_worker_processes` - 1) + 3 spare = 38. Before, the pool was 8 and a
  `cron.max_running_jobs` above 7 silently fell back to 5. Keep the pool >= 35 + spare.
- The pool is shared with parallel query and maintenance workers and logical replication.
  `max_parallel_workers*` have user context, so a session can use up to 35 workers in one
  query (was 5); memory, CPU and pids stay bounded by the cluster container (512m, 1 CPU,
  512 pids: worst case about 457 processes). Shared memory grows by about 1 MB.
- Existing projects: adoption hashes the files as on disk, so a running cluster is still
  adopted after an upgrade and its check reports nothing; the new file is rendered when the
  container is re-created (`project restart`, a node reboot, a stopped container).
- Tests: `TestCron_JobsRunInBackgroundWorkers` (pinned image; control without the setting;
  a second role's rights); reach `TestReach07_Roles/7c_scheduled_job`.
- Known limits: a job that finds no free worker (for example while parallel queries use the
  pool) is recorded as failed and not retried; jobs run only in `cron.database_name`
  (`postgres`); jobs that exhaust the container's memory make its server restart in a loop
  until they are unscheduled (that project only).

### 2026-11-20 — Dashboard interfaces: constants, bounds, the dashboard file, socket types
internal/dashcfg — computes only; reads no clock, socket or file.
- Constants: Studio, postgres-meta and pgcap uids 65527/65528/65529 (each also the gid),
  container names sp-studio, sp-pgmeta-0/1, sp-pgcap, images, ports 3000 and 8080,
  MetaPortBase 20000, project-bridge host offsets, the three roles, the two logins, and the
  read-only secret's name.
- Addrs/For/Static: Studio, PgMeta0, PgMeta1 and Pgcap are platform subnet base + 3..6; meta
  ports MetaPortBase..+Slices()-1; RestLo/RestHi are the fixed PostgREST addresses. For refuses
  (errors.Join; plain errors) a dashboard address that is the gateway's, in the allocation range
  or outside the subnet, a port range past 65535, no room for the PostgREST range, more than
  4096 slices, and a project uid range containing 70 or 65527-65532. Static never fails or
  panics: it returns For's value with each refused member zero (ports 0-0), never a port above
  65535; when For accepts, Static equals it. For assumes nodecfg.Validate already passed (Load
  and init run it). Hand a server For's Addrs, never Static's.
- DSN/ParseDSN: postgresql://<login>:<password>@<Pgcap>:<MetaPort(i)>/postgres?sslmode=disable.
  The password escapes every byte outside A-Za-z0-9-._~ as %XX, upper-case. ParseDSN accepts
  only that exact form: a non-empty password decoding to bytes 0x20-0x7e, the exact proxy
  address, a canonical port in range, at most 512 bytes, and Addrs that have a proxy address and
  a port range. Its vectors (testdata/dsn.json) are shared with Studio's twin; add vectors,
  never remove one.
- Paths: PathsFor(nodecfg.Paths) and ten path methods (KeyDir ... DataDir).
- LimitSet/Limits: the one bounds table. Check holds the nesting rules (strict <); a renderer
  refuses a set that fails it. SliceHoldSecs (8 days) must exceed the resolve disk and memory
  lifetimes plus rows 2 and 6, compared in milliseconds. StudioJSON is SUPAPACE_LIMITS: 14
  members in fixed order, no white space, without SliceHoldSecs. Figures change here and in
  TestLimits_DefaultsPassCheck only.
- StudioEnv(a, node, l, imageEnv): sorted NAME=value. The eight fixed names, plus from the
  image label only ListenerNames (a port name must be 3000) and
  ENABLED_FEATURES_[A-Z0-9_]+=false; anything else, a fixed name included, is an error.
  FixedEnvNames lists the fixed names. Docker's HOSTNAME and the image's own ENV are outside
  its reach.
- PgMetaEnv(l): postgres-meta's environment without CRYPTO_KEY, which the agent appends from the
  key file. It holds no PG*/libpq name; keep it that way (node-postgres reads them).
- NoForwardArgs: the four --sysctl arguments for containers on two networks.
internal/dashfile — the gateway's authorization table; one writer (Marshal), one reader (Parse).
- Parse: UTF-8 only; a first token pass checks exact member names (no case folding, escapes
  decoded), each once and all present, null only for issuer, value kinds, and the caps
  (MaxProjects 4096, MaxMembers 256, MaxRevocations 65536, MaxKeys 16) before the value is
  built. Then a single-value decode (no trailing data) and validate.
- validate: generation >= 1; node non-empty; studio_domain is a domain; studio is
  http://<IPv4>:3000; issuer iss, sub and every principal are 1-255 bytes of printable ASCII;
  client_id and authorize_url non-empty; session_seconds 1-28800; keys are kty RSA with kid, n
  and e non-empty; refs are ^[a-z0-9]{20}$; roles are the three; no duplicate (iss, sub) in a
  project; not_before >= 0.
- Marshal validates and writes one canonical form (projects sorted, empty collections [] and
  {}); Marshal -> Parse -> Marshal is byte-identical. The store must refuse at insert whatever
  validate refuses, or one row blocks every write. String lengths are not capped here: the
  reader bounds the bytes it reads. Errors carry no sentinel: match with err != nil.
internal/dashsock (proto.go): ResolveAnswer, DataAPI, KeysAnswer, SigningKey (json as on the
wire; dsn_rw, dsn_ro and service_role_key are omitted when empty); HeaderAssertion; RoleClass
("rw" for owner and developer, "ro" for read_only, "" otherwise).
cmd/sp-dashstub: sub-commands register in init() as
subcommands[name] = func(args []string, stdout, stderr io.Writer) int; an unknown one exits 2.
"limits" prints SUPAPACE_LIMITS; "limits --names" prints {"fixed":[...],"listener":[...]}.

### 2026-11-20 — restart: quota below usage refused, R3 rolled back, way out of a failed restart

- Before: a restart to a disk quota below the project's usage left it `restarting` for good (the
  cluster could not create its lock file; restart and delete refused; `op retry` set the same
  quota again), and a restart whose new cluster did not start (R3) was not rolled back.
- Admin API restart: a changed `disk_quota_mb` below the usage (rounded up to MiB) plus
  `store.QuotaHeadroomMB` (256) is refused with 409 `quota_below_usage` (CLI exit 1): "disk_quota_mb
  N is below the project's usage of U MiB plus the 256 MiB a clean cluster start needs; the
  smallest accepted value is M". Checked only for an active or restarting project; a usage that
  cannot be read is 500 `internal`. 256 MiB is a clean-start floor: a cluster that stopped at its
  quota (killed, or after a failed WAL write) replays up to 1 GiB of WAL at its next start and
  needs its usage plus 1280 MiB; the CLI help and the quota runbook say so.
- Saga R1 checks a changed quota again under the ref lock (forward pass only): refused with the
  final code `quota_below_usage`, the operation ends `failed` after R0 with nothing changed. A
  rollback restores the previous quota without the check.
- R3 sets the stored quota on every pass (changed or not). A failure of R3 rolls the restart forward
  to g+2 with the previous configuration, as one of R4 does, except on the rollback pass, a
  containment refusal, an assertion, an epoch divergence or a final failure. Params gain
  `rollback_step: "R3"` (absent after R4). Outcome `aborted`, last_error "rolled_back: ... because
  its stop/start step failed: ..." (R4: "because its health check failed").
- Way out: `SubmitOperation` also accepts a restart or a delete of a project `restarting` whose
  newest restart operation is `failed` (same row lock, one open operation, base generation); the
  worker's base check accepts `restarting`. The new restart's previous configuration is the
  failed one's. A retry of a superseded restart ends in `conflict`. A failed restart that leaves
  its project restarting appends to last_error the state and the three ways out (`op retry ID`,
  `project restart REF --set KEY=VALUE`, `project delete REF`); the CLI names restart and delete
  only then. `project abort` of a restarting project points to them.
- `project show` gains `disk_used_bytes`: the user quota's charge for the project's uid
  (`nodefs.DiskUsage(ctx, paths, uid)`, `xfs_quota` in its own process group, killed with its
  children when the context ends); read within 5 s, else null; null for a project not placed,
  purged or aborted. Not in `project list`.
- New: `store.CheckQuota`, `store.ErrQuotaBelowUsage`; `adminapi.Ops.DiskUsage`; saga `Agent`
  and `agent.Agent` gain `DiskUsage(ctx, spec)`.
- CLI help: `--user-role` replaces the default `authenticated`; the postgres credential is "the
  database role postgres, for schema changes".
- Known limits: a restart to less than usage + 1280 MiB for a cluster that stopped at its quota
  can fail at R3 or R4 and roll back to the old quota, below the usage, leaving the project
  `restarting` (way out: a new restart with enough quota). A new restart after a failed one
  rolls back to that failed configuration. The quota is still set by R3 without a time bound.

### 2026-11-20 — sp-dashstub socket and pgmeta: stand-ins for the dashboard socket
cmd/sp-dashstub gains two sub-commands (register in init()); test-only, never run on a node.
- socket --listen PATH --public FILE --node ID --table FILE [--mode answer|silent|refuse:CODE]
  Serves POST /v1/resolve and /v1/keys on a Unix socket; the socket file is mode 0666 (the
  directory decides who connects; the real socket is narrower, so a test that another uid is
  refused cannot use this stub). Order: refuse:peer (403 peer, before anything is parsed
  further), then the request target exactly as received (a query string, a percent-encoded or
  absolute-form target is 404 not_found), method 405 method_not_allowed, body (chunked too) 400
  bad_request, then dashtok.VerifyAssertion (401 bad_assertion; not exactly one assertion header
  is also 401), then any other refuse:CODE, then the ref in the table (404 not_here), then
  (iss, sub, role) among the members (403 not_a_member). Every refusal is {"code":"..."}.
  Refusal codes: peer 403, bad_assertion 401, rate_limited 429, not_here 404, not_a_member 403,
  unavailable 503. Only peer answers before the assertion is checked, as on the real socket.
  Bodies are JSON with no trailing line end.
- silent: accepts, logs with status 0, never answers; holds the request until the client leaves.
- Log: one JSON line per request appended to PATH.log: path, ref, sub, role, purpose, status
  (ref/sub/role/purpose empty when the assertion failed). The path is the parsed URL path, not
  the target: a refused "/v1/keys?x" is logged as /v1/keys with its status. One write per line
  on an O_APPEND file; a restart keeps earlier lines. A stale socket at PATH is removed; other
  files are not.
- Limits applied: header block 8,192 bytes, request line and final blank line counted (8,193 is
  431; net/http's MaxHeaderBytes is set to 4 KiB because it reads 4 KiB beyond it), header read,
  whole-request read, write and idle connection 2 s each. Not applied: 64 connections, the 800 ms
  whole request, per-ref rate, the peer check itself.
- pgmeta --listen ADDR --crypto-key-file FILE [--delay-ms N] [--size BYTES] [--status CODE]
  Answers /query and /generators/typescript with [{"login","port","n"}] (n = request number,
  space-padded to --size) after --delay-ms, with --status; the delay ends when the client leaves.
  The key is the file's bytes exactly as they are (a trailing line end is part of it). It decrypts
  x-connection-encrypted: base64 of "Salted__", 8-byte salt, AES-256-CBC with PKCS#7; key and IV
  from MD5 EVP_BytesToKey (crypto-js passphrase mode; openssl enc -aes-256-cbc -md md5 makes test
  data). Unreadable, bad padding or no port: 400. Other paths: 404.
- GET /_seen (not recorded itself): the last 1,000 requests, oldest first, [{n, method, path,
  headers{name:[values]} with lower-case names, body_bytes}]. Go moves Host and Transfer-Encoding
  out of the header map, so a test of "exactly these headers" must ignore transport headers.
2026-11-20: the socket stand-in now answers refuse:peer first, compares the raw request target,
  refuses any count of assertion headers but one, writes bodies without a line end and bounds
  header (exactly 8,192 bytes), read, write and idle time.

### 2026-11-20 — `internal/nsdial`: a TCP dial from inside a container's network namespace

Provides:
- `Target{PID int; StartTicks uint64}`: a container's init process: the pid Docker's inspection
  reports, and that process's start time in clock ticks (field 22 of /proc/<pid>/stat).
- `TargetOf(pid int) (Target, error)`: the pid with its start time read from /proc. A process that
  is gone is an error wrapping ErrChanged. The one reader of a start time: build every Target, and
  every recheck's result, with it; do not parse /proc/<pid>/stat elsewhere.
- `DialTCP(ctx, t, recheck, addr netip.AddrPort) (net.Conn, error)`: one TCP connection made from
  inside t's network namespace.
- `ErrChanged`: the process behind the Target is not the one inspected (gone, or pid reused).
  Match with errors.Is; it may be wrapped with the underlying /proc error.

Order: open /proc/<pid>/ns/net; compare the pid's start time with t; call recheck (the caller
inspects the container again, usually TargetOf of a fresh inspection's pid) and require the same
Target; refuse a non-root caller; then enter. Any mismatch returns ErrChanged and makes no
connection. An error from recheck is returned as is.

The entry runs on a goroutine that locks its OS thread and never unlocks it: setns, then a dial
of an address literal (no name is resolved), then the goroutine exits and the runtime ends the
thread. No other goroutine ever runs on a thread that entered a namespace. The returned connection
keeps its namespace and may be used from any goroutine. Multipath TCP is off for this dial
whatever GODEBUG says: its first use would run process-wide probes inside the namespace.

Caller rules:
- Always pass a context with a deadline; without one a filtered port waits out the kernel's SYN
  retries.
- The peer is whatever the namespace's owner routes the address to; authenticate it if the
  namespace is not the platform's own.
- Linux amd64 and arm64, root only; elsewhere both functions return an error.

Tests: unit tests need no root. The reach-tagged tests run as root on a bare test node through
test/harness/experiments/e44.sh: own listener only, no host connection made from the namespace
under concurrent load, restart between inspection and entry detected with no connection made,
deadline inside the namespace, thread count stable after 1,000 dials.

### 2026-11-20 — Management API contract: `sp-probe mgmt` and the upstream CLI pin

- `test/harness/experiments/pins-cli.env` pins the upstream `supabase` CLI 3.0.0 by archive
  SHA-256 (amd64, arm64). `e45.sh` verifies the archive in `IMAGE_CACHE` (fetching it when
  absent or wrong), extracts `supabase-cli-3.0.0-<arch>` from it on every run, and runs
  `projects list` only inside a throw-away container: no network, the caller's uid, no
  capabilities, read-only root, the binary and a scratch directory as the only mounts. The run
  image is built FROM scratch from the host's loader and the libraries the binary names (glibc;
  read with readelf, never run on the host). Container name from `E45_NAME`; container, image,
  scratch and partial files are removed on every exit. One PASS/FAIL line per try, each with a
  named control; `RESULT` and `VERDICT` lines; exit 1 when a try failed. A pin bump: rerun
  `e45.sh` and the contract test.
- `docs/management-api.md` holds only what `e45.sh` observes: the host is set by a profile file
  (`name`, `api_url`, `dashboard_url`, `project_host`; unknown keys, a non-http(s) URL or a
  missing member refused) chosen by `--profile`, then `SUPABASE_PROFILE`, then
  `~/.supabase/profile`; `SUPABASE_API_URL` does not redirect. `GET {api_url}/v1/projects`,
  `Authorization: Bearer TOKEN`, error document `{"message":"..."}`, 401/404 -> exit 1, no
  retry. Tokens must match `^sbp_(oauth_|v0_)?[a-f0-9]{40}$`; others are refused unsent.
- `sp-probe mgmt --listen ADDR --log FILE --token FILE`: serves `GET /v1/projects` (exact target,
  no query) for one bearer token: 200 one-project array; other or no Authorization 401
  `{"message":"Unauthorized"}`; anything else 404. Per request, before answering, it appends
  `request METHOD TARGET PROTO`, `header NAME` (sorted), `auth SCHEME` (1-32 letters before a
  space, `?` otherwise, `-` absent), `answer STATUS`; a failed log write answers 500. Header
  values are never logged; the target and header names are logged as received, so never carry
  a secret in either. ReadHeaderTimeout 10 s, MaxHeaderBytes 64 KiB.
- `TestMgmtContract_ProjectsList` reads the doc's table (any row of another call fails it) and
  runs the CLI named by `SUPAPACE_CLI` per row in an empty home; without the variable it skips
  with a message. It runs the third-party binary directly: only on a disposable machine or
  inside a container.
- Known limits: only `projects list` is checked; the control plane serves no part of this API.

### 2026-11-20 — `internal/dashsock`: the dashboard socket's server

- `NewServer(pub, node, baseDomain, addrs, m, p) *Server`: pub and node are the assertion key
  and node id; addrs must be `dashcfg.For`'s (a connection string rendered from a zero address
  is refused, 503). `Server.Log` (set before `Serve`; nil uses `slog.Default`) receives the log
  lines.
- `Listen(dashcfg.Paths)`: creates `SocketDir` (owner root, group `StudioUID`, 0750; a symlink
  there is refused); at `SocketDir/dash.sock` removes a stale socket and refuses anything else
  (a symlink, a file, a directory), leaving it untouched; listens there and sets owner root,
  group `StudioUID`, mode 0660. Must run as root.
- `(*Server).Serve(l)`: pass `Listen`'s listener itself. The peer's uid is read from
  `SO_PEERCRED` of the accepted Unix connection; a listener that wraps its connections makes
  every request `403 peer`.
- Interfaces the caller provides: `Members.MemberRole(ctx, ref, iss, sub)`; `Projects.Facts`
  (returns `ErrNotHere` for a project unknown, placed elsewhere or not live), `Passwords` (ro ""
  while there is no read-only secret), `Keys`.
- Requests: `POST /v1/resolve`, `POST /v1/keys`, no body, one `X-Supapace-Assertion` header.
  Checks in order, first failure answers `{"code":"..."}`: peer is Studio's uid (403 `peer`);
  request target exactly one of the two paths (404 `not_found`); POST (405
  `method_not_allowed`); no body, chunked included (400 `bad_request`); one valid assertion for
  this node (401 `bad_assertion`); per-ref rate, 20 a second, burst 40, counted before any store
  read (429 `rate_limited`); `Facts` and a state of active, restarting or restoring (404
  `not_here`); stored role for (ref, iss, sub) equal to the asserted role (403 `not_a_member`).
- Any error from `MemberRole` is `not_a_member`, except when the request's deadline has passed.
  Any other store error, and a key without its public part, is 503 `unavailable`, logged with
  ref and step only.
- Answers: `dsn_rw` for owner and developer; `dsn_ro` for every role when the secret exists;
  each string must pass `dashcfg.ParseDSN`. `service_role_key` only for an owner under purpose
  `reveal`; otherwise the member is absent.
- Logged: each resolve (ref, iss, sub, role) and each service-key release (ref, iss, sub). Never
  a string, a key, an assertion or an error's text.
- Bounds: 64 connections; request line and header 8 KiB (8192 bytes pass, 8193 get 431); header
  within 2 s; read and write of a request within 2 s; idle connections closed after 2 s; all
  store reads of one request share an 800 ms deadline.
- 431 and malformed requests are answered by net/http as plain text, not `{"code"}`.
- `nodecfg.LockedPostgresVersion()`: the text after the colon of the lock's postgres tag.
  `pgconf.PostgRESTSchemas` and `pgconf.PostgRESTExtraSearchPath`: the values postgrest.conf
  sets; the `data_api` answer splits them on ", ".

### 2026-11-20 — reach: assertions that single out their mechanism

- Test 02 bearer cases add `duplicate_role_permitted_last` (a forbidden role first,
  `authenticated` last). With `duplicate_role` both orders of a duplicated `role` member are
  covered: a decoder that kept either member fails the test.
- Test 02 row `R1b_issuer_claims_role_outside_user_roles`: an issuer token for a role that is
  neither a user role of the project nor forbidden. Only the user-role check refuses it, and
  the gateway's own 401 `invalid_token` is required. The forbidden-list check cannot be
  reached end to end (project create refuses a forbidden user role); the internal/jwtx unit
  tests cover it.
- Test 04 gate has two rows. `only_bridge_name`: the network has the scratch project's slice,
  IPv4 only and the isolated gateway mode, so only the bridge name is wrong; the test also
  checks that the project got that slice. `foreign_subnet`: the earlier case. Both want
  `containment_failed` and no cluster container.
- Test 07: with database-level `statement_timeout=1ms` stored, a check whose statement waits
  on a lock held on `pg_event_trigger` must end with code `timeout` (the platform's own
  bound), then `ok` once the lock is released. holdLock opens its session with the neutral
  startup options.
- Test 09 planted link: the check must report code `internal` (the no-follow open); `peer`
  means the link was followed and fails the test.
- Test 09 hostile init `sasl-iter`: the fake backend gets the platform's salt, so the
  iteration count is the one parameter that differs.
- sp-probe fakepg: `sasl-iter` requires `--salt` (hex) and sends that salt;
  `--password-file` is refused for it. Other modes' flag rules are unchanged.
- Test 09 comments: cleartext and the message-cap/byte-budget pairs are each refused by two
  mechanisms; one of each pair suffices.
- Suite helper daemonPids leaves out a process whose parent is a listed daemon: a child
  between fork and exec shows the daemon's executable and command line.

### 2026-11-19 — `internal/poolcfg`: pooler constants, addresses, connection arithmetic

Provides (imports internal/nodecfg and the standard library only; reads no clock, socket or file):
- Constants: PoolerUID 65526, PlatformDBUID 65525 (each also the gid); PoolerName "sp-pooler",
  PlatformDBName "sp-platform-db"; SessionPort 5432, TxnPort 6543, AdminPort 4000; PoolPortBase
  24096 (the proxy's class "pooler": PoolPortBase + subnet index, clear of the meta range at every
  slice count the dashboard admits); ManagerRole "supapace_pooler" (also the helper schema);
  AuthQuery; RegistryDB, RegistryRole; SecretManagerPassword; DefaultPoolSize 5,
  DefaultMaxClients 100; TierReserved 50; CancelsPerProject 2; ProxyFixedConns 112;
  DefaultProxyMaxConns 2128; ScramIterMax 32768; SourceConnMax 64; EgressFlowMax 4096;
  PoolerMemMB 1024, PlatformDBMemMB 256; SliceHold 25 h.
- RestrictionsOffered (var, false, pinned by a test): network restrictions are not offered until
  the address-preserving path is proven.
- ClassValues, PoolClass: the proxy's class "pooler" as plain numbers (burst 70, one default
  allowance; refusals in flight 48).
- Addrs; For(c) (Addrs, error); Static(c) Addrs; PoolPort(i).
- ValidLabel: 1-63 of [a-z0-9-], no dash at either end, not the shape of a project ref.
  Zone "<label>.<domain>"; Host "<ref>.<label>.<domain>"; ConnString(...) =
  postgresql://<login>.<ref>@<Host>:<port>/postgres?sslmode=verify-full (never a password).
- ProxyWanted(studioDomain, poolerLabel): true when either is set.
- Allowance(m) = m - TierReserved. MaxPoolSize(a) = the largest P with 2(2P+3) <= a, else 0.
  MinMaxConnections(P) = TierReserved + 2(2P+3), saturating at both ends. Fits(m, P) is nil or
  wraps ErrBudget (match with errors.Is), naming both figures, the largest pool that fits and the
  max_connections P needs; it refuses P < 1. ProjectConns(a) = a + CancelsPerProject.
- Tenant, Tenant.Body; ValidAllowList(c, list); OpenAllowList() = [0.0.0.0/0].

Addresses: platform subnet base+7 (platform database), base+8 (pooler); ingress subnet base+3;
pool ports PoolPortBase to PoolPortBase+slices-1. For refuses, with joined plain errors, a
non-IPv4 platform or ingress subnet, an address outside its subnet, a gateway address that is
one of the three, an allocation range holding a platform member, more than 41,440 slices, and a
project uid range holding either uid. It assumes nodecfg validation passed.
Static never fails or panics. It equals For where For accepts; otherwise every member For refuses
is the zero value and a refused port range is 0-0, so it never names an address that belongs to
something else. Renderers use Static and omit what is zero; init and servers use For and do
nothing when it refuses. The ingress network has no allocation range: attach the pooler with
--ip and treat "address in use" as a refusal.

Figures: the default tier's connection budget at max_connections 120 gives allowance 70, the
largest pool 16 (MinMaxConnections 120), a project's proxy share 72, and the ceiling
28 x 72 + 112 = 2128. Tests recompute each from the budget's rows and rules.

Tenant document: Body is exactly the registration JSON with one user (the manager, transaction
mode) and no sni_hostname. It refuses a host that is not IPv4 unicast (private ranges are
accepted), a port outside 1-65535, a pool size or client count below 1, an allow list that is
empty, longer than 32 or not masked IPv4, and an empty password; no error carries the password.
Callers substitute DefaultPoolSize, DefaultMaxClients and OpenAllowList() for zero values first.
String, GoString, Format and json:"-" keep the password out of fmt, slog and JSON. %p of a value,
or a Tenant in an unexported field of a printed struct, still prints it by reflection: never
format those.
ValidAllowList takes 1 to 32 canonical IPv4 prefixes and refuses overlap with the project block,
the platform, ingress, Docker-pool and backup subnets, 0.0.0.0/8, loopback, link-local,
multicast and 240.0.0.0/4.

internal/agent: Spec embeds OpsSpec (spec_ops.go: IOLimits, APISpec, Rate, OpsSpec; standard
library imports only, pinned by a test). Nothing reads a field yet. A zero OpsSpec renders the
cluster and the REST container byte for byte as before (recorded digests); a change meant to
alter a rendering re-records them. Spec is not serialized, so no stored form changes.

### 2026-11-19 — store: schema version 2, restore operations, parking guards, new epoch

- Migrations: Migrate applies schema.sql on an empty database (cp_meta at version 1), then every
  file of `migrations` above the stored version, setting schema_ver after each, all in one
  transaction under the migration lock; a stored version above schemaVersion (or below 1) is
  refused naming both. schemaVersion = 1 + len(migrations). A new version is one embedded file
  migration_<n>.sql plus one list element; tests compare with schemaVersion and with the tables
  the files create (schemaTables), never with literal numbers. A failing file rolls back all.
- Version 2 (migration_2.sql): project state restoring; operation states waiting_job and
  superseded; operation kind restore; operation.result (jsonb); project.slot_op; the
  operation_open index covers waiting_job; tables backup_state, backup_job, backup_set,
  backup_timeline, backup_gap, backup_notice, offsite_object, offsite_info_version. Nothing
  writes a job, backup or off-site row yet.
- openStates = pending, running, waiting_job, aborting: one open operation per ref, used by the
  submit and retry check and by NextOperation's "oldest open of its ref". readyStates (no
  waiting_job) is what NextOperation picks: a parked operation owns its ref but is never run.
  cmd/supapaced/boot.go's adoption list does not yet include waiting_job (nothing parks before
  layout 2); it must before any layout-2 project exists.
- Admission (one rule, under the project row lock, for SubmitOperation and SubmitRestore):
  active takes each kind; restarting takes a restart or a delete when the newest of its restart
  and restore operations is failed (supersedes nothing); restarting or restoring takes a restore
  when the ref's newest operation is a failed restore or restart; restoring takes a delete when
  the newest is a failed restore. The last two supersede that operation in the same transaction:
  state superseded (final, never retried), slot_op null, its queued jobs failed with code
  cancelled. A restoring project whose newest operation is a failed delete takes only op retry
  of it. Refusals are ErrConflict naming the open operation, else "<kind> needs ...; it is
  <state>", followed by "; operation N (kind) failed; op retry N continues it" when the ref's
  newest operation is failed. Match ErrConflict with errors.Is, not the text.
- RetryOperation: a failed operation back to pending with attempts 0 while no other operation of
  the ref is open; a restore only while it is the ref's newest operation (its set and target
  were chosen at its submit; restores keep the generation), else ErrConflict naming the newer
  one. The check runs under the project row lock that every submit takes. It also sets
  params.job_floor to max(backup_job.id) (0 if none).
- SubmitRestore(ctx, ref, params) (id, superseded, err): kind restore, pending, the project's
  generation and epoch; the project state is not changed. SetProjectRestoring(ref, opID):
  active|restarting|restoring -> restoring while opID is an open restore of ref.
  FinishRestore(id, result): a running restore -> done with result, its restoring project
  active, slot cleared, one transaction; anything else ErrConflict and nothing written (a second
  call after a commit is ErrConflict). Generation and applied_gen are untouched by restores.
- SetSlot(ref, opID): free -> opID, same opID no-op, another -> ErrConflict; ClearSlot frees it
  only if opID holds it. Neither checks that opID exists.
- RaiseJobFloor(id, count): running only; floor and optional attempt + 1 in one statement;
  returns both; other params members kept (re-read the operation afterwards). Requeue(id,
  notBefore): running -> pending, attempts - 1, last_error kept. SetOperationResult: running
  only (ErrConflict otherwise). RequestAbort accepts a create in waiting_job.
- EnterNewEpoch(ctx, uidFloor) (epoch, err), one transaction: epoch + 1; next_uid =
  greatest(next_uid, max(uid) + 1, uidFloor); queued and running jobs failed with code
  recovered; every open operation but a purge failed with "recovered: the node was recovered
  while this operation was open" (the create of a provisioning project aborted); a running purge
  pending, other purges untouched; provisioning projects aborted with their slice released and
  backup_state.offsite_purge set where a row exists; every slot cleared. Keys, generations,
  configuration and operation params are untouched. Each call adds one to the epoch.
- WALPosition and SwitchWAL run on the control plane's own database: the insert position; then
  pg_walfile_name(lsn) and pg_switch_wal(). The segment is complete afterwards only if WAL was
  written at or after lsn (with nothing written since the last switch the server does not switch).
- WindowError{From, To}: a restore target outside the window; match with errors.As.
- admit counts restoring projects. The pool holds 16 connections. ProjectConfig gains layout,
  upload_mb_per_day and upload_objects_per_day, omitted when zero: older stored configurations
  read and write back unchanged.

### 2026-11-19 — gateway: dashboard host classes, the dashboard table, the request rules

With `dash/domain` in the gateway directory the gateway serves a second class of hosts: the studio
domain (the apex) and one label under it (a project's dashboard). Without the file nothing changes.

Provides (internal/gateway):
- LoadDashboard(dir) *Dashboard: reads dash/domain, tls-studio/{cert,key}.pem, dash/assert.key.
  No domain file: nil. Any of them failing: logged, a Dashboard that serves nothing; the project
  API is served as before, studio hosts are unknown hosts, /-/health carries
  X-Supapace-Dashboard: unavailable (ok when loaded; absent without a domain file). Restart to
  retry. The first TLS pair still stops the process.
- (*Gateway).SetDashboard(d): call before serving.
- (*Gateway).Certificate: a GetCertificate hook; the studio pair for the domain and every name
  under it, nil otherwise (the first pair answers).
- (*Dashboard).Reload / Watch(ctx, every): dashboard.json is opened once per check and re-read
  when the open file's inode, size or mtime changed. A missing file unloads the table (every
  studio host 503). A file over maxDashFile (64 MiB) is refused by its size before anything is
  allocated, and again if more arrives while it is read; otherwise it is read into one buffer of
  its size. The path is opened without blocking; anything but a regular file (a FIFO, a device,
  a directory) is refused before it is read. A bad file, another studio_domain, a key whose kty
  is not RSA or that
  jwtx.DashboardKeyFromJWK refuses: error, the last good table stays, logged once per message,
  not read again until it changes. Refusals of rules 0-4 are counted and logged once a minute
  per ref, never per request.

Order on a studio host: server name must equal the host (421) -> no table 503 -> label not a
ref of the table 404 -> rule 0 (400) -> apex or /-/auth/ (exact, raw) to the sign-in seam ->
rules 2-10 -> slots (project 429, dashboard 503, gateway-wide 503) -> the forward seam.
Rule 0 refuses a raw "#" anywhere in the request target (path or query), and, in either reading
of the path (segments decoded one by one; the path decoded whole), an empty segment, ".", "..",
a backslash, a byte outside 0x20-0x7e, a broken escape, or readings that differ. "%23" is an
ordinary character in the path and in the query. Rules 2, 3, 7 read
lower-cased segments. An API path is /api itself or anything under /api/; /api/ai and /api/mcp
are refused with or without further segments. The read_only and reveal exceptions match the
path as sent, exactly. A host with a dot in its label, capitals, a trailing dot or a
non-numeric port is not a studio host.

Seams (unexported): dashAuth, dashForward func(w, r, *dashRequest); nil answers 503.
dashRequest: Table, Ref ("_" on the apex), Path, Lower, Session, Role, Purpose, Keys (issuer
keys as dashboard keys), Dash. The forward seam runs holding all three slots; r.Body is already
capped. writeDash(w, status, code) writes a refusal with the dashboard headers and no-store.
Every serveDash answer carries nosniff, the dashboard CSP (dashCSP), COOP, CORP and
Referrer-Policy same-origin, never the sandbox; answers made before the switch (/-/health, 505,
the origin-form 400) keep the as-built headers.
Known limits: refusals of rules 5-10 are not logged yet; a request with no TLS server name passes
the 421 check (as built); a refused non-regular table file is checked again on every tick.

### 2026-11-19 — gateway: informational responses, body limit, CI failure excerpt

- Informational (1xx) responses of the upstream. Before: relayed on both protocols, filtered,
  at most 8 per request. Now:
  - HTTP/1.1: relayed, filtered as before (no `Server`, `Set-Cookie2`, `Clear-Site-Data`, no
    `Set-Cookie` with `Domain`) and capped at 8 — except to a client that sent
    `Expect: 100-continue`, which gets none;
  - HTTP/2: none relayed.
  Every upstream 1xx still counts, relayed or not: the 9th ends the request with 502
  `upstream_unavailable` and the upstream connection is not reused. A client waiting for
  `100 Continue` gets it on both protocols: the server sends its own when the body is first
  read.
- Why. Over HTTP/2 the server writes a 1xx frame from the response's header map on another
  goroutine and stops waiting for it when the client resets the stream or closes the
  connection, while the proxy changes the map: a data race that outside the race detector can
  end the process, and the gateway is shared by every project. Over HTTP/1.1 the server writes
  its own `100 Continue` from the goroutine that first reads the body; a relayed 1xx could use
  the connection's write buffer at the same moment and garble or lose the answer.
- Body limit (8 MiB), unchanged for clients: a declared length over the limit is refused with
  413 `body_too_large` before the upstream is dialled; a streamed body is cut at the limit
  with the same 413. On HTTP/1.1 the connection is then closed after the answer — sending
  side first, a short wait, then the socket — so a client that is still sending receives the
  complete 413. Inside, the limit no longer holds the server's response writer (it set a
  header from the upstream connection's writing goroutine); the handler tells the server
  about the limit.
- A client that has gone gets no response. An HTTP/1.1 client that half-closes its connection
  after sending the request counts as gone and gets none either: the server library cancels
  the request at end of input. Not new; stated because it surprises.
- Caller rule (`internal/gateway/proxy.go`): hooks given to the upstream transport — trace
  hooks, the request body's `Read` — run on the upstream connection's reading and writing
  goroutines, not on the handler's. They must never touch the server's `ResponseWriter` or
  its header map, and must never panic (a panic there ends the process). Use atomics, or
  hand the result to the handler through the round trip's error.
- Tests. `TestForward_InformationalThenClientReset`, `TestForward_InformationalThenClientCloses`
  and `TestForward_BodyLimitWhileRelaying` detect a regression only under the race detector
  (CI runs it); `TestForward_InformationalWhileExpectContinue` and
  `TestServer_BodyLimitStillSending` also without it. The burst test closes idle connection
  pools while it waits for goroutines to settle: a dial that outlives its request adds an
  idle connection later.
- CI, `unit` job: for a failing `go test -race -v` the step prints each complete race report,
  each panic or fatal error (each cut at 400 lines), and the last 400 lines of each failing
  test's own output, subtests included; with none of these, the last 100 lines of the log.
  The exit status is unchanged.
- Known limits. The upstream transport has no idle timeout yet: up to 16 idle upstream
  connections per project stay open until the upstream closes them. The wait before the
  connection is closed after a 413 is the server library's; `TestServer_BodyLimitStillSending`
  fails if it goes away.

### 2026-11-19 — agent: route stress test runs until the race was exercised

`TestSetRoute_FlagDrainStress` no longer counts rounds after a fixed window: it runs at least
PR_STRESS_SECONDS (default 2 s) and until 10 rounds were contested (an activation accepted since
the round before), failing only after that window plus 2 minutes. A fixed window let a slow
2-core race-instrumented runner finish with 9 rounds, and a run of the test alone spend the
window generating the shared RSA keys with no activation accepted. The invariant check is
unchanged. New `TestSetRoute_FlagReadUnderLock` holds the route lock, waits until an activation
is parked on it, sets the flag and requires ErrContainment: it fails if the flag is read before
the lock is taken, which the stress test does not catch. No product code changed.

### 2026-11-19 — the pooler lab (test/harness/experiments: pool-lab.sh, lib-pool.sh, e40–e43, e48)
Scripts that start the shared connection pooler (Supavisor) by digest beside three clusters inside
a bare test node, under the node's own tables, and print one line per criterion. No Go code.

Run one: `make build && make node-bare NODE=<node>`, then
  test/harness/experiments/pool-lab.sh <node> test/harness/experiments/e4N.sh
Needs about 3.5 GB of memory for the node. The pooler's archive goes into
$IMAGE_CACHE/pool/ (the node's boot never loads that directory). Environment: IMAGE_CACHE,
LAB_PREFIX (default sp-test-<node without "sp-">), OUT_SUBNET (default 192.0.2.32/27; a
documentation range, one lab per subnet on a host). `make node-down NODE=<node>` at the end.

pool-lab.sh (host side, bash):
- checks the kit's cluster flags against clusterRunArgs in internal/agent/cluster.go;
- fetches the pooler's image index by digest (pins-pool.env) and checks it. The first run writes
  both per-architecture digests into pins-pool.env; later runs refuse an index that names others;
- pulls and saves the image once, then loads it into the node and addresses it there by the manifest
  digest of the host's architecture;
- refuses to start when <prefix>-out, <prefix>-client or the kit directory in the node
  (/var/lib/sp-exp/pool) already exists;
- creates the lab bridge <prefix>-out, a client container on it (the "outside") and the node's
  connection to it, all labelled supapace.test=1;
- copies the kit and the script into the node and runs them there. A script line
  "@@outside <base64>" is run in the outside client, with the command on its standard input
  (a step that reads stdin in the foreground would eat the rest of its own command);
- on every exit path: stops the run in the node by its recorded pid (TERM, KILL after 30 s), removes
  the node's lab objects by name prefix and label, then its own objects. Each removal is guarded by
  a flag set after the create succeeded and by the test label;
- loads no kernel module and calls no sudo.
Exit codes: the script's; 2 usage, node not running, unsupported machine; 1 a refusal above or a pin
mismatch; 130/143 on a signal.

lib-pool.sh (in the node, POSIX sh) — the functions scripts and later work call:
- lab_up: node tables loaded and verified; networks spi0, spl0, spp0..spp3; clusters 0..2 in the
  agent's two phases with the manager role supapace_pooler and its helper; registry database on
  slice 3; certificates; the pooler; a node-local client; tenants 0..2 registered.
- the pooler container: uid 65526, no capabilities, read-only root, tmpfs /tmp, nofile 16384 with
  RLIMIT_NOFILE=16384, command `sh -c '/app/bin/migrate && exec /app/bin/server'`, published
  0.0.0.0:5432 and 0.0.0.0:6543 on the ingress address. Joined to the four slices (the lab has no
  wire proxy).
- register I [ALLOW|EMPTY] [EXTRA_JSON] [EXTERNAL_ID] [AUTH_QUERY]: PUT of the tenant document;
  prints the HTTP status only. POOL and MAXC set the pool size and the client cap.
- terminate REF; admin METHOD PATH [BODYFILE]: status only, the body is discarded unread.
- pq I LOGIN PORT ADDR SQL [TENANT] (node-local, verify-full) and pq_out I LOGIN PORT SQL (from
  outside): status returned, the answer on one line in PQ. Any FATAL/ERROR/timeout/refused text
  counts as a failure even with status 0.
- hold/held, backends, asadmin I (SQL on stdin as the cluster's admin), helper NAME CONDITION,
  probe_start/probe_wait (prints transactions, failed, tps, pgbench status, aborted clients),
  pooler_oom, pooler_mem_mib, pooler_cpu_ms, outside CMD (sets OUT, returns the status).
- res WORD CRITERION FIGURE with PASS/FAIL/RECORDED/UNRUN/CONTROL; control NAME OK FIGURE (a failed
  control fails the run); finish NAME (exit status 1 on any FAIL); die exits 3.
- Slices: the kit addresses 10.213.0.<index x 64>/26 and refuses an index of 4 or more. More
  clusters need the node's own slice arithmetic first.
- Secrets are random per run, root 0600 under $KIT/s, and passed by environment, file or stdin only.
  A sampler reads every process's command line in the node twice a second and adds a criterion line:
  "no lab secret on any process command line". Limits: a process living under about 0.5 s may be
  missed; only the node's process table; command lines, not environments. The release cookie is
  left out because the pinned image's start script passes it to the VM as an argument (recorded).
- EXIT trap lab_down removes the node's lab objects and the kit directory. A script with its own
  EXIT trap calls lab_down itself.

The scripts (exit 0 when no line fails, 1 on a FAIL, 3 on a lab error):
- e40.sh: the source address the pooler sees for a remote client, a node-local client and the node
  connecting to its own lab-bridge address, read from the pooler's address-not-allowed refusal; then
  an allow_list of the remote client alone. At this pin the node's connection to its own address
  shows that address, so the run fails on that line.
- e41.sh: a per-source connection limit (table inet supapace_limit, L1 to L4) beside the node's
  tables:
  - one source at its limit;
  - a reload of the main tables under 200 active connections;
  - the terse listing while the set changes;
  - a full set with and without the companion rule;
  - the spe0 count.
  Needs the kernel module nft_connlimit, which nothing here loads. Without it the wrapper says so
  and the script runs only the controls that need no limit rule, prints UNRUN for every criterion
  and exits 4. UNRUN means not measured, never a pass.
- e42.sh: the hardened pooler: identity, read-only root, both modes with verify-full, distribution
  on loopback with the image's cookie refused, nothing on a project bridge, shard listeners,
  lockouts, an oversized auth-query result and an expensive verifier (no OOM kill, a neighbour's
  probe loses nothing).
- e43.sh: recorded only: an empty allow_list as a disable; txn_mode_leak_action.
- e48.sh: recorded only: a second tenant <ref>-ro of one cluster for the read-only login.

### 2026-11-19 — pgcap: the relay of one connection and the table's types; pgwire

`internal/pgwire` — the checks of the Postgres wire protocol that the platform's guards share.
Each reads only the bytes it is given and allocates nothing from a length a peer states.
- `Header(h [5]byte) (typ, bodyLen, err)` — the stated length less 4; `ErrLength` (match with
  `errors.Is`) when the stated length is below 4.
- `AuthSubtype(body)` — the first four bytes of an authentication request; an error if it is
  shorter. Constants `AuthOK`, `AuthCleartext`, `AuthMD5`, `AuthSASL`, `AuthSASLContinue`,
  `AuthSASLFinal` (0, 3, 5, 10, 11, 12).
- `ScramIterations(serverFirst)` — exactly `r=…,s=…,i=N` in that order with nothing after it;
  N is 1 to 2^31-1 in ASCII digits, no sign, no leading zero. Extensions are refused.
- `RowFields(body)` — the first two bytes of a row description.
- `EncryptionRequest(first8) (tls, gss)`, `CancelRequest(first8)` — length and code together
  (8 with 80877103 or 80877104; 16 with 80877102).
- `StartupLength(first8) (n, ok)` — the stated length when it is 8 to 10,000.
- `TooManyConnections()` — a fresh ErrorResponse: severity FATAL, SQLSTATE 53300, message
  "too many connections".

`internal/pgcap` — the per-connection half of the wire proxy that stands between shared
services and every project's database server, and the types of its table. Nothing in it names
a class and no cap is a constant: a class is a row of the table.

The table (`class.go`)
- `Table`, `Class`, `Stream` — one JSON document: `listen`, `project_block`, `slice_prefix`,
  `max_conns`, `preamble_ms`, `classes`, and `slices` (slice index → class name → allowance).
  0 means "none" for `message_bytes`, `conns_per_peer`, `cancels_per_peer`, `wall_ms` and
  `notices_max`; `stream` is null for a class without a stream window. Window kinds:
  `WindowConnection`, `WindowResponse`, `WindowNone`.
- `ParseTable(b)` — strict; its errors are texts that start `pgcap: table:` (nothing to
  match). It accepts only `Marshal`'s own bytes: white space, a repeated member, a member in
  another case, a null, an unknown member or anything after the document is refused. Also
  refused: two classes with one name or overlapping port ranges (a class has one port for
  every slice of the block); a port past 65535; a peer or `listen` that is not IPv4; a block
  that is not a masked IPv4 network; a slice prefix not longer than the block's or past /29;
  a window kind other than the three; `window_bytes` of 0 with a window; an iteration floor
  of 0 or above the cap; a stream rate of 0, an interval outside 10 to 1,000 ms or no stream
  connections; a buffer outside 4 KiB to 1 MiB; a deadline, rate, burst or refusal pool that
  is not positive; a negative cap; a count above 2^30; a slice index that is not a plain
  number inside the block; an allowance for a class that does not exist; `max_conns` below
  the sum of `Terms()`.
- `(Table).Marshal()` — the canonical form: members in declaration order, no white space,
  classes by name, slices in ascending numeric order. Always write the file with it.
- `(Table).Terms() (conns, cancels, refusals)` — what the node-wide ceiling must cover: per
  class the lesser of its allowances summed over the slices and its per-peer cap times its
  peers (the allowances alone without a per-peer cap); the cancel allowances the same way;
  the refusal pools, summed.
- `(Class).ConnBytes()` — the worst memory of one relayed connection: two copy buffers and
  four socket buffers at twice their size.

The relay (`relay.go`, `state.go`, `stream.go`)
- `Relay(ctx, Conn) error` runs one admitted connection to its end. `Conn`: `Class` (a copy: a
  reload does not change a running connection), `Client` (the accepted socket; Relay closes
  it), `First` (every byte already read from the client, its first eight at least; sent to
  the server first), `From` and `To` (dial source and target), `Accepted` (the accept time),
  `Streams` (the slice's `*StreamSlots` for this class; the zero value is ready).
- It returns nil when a peer closed the connection, otherwise the reason as an error whose
  text is meant for the log: a breach, the authentication deadline, the wall clock,
  `dial: …`, `fault: …`, or the cause of `ctx` (`errors.Is(err, context.Canceled)` when the
  caller cancelled without a cause). The reasons are not exported values.
- Cancelling `ctx` closes both sides of that connection at once and nothing else, also while
  a paced stream is waiting. When Relay returns, its two goroutines have ended, its stream
  place is released and both sockets are closed.
- Client to server: relayed unread through one buffer of `copy_buf_bytes` (never spliced: a
  connection has two descriptors and no kernel pipe).
- Server to client: one buffer of `copy_buf_bytes`, scanned in place. A read fills it; every
  header that lies complete in it is judged, in order, before any byte of its message is
  forwarded; what was admitted is written to the client in one write before the next read. So
  the relay reads ahead at most one buffer, holds no message (a body longer than the buffer
  streams through it; a dropped one is skipped the same way), and adds no delay: nothing
  admitted waits for more bytes from the server. An authentication request and the first two
  body bytes of a row description are held until they are whole, then checked, then
  forwarded. A breach closes both sides: the client has received every message admitted
  before the refused one and no byte of it. A fault leaves the client the same.
  - A stated length below 4, above `message_bytes` (when set) or above what is left of the
    byte window is a breach. A message counts 1 + its stated length. The window is the
    connection, the response (it starts again after each ReadyForQuery; the startup counts in
    the first) or none.
  - Before authentication-ok only authentication requests, errors (relayed) and notices pass.
    Any other type is a breach, a protocol-version negotiation included: a class's client
    must ask for protocol 3.0 without protocol options. An authentication request is at most
    1,024 bytes; the requests must be SASL, SASL-continue, SASL-final and ok, each once, in
    that order, and the continue's iteration count must lie within `scram_iter_min` and
    `scram_iter_max`. Any later authentication request is a breach. Only the order is
    checked: the relay holds no secret and does not prove that the server knows the password.
  - After authentication-ok a type the relay does not know is relayed under the byte caps.
  - Count caps: parameter-status messages (`param_status_max`) and notices with
    notifications (`notices_max`, 0 for none) are counted in the startup (until the first
    ReadyForQuery), then per window — the connection, each response, each interval of the
    stream state — and with no window in the startup only. Wherever those counts apply, one
    row description of more than `row_fields_max` fields is a breach (per description, never
    a sum). With `drop_notices`, notices and notifications are counted and not forwarded.
  - A copy-both starts the stream state, which ends at the next ReadyForQuery. A class
    without `stream` is closed at that header, and so is a connection beyond
    `conns_per_project` of its slice. In the state the byte window does not count: a read
    takes at most what is left of `bytes_per_interval` in the current `interval_ms`, and with
    nothing left the relay waits for the next interval — paced, not closed. What was already
    read beyond the copy-both counts in the first interval and is paid off, one budget an
    interval, before more is read: the one burst is that read, at most one buffer. An idle
    interval leaves no credit. Each stay in the state has its own interval.
- Deadlines, all from `Accepted`: the dial within `dial_ms`; authentication-ok within
  `auth_ms`; with `wall_ms` set, the end of the connection. Nothing else times a connection:
  a class without a wall clock can be held open by either peer.
- A panic while handling a connection is recovered and ends that connection alone (`fault:`).
  The build tag `faulthook` adds `FaultMarker` ('!'): a server message of that type, of any
  length, before authentication-ok too, panics its connection's handler, to test that rule;
  the product build has no such code and treats the type like any other.

Rules for the owner of the listening sockets (admission, the reload)
1. Derive one context per slice, start every relay of the slice with it, and cancel it when
   the slice leaves the table. Release your own counters after Relay returns; never close
   `Client` yourself. The package keeps no registry of connections.
2. `Accepted` is the accept time: every clock runs from it (a zero or old value ends the
   connection at once; a later one would lengthen every clock).
3. Set the class's `sock_buf_bytes` on the listening socket (`socketBuffers` as the listen
   configuration's control function), so that accepted sockets have it from their first
   packet; Relay sets the dialled socket's, which nothing outside Relay can reach.
4. Leave Nagle's algorithm off on accepted sockets (Go's default).
5. Keep one `StreamSlots` per slice and class for as long as the slice is in the table, not
   one per reload; nil with a streaming class refuses every copy-both.
6. `First` holds everything read from the client and is never an encryption or a cancel
   request: Relay does not read the client's bytes.
7. A first eight bytes with a request code (high sixteen bits 1234) that is not exactly one
   of the three forms above is no startup packet: close the socket unanswered.
8. Compute `From` and `To` from one slice index in one function: Relay cannot tell slices
   apart. A connection without an IPv4 `From` is refused before any dial; a `From` that is
   not the proxy's fails the dial.
9. Log Relay's error text as the reason; nil is a peer's close.
10. Write and accept the table only in `Marshal`'s bytes; a file that is anything else is a
    file that does not parse.
11. A class that streams: size its rate so that the bytes buffered ahead of the client — the
    socket buffers and one copy buffer — over the rate stay under half the sender's timeout.
    The rate paces a server that stays in the stream state; outside the state nothing is
    paced, so a service's sizing against a hostile server rests on the message cap and the
    byte window, not on the rate.
12. A class's client must ask for protocol 3.0; the proof with the real client records that,
    what the client reports when the dial fails, and how many statements a connection serves.

Known limits
- A dial that fails closes the client socket with its startup packet unread, which the client
  sees as a reset.
- Before authentication-ok the size of an error or a notice is bounded only by the class's
  message cap and byte window and by the authentication deadline.
- A result of many small rows is relayed at several million rows a second per connection
  (`BenchmarkRelay_SmallRows`, loopback); a row larger than the buffer costs one read and one
  write per buffer.

Tests: `go test ./internal/pgwire ./internal/pgcap` (add `-tags faulthook` for the marker
build). Test helpers live at package level in the package's test files: new tests there must
not reuse their names. The proof against the dashboard's database client image runs on a bare
test node with that image loaded: build it with `go test -c -tags reach ./internal/pgcap` and
run `TestNode_ClientAfterWrongServerSignature` there as root; it records what that client does
after a wrong server signature. `sp-probe fakepg` gained `--listen ADDR:PORT` (TCP, in place
of `--socket`) and the mode `scram-bad-signature`.

### 2026-11-19 — nodefs: layout-2 project directory, repository directories, quotas
- CreateProjectDirL2(p, ref, uid, gid, quotaMB): CreateProjectDir plus spool/, rspool/,
  rspool/req/, rspool/out/ (all uid:gid 0700, project id with inheritance), same resume rules:
  outer dir owned by uid:gid = complete, nothing below touched (a completed layout-1 directory
  stays layout 1; its spool directories come from a task at the project uid); root-owned =
  interrupted, redone; any other owner = ErrExistsForeign. CreateProjectDir is unchanged.
- EnsureRepoDir(p, subject, uid, gid, quotaMB): subject is a ref or "cp". RepoRoot/<subject>
  root 0755, repo/ uid:gid 0750, user quota of uid on RepoRoot set on every call and, on
  creation, before repo/ is chowned (a quota error leaves repo/ root's). repo/ owned by
  uid:gid is complete and left as the project left it; root-owned is completed; any other
  owner is ErrExistsForeign. quotaMB in 1..2^30.
- EnsureFetchDir(p, subject, uid, gid): fetch/ uid:gid 2750 (files written there get group
  gid); refuses when RepoRoot/<subject> is absent and never creates it. Same owner rules.
- RemoveEmptyRepoDirs(p, subject): repo/, fetch/, then the subject; RemoveEmptyFetchDir(p,
  subject): fetch/ only, repo/ and the subject never touched. Each removal is one
  unlinkat(AT_REMOVEDIR) from a descriptor: never recursive, never follows a link; a non-empty
  directory, a non-directory or a mount point fails and is left. An absent subject, repo/ or
  fetch/ is done; an absent or untrusted RepoRoot is an error. Empty the directories first.
- SetQuotaAt(mount, id, quotaMB): SetQuota's body on any trusted XFS mount; 0 clears.
  QuotaUsage(ctx, mount, id): used KiB and block hard limit KiB of id's user quota (0, 0 = no
  record). The quota tool runs in its own process group, killed when ctx ends; the error then
  wraps ctx.Err() (match with errors.Is); an ended ctx starts nothing.
- Ids for SetQuotaAt, QuotaUsage, EnsureRepoDir and EnsureFetchDir (uid and gid): a project id
  (65536..2^31-1), exactly 70 (control plane) or exactly 65530 (replicator); 0 and every other
  id refused before anything runs. SetQuota and DiskUsage still take project ids only.
- Every path is reached by descriptor from a root-owned, non-group/other-writable root with
  O_DIRECTORY|O_NOFOLLOW; links, FIFOs, devices, files and foreign owners are refused unopened.
  Root never opens anything inside repo/ or fetch/. The project uid can create nothing in its
  subject directory.
- Known limits: no check that a subject's ids belong to it ("cp" with 70 is the caller's
  rule). Reach tests mount throwaway loop XFS images; their helper creates missing loop device
  nodes and retries the attach three times.

### 2026-11-19 — Browser harness and the model of the dashboard sign-in

What it is
- test/harness/browsers: an image with Chromium, Firefox and WebKit (the pinned upstream
  browser-automation image, digest-pinned) plus the automation package at the same release, and
  run.mjs, a step interpreter: one JSON scenario on stdin, one JSON result on stdout.
  Steps: goto, click, fill, wait (url | contains, text), eval (expr | fetch), cookies, setCookie,
  requests, reload, drive (press each page's button; for script off), newTab, pause, clearCookies.
  A scenario names its engine, its host map, an optional CA, a timeout and script on/off.
- sp-dashstub flow: a model of the dashboard's sign-in and log-out on one TLS listener: S (one
  redirect), sign-in.S, <ref>.S and an issuer host. Same endpoints, cookie names and attributes,
  state format, statuses, page headers and order of requests as the gateway; no cryptography.
- test/browser (build tag browser): the CA/secure-context check, the public-suffix control and
  the sign-in and log-out scenarios in three engines, studio domain off and on the list.

Build and run
- Build (the only step that needs the network): docker build -t supapace-browsers:local
  -f test/harness/browsers/Dockerfile test/harness/browsers. The NSS tools are pinned to an exact
  archive version (checked after install); the automation package comes from the committed
  lockfile with npm ci --ignore-scripts.
- Run, in a node started bare with the image loaded, as root:
  go test -c -tags browser -o bin/browser.test ./test/browser, then run bin/browser.test in the
  node. sp-dashstub is taken from /opt/supapace/bin (override: SP_DASHSTUB). The model listens on
  the node's 127.0.0.1:443. Each scenario runs in a fresh container: --network host,
  --cap-drop ALL, no-new-privileges, read-only root, tmpfs /tmp, --memory 2g.
- The run needs no network. Names resolve only from --add-host; /etc/resolv.conf names a server
  that does not answer; every engine uses a proxy that does not exist, bypassed for the mapped
  names, so an unmapped name can be neither resolved nor reached.
- Certificate errors are never ignored: run.mjs installs the run's CA (a fresh NSS database for
  Chromium and Firefox, the system store for WebKit), and every top-level document must report
  window.isSecureContext true.
- The second configuration uses dyndns.org (a public-suffix entry, not HSTS-preloaded); the CA
  of each run is name-constrained to the studio domain and the issuer host.

The model's test-only endpoints (on the issuer host)
- /-/count: requests to the dashboard's hosts (favicon not counted) and to /authorize since the
  last read, as JSON; reading resets both.
- /-/clock?add=N: moves the model's clock N seconds ahead.
- /-/drop-session?n=N: the next N successful sign-ins set no session cookie (a browser that
  does not present it).
- /link?to=URL: a page on another site linking to a URL under the studio domain.
- The issuer page posts itself unless the issuer host holds the cookie hold=1.

Bounds the model enforces (the gateway's tests should reuse its tables)
- state v1.<target>.<a>.<n>.<p>, at most 1,404 characters; return path at most 1,024 bytes,
  rule 0 on its path, first segment neither "-" nor "api"; a raw 0x00-0x20 or 0x7f anywhere,
  "//" or "\" refuse it to "/"; a percent-encoded space is kept.
- At most 16 login cookies (a login with 16 or more clears them first); a login cookie is
  __Host-sp-login- and exactly 11 base64url characters.
- Callback and session endpoint: id_token and state exactly once; 16 KiB body; token at most
  8 KiB of the token alphabet; other methods 405.
- Session-page mark: Referer /-/auth/session?at=<n>, n at most 60 s past and not in the future.
- Log-out ticket: 1 to 16 refs, refused from 60 s after its first issue; chain cap 16.

What the model does NOT stand for
- No signatures: the ID token is "idt." plus the nonce, the session is "s." plus the ref, the
  ticket is "<iat>.<refs>". Token claims, signed tickets, revocation and login CSRF are tested on
  the real gateway only. Rule 0 is applied to return paths, not to request paths.
- Not yet: the ticket's "more" member, /-/auth/signed-out?ended=0 and ?more=1.

Engine facts (the harness's gate runs)
- All three keep __Host- cookies one label below a listed suffix; WebKit keeps no cookie on a
  host that is itself a listed suffix.
- The relay's cross-site post with a SameSite=None login cookie works in all three.
- The session page's script navigation and its no-script refresh both send the full
  /-/auth/session?at=<n> Referer, and a reload re-sends it, in all three.
- WebKit sends no SameSite=Strict cookie on a navigation the harness types after another site:
  start a log-out from a page of the origin, as a person does.
- Firefox and WebKit apply a proxy bypass entry to its subdomains; Chromium matches it exactly.

### 2026-11-19 — internal/offsite: object-store declaration, passphrase, escrow document

- secrets.SealNode/OpenNode(k, name, b): 12-byte random nonce || AES-256-GCM with additional
  data "node\x00"+name. A file opens only under its own name; an empty name is refused.
  Nothing detects an older file of the same name put back by root (root holds the key).
- offsite.Declaration{Endpoint, Region, PathStyle, CAPEM, Projects, ControlPlane Bucket};
  Bucket{Name, Prefix, Write, Read Credential}. Credential redacts under every fmt verb,
  slog (text and JSON) and encoding/json; never encode it with gob.
- Load(p, k) → (d, State, err): no file is StateUndeclared with a nil error; both bucket
  names and all four credentials → StateDeclared; any other valid file → StatePartial (the
  file recover writes). A file that does not open or does not check is an error.
- Save(p, k, d): checks d, seals it as "offsite", writes Paths.OffsiteSealed() 0600 by rename
  through nodefs.WriteFile (directory owned by the caller, no group or other write).
- Checks: Endpoint exactly https://host[:port] — no path, query, fragment, user, port 0; the
  refusal never quotes the endpoint. Each prefix is empty, or at most 256 bytes with no
  leading or trailing "/", no empty, "." or ".." segment, no segment over 255 bytes, no
  control byte. One bucket for both uses only with disjoint prefixes (empty overlaps all).
- EnsureControlPlanePass(p, k): returns the passphrase in Paths.CPStanzaSealed() (sealed as
  "cp-stanza"); when absent creates 32 random bytes, base64url (43 characters), by temp file
  and link in a directory that is a real directory of the caller's with no group or other
  write, so racing creators, processes included, all get the winner's. A file that does not
  open is an error and is kept: nothing regenerates it (that would orphan every backup).
- Resolve(ctx, d, c): IPv4 lookup of the endpoint's host, deduplicated and sorted, with the
  endpoint's port (443 by default); the whole answer goes through CheckAddrs, then the 16
  lowest are kept. An empty answer is an error.
- CheckAddrs(c, addrs) refuses the whole set for: not IPv4 with a port; loopback; link-local
  (169.254.169.254 included); multicast; unspecified; 0.0.0.0/8; 240.0.0.0/4 (broadcast
  included); the node's project block, platform, ingress and backup subnets and Docker pool
  (from c); the subnet of any bridge (an interface with /sys/class/net/<if>/bridge), read
  from the kernel at each call. Subnets of other interfaces are accepted. An interface list
  that cannot be read refuses. An empty set passes.
- BuildEscrow(k, d, cp, worker, version, now) → all, kek, rest: JSON, 2-space indent,
  created_at RFC 3339 UTC; of d only the endpoint, region, path style, CA (null when empty)
  and the control-plane bucket, prefix and read credential; read_only is false when that
  read credential equals the write credential. kek part: version, part, kek. rest part:
  everything but kek, kek_id included. What it returns always parses.
- ParseEscrow(all) or (kek, rest) in either order: exact member set by path (unknown,
  duplicate, case-folded, missing and null members refused; only ca_pem may be null), depth
  at most 4, at most 1 MiB a part, version 1 (a newer one is named as such), kek 32 bytes of
  strict base64 matching kek_id, stanza "cp-"+incarnation (a canonical decimal string up to
  2^64-1). Errors carry a byte offset or a member path, never a value. Escrow and
  EscrowControlPlane print and marshal redacted; Escrow.Offsite.Read is a Credential.
- KEKID(k): first 16 hex digits of SHA-256("supapace-kek-id\x00" || key).
  EscrowRestHash(rest): hex SHA-256 of a valid rest part re-marshalled without created_at,
  so every print of one state hashes alike.
- supapaced offsite set|show, root only. set reads four keys files (access key, newline,
  secret key; at most 4 KiB; no blank or control bytes), runs the object-store client's
  offline checks for each bucket and credential, then Save; it makes no request. show prints
  state, location and presence flags, never a key; exit 0 when undeclared, which needs no
  key. Further sub-commands register in offsiteCommands from their own init().
- init writes cp-stanza.sealed once, after the key escrow is acknowledged; a rerun with the
  file present does not load the key and reports nothing to change.

### 2026-11-19 — store: persisted job queue
- `internal/store/job.go`: table `backup_job`; two lanes, `push` (kinds push, replicate) and
  `backup` (every other kind); at most one running job per subject (unique index
  `backup_job_slot`, the per-project slot).
- `SubmitJob(ctx, NewJob)`: queues a job no operation owns; a non-zero `OpID` is refused.
- `SubmitJobAndPark(ctx, opID, NewJob)`: one transaction: inserts the job for opID and moves the
  operation running -> waiting_job with attempts - 1. Not running: `ErrConflict`; unknown
  operation or a subject without a `backup_state` row: `ErrNotFound`.
- Both refuse a job whose lane is not its kind's lane.
- `NextJob(ctx, lane)`: one update statement makes the next job running (runs + 1, started_at).
  Each subject offers only its lowest eligible queued job. Order: subject `cp` first, then the
  subject whose last job started longest ago, then the lowest id. A subject with a running job
  is skipped; a project whose `slot_op` is set admits only that operation's jobs.
  `ok=false` means nothing was picked: an empty lane OR a clash with the other lane's pick of
  the same subject at the same moment. Ask again on the next turn; never retry in a loop.
- `FinishJob(ctx, id, state, code, message, result)`: running -> done or failed only, else
  `ErrConflict` (unknown id: `ErrNotFound`); a failure without a code is `ErrConflict` and
  writes nothing. If the job's operation is waiting_job it becomes pending, due now; a failed
  job counts one attempt and sets last_error "<code>: <message>", except for the codes
  `interrupted` and `cancelled`, which count nothing. An operation in any other state is left
  untouched. A result that is not valid JSON ends the job failed with code `crashed` (counted,
  slot freed) and the call returns an error naming the job.
- `LatestJob`, `CountJobs`, `CountInterruptedJobs`: an operation's jobs of one step with an id
  above the operation's job floor only; the last counts those that ended `interrupted`.
- `InterruptJobs`: every running job -> failed/interrupted, its operation resumed, not counted.
  Call it only after every job container is gone.
- `CancelJobs(op)`, `CancelSubjectJobs(subject)`: queued -> failed/cancelled; running jobs are
  returned untouched for the caller to kill and record with FinishJob. No operation is changed:
  cancel an operation's jobs only after it has left waiting_job.
- `LastJob(subject, kind)`: the newest by id, any state; none after pruning is normal.
- `PruneJobs(olderThan, limit)`: deletes up to limit done/failed jobs finished before olderThan,
  referenced by no backup set, whose operation is not open. Repeat while it returns limit.
- Limits: the store bounds no text size (the caller sanitises); queued jobs per subject are
  bounded by the scheduler, not here; a pick reads every job row of the lane's queued subjects,
  so its cost grows with the retained history (no index on subject).

### 2026-11-19 — store: backup state, timelines and the record of uploaded objects

- backup_state: EnsureBackupState(subject) inserts the row once. A project's incarnation is
  "1"; the control plane's ("cp") is its database system identifier as an unsigned decimal,
  read when the row is inserted and never changed. GetBackupState; MarkStanza
  (stanza_created, plus timeline 1 recorded unless "cp"); SetSeeded; SetOffsitePurge;
  PauseReplication; MarkForcedFull(day) - false when that UTC day's forced full was taken.
  An unknown subject is ErrNotFound (match with errors.Is).
- RecordPush: last_push_ok = At only when Complete; spool figures replaced; the newest
  segment kept when none is reported (a malformed one is refused by the database); the quota
  report stored with quota_at = At when not nil. Each gap (cause "quarantine" only; any
  other cause is refused) is stored cleaned and cut to 256 bytes, with a notice of that
  code. Notice(subject, code, detail) upserts: count + 1, last_at, detail (cleaned, 256
  bytes). ListGaps returns the newest 64, newest first.
- RecordUploads: one transaction under the subject's row lock. Hashes are 32 raw bytes,
  not hex. Refused whole, nothing written: more than 2,048 rows or set labels, more than 4
  info versions, a key outside 1-1,024 bytes or with a control byte, a version id with a
  control byte, a size outside 0..SetFileMax, a hash that is not 32 bytes, a malformed set
  label. First hash wins: a recorded row that has a hash never changes and raises nothing.
  A row without one (rebuilt from a listing) takes hash, inode and ctime only from a
  report under the same version id - a missing id never matches - and otherwise is left
  as it is and raises notice offsite-differs (detail: the key, cut to 256 bytes). A key
  repeated in one call: the first is kept. Info versions: one row per version id. Each
  label in SetsComplete becomes replicated and gets listed_at = At (once) when the call
  carries info versions or a backup.info / backup.info.copy version exists at or after
  the set's stop. Day counters (UTC day of At, never moved back) add every reported row
  and its bytes. last_repl_ok = At when Complete. Returns whether a non-zero budget is now
  exceeded.
- MergeListing(page, epoch): one transaction per page. ErrConflict once rebuild_epoch >=
  epoch. A row with a hash keeps everything but seen_epoch; a row without takes the
  listing's size, version id and time - the last listed for its key, i.e. its oldest
  version - so pages must be merged once, in listing order, from the stored markers. A
  listed .history of a timeline 1..2^31-1 that has no row is inserted abandoned (never
  for "cp"). The last page raises record-not-in-store with the count of rows no page
  listed, clears the markers, sets rebuild_pages to 0 and rebuild_epoch to epoch.
- Lookups by name (HasArchiveObject, SegmentReplicated, NewestRecordedSegment) match any
  archive id under archive/<stanza>/ and check each candidate with walname.RepoPath.
  SegmentReplicated also needs last_repl_ok at or after that row's uploaded_at.
  ObjectRows streams the record in byte order of the key.
- Only RecordUploads and MergeListing insert object rows, and only MarkStanza,
  BeginRecoveryAttempt and MergeListing insert timeline rows - each by one statement with
  a column list. A source test pins this.
- Timelines returns the admitted set: every row, never nil; an empty list admits none.
  "cp" has none. For a restore: BeginRecoveryAttempt(ref, stanza, op, held) before each
  recovery start returns the pending timeline, or ErrTimelineConflict with nothing
  written; it refuses "cp". ConfirmTimeline(ref, op, tli) makes that pending timeline
  recorded and sets params.t8_done in the same transaction. Anything else, including a
  second call, is ErrConflict, so re-read the operation and skip the call once t8_done is
  set.
- LagCounts(push, repl): subjects - "cp" and every active or restarting project - whose
  last complete push / replication is older than the threshold. A subject that has never
  completed one is not counted. RepoQuotaTotals: sum and maximum of disk_quota_mb over
  projects that are neither purged nor aborted.

### 2026-11-19 — nft: egress for replication jobs, the saved address set, one ruleset lock

The ruleset (`internal/nft/ruleset.tmpl`) gains set `offsite4` (`ipv4_addr . inet_service`; the
elements line is omitted when empty) and four rules. Label order is
`I1 I2 F1 F5 F7 F2 F3 F6 F4 B1 B2 B3 B4 B8 B6 B10 B9`:
- F5: a new TCP connection from the backup bridge (spb0) to an element of `offsite4` is accepted.
- F7: established/related packets from spb0 are accepted. This carries the rest of a connection F5
  accepted, also after its address left the set. Without F7 only the handshake passes.
- F6: replies routed into spb0 (established/related) are accepted.
- B10: frames between spb0 members are dropped (B9 and the policy would drop them anyway; B10 is
  the rule a test can address).
Everything else from spb0 (UDP, DNS, other ports and addresses, the host, IPv6) falls to F2/I2.

Rendering:
- `RenderWith(c, set)`: IPv4 only, port 1..65535, at most 256 elements; sorted, no duplicates,
  so one set always renders the same bytes. `Render(c)` is `RenderWith(c, nil)`.
- No rule limits where an element points. Callers pass only `offsite.Resolve`/`CheckAddrs` output.

The saved set, `Paths.OffsiteAddrs()` (`/etc/supapace/offsite.addrs`):
- One canonical `ip:port` per line (`netip.AddrPort.String()`), a final newline, empty or absent
  meaning none.
- A regular file, 0600, owned by the daemon's uid, at most 64 KiB, opened without following
  links. Anything else is refused.
- `InstallSet` is its only writer. It holds the set the loaded tables hold.

One lock for every writer and check, in every process (`Paths.NftLock()`, a regular 0600 file
created on first use, never through a link):
- `Load`, `InstallSet` and `EnsureRules` take an exclusive flock; `Check`, `SavedSet` and
  `RenderSaved` a shared one.
- It is tried without blocking every 10 ms until the caller's context ends. Not obtained: `Check`
  answers `ErrUnverified`; `Load`, `InstallSet` and `EnsureRules` return an error matching the
  context's (`errors.Is(err, context.DeadlineExceeded)`).
- `SavedSet` and `RenderSaved` take no context and wait at most 30 s, then return an error
  matching `context.DeadlineExceeded`.
- Never call an exported locking function while holding the lock in the same process: flock
  conflicts between descriptors of one process, so it waits until the deadline.

API:
- `SavedSet(p)`: the saved set; no file means none.
- `RenderSaved(c, p)`: `RenderWith(c, SavedSet(p))` under one hold of the lock.
- `InstallSet(ctx, p, c, set)`, under the lock, in this order: render; write the ruleset file if
  it differs; load; only then write the addresses file if it differs (or its mode/owner is
  wrong); then the checksum.
  - A failed load puts the previous ruleset file back, with no reload.
  - A failure after the load puts both files back and loads the previous ruleset again, on its
    own 1-minute context detached from the caller's.
  - A failed restore of the addresses file ends the put-back: files and tables stay at the new
    set under the old checksum, so `Check` reports drift and `EnsureRules` converges.
  - Load failures match `ErrUnverified` (nft could not apply the file); this is not a lock error.
- `EnsureRules(ctx, p, c, load)`: renders from the saved set and writes the ruleset file when its
  content, mode (0600) or owner differs; reports whether it wrote. With `load` it loads when the
  file changed or `Check` fails, then checks again; a check that still fails is its error. It is
  the only way the ruleset file is written outside a set change. `init` calls it without `load`.
- `Load` and `Check` are unchanged apart from the lock. `Check` now creates the lock file.

Known limits:
- The daemon's start still renders with `RenderSaved`, then writes and loads outside the lock. A
  start racing another process's `InstallSet` can load the older set (Check passes) until the next
  install.
- The drift reload loads the file as it is.
- init's removal of leftover temporary files runs outside the lock; a concurrent install then
  fails cleanly.
- A flow to an address removed from the set lives until it closes; new connections fail.

### 2026-11-19 — gateway: sign-in host, studio-domain redirect, transport security

Host classes under the studio domain S, after the TLS server-name check (421) on each:
- S itself answers one thing, with no table and no path rule: GET or HEAD of exactly "/" (any
  query) is 302 to https://sign-in.S/ with no-store; every other path or method is 404. Nothing
  of the request reaches the answer; no cookie is read or set.
- sign-in.S (dashcfg.SignInLabel, a label no ref can have) is the sign-in host: no table 503;
  rule 0; then every request goes to the sign-in seam with Ref "_", holding no slot.
- <ref>.S is a dashboard host, as before. Its /-/auth/ paths also go to the sign-in seam.

Rule 5 exception: a navigation without a valid session whose single Referer is exactly
https://<ref>.S/-/auth/session?at=<n> (S as configured, no port; n plain decimal seconds, no
sign or leading zero, not in the future, at most 60 s old by the gateway clock) is not
redirected: dashRequest.Unpresented is set and the request goes to the sign-in seam, after
rules 2-4 and before any slot. Anything else gets the 302 to /-/auth/login as before.

Every answer the gateway writes on S, sign-in.S and dashboard hosts carries
Strict-Transport-Security: max-age=31536000, never includeSubDomains (dashHeaders); project
API answers do not. A seam that writes its own answer must call dashHeaders to keep it.

### 2026-11-19 — internal/pooler: the connection pooler's admin client

- pooler.New(dial, apiSecret) *Client: each call opens one connection with dial (the caller's;
  in the daemon a dial into the pooler's network namespace, 127.0.0.1 and the admin port, made
  again for every call) and signs an HS256 token whose only claim is exp, 60 s ahead. The secret
  slice is kept, not copied: do not change it while the client is in use. An empty secret is
  refused before any dial.
- Health(ctx); PutTenant(ctx, ref, poolcfg.Tenant) — register or update, PUT
  /api/tenants/<ref> with Tenant.Body(); Terminate(ctx, ref) — GET .../terminate, nil when there
  is no tenant; Delete(ctx, ref) — Terminate, then DELETE, nil when there is no tenant, and no
  DELETE when the terminate failed (a delete alone leaves pools and sessions running);
  ClearBans(ctx, ref, addrs) — DELETE .../network_bans with {"ipv4_addresses":[...]}.
- ClearBans with no address reads the tenant's ban list and clears every entry that is an IPv4
  address in canonical form (the pinned pooler has no clear-all; its ban keys are the peer's
  IPv4 address or "undefined"). A list over the read bound (about 1,000 entries) is
  ErrTooLarge, which matches neither ErrRefused nor ErrUnavailable, and nothing is cleared: name
  the addresses. A non-IPv4 or zero address in addrs is refused before
  any dial. An absent tenant is ErrRefused (404) for ClearBans, unlike Terminate and Delete.
- ref must match ^[a-z0-9]{20}$; anything else is refused before any dial.
- Bounds per request, dial included: Health 5 s, PutTenant 30 s (registration logs in to the
  cluster), Terminate and each of Delete's two requests 75 s, each ClearBans request 30 s. The
  caller's context still applies; its end closes the connection on every path.
- Answers are hostile: at most 64 KiB is read, status line and headers included; only the status
  is used and every body but the ban list is discarded unparsed (tenant answers hold the
  manager's password in clear). 2xx is nil. 4xx is ErrRefused, the message being the status
  alone ("pooler: the call was refused: status 403"). Dial failure, deadline, 5xx, 1xx, 3xx, a
  malformed or cut answer are ErrUnavailable; no redirect is followed. Match with errors.Is; a
  dial error stays matchable under ErrUnavailable. No error carries a byte of an answer, the
  token or the secret.
- At the pinned pooler, terminate answers 200 for any ref and reports its own fan-out failures
  only in the body, which is not read: success means the call ran. Terminate and delete cut
  client sessions and stop pools but send the cluster no cancel: a statement already running on
  a pooled server connection runs to its end (and commits) before its backend goes. To end it,
  terminate the backend in the cluster (by role name: pooled backends log in as the role), or
  stop the cluster.
- The pooler's admin token is accepted by anything that verifies HS256 with the same secret:
  keep the admin secret distinct from every other secret, and leave the pooler's claim
  validators unset (a required role would refuse every call).
- pooler_reach_test.go (tag reach): one admin call per run against a running pooler through the
  namespace dial, driven by a lab script; secrets come from files named in the environment.

### 2026-11-19 — store: dashboard members, issuer, revocations; dashboard file writer; slice hold

- Schema version 3 (migration_3.sql): member, principal_revocation, dashboard_issuer,
  slice_hold, readonly_cleanup. Nothing existing changes. schemaVersion = 1 + len(migrations).
- store.AddMember: project active, restarting or restoring. ErrConflict for an existing member,
  the 257th member of a project (dashfile.MaxMembers, counted under the project row lock) and the
  16,385th member row of the node (dashfile.MaxMemberRows, counted under the node advisory lock
  Place takes; rows of deleted, purged and aborted projects are not counted).
- store.ChangeMember(ref, iss, sub, fromRole, toRole): toRole "" removes; no row is ErrNotFound;
  a stored role other than fromRole is ErrConflict. It is changeMemberTx in its own transaction;
  any other path that changes a role must call changeMemberTx.
- A change from read_only to anything else writes the clean-up record in the same transaction,
  only through oweReadOnlyCleanupTx(ctx, tx, ref): due = later of stored and now() + delay;
  due_fixed false, failures 0, next_try now(). Never insert into readonly_cleanup elsewhere.
- Converger functions: ReadOnlyCleanups(limit) lists records of active projects whose next_try
  has come, earliest first, with the database's now(). FixReadOnlyCleanupDue(ctx, ref,
  generation, seenDue) fixes due once to the later of due and generation (ms) + delay, only
  while due still equals seenDue (the due the caller read); otherwise it changes nothing and
  the next round fixes it. FailReadOnlyCleanup(ref, retry) backs off, doubling, at most an hour.
  DoneReadOnlyCleanup(ref, startedAt) deletes a fixed record due by startedAt; otherwise sets
  failures 0 and, on a fixed record only, next_try = due.
- store.Revoke: one transaction under a table lock; rows older than MaxSessionSeconds (28,800)
  are deleted first; a principal without a row when dashfile.MaxRevocations (4,096) remain is
  ErrConflict; the later of two times is kept. Callers pass now: a future time holds a place.
- store.SetDashboardIssuer: issuer 1-255 bytes of printable ASCII; client_id, authorize_url,
  end_session_url within the file's caps; session_seconds 300-28,800; at most 16 keys, each RSA
  with kid, n, e within caps and accepted by jwtx.DashboardKeyFromJWK. The stored jwks is read
  back in the same transaction and must decode to the same keys (refuses repeated members and
  members that differ only in case). Every RSA key stored becomes a sign-in key: pass only the
  keys jwtx.ParseDashboardJWKS kept. GetDashboardIssuer: ErrNotFound while unset.
- Every refusal is ErrConflict (match with errors.Is). Rule: the store refuses at insert every
  value or count the dashboard file refuses; one row that Marshal or the gateway refuses would
  stop every push, revocations included. A new column or cap must keep this.
- store.DashboardTable: one repeatable-read, read-only snapshot: issuer, revocations younger than
  MaxSessionSeconds by the database clock, live projects with their members in ref order.
- SetCleanupDelay and SetSliceHold are process-wide (package variables), zero until set; the
  daemon sets both once, before the saga runner, the clean-up converger and the admin API start.
- Slice hold: with the hold above zero, a purge writes slice_hold (node, index, now() + hold,
  later time kept) in the transaction that frees the index; Place skips held indices, drops
  passed rows, and with none free answers ErrNodeFull "no free slice; N held until <RFC 3339>".
  An abort is not held. With the hold at zero Place reads no hold row (as before).
- internal/dashpush: New(src, cfg, paths); Push renders one snapshot, compares it with the file
  on disk without its generation, and when they differ writes by rename (temp file in the same
  directory, mode 0444, file and directory synced) with generation max(disk, now ms) + 1.
  InForce compares and writes nothing. Generation 0 always means no file is in force: with no
  studio domain both return 0. New does not yet read a studio domain (node config has none);
  the change that adds one sets it in New. Keep one Pusher per process: its mutex orders the
  snapshots, and a second pusher can put an older one in place last or remove the other's
  temporary file. A push removes leftover ".dashboard.json-*" names in the directory (the
  name itself, never followed). The path is read with O_NOFOLLOW|O_NONBLOCK; anything that is
  not a regular file of at most MaxBytes that parses is replaced.

internal/dashfile — supersedes, in the entry above, "(MaxProjects 4096, MaxMembers 256,
MaxRevocations 65536, MaxKeys 16)" and "String lengths are not capped here: the reader bounds
the bytes it reads":
- Caps: MaxProjects 4096, MaxMembers 256, MaxRevocations 4096, MaxKeys 16, MaxMemberRows 16384
  (whole file). Strings, in bytes before encoding: node 255, issuer and subject 255, client_id
  255, authorize_url and end_session_url 2048, kid 255, n 1400, e 16, project name 64.
- MaxBytes = 64 MiB bounds Parse's input, Marshal's output and the gateway's read. The largest
  file the caps allow is 65,486,655 bytes (every byte escaped to six);
  TestCaps_WorstCaseFromTheConstantsFitsMaxBytes pins that figure: a cap raised fails it.
- TestDashTable_AtTheCaps_GatewayHeap (internal/gateway, run without -race) bounds the heap
  growth of one reload at the caps under 128 MiB (measured in a child process, GOGC=10); a
  reload allocates about 3.7 times the file size in short-lived garbage.

### 2026-11-19 — supapaced: the endpoint resolver; InstallSet replaces a non-regular path

Resolver (`cmd/supapaced/resolver.go`), started by the daemon's wiring:
- `newResolver(cfg, paths, kek)`; set `r.onChange` before `go r.run(ctx)`.
- `run(ctx)`: a round at once, then every 60 s, until ctx ends (it returns when the round in flight
  ends; SavedSet waits take no context, up to 30 s each).
- A round loads the off-site declaration. Undeclared means the empty set. Otherwise
  `offsite.Resolve`: IPv4 only, sorted, deduplicated, at most 16, and refused whole when any
  address fails `offsite.CheckAddrs`. Only that answer, or the empty set, is ever installed.
- A failed declaration load or a failed or refused resolve installs nothing: the last set stays.
- The set is installed with `nft.InstallSet` (on a context bounded at 50 s) when it differs from
  `nft.SavedSet`, or when the saved set cannot be read (that install rewrites a refused file).
- InstallSet errors: `nft.ErrUnverified` means a failed load (the package put the previous files
  back); a context error means the lock was not obtained. Both are logged and retried next round.
- The first round that reads the saved set checks it with `offsite.CheckAddrs` (an unreadable
  interface list refuses). On a refusal it installs the resolved answer, or the empty set when
  there is none. A refused set is never handed out, also while that install fails.
- `current()` returns (declaration, state, saved set, error). The declaration and
  `nft.SavedSet` are read at each call, never cached. A set that cannot be read (a refused file,
  the lock not obtained within 30 s) or a declaration that does not load is an error and no set:
  the caller keeps what it has. "Unknown" is never "empty".
- `onChange(set)` runs on the loop goroutine, after any install. It is called only with a set
  just read, whenever it differs from the one last handed out (a first set always differs). Keep
  it short; never call an nft locking function from it while holding the lock.
- An unreadable saved set is logged at most once a minute.

nft (`InstallSet`, change): the previous addresses file is read as `SavedSet` opens it
(`O_NOFOLLOW|O_NONBLOCK|O_NOCTTY`, at most 64 KiB):
- A link, FIFO, socket or device at the path is unlinked without being read or followed (a
  link's target is never touched), then the new file is written.
- A directory there is an error and is left as it is.
- A regular file over 64 KiB, like the kinds above, holds no set.
- A put-back after a later failure therefore leaves no addresses file (SavedSet: none). The
  ruleset file and the tables go back to the previous ruleset, so the tables may hold addresses
  no file names until the next install or start converges; the saved set never names an address
  the tables lack.

### 2026-11-19 — gateway: dashboard sign-in, log-out chain and project picker

The gateway answers the sign-in host (sign-in.S) and /-/auth/ on every dashboard host itself
(internal/gateway: dashauth.go, dashlogout.go, dashpages.go; init assigns dashAuth). Nothing
of it reaches Studio. It keeps no state, takes no slot, opens no connection and logs nothing.

Endpoints
- GET /-/auth/login?return=<path>[&retry=1] (both host kinds): makes an attempt, sets its
  cookie, 302 to the issuer's authorize_url with response_type=id_token,
  response_mode=form_post, scope=openid, client_id, nonce, state and
  redirect_uri=https://sign-in.S/-/auth/callback. A request showing 16 or more login cookies
  has every one cleared first. A parameter counts only when the query parses and holds it once.
- POST /-/auth/callback (sign-in host only): reads no cookie and verifies nothing; answers
  the relay page, which posts id_token and state unchanged to
  https://<target>/-/auth/session?at=<gateway clock>. The target is "_" (the sign-in host) or
  a ref of the table.
- POST /-/auth/session (both): checks in order — the state's form and that its target is this
  host (else the 400 page, the cookie not read); the attempt's cookie, exactly once and holding
  43 base64url characters; the token (jwtx.VerifyID with the table's keys, issuer and client
  id, nonce = SHA-256 of the cookie's value). Success: sets the session cookie and answers a
  200 page that navigates to the return path. No cookie, the cookie twice, or
  errors.Is(err, jwtx.ErrNonce): a binding failure — the retry page (200, to
  /-/auth/login?...&retry=1) for n 0, the final 401 page for n 1. Any other token error: the
  401 page at once. The cookie is cleared on every answer that read it.
- GET /-/auth/logout (both): with this host's session it clears it and redirects to the first
  of the principal's other projects (ref order, at most 16) with a signed ticket in t; without
  a session it clears the cookies it was shown and redirects to
  https://sign-in.S/-/auth/signed-out?ended=0, never an error. With t (dashboard hosts only):
  the ticket must verify, name this host first and only refs of the table; the hop clears its
  session cookie without needing one and passes on a ticket for the rest with the same iat,
  exp and more; the last hop redirects to the signed-out page, with ?more=1 when more is true.
- GET /-/auth/signed-out (sign-in host only): clears that host's session cookie and the login
  cookies shown, on every visit. more=1 and ended=0, each written exactly so and once, select a
  fixed sentence; nothing of the query is rendered.
- GET / (sign-in host): the picker — the session's principal's projects from the table, each a
  link to its origin, and a log-out link. Without a session: a navigation is 302 to
  /-/auth/login, anything else 401 login_required.
- A navigation without a session whose Referer is this host's own session address of the last
  minute (dashRequest.Unpresented; the picker tests it itself) gets a 401 page of its own
  words with a link to sign in again. Nothing follows it by itself.

Formats
- Attempt: id a = 8 random bytes (11 base64url characters), secret R = 32 random bytes (43).
  Cookie __Host-sp-login-<a>=<R>; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=None.
  nonce = unpadded base64url of SHA-256 over R's 43 characters.
- State: v1.<target>.<a>.<n>.<p>, at most 1,404 characters; target a ref or "_"; n 0 or 1; p
  the return path in strict unpadded base64url, not empty. Not signed and not secret.
- Session cookie: __Host-sp-session=<dashtok session>; Path=/; Max-Age=<session_seconds>;
  HttpOnly; Secure; SameSite=Strict. Clearing either cookie: same attributes, Max-Age=0.
- A login cookie is a name of __Host-sp-login- and exactly 11 base64url characters; no other
  name is counted, read or cleared.
- Return path (returnPath, applied at the login, in every state read and for the 401 link):
  begins with one "/", no "//", no backslash, no byte 0x00-0x20 or 0x7f, at most 1,024 bytes;
  the part before "?" or "#" passes readPath; its first segment, decoded once and lower-cased,
  is neither "-" nor "api". Anything else becomes "/". Query and fragment are kept.
- dashtok.Ticket gained More (payload {"iss","sub","refs","more","iat","exp"}); a ticket
  lives 60 s and is refused from its 60th second; the vector file holds two accepted tickets
  and the old five-member token as a refused case.
- jwtx.VerifyID needs azp only when aud is an array of more than one member; a present azp
  must be the client id.

Answers
- Pages are constant html/template pages: relay, session and retry (one template), refusal,
  signed-out, picker. The relay page and the navigating page have one constant script each;
  no other answer has a script. The only request-derived strings a page shows are the return
  path (an attribute and a refresh address), a project's name and the display name, all
  escaped.
- Every answer: the dashboard headers (dashHeaders), Cache-Control: no-store and
  Content-Security-Policy: default-src 'none'; script-src <that page's script hash, or
  'none'>; style-src <hash>; frame-ancestors 'none'; base-uri 'none'; form-action 'none' —
  on the relay page form-action is the one origin it posts to. Answers of the sign-in host add
  Origin-Agent-Cluster: ?1. A new page or script must go through signIn.page/headers.
- Refusals that are not pages (JSON code): 401 login_required, 403 cross_origin, 404
  not_found, 503 unavailable (no table, no issuer, an authorize_url that is not https with a
  host and without a fragment). Pages: 400 (state, fields, ticket, body), 401 (three
  wordings), 405 (any other method on the two posts, never a redirect).

Rules and bounds
- The two posts take application/x-www-form-urlencoded bodies of at most 16 KiB
  (dashcfg.Limits.SignInBodyBytes), id_token and state each exactly once; every other field
  is ignored, but error on the callback refuses. The query of a post is never parsed. The
  token is at most 8 KiB of its alphabet.
- The two posts are exempt from the same-origin rule and check no Origin. Every other request
  with a Sec-Fetch-Site that is neither same-origin nor none is 403, unless it is a GET
  navigation to a document. Other methods on the GET endpoints are 404.
- The handler reads the current table once per request and uses that snapshot throughout; a
  table replaced between two requests of an attempt is judged per request.
- The display name is cleaned before it is signed: invalid UTF-8, control characters, U+2028
  and U+2029 removed, cut to 128 bytes at a rune boundary.
- end_session_url is linked on the signed-out page only when it begins https://.

Tests
- internal/gateway/testdata/signin.json holds the cases that need no signature; the tests of
  sp-dashstub flow read the same file. Placeholders: {A} {B} {D} {S} {c*N} {now+N} {now-N}.
- dashauth_fuzz_test.go: FuzzReturnPath and FuzzParseState.
- TestLogin_CookieStateAndRedirect replaces crypto/rand.Reader for one request: the tests of
  this package must stay serial.

Known limits
- No count and no log line for sign-in answers: why a sign-in was refused is not visible to
  an operator yet.
- A ticket is not single use and names no browser: inside its minute it ends the sessions of
  its refs in any browser that follows it. A project that leaves the table inside that minute
  ends the chain at the next hop; the hosts not yet visited keep their sessions.
- An ID token is not single use either: what binds it is the attempt's cookie, cleared when
  read.
- The answers the host switch makes before the handler on the sign-in host (421, 503 without
  a table, the path rule's 400) carry the dashboard policy and no Origin-Agent-Cluster.
- A request showing very many login cookies gets one clearing line for each (bounded by the
  header limit of 32 KiB: about 1,200 names).
- The sp-dashstub flow model has no ended=0, no more and lists both script hashes on every
  answer; those are tested on the gateway only.

### 2026-11-19 — Harness: repository filesystem, object-store stand-in, worker image, hold

What it provides
- `/var/lib/supapace/repo` in every test node: a loop XFS (8G sparse, `state/repo.img`) mounted
  `loop,usrquota,nosuid,nodev,noexec` in bare and full mode, unmounted on stop.
- `deploy/worker/Dockerfile`: pgBackRest 2.58.0 built from source on Alpine. The base comes by
  digest (`worker_base`), the source archive by SHA-256 (`worker_source`) and is checked before it
  is unpacked. Build and runtime packages are pinned. The final stage holds `/usr/bin/pgbackrest`
  and its libraries only, names uid/gid 70 `postgres`, and has no `pgbackrest.conf`, no server
  binaries and no set-uid file. `make images` builds it, archives it as `supapace-worker.tar`
  named `supapace-worker:local` (with `PULL_ONLY=1` it stays in the local Docker), and keeps the
  source archive in `$(IMAGE_CACHE)/src/` once its checksum matches.
- `images.lock` entries `s3_standin`, `worker_base`, `worker_source`. `cache-images.sh` skips them
  (none is loaded into a node).
- `cache-images.sh --save IMAGE NAME ARCHIVE`: archives a locally built image under NAME, whatever
  its own tag. Used for the gateway and the worker, so `GATEWAY_IMAGE=`/`WORKER_IMAGE=` overrides
  still load as `…:local` in the node.
- The object-store stand-in (`test/harness/s3/setup.sh`, run by `node-up`/`node-bare` unless
  `SP_OFFSITE=0`):
  - `$(NODE)-s3` on two networks `$(NODE)-net`, `$(NODE)-net2`, created `--internal` with
    `com.docker.network.bridge.inhibit_ipv4=true`, so the workstation has no address on them;
  - the node joins both; `s3.sp.test` is set by `--add-host` at `docker run`;
  - TLS from a throw-away harness CA; data on tmpfs;
  - buckets `sp-projects` and `sp-cp`: created with the object-lock header, then versioning
    enabled, compliance lock 1 day, lifecycle (abort uploads after 1 day, noncurrent versions
    expire 1 day later);
  - identities: admin, projects-write/read (sp-projects only), cp-write/read (sp-cp only);
  - `/var/lib/sp/s3/`: `endpoint`, `addrs` (the stand-in's two addresses), `ca.pem` and
    `<role>.keys`; root, dir 0500, files 0400. The keys are random per setup;
  - a full node then declares it: `node-init.sh declare-offsite`, the same function as at boot.
    Region `us-east-1`, no prefixes, path style.
- The lab slot: `S3_SLOT` (default: the cksum of the node name mod 250, plus 1; override 0..255).
  The networks are 10.215.<slot>.0/25 and 10.215.<slot>.128/25, the stand-in at .10 and .138,
  the node at .5 and .133. `make lab NODE=…` prints them. Only the Makefile derives them;
  scripts take them from their command line or from the node's `addrs` file.
- The supervisor hold: while `/run/sp-hold` exists, node-init does not start `supapaced` (it logs
  `supapaced held` once). The daemon never reads the file. /run is fresh at every boot, and the
  suite reset removes it. To hold: create the file, then stop the daemon.
- Makefile:
  - `standin-test`: `TestStandin_*` with `SUPAPACE_STANDIN_TEST=1`; it needs the stand-in image
    pulled by `make images`;
  - `harness-test`: `test/harness/harness-test.sh` against `$(NODE)`;
  - `lab`: prints the lab slot and addresses;
  - `reach` passes `SUPAPACE_STANDIN=1` when `$(NODE)-s3` exists;
  - `node-down` removes the stand-in and exactly its two networks too.
- `install-node.sh` refuses before writing anything unless `/var/lib/supapace/repo` is the top
  mount, XFS, user quota enforced, `nosuid,nodev,noexec`, not the projects filesystem (same
  mount source), and `BIN_DIR/supapace-arch` exists. It installs `supapace-arch` and writes
  `fs.protected_hardlinks = 1` to `/etc/sysctl.d/90-supapace.conf`.

Running a node on a shared Docker host
- With the stand-in (the default):
    make node-up NODE=sp-<id> [NODE_IMAGE=… GATEWAY_IMAGE=… WORKER_IMAGE=… IMAGE_CACHE=…]
  Each node's lab slot follows its name. If two names collide, setup.sh fails with
  "the lab slot S3_SLOT=<n> is in use"; run `make node-down NODE=sp-<id>`, then repeat with
  `S3_SLOT=<another>` on every make line for that node. `make reach` then fails, rather than
  skips, a test that needs the stand-in.
- Without the stand-in: add `SP_OFFSITE=0` to `node-up`/`node-bare`. No lab networks are made;
  tests that need the stand-in skip, and `make reach` sets no `SUPAPACE_STANDIN`.
- Always end with `make node-down NODE=sp-<id>`: it removes the node, its volumes, the
  stand-in and the node's two lab networks, nothing else.

Rules and limits
- The stand-in is never archived into the image cache and never loaded into a node; harness-test
  checks both. Bump its digest in `images.lock` and in every `seaweedfs@sha256:` test pin together
  (`standin-digest`).
- The stand-in also serves non-TLS ports on its lab addresses. Only the node's root namespace
  reaches them; jobs reach the declared address and port only (the node ruleset). Assert object
  lock and identity scope through the endpoint only.
- Pinned Alpine versions fail the worker build with apk's "unable to select" once Alpine moves a
  package. Bump the pin; do not unpin.
- A bare node loads no ruleset: there, any inner container reaches the stand-in.
- Keep new test addresses out of 10.215.1.0-10.215.200.255 (the lab slots in common use).

### 2026-11-19 — admin API and CLI: backup state and restore requests

- Routes: GET /v1/projects/{ref}/backups (a read: served in every project state and while
  containment is failed; not_found, bad_ref) and POST /v1/projects/{ref}/restore (a mutation:
  containment_failed 503 first) -> 202 {"ref","operation_id"}.
- Request bodies, every route that takes one (create, restart, restore): one JSON object, no
  unknown member, no member repeated at any depth, every top-level member name in lower case,
  nothing after it; else 400 bad_request ("request body: member \"X\" is repeated or not in lower
  case"). Names inside restart's "set" (setting names) keep their case. Clients of later routes
  must comply. check, delete, purge, abort and op retry refuse any body.
- Restore body {"to", "timeline", "from"}: to is required - "latest", an RFC 3339 time with its
  offset, or a WAL position X/Y or lsn:X/Y (1-8 hex digits each); at most 64 bytes. timeline
  1..2147483647 and from "local" | "offsite" are optional. All is checked before the store is
  touched. Ops.Submit(ctx, "restore", ref, params) always gets the three members: timeline 0
  and from "" when not given (an explicit "from":"" is refused); a position as lsn:X/Y, a time
  as given (parse it with time.RFC3339; render the instant, never the text).
- Errors added: out_of_window (409) when Submit returns a *store.WindowError (match with
  errors.As); the body also has "window":{"from","to"}, null for a bound that is not known, and
  the message ends "; see 'supapace project backups REF'". Other Submit conflicts pass through
  with their reason.
- Backups document, read from the store only (nothing asks the host, a project or a job): ref,
  stanza (<ref>-<incarnation>), incarnation, layout, sets, window {from: the oldest set's stop,
  to: the last complete push}, push (as the project's last push job reported it), quota (the
  quota report of the last push, MB; null before one), replication (declared, last_ok, lags,
  paused_until, rebuilding, bytes/objects today - 0 when the stored day is not today UTC -
  budgets from bklimit.Budgets, objects recorded), info_versions, timelines, gaps, notices,
  restores. Lists are [] never null; at most 64 sets, 16 info versions, 64 gaps, 32 notices and
  16 restores (from the ref's newest 200 operations), newest first. Every stored text is cleaned
  (pgsock.Sanitize) and cut. Layout 1, or layout 2 before its backup-state row: stanza,
  incarnation, push, quota and replication null, lists empty (layout 2 still lists restores).
- Operations carry "result": the stored result, every string and member name cleaned, numbers
  kept exactly; null when there is none.
- DefaultLayout (var, 1): the layout a create gets and a restart raises a project to; a restart
  never lowers it, and a raise cannot be undone. Layout 1 is stored as 0 (the member omitted).
  "layout": 1 at create is accepted only on a development node (the dev-mode marker, a regular
  file beside node.json); any other value is bad_request. Only tests and the literal write it.
- Create and restart accept the top-level members upload_mb_per_day and
  upload_objects_per_day, each 0 (the default) to 16777216; a restart keeps them unless given.
- A create is refused (409 conflict "off-site store partly declared; run 'supapaced offsite
  set' on this node to give the projects' bucket its credentials") while the off-site
  declaration is partial. The state comes from an optional capability of Ops,
  interface{ Offsite() string }, asserted at use; absent, or an answer other than undeclared,
  partial or declared, counts as undeclared. The Ops interface itself is unchanged.
- restoring is a listed project state (project list --state restoring).
- CLI, new commands and flags:
    project backups REF
    project restore REF --to TARGET [--timeline N] [--from local|offsite] [--no-wait]
    project create ... [--upload-per-day SIZE] [--upload-objects-per-day N] [--layout N]
    project restart REF --set upload_per_day=SIZE --set upload_objects_per_day=N
  SIZE is whole MiB with an optional m, g or t suffix (case-insensitive; 0 = the default),
  sent as upload_mb_per_day; anything else exits 2 with "want whole MiB: a number with an
  optional m, g or t suffix (512m, 16g; 0 for the default)". --layout 1 is for tests on a
  development node. The restore help states that changes after the target leave the project,
  and the way back: project restore REF --to latest --timeline N, N being previous_timeline
  in the operation's result.
- A restore waits like every mutation (Ctrl-C: exit 130, the operation continues). superseded
  is a final state: exit 1 with "supapace: a later operation of the project replaced it, and
  it is not retried; see 'supapace op list REF'". A failed restore prints "supapace: retry it
  with 'supapace op retry N'" and "supapace: or restore again with other options: 'supapace
  project restore REF --to TARGET'; a project left restoring (see 'supapace project show REF')
  can also be removed: 'supapace project delete REF'". A restore that fails before the project
  stops serving leaves it as it was.
- Known limits: restores older than the ref's newest 200 operations are not listed; timelines
  are not capped; an operation's result has no size bound of its own (the daemon writes it).

### 2026-11-19 — agent: layout-2 cluster, repository directories, quota use, purges
- Layout 2 (Spec.Layout == 2) cluster, first boot and networked start alike: mounts
  P/spool -> /opt/supapace/spool and P/rspool -> /opt/supapace/rspool (rw) right after the
  tools mount; command = postgres -D /etc/postgresql + pgconf.CommandLine(image) +
  pgconf.Pins(GUC), the pins last (the last -c wins, and the command line outranks every
  configuration file); override file from pgconf.OverridesPinned. Layouts 0 and 1 render argv,
  files and label byte for byte as before; testdata/layout1.golden pins them (it changes with
  the image fixture of internal/pgconf; regenerate with -update-golden only on purpose).
- Archive binary: supapace-arch beside the daemon's executable is copied to
  <render>/tools/supapace-arch (root 0555, temporary name + rename, only when the bytes differ)
  at every layout-2 ensure, before the adoption check, and by RenderCluster. It is not in the
  configuration label: a new binary keeps a running cluster adoptable. Missing source = error,
  the running cluster untouched.
- State phases: A-done, B, R (PhaseR, a recovery start). Only state B with a matching container
  is adopted; a container labelled supapace.phase=R is never adopted and is removed first; a
  normal start after state R records B. StopCluster removes pg-<ref> whatever its phase.
- CheckCluster/VerifyCluster: the verdict is the SCRAM login only; drift rows come from
  bootstrap.AssertPins with pgconf.PinnedNames(max(layout, 1)) — advisory, the cluster's word.
  The archiver statistics are no longer read.
- EnsureDir: layout 2 -> nodefs.CreateProjectDirL2. EnsureSpoolDirs: a task at the project's
  uid (mkdir -p -m 0700 of spool, rspool, rspool/req, rspool/out; project dir mounted at /p);
  root creates nothing in the project tree; an existing directory of any owner is accepted, so
  it must run before any layout-2 start of a directory made at layout 1.
- SetQuota: disk quota, and at layout 2 the repository quota (nodefs.SetQuotaAt(RepoRoot, uid,
  RepoQuotaMB)); layout 2 with RepoQuotaMB <= 0 is refused before anything is set.
  EnsureRepoDir: nodefs.EnsureRepoDir with the spec's ref, ids and RepoQuotaMB.
- DiskUsage: layout 2 = the larger of the uid's use on the projects and the repository
  filesystem (via QuotaUse); otherwise as built. QuotaUse(ctx, uid): both quota reports, each
  tool bounded by ctx (errors.Is(err, ctx.Err())). RepoSpace(ctx): statfs of the repository
  root, size and space available to users, MiB.
- HostState: ProjectDir (a real directory, not a link), StateFile, ClusterRunning, QuotaFull
  (disk quota used within 4 KiB of a non-zero hard limit). Reads both quota reports, so it
  fails on a node without a repository filesystem.
- GrantBackupRole: state B required; one SCRAM superuser session to the recorded postmaster:
  bootstrap.GrantBackup (its error is the call's), then bootstrap.ResetStatementStats, best
  effort (WARN on error, INFO when absent). WipeData: the first boot's wipe, exported.
  RenderCluster: renders the platform files without starting anything.
- PurgeRepo: refuses while a job container of the ref (any state) or pg-<ref>/postgrest-<ref>
  exists, or the container listing fails. An absent <repo>/<ref> launches nothing: at layout
  0 or 1 it is done; at layout 2 the repository quota is still cleared through nodefs, which
  fails on an absent or untrusted repository root (an unmounted repository is not purged).
  Otherwise clears the disk and repository quotas first, empties repo/ by task
  task-<ref>-purge-repo at u:g and fetch/ by task-<ref>-purge-fetch at 65530:g (each mounts
  <repo>/<ref> at /r, rmtree --keep-root), then nodefs.RemoveEmptyRepoDirs. A non-directory
  where a repository directory belongs is an error.
- RemoveFetch: fetch/ only — the 65530:g task, then nodefs.RemoveEmptyFetchDir; repo/ and the
  subject stay; absent = done. No job refusal: callers keep it from overlapping a fetch job.
- Spec: Secrets is json:"-"; Format prints String(). Known limit: %p of a Spec value, or a Spec
  in an unexported field of a printed struct, prints raw (fmt bypasses every method there).
- Tests: the fake Docker looks an unmodelled verb or --format up in fakeVerbs (filled by a test
  file's init) before failing.

### 2026-11-19 — Studio image build pipeline (studio/)
The dashboard image is Supabase Studio (Apache-2.0) at the commit in `studio/PIN`, less the paths of
`studio/delete.txt`, plus the patch series `studio/patches/NNNN-<topic>-<slug>.patch`.

Sub-commands of `studio/build.sh`:
- `image [--variant NAME] [--cpus N] [--memory SIZE]`: the whole pipeline to
  `supapace-studio:local`, `$IMAGE_CACHE/supapace-studio.tar` and
  `supapace-studio.build-record.json` beside it (also in the image at
  `/opt/supapace/build-record.json`). `--variant NAME` adds `studio/test-patches/NNNN-NAME.patch`
  and writes only `supapace-studio:NAME`, `supapace-studio-NAME.*` and `work-NAME/`; a missing
  patch is an error. `IMAGE_CACHE` defaults to `~/.cache/supapace/images`.
- `test`: vitest files the series adds, in the build container.
- `prove [NAME]`: `bash studio/prove/X.sh supapace-studio:local` from the repository root, each
  proof or the one named; results go into the archived record's `proofs`.
- `paths`: `node studio/prove/paths.mjs SRV` with `paths.in` on stdin and `paths.json` on stdout;
  SRV is the last product build's `.output`.
- `export DIR`: a private clone's commits after the pin into `studio/patches/`.

Running a build on a shared machine:
- Host needs bash, git, docker, go and flock. The bundler only runs in containers of the pinned Node
  base, `--memory 12g --cpus 4` by default; only the dependency install has a network.
- One build at a time per host: `flock` on `/tmp/supapace-studio-build.lock` (released when the
  process ends, also on a kill). A second build refuses at once; wait and retry. A lock file you
  cannot open (another user's) also refuses.
- Memory need: `MemAvailable` of 10 GiB for `image`, `prove` and `paths`, 4 GiB for `test`, checked
  at start. Measured at 4 CPUs: peak about 8 GiB (cgroup peak up to 9.6 GiB with page cache), cold
  about 12 minutes, warm 3 to 5.
- What it leaves: under `$IMAGE_CACHE/studio`, the upstream clone (~0.6 GB), the dependency archive
  `deps-<hash>.tar` (~2.1 GB; keyed by pin, Node base, lockfile and the series' manifest changes),
  `work/` (~1.2 GB, the last product build), `work-NAME/` and `work-test/`; the image, its
  archive and record; BuildKit cache. Its containers and images carry `supapace.build=studio`;
  it removes its containers on exit. A killed build.sh can leave a running container with that
  label: remove it before the next build. Never prune others' objects; `supapace.test=1`
  clean-ups do not apply.
- Outputs are replaced together. A hard kill while they are being replaced can leave the tag on the
  new image and the archive and record on the previous one; the next `image` replaces all three.

Gates, interface for later patches:
- `bash studio/gates/NN-name.sh DIR`, run in name order on one input directory; each gate's header
  names its files, and no listed input may be empty. A failing gate names what differs.
- Seeds: `studio/gates/seeds/<gate>.<slug>.sh DIR` change a copy of DIR, and the gate must then fail
  for that reason alone. A copy for `20-apply` needs a clean work tree of its own at
  `DIR/base-commit` as `DIR/repo`. `*.patch` seeds need a build and are skipped by a selftest.
  `seeds/gen.sh CLONE OUT` writes seeds that need an upstream value into the build's temporary
  directory, never under `studio/`.
- A package that adds a way of failing adds its seed in the same commit.

Gates of this package:
- `10-delete`: a delete-list path missing at the pin.
- `20-apply`: a patch that does not apply or is misnamed; a work tree not clean or not at the base.
- `30-dotenv`: a `.env*` file in the build tree or the image; image ENV names other than PATH,
  NODE_VERSION, YARN_VERSION.
- `40-compat`: upstream's `next/*` import check fired or is no longer registered.
- `55-record`: the record's `bypass`, `mcp_chunk_importers`, `pages_with_project_data` or `listener`
  differs from `studio/record.expect.json`, or a listener variable is not in
  `sp-dashstub limits --names`.
- `80-licence`: the image lacks LICENSE, NOTICE.supapace or THIRD-PARTY-NOTICES; a server-bundle
  package has no notice; a modified file lacks its change notice (in its first three lines); or
  NOTICE.supapace does not list a changed file.

Files the gates read:
- `apps/studio/.supapace/resolved-config.json` (written by the build): `define`, `environments` (the
  define map per environment), `env` (the `import.meta.env` map) and `plugins` (names). Values are
  the replacement text, JSON-encoded.
- The build record: one member per line; 55 compares lines. `gates`, `proofs` and
  `total_seconds` are filled into the archived record only. `output_sha256` hashes `.output`
  without `nitro.json`, so two builds at one pin can be compared. Re-record
  `record.expect.json` only for an intended change.

The image:
- Node base plus `.output`, with no source maps and no `.env*`.
- Entrypoint `node apps/studio/.output/server/index.mjs`, with no shell.
- Runs as a non-root uid with a read-only root and a tmpfs `/tmp`.
- Label `supapace.studio.env`, a JSON object: `PORT` and one `ENABLED_FEATURES_<KEY>: "false"` per
  line of `studio/features-off.txt` (KEY upper-cased, other characters `_`, as upstream derives it).
- The MCP library sits in a chunk that only the MCP route loads, when it runs (patch 0003 is the one
  upstream source edit of the build topic).

The listener reads PORT, HOST, NITRO_PORT, NITRO_HOST, NITRO_SSL_CERT and NITRO_SSL_KEY;
`dashcfg.StudioEnv` refuses the TLS pair from the label.

### 2026-11-19 — Gateway: per-project rate limit, audience check, the stopped state

Route file (`internal/routes`), new members, all optional and omitted when empty, so a file
without them encodes byte for byte as before:
- `Project.Aud []string` (`aud`): at most 8, each 1-255 bytes of 0x20-0x7e. Empty or absent: no
  audience check.
- `Project.Rate *Rate` (`rate`), `type Rate struct{RPS, Burst int}` (`rps`, `burst`): RPS 1-100000,
  Burst from RPS to 10 x RPS. Absent: no bucket.
- `File.IdleStopS int` (`idle_stop_s`): >= 0; 0 means no idle project is reported. Nothing reads
  it yet.
- States `asleep` and `stopped` join `active` and `draining`; every state needs `rest`. Parse and
  Marshal refuse anything outside these bounds. The agent's writer (`checkRoute`) still accepts
  only `active` and `draining`.

Gateway request order: health, route table, host, TLS name, draining (503 project_restarting),
stopped (503 project_stopped), upgrade refusal, apikey, bearer with the audience check, rate
bucket (429 too_many_requests), route (404), declared body length (413), in-flight caps, proxy.
- Stopped: a fixed body {"code":"project_stopped","message":"the project is stopped"} and no
  Retry-After; it answers before any key is looked at. Every other 503 keeps Retry-After: 5.
- Audience: only for bearer tokens signed by an issuer-class key, and only when the entry has
  `aud`. The token's `aud` (a string, or a list whose non-string members are ignored) must hold
  one listed value, matched exactly; otherwise 401 invalid_token, "token is invalid". Tokens of
  the anon and service_role keys are never checked. Verification is unchanged and runs first.
- Rate bucket (`rate.go`, `rates` on `Gateway`, zero value ready): one per project ref, refilled
  at RPS a second, holding at most Burst; one token per request that passed the key check, so
  requests refused before it take none and an authenticated 404 or 413 takes one. The 429
  carries Retry-After: 1 (with RPS >= 1 a token is back within a second). Buckets live outside
  the route table: a reload neither refills nor resets them; new figures apply from the next
  request. A clock that steps back adds nothing. Full buckets are dropped when new ones are
  made, so memory follows the projects busy in the last Burst/RPS seconds.
  That sweep runs when the map has doubled since the last one, so no request pattern makes
  every request walk the map; the map holds at most twice the recently busy projects, plus one.
- Known limit: the bucket is per project, not per source. A holder of the project's public anon
  key can drain it for the project's other clients. Floods without a valid key are bounded only
  by the connection limits (per source, gateway-wide).
- Until the wake lands, an `asleep` entry must not be proxied (its REST service is stopped).

Upstream transport: `newTransport(idle time.Duration)`; `New` passes `upstreamIdle` (60 s), so
an idle upstream connection, which holds one of the project PostgREST's slots, is closed.

Caller rules: files added to the gateway for these features (`gatewayAdditions` in
rate_test.go) give the upstream transport no hook, wrap no request body, and start no goroutine
(`go`, `time.AfterFunc`); `TestGatewayAdditions_UseNoTransportHook` checks each listed file.

### 2026-11-19 — gateway: forwarding to Studio, the response filter, the access line

dashproxy.go assigns dashForward = forwardDash; it is reached only from serveDash, after rule 0,
rules 2-10 and the three slots.
- Methods: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS; any other is 405 method_not_allowed.
- Target: forwarded as sent (url.URL.Opaque), never re-encoded. Rule 0 refuses a raw "#" or a
  raw space anywhere in the target (an HTTP/2 path may hold a space).
- Host and X-Forwarded-Host are <ref>.<studio domain> as configured; a client's HTTP/2 host
  field is never written. X-Forwarded-Proto https; X-Forwarded-For the peer address.
- Removed: Authorization, apikey, x-connection-encrypted, Forwarded, X-Forwarded-*, X-Real-IP,
  X-Supapace-Assertion, the method-override and URL-rewrite headers, every __Host-sp-* cookie
  (any letter case), Accept-Encoding on an API path; hop-by-hop headers as ReverseProxy does.
- Added: X-Supapace-Assertion, signed per request from the verified session, the table's role
  and rule 9's purpose; 30 s lifetime. A signing failure is 503 unavailable.
- Transport of its own (newDashTransport): dial 5 s, header wait row 2, StudioConns conns,
  32 idle kept for 4 s (below Studio's 5 s keep-alive), 32 KiB response header, no compression.
- Deadlines: at entry read and write = now + row 2 + row 1; at Studio's header both = now +
  row 1. Go's own ReadTimeout does not run once an HTTP/1.1 request is read, but closes an
  HTTP/2 body at 60 s: the entry read deadline is what lets a slow upload through.
- Failures: no connection 502, no header within row 2 504, header over the bound 502, body over
  the cap 413 (told to the server from the handler; the cap's reader holds no writer), client
  gone: abort. An unsolicited 101 is 502; Upgrade never reaches Studio (rule 10).
- Response (dashfilter.go): drop Server, Clear-Site-Data, Set-Cookie2, Access-Control-*, and
  Set-Cookie with Domain or a __Host-sp- name; no-store on API paths and on any status but
  2xx/304; then dashHeaders last. Trailers filtered and may not reuse a set name. 1xx filtered,
  relayed on HTTP/1.1 only, never to an Expect client, counted (the ninth is 502).
- Access line: one per forwarded request and per refusal of rules 5-10 (the 302, the refusal
  path, the slot refusals, the forwarder's 405), via log.Print after the logger's prefix:
  {"t","ref","iss","sub","role","method","path","status","ms"}. Path without query, at most
  256 bytes; method at most 16 bytes; control characters removed; ms is 0 for a refusal.
  Never a query, cookie, token, header or body.

### 2026-11-19 — nft: the platform bridge's closed list

The bridge chain's rules for the platform bridge (spl0), in order:
- B4: ARP.
- B11: gateway -> port 3000 of the fixed PostgREST range (PlatformAddr(0)..PlatformAddr(n-1)).
- B12: gateway -> Studio's port 3000.
- B13: Studio -> port 8080 of the two postgres-meta instances.
- B14: postgres-meta -> the wire proxy's meta ports (MetaPortBase..MetaPortBase+slices-1).
- B8: drops every other new, invalid or untracked IPv4 connection, whatever its source.
- B6: accepts the rest (replies of accepted flows).
- B9: drops everything else (IPv6 and other non-IP frames included).
B11–B14 are TCP, `ct state new`, each naming a source, a destination and a port. Full label order:
`I1 I2 F1 F5 F7 F2 F3 F6 F4 B1 B2 B3 B4 B11 B12 B13 B14 B8 B6 B10 B9`.

Rendering:
- `Render`/`RenderWith` keep their signatures. The inputs now include `dashcfg.Static(c)`, which
  never fails, so the ruleset of a node without a studio domain renders as on any node. The rules
  for absent containers match nothing; the node check refuses anything at those addresses.
- A zero input renders nowhere: its define and every rule naming it are left out, and a set keeps
  its valid member (B12 needs Studio; B13 needs Studio and one postgres-meta; B14 needs the proxy,
  a port range and one postgres-meta; B11 needs both PostgREST ends, always valid for a validated
  node.json).
- A one-value range (a node of one slice) is rendered as the single address or port, since nft
  refuses `a-a`.
- Ports 3000 and 8080 are literals in the template; a test ties them to `dashcfg.StudioPort` and
  `dashcfg.PgMetaPort`. Ranges are rendered from `dashcfg.Static` without further checks; a test
  guards `Static`'s meta-port range (0-0 or 20000 <= lo <= hi <= 65535).

Caller rules and limits:
- `internal/nft` imports `internal/dashcfg`; dashcfg must never import nft.
- A new platform flow is a new row before B8, never a weakening of B8.
- The source-address rows rely on every platform member being capability-less (node check and
  start gate); the ruleset pins no address or MAC to a port.
- Bridged frames never reach the inet forward chain while bridge-nf is off; Load keeps it off and
  Check reports ErrBridgeNF.
- The saved off-site set, the lock, InstallSet and EnsureRules are unchanged.

### 2026-11-19 — the backup experiments' kit (test/harness/experiments: lib-backup.sh, bk/)
Test tooling that stands one or more layout-2 projects up inside a bare test node (no daemon),
with the platform's own code where it exists, and runs one experiment script there.
Nothing of it is built by `make build` or `make images`; bk is built into a scratch directory.

Run: make build && make images && make node-bare NODE=<node>   (SP_OFFSITE=0: no stand-in), then
  test/harness/experiments/bk/lab.sh <node> <script>
  test/harness/experiments/bk/lab.sh <node> test/harness/experiments/lib-backup-selftest.sh
The selftest prints "SELFTEST ok" (about 3 minutes): stanza, full backup, three pushes (one entry
of a timeline that is not admitted is quarantined), a copy to the stand-in and back, a time-target
restore, the re-key, the networked start with the new password, the old one refused, labels.
Exit status: 0 all lines pass, 1 a line failed, 3 a lab error, 4 a criterion not run (UNRUN: the
copy step without the stand-in); lab.sh: 2 usage or node not usable, 1 a refusal.

lab.sh (host, bash): checks CLUSTER_FLAGS and the container-side mounts of lib-backup.sh against
clusterRunArgs in internal/agent/cluster.go (flag names, literal values, mount targets and their
order; --user, --memory, --pids-limit, --network and --sysctl are not compared); builds bk; refuses
a node with a daemon, a missing node, or an existing /var/lib/sp-exp/bk; copies the kit in and
runs the script as root; on every exit path (also TERM, INT, HUP) stops the run by its recorded
pid and removes what is left: containers and networks named sp-test-bk-... with the label
supapace.test=1, the lab projects' trees and quotas, the kit directory. Nothing prunes.

lib-backup.sh (POSIX sh, in the node), REF = 20 characters, UID = the project's uid and gid:
- lab_up; project REF UID IDX; cluster REF A|B|R (first boot, networked, recovery start);
  mk REF UID IDX (all of it); stopc; sql / tsql REF SQL (SCRAM / trust session through bk);
  rekey REF GEN; wipe; restore_files REF [OPTS]; recover REF PINS-ARGS (leaves the promoted
  cluster running); serve_start / serve_stop.
- worker REF push|db|restore|serve CMD..., job REF ARGS..., pushall REF: job containers of the
  worker image at the project's ids, no network, every pgBackRest option by environment (an
  env file, root 0600, removed at teardown). Knobs: ADMIT, LLC, WARGS, WDETACH, REPOSRC,
  PROMOTE_WAIT, DISK_MB, REPO_MB.
- s3 ROLE ..., copy_out REF PREFIX [ROLE], copy_back REF PREFIX [ROLE]: sp-probe s3 with one
  role's keys; a copy at the replicator's uid with the project's group. Use a fresh PREFIX per
  run: the stand-in keeps what earlier runs wrote. copy_back fetches current objects only (no
  as-of mode; compose `s3 ROLE versions` and `get --version`).
- res WORD CRITERION FIGURE, check, control, finish NAME.

STAND-INS: the push, job, serve and copy programs are shell scripts mounted at /x, not the
platform's job programs. A result they print is not a result of the product. Re-run with the real
programs: push (spool filter, links, lock path), stanza-create/backup/check, restore and serve,
replicate and fetch (walk, allow-list, backup network, limits: the copy job here has the
node's network, 512m/256/128m). The environment names, mount targets and job flags are written by
hand and must be compared with the product's once it exists.

bk (Go, package main, imported by nothing): render (directories and quotas by nodefs, files by
pgconf, command line and PGOPTIONS), bootstrap, sql (SCRAM via pgsock, generation GEN), scram (the
re-key session in the agent's order), trust (pgx with an explicit parameter list: the platform's,
plus -set/-unset), pins (recovery start: extension pins, then the recovery pins, target last;
always with the three extension pins: not for the control plane). Passwords are lab values
(lab<gen>-<hex>) derived inside bk and never on a command line; SQL text is on one.
Limits: no control-plane set-up; no ruleset on a bare node; the restore prints unknown user and
group warnings (project ids are not in the worker's passwd); set -e does not apply inside a
function run by check.

### 2026-11-19 — bootstrap: pooler manager and helper, canary table, session statements

internal/bootstrap gains the pooler's manager role with its lookup helper, the backup canary's
table and four bounded session calls. Every statement is a package constant; the one built at
run time is still setVerifier's, through verifierStatement.

Provides
- Secrets.PoolerPassword: empty means nothing of the manager is sent or expected. Its salt is
  ScramSalts["supapace_pooler"] (pgsock.ScramSalt). It must differ from the three platform
  passwords. A shared password or a missing salt is refused by Run, Rekey and
  EnsurePoolerLogin before any statement.
- EnsurePoolerLogin(ctx, conn, s): a session as supabase_admin. Sends, in this order: create
  role supapace_pooler (SQLSTATE 42710, it exists, is success); the manager's password
  statement (login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls
  connection limit -1 valid until 'infinity' and the verifier: every attribute is set each
  time); schema supapace_pooler (owner supabase_admin, nothing for PUBLIC, USAGE for the
  manager); function supapace_pooler.get_auth(text), owner supabase_admin, EXECUTE for the
  manager alone; then two reads of what it made. It stops at the first statement the server
  refuses. Idempotent: the attributes, owners, body and grants it sets are set back.
- The read-back requires: the seven compared attributes; no membership that names the manager
  (as member, as granted role or as grantor); the schema's access list exactly
  {supabase_admin=UC/supabase_admin,supapace_pooler=U/supabase_admin}; the helper's owner,
  body, security definer, its one SET clause, and EXECUTE held by supabase_admin and the
  manager only. A difference is an error naming the first one. A membership, an extra entry of
  the schema or a grant of EXECUTE to another role is refused, never taken back: the call
  fails until an operator removes it as supabase_admin.
- supapace_pooler.get_auth(text) returns (username, password): the SCRAM verifier of one login
  role, for the pooler's lookup. Security definer, empty search_path, every type, relation and
  function in its body written with its schema, so nothing a calling session defines is used.
  No row for a superuser, a role without the login right, an expired role, a password that is
  not SCRAM-SHA-256, a pg_ role, or one of supabase_admin, supabase_auth_admin,
  supabase_storage_admin, supabase_realtime_admin, supabase_replication_admin,
  supabase_etl_admin, supabase_privileged_role, dashboard_user, pgbouncer, authenticator,
  supapace_backup, anon, authenticated, service_role. The manager's own row is returned: the
  pooler reads it when a project is registered. The list is reservedMembers plus
  authenticator and the three API roles, minus supabase_read_only_user; a test holds it there.
- Run: after the auth functions, the manager and helper when PoolerPassword is set, and the
  canary table always.
- Rekey: with PoolerPassword set, the manager's password statement follows the three. SQLSTATE
  42704 (no such role) on it is a skip: the re-key creates no role. This package built that
  skip: the entries whose role may be absent are a second list, sent in a loop after the three
  mandatory ones, and a later optional entry joins that list. On one of the three 42704 stays
  an error, and so does any other refusal of an optional entry. Nothing reports a skip.
- sqlPasswordReadOnly: the read-only login's password statement, in the one form of the three.
  This package owns the constant; a later package that sets that role's password uses it and
  declares no second one.
- EnsureCanary(ctx, conn): schema supapace (owner supabase_admin, set back each time, nothing
  for PUBLIC) and table supapace._backup_canary (id smallint primary key check (id = 1),
  written_at timestamptz not null) owned by supabase_admin. It reads what holds the table's
  name first: a table another role owns is dropped with everything that depends on it and
  made again; a relation of another kind is refused with an error and nothing is written.
  It requires the schema's access list to be exactly {supabase_admin=UC/supabase_admin}:
  another entry is refused with an error, never taken back.
  WriteCanary(ctx, conn) calls it, then upserts row 1 with the server's time. The row is that
  cluster's evidence about itself and gates nothing.
- RekeyLogin(ctx, conn, role, verifier) (RekeyResult, error): role is postgres or
  supabase_read_only_user; another role or a malformed verifier sends nothing. First the
  password statement (it also sets login, connection limit -1 and no expiry), then
  pg_terminate_backend for every backend the server lists under that role name, pooled
  connections and the role's background workers included. Never narrow that statement. For
  supabase_read_only_user it then removes the large objects that role owns: 10,000 a
  statement, at most 10 statements. A refused password statement or termination is the call's
  error. A failed removal is not: the call succeeds, is not repeated, and says so in the
  result. Repeating the call with the same verifier is safe.
- RekeyResult{Terminated, LargeObjects, LargeObjectsLeft, LargeObjectsError}: counts as the
  server answered them; LargeObjectsLeft when a batch was full at the end or the removal
  failed; LargeObjectsError is that failure's cause, the server's code and message, sanitised
  and at most 256 bytes, or "more than 10000 rows".
- SetReadOnlySignal(ctx, conn, on): alter database postgres set default_transaction_read_only
  = on, or reset. It reaches sessions opened afterwards only; platform sessions are not reached.
- CreateRestorePoint(ctx, conn, name) (lsn, error): exactly one row in the form X/X (upper-case
  hex), else an error. Read the timeline with ReadTimeline in the same session.
- AssertServices(ctx, conn, pooler): with pooler true, one row per difference of the read-back
  above under the check name service-logins. With false it reads nothing. The frozen set of
  check names gains service-logins.
- BaselineFor(version) (Baseline, error): the embedded baseline_<version>.json. An unknown
  version is an error naming the versions there are. LoadBaseline stays the locked image's.

Caller rules
- One fresh pgsock session as supabase_admin (the superuser startup list) per call;
  RekeyLogin and EnsurePoolerLogin first in it. After any error the session is finished.
- The statements outside function bodies rely on that session's startup search_path
  (pg_catalog first): never send them over a connection that pgsock.Dial did not open. A test
  holds that settings of the role and of the database do not reach such a session.
- Errors wrap pgsock's: test a bound with pgsock.IsBudget and a server refusal with errors.As
  to *pgsock.ServerError. Server text in errors and findings is sanitised and capped.
- Everything read back is the cluster's word: use it for that project only.

Known limits
- The schema's access list is compared as text: the same two entries in another order are a
  difference. Settings on the manager role and grants to it elsewhere are not read back.
- A function of another signature under the helper's name fails the call (SQLSTATE 42P13).
- A type that is no relation under the canary's name fails EnsureCanary (SQLSTATE 42710).
- The termination reaches the sessions the server lists when it runs.
- A batch of large objects that does not finish inside the statement bound is not removed.
- WriteCanary's owner statement waits for the table's lock; under a reader's lock it ends at
  the statement bound with a budget error.
- After RekeyLogin of supabase_read_only_user the check service-passwords reports that role
  until servicePasswordRoles no longer lists it.
- Tests: the cluster tests need the pinned image and skip without it.

### 2026-11-19 — internal/backup: job runner (lanes, scheduler, launch, push and backup records)
- `backup.New(st, ag, pr, kek, cfg, paths) *Runner`. `Agent` lists every node-agent method the
  runner calls; `Projects` gives `SpecFor(ctx, ref)` and `Adopted(ref)` (not in the pending set).
- Daemon wiring, in this order: `New`; `Start(ctx)` - `KillJobs(ctx, "")` (job containers,
  recovery clusters, job files), then, only if that succeeded, `store.InterruptJobs`; a failed
  `Start` touches no job row and is retried before anything else runs. Then hand the runner to the
  operation worker as its `saga.Jobs`, start `Run(ctx)` (two push-lane and two backup-lane
  workers and the 5 s scheduler) and the operation worker. `SetOffsite(decl, state, addrs)` is
  called by the resolver loop after each install of the address set (addrs copied); before the
  first call the state is `undeclared`. Stopping = cancelling Run's ctx: a running job is left
  `running` and the next `Start` ends it `interrupted`.
- `saga.Jobs`: `Cancel(ctx, op)` / `CancelSubject(ctx, subject)` end queued jobs `cancelled`, stop
  the running ones, re-read every second, and return once each is recorded or no longer running
  (bounded by ctx). Call `Cancel` only for an operation that has left `waiting_job`.
  `PushNow(ctx, subject, wait)`: `ok`, `incomplete`, `timeout` (a wait of 0 asks once and
  returns `timeout`), `failed`; never a second push beside a queued or running one.
  `Offsite()`: `undeclared`, `partial` or `declared`.
- Pick-time check, one function of the job row: no operation - an `active`, or `restarting`,
  project adopted here (`cp` exempt); an operation - that operation is `waiting_job`. Else
  `cancelled`, nothing launched; a check that cannot read the store: `interrupted`. While
  containment has failed nothing is picked, a picked replicate/fetch is `interrupted` and the
  tick stops running ones with `interrupted`.
- Secrets: `SecretEnv` holds only `PGBACKREST_REPO1_CIPHER_PASS`, for push, stanza-create, backup,
  check, restore and serve (the job program builds the rest of the tool's environment). replicate
  gets its bucket's write and fetch its read-only credential in `Cred`
  ("<access key>\n<secret key>", no final newline), the `SUPAPACE_S3_*` environment, the loaded
  address set and `/job/ca.pem` when declared; while not `declared` such a job ends `internal`.
  The control plane's passphrase is read from its sealed file, never created here.
- Job parameters, strict (exact unique member names, else `internal`):
  restore `{"set":"<label>","mode":"none"|"standby","target_timeline":N}` (N >= 1 with standby
  only); recover `{"target":{"time":"<RFC 3339>","lsn":"<hex>/<hex>","timeline":
  "latest"|"current"|"<decimal>"}}`, `time` and `lsn` omitted when unset.
- Results: parsed by `jobio.ParseResult`; exit 0 with ok, 1 with a failure, else `crashed`; no
  line -> `crashed`; launcher mount-source refusal -> `host_state` (matched by the error's text
  until the agent exports it); other launch errors -> `internal`; `TimedOut` -> `deadline`.
  Code rule: a job's own failure code that the runner, the store or a step assigns (deadline,
  interrupted, cancelled, crashed, host_state, record_not_rebuilt, fetch_too_large, internal,
  recovered, recovery_failed, target_not_reached, interrupted_limit) -> `crashed`. Messages are
  sanitised and cut to 256 bytes.
- Bounds, checked before any write (else `crashed`, nothing written): push (also nested in
  stanza-create, check, backup) `pushed` 0-56; counts >= 0; `spool_entries` <= 2^31-1;
  `first`/`last` empty or a spool name; `histories` <= 64 history names; quarantined names 1-255
  bytes without a control byte, reasons timeline|shape|refused-44|45|46; `newest` keys
  `^[0-9A-F]{8}$` of admitted timelines, values segments of that timeline, the highest one
  recorded. Backup label, timeline, segments and positions by pattern; restore mode; seed counts.
  A serve result is kept by its recover job only if exit 0 and every name is a request name,
  else `serve` is null. Stored is the parsed value re-encoded, never the raw line.
- Records: push -> `RecordPush` with `QuotaUse`; backup -> `RecordSet`; stanza-create ->
  `MarkStanza`; seed -> `SetSeeded`; a quarantine -> one forced full per UTC day; a push or backup
  recorded done -> a replicate (store declared, none queued or running); one lost to a daemon stop
  is queued after the next done push. `repository_quota` -> notice `repo-quota-full`, a failed
  backup -> `backup-failed`. A failed record is retried (1 s doubling to 30 s) until written,
  refused as not running, or the daemon stops.
- Recover job: `EnsureRecovery`, a serve job beside it, `RecoveryState` every 2 s until promoted
  (serve stopped, its result kept), exited (`recovery_failed`, or `target_not_reached` when the
  serve's `last_none`), an error, or the deadline (`deadline`); on every outcome but promotion the
  serve job is stopped and the recovery cluster removed first.
- Scheduler: `cp` once its stanza exists and every layout-2 project `active` (or `restarting` with
  an open restart), adopted, with its stanza: a push 60 s after the last when none is queued or
  running; 2 + 2N store calls per tick whatever the table holds; one subject's error skips only
  it. Hourly: `PruneJobs` repeated while it deletes 10,000; `cp-quota-half`, `repo-space-low`;
  `RemoveFetch` for adopted layout-2 projects without an open restore.
- Seam for the replication files (same package): `buildReplicate`, `buildFetch func(ctx,
  *Runner, store.Job, *jobio.Input, *agent.JobSpec) error` complete a spec that already holds the
  credential, environment and addresses (never replace them; refuse with `jobErr(code, msg)`);
  `recordReplicate func(ctx, *Runner, store.Job, jobio.ReplResult) (json.RawMessage, error)`,
  `recordFetch` likewise with `jobio.FetchResult`: handed the job row (its launch number
  included) and the parsed result, they return the stored document; an error -> `crashed`. While
  nil, such a job ends `internal`.
- Known limit: the backup-lane bound is ceil(k/2) x the deadline plus, per pick, the 0-2 s delay
  and the removal of a container killed at its deadline.

### 2026-11-19 — init: the studio domain and its certificate

- `supapaced init` takes `--studio-domain S`, `--studio-tls-cert F` (a PEM chain, leaf first)
  and `--studio-tls-key F`. Without them init writes exactly what it wrote before: node.json
  has no `studio_domain`, there is no tls-studio directory, and the development CA is
  constrained to the base domain alone.
- nodecfg.Config.StudioDomain (`json:"studio_domain,omitempty"`, last field); empty means the
  node has no dashboard. Validate, at init and at every Load, refuses a studio domain that is
  not lowercase LDH labels, is longer than 232 bytes (a 20-letter label under it must still
  be a name), ends in a numeric label (decimal, or 0x and hex: a browser reads it as an IPv4
  address), equals the base domain, lies under it, or has the base domain under it. The
  comparison is on label boundaries: myexample.test and example.test are disjoint. Validate
  is the one owner of this rule; the gateway and the agent do not check it again.
- Validate refuses a node_id that is empty, over 255 bytes, invalid UTF-8, or holds a Unicode
  control character, U+2028 or U+2029: what the dashboard's tokens can sign.
- init also refuses, before writing anything: a studio domain with the label `sign-in`
  (dashcfg.SignInLabel); any node with a studio domain that dashcfg.For refuses (checked on
  every run, also when the domain comes from node.json); and another value for a studio
  domain already set. The studio domain is set once: init keeps it when the flag is absent,
  and there is no supported way to change or remove it.
- Without --dev the pair is required the first time S is set, and on any run where node.json
  names S and no pair is stored. The certificate must match the key, list both S and *.S
  literally among its DNS names (the gateway's loader requires exactly this; the wildcard
  covers sign-in.S and every <ref>.S), be valid now, and allow serverAuth when it lists
  extended key usages. It is not verified against any trust store. A rerun without the pair
  flags keeps the stored pair; to renew, rerun init with the new pair.
- Both pairs (base and studio) are read through one reader: links are followed (an ACME
  client's current files work), what is opened must be a regular file of at most 1 MiB, and
  a FIFO or a device is refused at once instead of blocking. The studio pair is stored as
  /etc/supapace/tls-studio/{key,cert}.pem, root 0600 in a root 0700 directory, key first,
  by temporary name and rename, never through a link; leftover temporary files there are
  removed by the next run.
- With --dev the pair flags are refused. A new node's CA is name-constrained to both domains
  and init issues the studio pair (S and *.S, serverAuth, 825 days), reissued by any init run
  when it cannot be loaded or expires within 30 days. An existing development CA without S
  is refused with what to do: remove /etc/supapace/ca and /etc/supapace/tls and rerun
  init --dev --studio-domain S; the projects are kept and clients must trust the new ca.pem.
- dashpush.New takes the studio domain from the node file: with one, Push writes the
  dashboard file; without one it writes nothing and returns generation 0.
- For the packages that start Studio and wire the daemon: only init writes or renews
  tls-studio (the daemon never does), so the gateway's copy must be refreshed from it by
  digest at every repair round, and the gateway re-created when it changes. Nothing writes
  the gateway's dash/domain file or its tls-studio copy yet, so until those packages land a
  node with a studio domain serves the base certificate for every name and has no dashboard
  host class. A node.json edited by hand can still name S with no stored pair; the gateway's
  "dashboard unavailable" path must stay.
- Known limits: a pair replaced in place is written key first, so a crash between the two
  files leaves a mismatched pair until init is rerun with the pair; an xn-- label is
  accepted as LDH without checking its punycode.

### 2026-11-20 — test/reach: backup helpers; archive, spool, worker and quarantine tests
- Tests written ahead of the features: TestReach20_NoBackupSecret, TestReach21_ArchiveContract,
  TestReach22_Spool, TestReach23_WorkerConfinement, TestReach26_BackupRole,
  TestReach28_Quarantine (tag reach). Each starts with needBackups: at layout 1 it skips with
  "the node creates projects at layout 1; the backup tests need layout 2", or fails when
  SUPAPACE_BACKUP=1. Sub-tests that need the object-store stand-in call needStandin (skip, or
  fail when SUPAPACE_STANDIN=1, which `make reach` exports when the stand-in exists).
- Helpers (untagged, backuphelp_test.go; self-tests in backuphelp_self_test.go, no daemon):
  nodeLayout/layoutOf - `project show`'s config.layout, absent = 1, anything but 2 fails;
  backups(t, ref) - `project backups`, must answer for ref; restore(t, ref, args...) - the
  operation document and exit status; waitPush(t, ref) - returns after two complete pushes
  recorded after the call (a push running at the call may have listed the spool before it),
  5 min per push; opListing - one `op list` by id; holdDaemon(t) - writes /run/sp-hold, kills
  every `supapaced serve`, returns an idempotent release (also a cleanup) that waits for the
  admin socket; s3(t, role, args...) - sp-probe s3 with the role's keys, the role's bucket
  unless --bucket is given, only the stand-in's declared addresses; returns the whole output
  and the exit status, which must agree with the last line's verdict ("error" fails; an empty
  `versions` output is an empty listing); asProjectUID / workerRun - a worker-image container
  at a uid with no network, cap-drop ALL, no-new-privileges, read-only root, private /tmp
  (a subset of the job flags); environment values pass through the docker client's
  environment, never its argv.
- Tree readers: spool (as root, links not followed), quarantined (entries outside the archive
  pattern that are not `.tmp-` temporaries), repoFiles, archived (a segment, label or history
  of a stanza by its repository name). secretsReadableBy(uid, gid, roots, mounted, needles):
  mode bits only; host roots are traversed from `/`, mount sources (mounted=true) from the
  source down, as a container reaches them.
- The first phase's suite: phaseBMounts(layout) and writableClusterMounts(layout) add the two
  spools at layout 2; createSteps(layout) adds 5a-5d and 12a, 12b; the queue sub-test allows a
  second create to run while the first waits on a job, never both running in one listing.
- Known limits: the stalling fake server is the only hostile-server mode run; the restore-spool
  temporary-name case waits for the serve job's naming; "a link swapped in during a backup" is a
  race whose every outcome is checked; the documents' pointer members decode into values.

### 2026-11-20 — adminapi and CLI: dashboard members, issuer, revocations, rotation, audit

Routes (internal/adminapi/members.go, audit.go; registered in New). Writes answer 200 when in
force, 503 not_in_force when committed and not yet in force:
- GET /v1/projects/{ref}/members; POST …/members {issuer?,subject,role}; POST …/members/role
  {issuer?,subject,role,service_key?}; POST …/members/remove {issuer?,subject,service_key?}.
  The principal travels in the body only; issuer omitted = the stored dashboard issuer
  (conflict when none). subject and issuer: 1-255 bytes of printable ASCII. role: owner,
  developer, read_only. service_key: default (also omitted), keep, rotate.
- POST …/members/clean-jobs (no body); POST …/service-key/rotate (no body);
  GET …/audit?tail=N (1-1000, default 100).
- GET /v1/dashboard (conflict without the pusher capability); GET and PUT
  /v1/dashboard/issuer; POST /v1/dashboard/revocations.
- Every route but audit and service-key/rotate answers conflict on a node without a studio
  domain. The body rules of the API hold (unknown, repeated or upper-case member: bad_request).

Containment: while it is not verified, member add and a raised role (read_only < developer <
owner) answer 503 containment_failed before any write. Removals, lowered roles, revocations,
the issuer and rotations are served. A read_only membership that ends is committed and pushed
but its clean-up is not run in the request (jobs "not run: containment not verified", 503);
clean-jobs is refused; the round runs the owed record after its containment check.

Member document: ref, issuer, subject, role (null when removed), previous_role, service_key
("unchanged" | "rotated" | "kept"), rotation ({gateway, rest} or null), still_valid (text when
an owner's key was kept, else null), jobs ("ran" | "failed: …" | "not run: …" | null),
dashboard_generation (null when the file is not in force).

Rotation rule: an owner whose membership ends (removed or another role) rotates the project's
service_role key unless service_key is keep; rotate rotates any change; an owner who stays an
owner never rotates (service_key rotate is then bad_request: use rotate-key).

Order of a member write: every check and every needed capability first (nothing is written
when one is missing); the store change (ChangeMemberRotating when rotating, else
store.ChangeMember with the role read just before: a concurrent change is conflict); the
dashboard push; then, only if the previous role was read_only and the new one is not, the
push gave a generation above 0 and containment is verified, DropReadOnlyJobs under 20 s.

503 not_in_force: one JSON object, "code":"not_in_force", "message":"committed; not yet in
force: <step>: <cause>[; …]" with step "dashboard file", "service-key rotation" or "read-only
clean-up", then the document's members. A repeated request answers conflict or not_found:
the change is made. clean-jobs answers 503 with jobs "not run: …" or "failed: …" and a
message without "committed".

Capabilities, asserted at use on Ops (Ops is unchanged); the daemon implements them:
- StudioDomain() string; PushDashboard(ctx) (generation, error) and DashboardInForce(ctx)
  (generation, inForce, error): generation 0 means no file in force, also with a nil error;
- ChangeMemberRotating(ctx, ref, issuer, subject, fromRole, toRole) (RotationOutcome, error)
  and RotateServiceKey(ctx, ref) (RotationOutcome, error): a non-nil error means nothing was
  committed (wrap store.ErrNotFound / store.ErrConflict); a committed rotation whose later
  step failed returns RotationOutcome.Err;
- DropReadOnlyJobs(ctx, ref) error.
Every error text of a capability is shown to the operator, sanitised and capped at 1 KiB:
it must carry no secret. Keep each call bounded: the whole request must end inside the
admin server's write timeout.

Issuer (PUT): the key set is parsed with jwtx.ParseDashboardJWKS; only the keys it keeps
(RSA; use sig or none; alg RS256 or none; key_ops absent or holding "verify") are stored,
re-encoded by jwtx.MarshalJWKS. A key_ops that is not an array of strings refuses the set;
the project path (ParseJWKS) does not read key_ops. An encryption-only set is bad_request and
the stored issuer is unchanged. At most 16 keys; kid 1-255 printable ASCII. authorize_url and
a non-empty end_session_url: https, a host, no user information, no '#', printable ASCII, at
most 2048 bytes. session_seconds 300-28800 (default 28800). A key whose modulus equals a
stored project key is bad_request. Known limit: a project created later with the same public
key is not refused (it gains no private key).

Revocation: not_before is printed rounded up to the second (the time the file refuses from).
GET /v1/dashboard: in_force true only with a generation above 0; members counts live
projects.

Audit: <DataDir>/<ref>/audit.log.1 then audit.log, Studio's files and untrusted: DataDir and
<ref> opened O_DIRECTORY|O_NOFOLLOW by openat, files O_NOFOLLOW|O_NONBLOCK, fstat regular
with one link only (a link, hard link, FIFO or directory is conflict naming it; absent is an
empty list), 16 MiB together newest first, lines walked in place, at most 2 x tail records
held, lines of at most 4 KiB with exactly the record's members (sql_sha256 optional) and the
project's ref, each text sanitised; others count in skipped. truncated: bytes left unread or
records beyond tail.

CLI (cmd/supapace/members.go): member add|set-role|remove|list|clean-jobs, dashboard issuer
set|show, dashboard revoke ISSUER SUBJECT, dashboard show, project rotate-key REF --service,
project audit REF [--tail N]. stdout is the one answer document (503 included); notes go to
stderr, cleaned; exit 0 success, 1 any API error including not_in_force, 2 usage, 130
interrupted. dashboard show exits 1 unless in_force. member add always prints the revoke
hint (a removal does not end a session). A not_in_force removal or revocation says the
principal is still admitted; a failed rotation step says the old key may still pass. When
an answer is lost, the commands name where to look (call.look).

### 2026-11-20 — store: schema 4, admission terms, settings, alerts, backup-operation records

- Schema version 4 (migration_4.sql): operation kinds settings and rekey-login; job kinds
  expire, verify, drop-spool and offsite-expire; sequence backup_job_launch; node.conn_alloc
  (2128), desc_alloc (2^29), pass_at, clock_hold_until; project.conns (back-filled from the
  stored max_connections), settings, read_only_since, rekey_pending; schedule columns on
  backup_state; expired_local_at and offsite_removed_at on backup_set; sent_count and
  sent_at on backup_notice; tables restore_point, alert and issuance. Additive but for the
  two kind checks. Migrate runs before any admission; admit's two terms apply from version 4.
- Launch numbers: NextJob's pick draws one (Job.Launch; 0 while queued or for a job launched
  before version 4). offsite_object.launch and backup_timeline.launch are NOT NULL with no
  default, so every insert names the column. RecordUploads takes Uploads.Launch, MergeListing
  ListingPage.Launch, MergeUnrecorded the launch of the job id it is given; a number that is
  not above zero is ErrNoLaunch, before any write. An existing row keeps its number.
  ConfirmTimeline stamps the recorded timeline; a recorded timeline above 1 without a number
  fails a check constraint. Callers fill Launch from the store.Job whose result they record.
- Admission: Place refuses with ErrNodeFull (the figures in the message) when the counted
  projects' conns plus this one's plus poolcfg.ProxyFixedConns exceed node.conn_alloc, or
  their memory admission times 2^20 / 230 exceeds node.desc_alloc. ProjectShare(cfg) is a
  configuration's share: max_connections - 48, 72 at the default 120. At the default ceiling
  a node holds at most 28 default projects, whatever its memory. CheckAdmission(ctx, memMB,
  share) is the advisory form for the create handler; Place stays the authority. CheckConns
  and SetConns for a share change; SetNodeAllocs(conn, desc), both above zero, is the
  daemon's at start (until then the defaults stand). SetAbortSliceHold(d): an aborted
  create's slice is held for d (0, the default: not held); process-wide, set once.
- Settings: ProjectSettings with api, pooler, rate, aud and stopped; JSON snake_case
  (schemas, extra_search_path, max_rows, pool_size, max_clients, allow_list, rps, burst).
  Validate holds every bound, including the effective pool size (the default 5 when none is
  given) through poolcfg.Fits, and refuses an allow list while restrictions are not offered,
  before it reads the node's addresses. SubmitSettings needs an active project, no open
  operation and the stored document equal to base; StoreSettings writes for an open settings
  operation. Refusals are ErrConflict; match with errors.Is.
- Re-keys: SubmitRekey submits rekey-login for a free active project, else queues the login
  once (at most 16 a project; a 17th is ErrConflict). PendingRekeys lists every project's
  queue, so filter the free ones yourself; FailedRekeys lists the logins whose newest
  rekey-login failed. PromoteNextSecret moves name.next into name, takes the login off the
  queue and, for the read-only login, owes its clean-up again; with no .next it writes
  nothing.
- Alerts: RaiseAlert upserts (count + 1; an open page stays page; a lift to page or a
  re-open is pending at once); at most 64 rows a subject and 16 numeric figures. ClearAlert
  closes a row. PendingAlerts returns alert rows, cleared ones included, and backup notices
  whose count moved and whose last delivery is older than repeat. MarkAlertSent never lowers
  the count sent. OpenAlerts returns open rows only.
- Backup operations:
  - Schedule, MarkSchedule, SetFullDue.
  - ExpireAllowed: the record is rebuilt, and a complete copy was launched after every
    writer other than the expire itself.
  - MarkExpiredLocal.
  - OffsiteExpirePlan reads launch numbers only. It fails with ErrNotRebuilt, or with
    ErrClock when a job of the subject is dated after now. It returns at most max keys, with
    More set when there are others. An anchor may come with no key.
  - RecordPass and ClockHold.
  - MergeUnrecorded needs a version id on every row.
  - MarkPurgeSeen, PurgeAllowed ("state" / "wait"), SetPurgeWait (--keep; --now only while
    the purge flag is set, else ErrConflict), ClearOffsitePurge.
  - MergeUnrecorded and PruneObjects take at most 2,000 keys.
  - PruneInfoVersions keeps each name's newest and both fetch candidates of every staying
    set.
  - InfoVersionsAsOf, InfoVersionsFor, SetsListedBy, DropsSince.
- poolcfg.ValidAllowListOn: ValidAllowList, plus a refusal of any prefix holding one of the
  node's addresses (named by its position, never by its text). An empty address list is an
  error.

### 2026-11-20 — pgcap: admission, the reloadable table and the program

`cmd/pgcap TABLE` is the wire proxy's program: one argument, the path of its table. It exits 2
on a wrong argument list, 1 when the first table cannot be read or served, 0 at SIGTERM or
SIGINT. Its log is JSON lines on standard error. `deploy/pgcap/Dockerfile` puts the static
binary alone in an empty image, with a numeric user and the command `/pgcap
/etc/pgcap/pgcap.json` (a command, not an entry point: whoever starts the container passes the
whole command or none). The image needs no capability, no shell and nothing writable. Its
`GOMEMLIMIT` fits a 64 MiB container: pass another at creation for another limit.

`internal/pgcap` gains one export:
- `Run(ctx, path, logw) error` — serves the table at `path` until `ctx` ends, then closes every
  listening socket and connection and returns nil. It returns an error only when the first
  table cannot be read or served, and then leaves nothing open.

One listening socket per placed slice and class, at `listen`, port `port_base` + the slice's
index, with the class's socket buffers (accepted sockets inherit them). A slice that is not in
the table has no socket: the kernel refuses its port. The cluster of slice i is host 2 of the
slice, port 5432, and the proxy dials it from host 4; one function (`sliceAddrs`) computes
both and nothing else may.

From accept to a decision, in this order:
1. The socket's local address must be `listen` and its remote address a peer of the class,
   or it is closed at once: nothing read, nothing counted.
2. With `max_conns` units held it is closed. A kept socket holds one unit until it is closed.
3. It needs a place in its class's pool (`refusals_max`) or is closed, and keeps the place
   until it is admitted as a connection or a cancel. So every unit belongs to a connection, a
   cancel or a place: a class never holds more than its own terms, and a table whose
   `max_conns` covers `Terms()` does not reach the ceiling. No socket is exempt from the pool.
4. The first eight bytes are read within `preamble_ms` of the accept. A TLS or GSS encryption
   request is answered `N`, never forwarded, and the next eight bytes are read in its place;
   the second request of one kind closes the socket.
5. A cancel request (length 16, code 80877102) is admitted outside the connection caps, under
   `cancels_per_project` for the slice and `cancels_per_peer` for the peer (0: none); over
   either it is closed. Admitted, its other eight bytes are read, the cluster is dialled and
   exactly the sixteen bytes are written, all within `cancel_ms`; nothing is read back.
6. Any other code whose high sixteen bits are 1234 closes the socket: it is no startup.
7. Anything else is a startup, admitted against the slice's allowance, then `conns_per_peer`
   (0: none), then the slice's rate — a bucket of `conns_burst` tokens refilled at
   `conns_per_second`, full when the slice enters the table. A refusal spends no token.
   Admitted, the socket goes to `Relay` with the accept time: every clock runs from the
   accept. `Relay`'s reason is logged; a peer's close is not.
8. Refused, the rest of the startup packet is read (a stated length outside 8 to 10,000
   closes the socket) within what is left of `preamble_ms`, nothing is dialled, and the client
   reads FATAL 53300 "too many connections" and an orderly close.
Every wait above ends when the slice leaves the table, and a socket that has ended keeps no
memory, however it ended.

The table's file is looked at every second (inode, size, modification time) and read when one
changed, if it is a regular file of at most 1 MiB. A file `ParseTable` refuses keeps the table
in use. Applied from a new file: caps, rates and deadlines for sockets accepted from then on;
allowances (a lowered one is reached as connections end: none is cut); slices and classes of
slices that enter or leave. A slice's place in a class that leaves has its listening socket
closed and every socket of it closed — relayed connections, cancels and refusals — and new
listening sockets open only after those have ended. A slice whose port cannot be opened is
logged and tried again at every look until it opens. Not applied by a reload, the table's
shape: `listen`, the block, the slice prefix, `max_conns`, the set of classes and each class's
name, port base, peers, pool and two buffer sizes. A file that differs there keeps the shape
in use and has the rest applied if the result is still a valid table; a file with another
`listen`, block or prefix is kept out whole. `ParseTable` refuses the unspecified address as
`listen`.

Log lines: `{"class","index","reason"}`, at most one a second per class and index, with
`"not_printed":N` for what was held back. A reason is one of the proxy's fixed texts, at most
followed by the text of a failed read, dial or listen (addresses); nothing a peer sent is
logged. Table events are `{"table":"…"}`: `kept the table in use: …` for a file that was kept
out, a line for a file that changed the shape, and `cannot look at the table: …` once for
each change of that state (a missing file, one that is not regular or is too large).

The dashboard's defaults are in `internal/dashcfg` (`Limits.Proxy`): a ceiling of 80, a pool
of 32, a burst of 60 connections refilled at 30 a second. `Limits.Check()` requires the pool
to be at least twice the per-instance cap.

Rules for whoever writes the table and starts the container
- Write the table before the container is created, with `Marshal`, by rename.
- A class with per-peer caps gets a pool of at least `conns_per_peer` × its peers, so that
  every connection its peers may open can wait for its first bytes at once. A class without
  them cannot have that: measure its reconnect burst against its pool and rate.
- The dashboard's database client opens one connection per statement and keeps none, and a
  page's statements arrive two at a time as fast as they are answered: the rate must hold a
  page as a burst. The refill is one page's worth a second and the burst two, a page taken
  as thirty statements until a real page load is measured.
- A change of the shape needs the container re-created; a new class is one.
- Connection strings for clients behind the proxy carry no request for TLS: the proxy answers
  `N` and such a client fails.

Known limits
- A count falls when `Relay` has returned, a moment after the client's close: a client that
  runs at exactly its allowance back to back is refused now and then.
- A port that stays unavailable is logged once a second for its slice.
- A connection cut with its slice is logged as `context canceled` or not at all.
- The proof with the real client sends its page of thirty statements five at a time over two
  seconds, which the default rate cannot refuse; the two-at-a-time shape is measured where a
  real page is loaded.

Tests: `go test ./internal/pgcap ./cmd/pgcap`; the tag `nopeer` builds a test binary without
the address check (`nopeer.go`; the product build has the check on and nothing that turns it
off), the tag `faulthook` one with the marker of the relay. The unit tests give every test
proxy a loopback block 127.X.0.0/16 of its own and bind port 5432 on addresses of it: a server
on port 5432 of every address fails them. Test helpers live at package level: new tests must
not reuse their names. The proof with the real client
(`TestRelay_RealClientLibrary`, tag `reach`) runs as root on a bare test node with the
proxy's and the client's images loaded. `sp-probe fakepg` gained the modes `scram-low`,
`copy-both` and `param-flood`.

### 2026-11-20 — tests: rules for time-dependent tests
- A ceiling on elapsed time must sit well above the bound under test and well below the time the
  defect would take (the script's own end, the next timer); never just above the timeout tested.
- Replace a sleep before an assertion by a positive wait for the state needed: a received event,
  a hit counter, a refused or accepted dial. A socket file existing is not the server listening.
- Counts of goroutines and descriptors are polled until they settle (up to 10-20 s), and compared
  with `>` against the start, not `!=`.
- Every wait (receive, WaitGroup, poll) has a deadline that fails by assertion, shorter than the
  binary's timeout; a defect must end a test with a message, never with a hung binary.
- Give a test its own clock where it can: pin the model clock, give non-clock cases timeouts they
  cannot reach, and derive deadlines from the one under test.
- When two real timers decide an outcome, widen their gap or assert a property that does not
  depend on the order; add a clock seam only if neither works.

### 2026-11-21 — Operations that wait for backup jobs; create steps 5 and 12; abort C0

What it provides (internal/saga):
- Agent gains EnsureRepoDir, EnsureSpoolDirs, GrantBackupRole, PurgeRepo,
  RemoveFetch, RenderCluster, WipeData, HostState (all on *agent.Agent).
- Jobs: Cancel(op), CancelSubject(subject), PushNow(subject, wait) and
  Offsite(); *backup.Runner satisfies it. Runner.SetJobs(j) before Run.
- Recoverer: Rekey(ctx, Spec) (timeline, err). Runner.SetRecoverer before Run.
- A nil Jobs or Recoverer: the step that needs it fails final, code internal.
  No layout-1 step needs either.
- Submit("restore") answers ErrConflict: the restore table is empty for now.
- SpecFor fills Layout and RepoQuotaMB (= DiskQuotaMB) at every layout, and
  at layout 2 Stanza ("<ref>-<incarnation>") and StanzaPass (secret
  backup.cipher_pass). Each of the last two is empty while it does not exist.

Parking (worker):
- A step returns a park on a new job. SubmitJobAndPark queues it and moves
  the operation to waiting_job in one transaction. The attempt ends and the
  ref lock is released. The job's end puts the operation back to pending.
- Re-entry reads LatestJob(op, step, job_floor): done -> consume; failed or
  none -> submit again. A queued or running job seen by a running operation
  is an error (it cannot happen through the store).
- Five interrupted jobs of one step above the floor: final, code
  interrupted_limit. Cancelled jobs cost nothing.
- The start-of-attempt check ends an operation past its attempts with the
  stored last_error when there is one (the fifth failed job's own code and
  message), else with its own "interrupted too many times" text.
- A step may return later(d): Requeue, the attempt given back, last_error
  kept, one INFO line per wait.
- A step may return a rewind to an earlier step. RaiseJobFloor (counting an
  attempt unless a counted failed job caused it) comes first, then
  AdvanceStep to the step before the target, then a re-read of the
  operation. Past the limit (attempts less params.requeued above five) the
  operation fails with the cause's code.

Create at layout 2 (layout 0 and 1 run exactly the as-built steps):
- 2: the stanza passphrase (once) and cp_lsn (the control plane's WAL
  insert position, once).
- 3: EnsureRepoDir and EnsureBackupState between EnsureDir and
  EnsureNetwork.
- 5a stanza-create (skipped when stanza_created), 5b backup, 5c check:
  each waits for its job.
- 5d replicate: rebuild pages and copies with complete false and stopped
  caps repeat the step. It ends on a complete copy or a skipped result.
  Other stopped values fail final: replication_stopped. Bounds, final with
  code replication_incomplete: ReplLoopMax(Qd) counted copies, and
  RebuildMaxPages from backup_state. Rebuild pages and adoption-only copies
  are not counted (params member repl_free = {step, floor, last, n}).
- 12a: SwitchWAL(cp_lsn) into cp_segment (once), then PushNow("cp", 0).
- 12b: waits without a job (later 5 s) until SegmentReplicated("cp",
  cp_segment). It fails after 900 s from wait_started (code
  cp_not_replicated). wait_started survives op retry.
- 5d and 12b complete at once unless Offsite() is "declared".

Abort of a create:
- C0 (layout 2): Jobs.Cancel(op) before anything is removed.
- C6: RemoveNetwork, PurgeDir, PurgeRepo (every layout, placed projects),
  then SetOffsitePurge (a missing backup_state row is fine).

Caller rules:
- A code path that rewrites a whole parameter document must carry every
  member steps write (job_floor, repl_free, requeued); patchParams keeps
  them.
- Re-read the operation after any store call that changes params in SQL.

Known limits:
- A parked operation has no wait bound of its own until its job is picked.
- Until the daemon wires SetJobs, a layout-2 create fails at 5a and its
  abort at C0, both with code internal.

### 2026-11-21 — The served surface: route, environment, origin and frozen-value tables
Files of studio/ (tab-separated, # comments). A patch that changes what is served, read or
frozen changes its rows in the same commit.
- routes.tsv: KIND ID METHODS CLASS REF PHASE. Every API route, page route and server function
  of the build; class served | opt-in | deleted; phase P1 | P2 | never, - when served. A
  deleted route's file is a line of delete.txt. At this pin: api 32 served, 13 opt-in
  (/api/ai/, /api/mcp), 59 deleted; 223 pages; 1 server function.
- env.tsv: NAME set | unset, or NAME dynamic FILE. set: the process environment (the agent's
  fixed names, the image label's names, HOSTNAME, HOME, the image's ENV). unset: read by the
  server bundle, never set; the code takes its default. dynamic: FILE (hash written [hash])
  has a read that cannot be resolved; one row per name it can yield, PREFIX_*, * (hands the
  whole environment on) or - (none). A dynamic row excuses its whole file.
- public.tsv: the bundler's replacement map as built (NAME TEXT), and
  @upstream:<file>:<name> FILE rows for upstream's hosted values found in the bundles.
- origins.txt: DIGEST BUNDLE ROLE. DIGEST: first 16 hex of SHA-256 of the lower-cased
  scheme://host literal, or @upstream:<file>:<name>; BUNDLE client | server | both; ROLE
  text | request (a page or the server contacts it on load). Gate 70 prints every built
  origin with its digest and bundle on every build: review that list.
Gates (studio/gates/, run in name order by build.sh image):
- 50-routes: route tree, route registrations, server-function manifest, and the server's own
  router (one /** route to the renderer, rules only headers, the public-file middleware
  alone) against routes.tsv, both ways; ref-shaped static segments, public file names and
  function ids fail.
- 60-env: syntax-tree walk of every server-bundle file with the bundler's parser.
- 70-public: the replacement map and hosted values against public.tsv; origins of any case,
  with escaped slashes, in .js .mjs .cjs .html .css .json .svg .webmanifest.
- 90-selftest: every seed of every gate but 40 must be refused; writes gates.json,
  [{gate, seed, result}], result refused | passed | not applied | needs a build. Seeds may
  add files under DIR/output/.
Limits: the walks read the bundle as written, one file at a time; a value reaching the
process object, the environment, a handler table or an origin through an alias plus a
computed key, a non-literal module name, a reflective call, code compiled at run time, or a
URL assembled at run time is not seen (the recorded browser session finds contacted origins).
Public files are held only by their names' shape. A deleted route's path reaches the page
fallback (404 page, 406 for JSON, 307 for a trailing slash); the hard 404/405 for API paths
is the Studio request guard's, a later patch.

### 2026-11-21 — agent: the purge removes the spool trees
- `PurgeDir`'s task runs `rmtree /p/data /p/sock /p/spool /p/rspool` at every layout, with no
  layout test: an absent path is done for rmtree, and a layout-1 directory left with spool trees by
  a rolled-back switch needs it as well. Root's non-recursive removal of the project directory
  failed "directory not empty" on every layout-2 abort or purge before this.
- Every writer of `spool/` and `rspool/` is the project uid, so the task at that uid removes all of
  it; links in these tenant-writable trees are unlinked, never followed.
- `TestPurgeDir_RunsAtProjectUID` pins the four paths in order; the reach test
  `TestAgent_PurgeDirLayout2RemovesSpools` purges a filled layout-2 directory (files, a nested
  directory, a link out of the project directory) with layout-1 controls with and without spool
  trees. The unit fakes model no subdirectories: only the reach test catches a missed tree.

### 2026-11-21 — alert: the alert transport and supapaced alert
internal/alert delivers alert rows as JSON documents to one operator-declared HTTPS endpoint
and pings a dead-man address per stanza.
- Declaration{URL, CAPEM, DeadmanURL}: prints and marshals with paths and queries cut
  (Redact: scheme://host[:port]). Load/Save: Paths.AlertSealed() (/etc/supapace/alert.sealed),
  sealed under the node key with the name "alert", 0600, owned by the caller; no file is
  (zero, false, nil). Load refuses a link, a non-regular file, more than 1 MiB, a mode wider
  than 0600 and another owner.
- Save refuses: not https (http only to 127.0.0.1:<port> on a node whose dev-mode marker is a
  regular file); over 2,048 bytes; non-printable; user information; fragment; bad port; a
  dead-man template without {stanza} or outside the same rules; a CA bundle over 512 KiB or
  without certificates. No refusal quotes an address. Load re-checks against the marker.
- ReadAddressFile(path): one printable line from a regular file not reached through a link,
  at most 2,048 bytes and a final newline; the error never quotes the content.
- MarkTested(p, k, d): records a delivered test only while the file still holds d; Save
  always clears it. NotReady(): "alert destination not declared" | "dead-man address not
  declared" | "no test alert delivered to the declared destination" | "".
- NewSender(st, node, load); Run: a round at once, then every 15 s: PendingAlerts(1 h, 64),
  one POST each, marked after delivery (at least once). The first failure ends the round.
  Status(): last success and last failure times. Ping does not touch Status.
- Send: POST application/json over HTTP/1.1, 10 s, no redirect, no proxy, at most 16 KiB of
  answer header, body unread, 2xx delivered. Errors name scheme://host and a fixed reason
  only; ErrUndeclared. Ping(ctx, stanza): GET of the template with {stanza} replaced,
  stanza [a-z0-9][a-z0-9-]{0,62}; ErrNoDeadman when none is declared.
- Document members: node, subject (node|cp|ref), code, severity, count, first_at, last_at,
  figures (at most 16, names [a-z][a-z0-9_]{0,31}; {} when none). Severity(code) is the
  fixed table; a new notice code needs a row there (a test reads the store's and the
  runner's raisers). A row whose code or subject no document can carry is logged and sent
  as code unlisted-code: its subject and severity when valid (else node, page), its count
  and times, no figures.
- supapaced alert set --url-file F [--ca-file F] [--deadman-url-file F] (--url and
  --deadman-url exit 2), show, test (records the test in the sealed file), send --code C
  (no daemon or database; an unlisted code exits 2). Root only; failures exit 1.
- Known limits: a destination that refuses one document holds back the others until that
  row is raised again; alert test does not exercise the dead-man address.

### 2026-11-21 — Gateway: lazy wake; the wake socket

internal/wakesock: the wake socket, both ends. HTTP/1.1 over one Unix socket.
- SocketName "wake.sock"; WakeBound 10 s (the gateway's hold and the daemon's bound for one
  wake); Backoff 60 s (no wake asked for a project after a failed one); MaxIdleRefs 1024.
- POST /v1/wake/<ref>, no body: 204 woken, 409 busy, 504 failed or not in time.
  POST /v1/idle {"refs":[...]}: at most MaxIdleRefs refs, 204. Bodies at most 64 KiB of
  strict JSON (unknown members, trailing data refused). Anything else, a ref not of the
  20-character form, or a request not of HTTP/1.1 is refused (400/404/405/505) before the
  handler. The target is matched as sent: no query, escape or other spelling reaches it.
- NewClient(path) / (*Client).Wake(ctx, ref): nil | ErrBusy | ErrFailed | ErrUnavailable
  (match with errors.Is; a call that ran out of time is ErrUnavailable joined with
  context.DeadlineExceeded). (*Client).Idle(ctx, refs). Nothing is dialled without a socket
  file at the path; one connection per call, none kept; every call returns within WakeBound;
  answer header 8 KiB, body read 64 KiB at most.
- Serve(ctx, path, peerUID, h): replaces a stale socket, refuses anything else at the path,
  sets root:<peerUID> 0660 (the owner only when run as root), closes a peer of another uid
  unanswered, at most 16 connections, header 8 KiB within 2 s, body within 2 s, idle 2 s.
  Each Handler call (Wake and Idle) gets a context ending at WakeBound and is answered then
  (504) whether or not it returned; a handler that ignores its context keeps its goroutine,
  so it must return within WakeBound. Up to 16 calls may run at once.

Gateway (wake.go; route entries gain their own asleep state, the route file's idle_stop_s
is at most 86400):
- An asleep project is woken only by a request that passed the key check, the rate bucket,
  the route check and the declared body length; a keyless request gets 401 as for an active
  project. One wake per project in flight, the others wait on it; at most 4 on the node; a
  source (IPv6 /64) asks at most 6 wakes a minute per project (joining spends none). A
  project holds at most its in-flight cap (128) of waiting requests, asker included, counted
  until each is answered: at most 512 on the gateway. A request waits at most WakeBound for
  the wake and for the table to show the project active, then forwards; every refusal is
  the draining 503 project_restarting with Retry-After: 5, at once when over a limit.
- A wake that failed or was not answered within the bound backs the project off for Backoff
  (its requests answered at once); ErrBusy starts none and is answered at once.
- (*Gateway).SetWake(*wakesock.Client) before serving; (*Gateway).ReportIdle(ctx) runs the
  idle report every 30 s: the active projects with no request in flight and none for
  idle_stop_s since the report at which each was first seen active; sent in pieces of
  MaxIdleRefs. Activity is a request that passed the checks above; anyone holding a
  project's public anon key can keep it awake.
- cmd/gateway dials /run/wake/wake.sock; the gateway's container needs that directory
  mounted (read-only is enough). Without the socket an asleep project answers 503
  project_restarting and nothing is sent.
- Known limits: held requests sit outside the in-flight caps (bounded at 512 above); a tenant
  owning many projects whose wakes stall can keep the four places busy; the declared body
  length is checked before the wake, a chunked body over the cap is refused while streaming.

### 2026-11-21 — bkjob: the job environment, the tool runner, the push job; supapaced job
internal/bkjob runs inside a backup job container; cmd/supapaced/jobcmd.go dispatches it.
- Env(stanza, kind, controlPlane): the pgBackRest environment of a job kind, every option pinned,
  PGBACKREST_CONFIG=/dev/null for all; push has no PG1 options; stanza-create, backup and check
  add the socket, the user (supapace_backup, control plane supapaced) and PGOPTIONS from
  pgsock.StartupParams(false) ("-c name=value", space and backslash escaped). Environ adds the
  passphrase (PassName) for push, stanza-create, backup, check, restore and serve only.
- Run(ctx, args...): execs Tool (/usr/bin/pgbackrest) without a shell, the job's environment;
  stdout and stderr captured together, the last 64 KiB kept, never written to the job's stdout.
  A tool that exits: (code, output, nil); err only when it could not start or was signalled.
- Error{Code, Message}: a job program's failure; the message is cut to 256 bytes on a character
  boundary. Codes(kind): the failure codes a kind's program can end with — the one list; the
  recorder (internal/backup) records any other code of a listed kind as crashed. Kinds that
  are not listed keep the rule that refuses the runner's own codes. A new job program lists
  its codes here; a nested push's codes must be mapped to the outer kind's.
- Push(ctx, in, spool): lists the spool in batches of 1,024, keeps the lowest candidates up to
  in.MaxEntries (cap bklimit.PushMaxEntries, 56): histories first, then by name. Each entry is
  opened O_NOFOLLOW|O_NONBLOCK and must be a regular file of in.UID within SegmentMax (segments,
  at least 1 MiB) or SmallMax; it is copied below /tmp and that copy is pushed; the spool entry
  is unlinked only after exit 0. Set aside (renamed <name>.quarantined-<16 hex>, bytes kept):
  a timeline not admitted (timeline), any other shape (shape), the tool's exit 29 (shape) and
  44/45/46 (refused-<n>) — only once the pass has its result, which lists them. Failure codes:
  repository_quota (exit 104 naming error 122), repository, spool, stopped (context ended); a
  failed or stopped pass sets nothing aside. Old .tmp- entries (bklimit.SpoolTmpAge) are
  unlinked unopened, 1,024 a pass; other names are counted in other_entries.
- Result: newest = per admitted timeline the highest segment in /repo when the job ends (names
  checked with walname.RepoPath, the 64 highest timelines); histories = every history name in
  the repository, the 64 highest, [] when none; spool_entries/bytes/oldest = matching entries
  left untaken (spool_entries == remaining).
- supapaced job KIND reads /job/input.json (strict, kind must match), replaces every PG*
  variable by Environ (passphrase from the container), stops on SIGTERM/SIGINT, prints one
  result line: exit 0 result, 1 failure, 2 usage, 3 internal (no line: recorded crashed).
  Only push is dispatched (jobKinds); later kinds add their entries.
- Known limits: exit 29 as content-only is a property of pgBackRest 2.58, re-check at a tool
  bump. A kill between the renames and the result line leaves renamed entries unlisted. A
  synchronous archive-push takes no lock.

### 2026-11-21 — internal/repl: the replication program; supapaced replicate
Runs only inside a replication or probe job (replicator uid, the project's group). Reads
/job/input.json, /cred, /job/ca.pem (optional), /repo (read-only), /index (copy only).
- `supapaced replicate copy|rebuild|probe`: one result line (jobio.MarshalResult), exit 0; a
  failure document, exit 1, code from `repl.Codes(kind)` (replicate: input, credential, index,
  repository, store, result; probe: input, credential, store, result); exit 2 for usage and for
  an empty SUPAPACE_S3_ADDRS (refused before any client exists: the name is never resolved).
- `Key(prefix, subject, rel)`: the one key constructor, "<prefix>/<subject>/<rel>" (no leading
  slash for an empty prefix); rel must pass walname.RepoPath for a stanza of that subject; ErrPath.
- `Copy`: info files read first, uploaded last, only when they changed and the job stopped
  nowhere, walked the whole tree and found nothing unreadable, changed or held. Data files by
  conditional create (multipart above 32 MiB; an unfinished upload is aborted). An existing key is
  compared by HEAD (size and the sha256 metadata): equal is adopted, different is the notice
  offsite-differs; nothing is overwritten. Ascending key order; a timeline's segments wait for its
  history; stops at the first failed upload, at max_files (uploads + adoptions + info), max_bytes,
  the day's budget and its own time bound (stop reason caps).
- Walk: never follows a link at any level, never blocks on a FIFO, depth 12, at most max_entries
  (250,000) entries newest name first, regular files of the project's uid only, size bound per
  kind; a directory read error is unreadable-entry, never a short listing.
- `Rebuild`: one page of at most page_rows (4,000) listed versions, delete markers counted; a row
  per key with its oldest version on the page; next markers and last; keys outside the layout are
  dropped and counted in the one notice a page may carry, unlisted-entry.
- `Probe(ctx, in, ProbeTargets, Deleter)`: the operator check's twelve rows, each denial with a
  positive control on the same credential; an undecidable row is ok:false with "unknown: ...".
  It writes and deletes only below "<prefix>/.probe/" (`Signer` refuses any other DELETE and any
  multi-object delete) and aborts every upload it opened. The credential file holds 4 lines:
  the write pair, then the read-only pair (copy and rebuild: 2 lines).
- `Store` is the subset of *s3x.Client the program calls, plus `Prefix()`; `NewBucket` makes one.
- Index file: jobio index rows, read once at 40 bytes a row (about 230 MB peak at 2.95 M rows
  with a full walk); a malformed file is code index.
- Bounds: copy and rebuild end within CopyBound (240 s), the probe within ProbeBound (100 s),
  below their job deadlines; CallTimeout 60 s per call; s3x bounds each connection attempt at
  10 s, so at most five dropping addresses ahead of a good one are tolerated.
- Secrets: never in the environment (a name with PASS, SECRET, KEY or TOKEN is refused); keys
  are printable ASCII and scrubbed, with every prefix of 8 bytes or more, from all printed text.
- Tests against the object-store stand-in: SUPAPACE_STANDIN_TEST=1, TestStandin_* (this
  package's TestMain starts it; a later file of the package reuses it).

### 2026-11-21 — backup runner: replication records, index files, budgets, rebuild, fetch plan
`internal/backup` `replication.go`, `rebuild.go`, `index.go`, `fetchplan.go`: replicate and fetch
halves of the runner. Their `init()` assigns the four seam variables of `jobspec.go`
(`buildReplicate`, `buildFetch`, `recordReplicate`, `recordFetch`); nothing is exported.

Launch, replicate. While `backup_state.rebuild_epoch` is below the epoch the job is a rebuild page
from the markers stored at its launch (never from a result or memory); past
`bklimit.RebuildMaxPages` pages it is refused, code `internal`, no container. Otherwise a copy:
a subject paused for its budget is refused, code `budget` (and `queueReplicate` queues none while
paused); input = what is left of today's budgets (never negative; -1 for `cp`, which has none)
and each info file's newest recorded hash. `MemMB = bklimit.ReplMemMB(ObjectCount)`.
Launch, fetch. `fetchPlan` builds `/job/plan` from the record alone: the set's files, other sets'
files recorded at or before its `listed_at`, each info file at its newest version at or before it
(sized `bklimit.SmallMax`: an upper bound, the record keeps no size), the history of every
timeline row (recorded, pending, abandoned), archive files of admitted timelines from the set's
start segment: all for `latest`, through the segment of a position (16 MiB segments), or up to a
time plus `bklimit.FetchMargin(archive_timeout, extra)` and the lowest later segment per timeline.
Refused as a failed job without a container: `record_not_rebuilt`; `fetch_too_large` (sum above
the repository quota, saturating; notice `fetch-too-large`). `max_bytes` = the repository quota;
`SetReplicatorQuota(2 x largest quota)` just before the launch. `cp` is refused (`internal`):
`recover` fetches it. The plan's history names are kept in memory per runner and subject until
that job's record; a record without its own plan is `crashed`.

Record. Every bound is checked before the first store write; a failure is `crashed` and nothing
is recorded. Copy: probe rows <= 32, notices <= 16, info <= 4, uploaded+adopted <= 2,048, figures
not negative, stop in {"", caps, budget, upload-failed, held}, every key a repository path of the
subject's stanza and of an admitted timeline within its kind's size. Rows and info versions are
recorded at the runner's own time, never the job's `at`. `complete` is false while segments are
held, and `stopped` becomes `held` when the job gave no other stop. Over budget, or stopped at
it: paused until 00:00 UTC, notice `budget-exceeded` with the projected time to a full quota.
Rebuild page: no copy lists; last page complete with no stop, others stopped `rebuild` with a
next key marker that sorts after the launch markers (or the same key, another version); merged
with the job row's launch number; `store.ErrConflict` (already rebuilt) is a late page, done.
Notices: copy codes as listed in `copyNotices`, rebuild only `unlisted-entry`; count not
negative, detail <= 1,024 bytes (the store cleans and cuts it to 256). The store keeps one row
per subject and code: its count is the number of reports, the detail the last report's.
Stored documents: replication = counts, not lists: {ok, mode, complete, stopped, uploaded,
adopted, info, sets_complete, rows, notices, bytes, objects, walked, truncated, held, last};
fetch = {ok, files, bytes, histories (from the plan)}. Readers must not use `jobio.ParseResult`.

Index file `nodecfg.Paths.IndexFile(subject)`: the daemon's regular file, 0444, in a root 0700
directory; one `jobio.IndexRow` line per record row; no promised order (a rebuild writes key byte
order, appends follow); at launch its line count equals the record's and every line parses with
`jobio.ParseIndexRow`; keys unique then; never written while the subject's job runs. Appended
all or none after a copy; rebuilt by rename after an adoption, after the last rebuild page, and
when a copy launch finds it missing, another mode, owner or type, a bad or torn line, or another
line count. A file the runner wrote or parsed is remembered (inode, size, mtime) and not re-read;
a restart parses each file once. Known limit: a file changed in place by root to the same size
and mtime is taken as known. Stale temporaries `.<subject>.idx-*` go at the next rebuild.

### 2026-11-21 — harness: dashboard node mode, issuer and delay stand-ins, dashboard test build

Make (all without DASH behave as before, but for the memory check):
- `make node-up` / `node-bare` refuse unless MemAvailable (whole GiB) >= NODE_MEM + 2. NODE_MEM is
  4, or 6 with DASH=1. On a 16 GiB CI runner that is about 8 GiB of margin.
- `make build` also builds `bin/pgcap-nopeer` and `bin/pgcap-faulthook` (tags nopeer, faulthook);
  test binaries for bind mounts, never in an image.
- `make studio`: `studio/build.sh image` with IMAGE_CACHE=$(IMAGE_CACHE)/dash (archive, build
  record and the build's own cache under dash/). Never part of `make images`.
- `make images DASH=1`: also `supapace-pgcap:local` and `dash/supapace-pgcap.tar`; refuses when
  `dash/supapace-studio.tar` is missing. DASH=1 exports SP_DASH=1 for scripts/cache-images.sh.
- `make browsers`: `supapace-browsers:local` and `$(IMAGE_CACHE)/browsers/supapace-browsers.tar`
  (needs the network; not under dash/, so dashboard nodes do not load it at boot).
- `make node-up DASH=1 [STUDIO_DOMAIN=studio.test]`: 6 GiB node; node-init.sh passes
  `--studio-domain` to init only when the variable is set and `supapaced init -h` lists the flag,
  and only then loads `/images/dash/*.tar`. init runs on first boot only: run `make node-down`
  before switching a node between modes.
- `make reach-dash [REACH_ARGS=…]`: builds `bin/dash.test` (tags `reach dash`), loads the browser
  archive into the node when it exists, runs bracketed by the suite reset like `make reach`.
- `make node-proof PKG=<dir> [RUN=<re>]`: `go test -c -tags reach` of that package, run as root in
  a bare node (loads the dash/ archives it lacks, never a `supapace-studio-*.tar` variant); without
  RUN it runs `^TestNode_` only, since a package's unit tests may read the source tree.
- `make browser-test [RUN=<re>]`: test/browser (tag browser) in a bare node, browser image loaded.

Suite (test/reach):
- `suiteHooks []func(testing.TB)`: run once in TestMain after fixtures A and B; a failing hook
  stops the run ("a suite hook failed; no test ran"). Empty in reach.test.
- dash.test = reach.test + `//go:build reach && dash` files; `-test.list` is identical until a
  `dash_<topic>_test.go` exists. New package-level names in dash files start with `dash`.
- dashSetup (hook): fails at once on a node without a studio domain; starts `sp-dashstub issuer`
  on 127.0.0.1:<random> as issuer.<base domain> (leaf from the node's dev CA), registers it with
  `supapace dashboard issuer set`, adds members a-owner, a-developer, a-read-only on A and
  b-owner on B. On a rerun a member with another role fails the run, naming it.
- Helpers: needDash(t) the studio domain; issuer(t) *dashIssuer (Iss, Host, AuthorizeURL, Addr,
  Priv, KID, SetSubject); signIn(t, ref, sub) the session cookie via login, callback and session
  post; dash(t, ref, cookies...) *dashClient{Origin, Addr, H1, H2} ("_" is the sign-in host;
  clients send browser Sec-Fetch-* headers, keep any header the test set, never follow
  redirects); addMember(t, ref, sub, role); bypassGateway(t) a client dialling Studio from the
  gateway's netns (the test sets the assertion; dashAssert(key, a, now), dashNodeKey(t));
  socket(t, uid) a client of the dashboard socket whose connects run as uid:uid on a locked
  thread that is never reused (supplementary groups dropped first); withRTT(t, d) the delay
  relay's address towards the gateway (set
  dashClient.Addr); studioMem, pgmetaMem(t, i), proxyMem: cgroup current and peak bytes;
  browsers(t, scenario) the browser image's JSON result (same container shape as test/browser).
- Untagged: dashNewIssuer, dashIDToken (300 s), dashAssert (30 s), dashScenario, dashFetch,
  dashPathForms(p, ref, foreign) map of named path forms.
- TestReach14 full-node clause: fills with scratch projects up to mem_alloc_mb / 768, asserts
  node_full, removes them; a node without a studio domain must need no filler.

sp-dashstub:
- `issuer --listen --cert --key --signing-key (PKCS #8 DER RSA) --issuer --client-id
  --subject-file`: GET /authorize (response_type id_token, response_mode form_post, client_id,
  nonce, https redirect_uri; else 400; other path 404, other method 405; empty subject 409)
  answers a form posting id_token (RS256, 300 s), state unchanged and session_state; the page
  submits itself unless the request carries the cookie hold=1. Subject file read per request.
- `delay --listen --to --rtt`: TCP relay; each chunk (<= 32 KiB) delivered rtt/2 after it was
  read; at most 16 chunks queued per direction, then reading stops; EOF passed on as half close.
- Usage errors exit 2, runtime errors 1; both print "listening ADDR" on stdout once bound.

CI: job `dash` (matrix: studio.test, and the public-suffix name of test/browser), Studio archive
cached on the hash of its inputs; loads nft_connlimit; runs browser-test once, then `make reach`
on the dashboard node until a test/reach/dash_*_test.go exists, then `make reach-dash` (second
configuration: `-test.run Browser`, i.e. TestDash14_SignIn_Browser and
TestDash15_CrossSite_Browser; the step fails when a dashboard test file exists and no test
matches). unit also vets tags `reach dash` and `browser`.

### 2026-11-21 — The sign-in seam's answers counted by cause; the sign-in model as the gateway

The gateway (internal/gateway):
- signInCause: a fixed list of twelve causes - ok, state, binding, token_key,
  token_signature, token_claim, token_time, token_form, issuer_error, ticket,
  cross_origin, not_presented. Nothing of a request names one.
- Dashboard.countSignIn(ref, cause): one count, under d.mu, beside the rule
  counts. Every count is made after the handler's hosted check, so ref is "_"
  (the sign-in host) or a ref of the table. The map holds at most the refs the
  table had in the minute, plus one.
- logRefusals, once a minute: after the rule lines, one line per ref that has
  counts, in ref order:
    gateway: dashboard sign-in in the last minute: ref <ref>: ok N state N
    binding N token_key N token_signature N token_claim N token_time N
    token_form N issuer_error N ticket N cross_origin N not_presented N
  (one line; the logger's prefix comes first). Both maps are swapped under the
  lock and written after it is released: a request never waits on the log.
  Nothing is logged per request; no token, cookie, state, nonce, return path,
  subject or error value reaches the line.

What counts as what:
- ok: a session cookie set.
- state: a state that does not parse or names no table host (callback), or
  that is not this host's (session endpoint).
- binding: the attempt's cookie absent, doubled or not 43 characters, or
  jwtx.ErrNonce - on the retry page and on the final 401 alike.
- token_key: ErrNoKID, ErrUnknownKID (also a kid listed twice in the set),
  ErrAlg, ErrKey.
- token_signature: ErrSignature. token_claim: ErrClaim.
- token_time: ErrExpired, ErrNotYetValid.
- token_form: ErrMalformed, ErrDuplicateMember, a body or field either post
  refuses (a state field absent or doubled among them), and a callback token
  over 8 KiB or outside its alphabet.
- issuer_error: the callback's body holds "error" (its value never read),
  with or without a token.
- At the callback the first of: issuer_error, a refused body or field, state,
  the token's form.
- ticket: every log-out 400.
- cross_origin: the seam's 403.
- not_presented: the 401 page of rule 5's exception and of the picker.
- Not counted: the login's 302, 404, 405, 503, 401 login_required, the log-out
  redirects (?ended=0 included), the signed-out page, the relay page, and the
  picker's page and its redirect.
- signIn.fields reports "error" for any body that parses. The answers are
  unchanged: the callback refuses either way, the session endpoint ignores it.

The model (cmd/sp-dashstub flow) answers as the gateway does:
- Log-out without a session ends on signed-out?ended=0.
- The unsigned ticket is "<iat>.<0|1>.<refs>": more is set past 16 other
  refs, carried by every hop, and the last hop adds ?more=1.
- The signed-out page has the gateway's three sentences: ended=0 and more=1,
  each written exactly once, select them; both at once show both.
- The policy: script-src is the page's own hash (the relay's, or the
  navigating script's on the session and retry pages) or 'none'; style-src is
  the one style's hash.
- On the sign-in host any method but GET of its endpoints is 404, and so is
  POST / with a session.
- The posts read the body alone.
- The not-presented page's link carries a validated return path.
- cross_origin, not_found and login_required are JSON refusals; Accept is
  read in any letter case.
- The state's path must be strict base64url; the cookie must hold a
  43-character secret.
- A project page checks the session before the same-origin rule.
Known limit: the model reads the first segment raw where the gateway reads
it percent-decoded (/%61pi).
test/browser: the log-out scenarios wait for signed-out?ended=0 (no session,
or reached from another site) and signed-out?more=1 (from the sign-in host).

### 2026-11-21 — saga: the switch in restart; the delete's final jobs; purge
What it provides (internal/saga):
- Restart steps R0 R1 S1 R2 R3 R4 R5 S2 S3 S4 S5 S6. The S steps run only
  when the pass's target configuration is at layout 2; a rollback to a
  layout-1 configuration skips them.
- S1, before R2 on the candidate's spec: EnsureSpoolDirs, EnsureRepoDir,
  EnsureBackupState and the stanza passphrase (secret backup.cipher_pass,
  made once), all idempotent. Its failure leaves the project serving.
- S2 decides once, into params first_backup: true when no roll-forward is
  recorded and the project has no backup set; then the backup role's grant.
  S3 stanza-create (skipped with a stanza), S4 backup, S5 check, S6
  replicate run only when first_backup is true. The project is active
  again from R5, so a failing grant or job leaves it serving; op retry or
  any later restart completes the switch.
- R2 of a project whose previous configuration is layout 2: after the
  route drains, Jobs.PushNow(ref, bklimit.DrainPushWait); its outcome in
  params drain_push (ok, incomplete, timeout, failed; skipped without a
  stanza). Never fails R2.
- The roll-forward (R3, R4) writes rollback_gen, rollback_error and
  rollback_step (absent after R4) into the stored parameters and keeps
  every other member, unknown ones included.
- sameConfig compares every configuration field (JSON), a nil and an empty
  GUC map equal: the same relation as the store's own config comparison.
- Delete steps D1 D2 Db D3 Dp Dr D4 D5. D1: project deleting, then
  Jobs.CancelSubject (layout 2), then the route. Db backup (cluster up),
  Dp push until a push reports complete (at most PushLoopMax jobs), Dr
  replicate (declared store only) are layout-2 steps and best effort.
- The delete's result document: final_backup, final_push,
  final_replication, each ok, skipped (no stanza; Dr: store not declared),
  incomplete (push loop at its bound) or the failing job's code
  (interrupted_limit among them). An interrupted job is submitted again.
  None fails the delete.
- Purge: P1 cancels the project's jobs before the stops; P4 cancels again,
  then PurgeDir, PurgeRepo (every layout) and the off-site purge flag.
  Nothing is deleted off-site.

Store (internal/store/job.go):
- A failed job of a delete moves neither the operation's attempts nor its
  last_error (FinishJob); other kinds count as before.

Caller rules:
- Readers of backup_state must filter on layout 2: a failed S1 or a switch
  rolled back to layout 1 leaves its row, passphrase, spool and repository
  behind (the purge removes them).
- Jobs queued for a deleting project after D1 are refused at pick by the
  job runner (op-less jobs run only for active or restarting projects).

Known limits:
- A delete after a failed restore backs up whatever cluster runs; a failure
  is recorded only.
- A delete parked on a job that is never picked waits without a bound of
  its own.

### 2026-11-21 — Studio: the project of a request and the control-plane client
Patches 0005-0009 (topic context), files under apps/studio/lib/api/self-hosted/. One server
process serves many projects; what it knows of a request's project comes from the control
plane's answer and is held for that request alone. No route calls these yet: the request guard
(a later patch) verifies the assertion, calls resolve and runs the route inside the context.
- limits.ts: limits() - SUPAPACE_LIMITS parsed at the first call: exactly the fourteen members,
  each a positive safe integer. parseLimits(text) throws; orStop(read) logs one line and exits
  1. Nothing is read at import: the build's prerender starts the server without the node's
  environment. So a bad setting stops the process at the first use, not at start;
  checkSettings() (exported: limits, then the key file) is for a start hook of a later patch.
- project-context.ts: Assertion {text, ref, iss, sub, name, role, purpose} (as verified);
  ResolveAnswer (the socket's members); ProjectContext = the answer + principal {iss, sub,
  name}, role, purpose, assertion (the text); projectContext(assertion, answer) (frozen;
  refuses another ref); runWithProject(context, fn); getProjectContext() throws ProjectError
  500 no_project_context outside a request. ProjectError(status, code, message) holds nothing
  else. roleClass(role): rw for owner and developer, ro for read_only, else 401 bad_assertion.
- dash-socket.ts: resolve(assertion), keys(assertion), dropProject(ref), checkDsn(dsn, pgcap?),
  MAX_ANSWER_BYTES (64 KiB), MEMORY_ENTRIES (4096). Settings at the first call, a bad one stops
  the process: SUPAPACE_DASH_SOCKET, SUPAPACE_DASH_DATA, SUPAPACE_DASH_KEYS (absolute paths),
  SUPAPACE_PGCAP (<IPv4>:<first port>:<last port>), <keys>/cache.key (43 base64url
  characters, an optional = and line end).
- util.ts: getConnectionString({readOnly}) - the context's dsn_ro when asked or when the role
  is read_only (none: ProjectError 403 no_read_only_login), else dsn_rw. The POSTGRES_*
  connection constants and their defaults are gone; outside a request it throws.
- generate-types.ts: sends x-connection-encrypted for the context's string; a caller's header
  of any spelling is replaced.
Caller rules:
- resolve and keys take an assertion whose signature the caller has verified; a warm entry is
  answered without asking the socket.
- Read the context before waiting on anything another request may complete: a callback run by
  another request runs in that request's context.
- A ProjectError is the answer {code, message} with its status; mapping it is the caller's.
One call: POST /v1/resolve or /v1/keys on the Unix socket, header X-Supapace-Assertion, no
body; bounded by socket_call_ms from its creation, response head 8 KiB, body 64 KiB.
- 200: fatal UTF-8, JSON, a closed schema (unknown members dropped); ref and api_url must be
  this project's; dsn_rw present exactly for the class rw; each string through checkDsn; both
  logins on one port; service_role_key only for an owner under purpose reveal. A 200 that
  fails a check is 503 project_unavailable.
- Passed on with status and code: 401 bad_assertion, 403 not_a_member, 404 not_here, 429
  rate_limited, 503 unavailable. Every other answer is 503 project_unavailable.
- No answer (no connection, no response head in time, connection ended before a head): for
  resolve the disk entry, else 503 project_unavailable; for keys always 503. Once a head has
  arrived the socket has answered: no disk entry, whatever follows.
Caches (resolve only):
- memory: key (ref, iss, sub, role class), resolve_memory_s (60 s), at most 4096 entries
  (expired swept, then the oldest dropped); requests of one principal that arrive together
  share one call. A member removed from a project can be answered from a warm entry for up to
  that time.
- disk: <SUPAPACE_DASH_DATA>/<ref>/cache/<rw|ro>.bin = 12-byte nonce, AES-256-GCM of the
  answer's JSON, 16-byte tag; associated data <ref>:<class>; 0600 in a 0700 directory; written
  by rename at every answer of the socket; never written or touched on a read; not used when
  its modification time, or the answer's own `at` inside the sealed bytes, is older than
  resolve_disk_days or more than 60 s ahead of the clock (so a restore that drops file times
  revives nothing). Before a write, at most 64 leftover <rw|ro>.<16 hex>.tmp names are removed.
  Per role class, not per member: on silence any member the gateway admits gets the class's
  entry. Never copied into memory.
- dropProject(ref) removes the project's memory entries and its cache directory.
checkDsn accepts postgresql://<login>:<password>@<proxy address>:<port>/postgres?sslmode=disable
and nothing else: login postgres or supabase_read_only_user; password of printable ASCII,
every byte outside A-Z a-z 0-9 - . _ ~ as %XX in upper case; the port in the proxy's range,
canonical decimal; at most 512 bytes. Same vectors as internal/dashcfg (testdata/dsn.json).
Its messages never hold the string.
Known limits:
- Which postgres-meta is asked, the header-encryption key, and every route that answers from
  the process (project, settings, configuration, keys, snippets, profile) are unchanged here.
- A stand-in or fixture that seals an answer must take `at` from the clock: a fixed date stops
  being served from disk seven days later.
- The memory lifetime is counted on elapsed time (performance.now), not the wall clock.
- Upstream's tests of the removed constants are skipped in place.
- Unit tests: studio/build.sh test (an HTTP server of the test on a Unix socket).

### 2026-11-21 — internal/repl: fetch (supapaced replicate fetch)
`repl.Fetch(ctx, in, plan, dest, st)` writes objects of the store below the job's fetch
directory with the subject's read-only credential; `supapaced replicate fetch` runs it (one key
pair in /cred, the plan at /job/plan, a regular file; the destination /fetch).
- By plan (a project): every jobio.PlanRow is checked before the first request — a repository
  path of the job's own stanza (walname.RepoPath), an admitted timeline, a key built by Key, no
  duplicate, a version id of the right shape, a size within its kind's bound — else code path.
  A row without a version id takes the oldest version that is an object. Every body is checked
  against its row: the version the store answered, the size (exact; an info file's row carries
  its kind's bound), the sha256 when the row has one. At most 262,144 rows (too_large above).
- list_current (subject cp only, no plan): lists the stanza's two trees ("archive/<stanza>/",
  "backup/<stanza>/"), takes write-once kinds at their oldest object version and the four info
  files at their newest, never a delete marker; keys the layout refuses are skipped. Reports
  newest_set (the newest label whose backup.manifest it fetched; none is code missing) and
  newest_segment (the highest segment number fetched, whatever its timeline; may be absent).
- Writes: every directory opened from its parent's descriptor without following a link,
  created 2750; files created exclusively (O_CREAT|O_EXCL, never through a link), 0640; a file
  that fails is unlinked. A stale or linked target fails with code path; /fetch must be empty.
- Bounds: at most max_bytes written in all (too_large); each version listing at most
  ListCurrentMaxPages (2,048) pages (code store); the program ends within FetchBound(max_bytes),
  the fetch deadline for that quota less 60 s; each listing page 60 s, each GET 60 s plus its
  object's bound at 4 MiB/s; each connection attempt 10 s. The job's deadline and max_bytes must
  come from one quota figure.
- Codes, repl.Codes("fetch"): input, credential, path, missing, mismatch, quota (EDQUOT,
  ENOSPC), too_large, store, result.
- Trust: a holder of the write credential can offer older info files or deny the fetch, never
  other content under a write-once name; whoever controls the listings can offer an older state
  unseen.

### 2026-11-21 — Logs by container: a project's and the node's

What it provides
- GET /v1/projects/{ref}/logs?container=cluster|rest&tail=N and
  GET /v1/node/logs?container=gateway|pooler|proxy|platform-db&tail=N answer
  {"lines":[{"container","at","text"}],"notes":["..."]}. A project's container is optional (both,
  merged by time); the node's is required. tail is 1 to 1000, default 100. Any other query key, a
  repeated key or a value outside the lists is 400 before the daemon is asked.
- adminapi: LogLine, Logs (the answer and what the daemon returns), LogsMaxTail (1000),
  LogsMaxBytes (1 MiB of text), LogLineMax (16 KiB), LogAtLayout
  ("2006-01-02T15:04:05.000000000Z": UTC, nanoseconds, fixed width, so string order is time order;
  the API's other times are in seconds), ProjectLogContainers, NodeLogContainers.
- The daemon's capabilities, asserted at use: Logs(ctx, ref, container, tail) (container "" = both)
  and NodeLogs(ctx, container, tail); each returns at most tail+1 lines a container, so a cut is
  known. supapaced's projectLogs and nodeLogs implement them; until ops offers them both routes
  answer 409 conflict "logs are not available on this node: ..." (after 400 and 404).
- supapace project logs REF [--container C] [--tail N]; supapace node logs --container C [--tail N].
  stdout is the body; stderr lists "CONTAINER TIME | TEXT", then the notes. Exit 0 on 200, 1
  otherwise, 2 on a usage error.

Contracts
- A project's lines come only from containers labelled with its ref and the role cluster or
  postgrest, read by id; task and job containers are not included. The node's come from a closed
  map: gateway sp-gateway, pooler sp-pooler, proxy sp-pgcap, platform-db sp-platform-db; an absent
  one is a conflict naming it. A shared container's lines are never under a project, whatever
  they say.
- container is set by the daemon from the container it read; at is Docker's own time prefix. The
  API fails the whole answer (500) on a line of a container the route does not serve or with a
  time outside LogAtLayout, and neither answers nor logs its text.
- Text and notes lose invalid UTF-8, C0 and C1 controls (CR, LF, ESC included; a TAB becomes one
  space) and Unicode
  Cf, Zl and Zp (bidi overrides among them); the CLI cleans again. JSON consumers get valid UTF-8.

Bounds
- The answer: the newest tail lines, at most 1 MiB of text (newest kept), no line over 16 KiB;
  each cut is a note, and there is no note without a cut. At most 16 daemon notes of 1 KiB.
- One read: at most two at once; a third waits at most 15 s for a slot (then a conflict saying two
  reads are running), and a read that has its slot runs its Docker calls within its own 15 s.
  A call over the Docker client's
  output caps (4 MiB of stdout, 64 KiB of stderr) is asked again for half the lines, down to one;
  the note says how many were read. The lines are always the newest. A container that writes its
  log to stderr (the database, PostgREST, the gateway) thus yields at most 64 KiB a read.

Errors
- Daemon refusals wrap store.ErrConflict (match with errors.Is) and are answered 409 with the
  reason: no slot, past the deadline, an absent node container, a newest line over the cap, a
  read that failed before its deadline (a container replaced mid-read: "try again"; the daemon
  logs one fixed line with the container's role and the exit status, nothing Docker printed).
- While the routes answer 409 the CLI prints, per container, the command to run on the node:
  docker logs --timestamps --tail N NAME 2>&1 | cat -v (both streams filtered).

Known limits
- On a terminal narrower than a long line, a wrapped row can look like a line of its own; use the
  JSON on stdout or less -S. Docker splits a long line into 16 KiB chunks: their time stamps can
  appear inside the text, and a tail may begin with a line's last chunk.

### 2026-11-21 — agent: recovery start and re-key; pgsock: startup parameters of platform sessions
internal/agent/recovery.go starts a restored data directory, reports its promotion and gives
it the platform's passwords. Layout 2 only.
- EnsureRecovery(ctx, Spec, pgconf.RecoveryTarget) error. Order: spec check; layout 2 (else an
  error naming the layout); pgconf.RecoveryPins (a refusal wraps pgconf.ErrGUCValue and
  touches nothing); state.json compared (ErrEpochDivergence, ErrStaleGeneration); any
  pg-<ref> removed — a failed removal ends the call, so one directory never has two
  servers; platform files rendered (override file by OverridesPinned, archive binary);
  create, start gate, start; state.json written with phase R, the init's pid and start time.
- Its argv is the first boot's (every hardening flag, no network, no access-file mounts: the
  image's own files stand at the pinned paths) without the password variable, with label
  supapace.phase=R and no configuration or image label. Command line: the image's pins,
  pgconf.Pins, pgconf.RecoveryExtensionPins(), recoveryStartPins, then
  pgconf.RecoveryPins(t) — nothing after it, the chosen target last. A line of the restored
  system file does not override a pin.
- recoveryStartPins, for the recovery start only: pre_auth_delay=0; pg_net.database_name and
  cron.database_name empty (no database has an empty name: the HTTP extension's worker and
  the scheduler's launcher cannot connect, so neither runs anything the restored database
  defines); autovacuum=off; max_logical_replication_workers=0 (a restored subscription gets
  no apply worker). The two workers are started again every second after the
  promotion, two log lines each, until the container is stopped; none starts during replay.
  The normal start after it carries none of these.
- It never wipes and never bootstraps. Without the password variable the image initialises
  nothing: an empty data directory ends as a failed start ("is not running after docker
  start") or an exited container, never as a fresh cluster.
- A failed start leaves state.json as it was and keeps the container for its logs; the next
  EnsureRecovery, EnsureCluster or StopCluster removes it. A phase-R container is never
  adopted: EnsureCluster removes it and makes a normal start.
- RecoveryState(ctx, Spec) (promoted, exited bool, err error): needs state.json at phase R of
  the spec's epoch (else an error and no session). exited comes from Docker's record alone
  (absent or not running). promoted comes from one bounded session without a password to
  the recorded process (bootstrap.InRecovery). Not promoted and no error: pgsock.ErrConnect,
  pgsock.ErrNotSocket, a budget error of the dial or of the statement, SQLSTATE 57P03. Any
  other failure: exited when the container stopped meanwhile (a session cut by the server's
  own exit), else an error — pgsock.ErrPeer for another process than the recorded one, a
  refused login, a malformed answer. The answer is the restored cluster's word about itself.
- Caller rule: RecoveryState never ends a wait. A server that neither exits nor promotes
  reads "not promoted" for ever; the caller polls under its own deadline and stops the
  container when it passes. A start that exits at once can fail EnsureRecovery instead.
  Stop the recovery start soon after the re-key: it logs until it is stopped.
- Rekey(ctx, Spec) (timeline int, err error): one session without a password to the recorded
  recovery start: bootstrap.Rekey (the password statements first), bootstrap.ReadTimeline,
  bootstrap.ResetStatementStats (best effort: logged with the ref, 256 sanitised bytes,
  never returned). It does not ask whether the server is in recovery. Errors are cleaned
  and keep *pgsock.ServerError (25006 on a server still in recovery) and the budget
  sentinel. It can be repeated after a cut at any statement: no password is needed.
- Stopping a recovery start is StopCluster. Pass RecoveryState and Rekey the spec given to
  EnsureRecovery.

pgsock.StartupParams. The common list (every platform session; internal/bkjob sends it as
the jobs' PGOPTIONS) now has synchronous_commit=local — a platform write is durable on this
server alone and never waits for a standby named in the system file — and post_auth_delay=0.
StartupParams(true) adds nineteen parameters only a superuser session sends
(superuserParams, each with its reason): event_triggers=off, session_preload_libraries
(empty), log_statement=none, log_min_duration_statement=-1, log_min_duration_sample=-1,
log_transaction_sample_rate=0, log_duration=off, log_min_messages=warning,
log_min_error_statement=panic, debug_print_parse=off, debug_print_rewritten=off,
debug_print_plan=off, track_activities=off, pgaudit.log=none, pgaudit.role (empty),
auto_explain.log_min_duration=-1, pg_stat_statements.track=none,
pg_stat_statements.track_utility=off, plan_filter.statement_cost_limit=0.
- They are in force from the startup packet in every start kind, above any setting of the
  login role, the database or the system file. A platform session therefore does not load
  the image's session-preloaded library, shows no statement in pg_stat_activity, keeps none
  in the statement statistics, and a failed or killed statement is logged without its text.
- A role that is not a superuser is refused (42501) when it sends one of the sixteen the
  server reserves to superusers; the three debug_print_* are settable by any role.
- The lists are pinned by TestConfig_StartupParameters,
  TestStartupParams_SuperuserListIsTheReviewedNineteen and the LIST and SUPER lists of
  test/harness/experiments/e15.sh; each parameter has a case against the pinned image that
  fails without it (session_cluster_test.go, session_system_test.go). An image bump re-runs
  them before the bootstrap baseline is regenerated.

bootstrap: the drift check does not report a pinned name as missing from the command line
when the platform session sets that name itself (it reads source "client" there); the pin
is the container's command line, covered by the configuration label. For such a name it
reads the settings catalogue's rows for every role and reports "… is set for every role of
a database, not only on the command line". Lines of the system file are still reported for
such names (pg_file_settings).

Known limits. Settings of the system file that the command line does not pin are the
project's own: one that stops the server, moves its socket or names a start-time script
fails the platform's sessions, and with them a restore, for that project only; in a normal
start so does pre_auth_delay, for that project's own sessions. The same holds when the
platform's login role lost its login right or its superuser attribute, or the database is
closed to connections. A restored subscription runs nothing in a recovery start: no logical
replication worker is allowed there (and a backup holds no replication slot). Every read in a
platform session is answered
by the cluster and can log itself; none carries a secret. Password verifiers are written
to WAL and to the role catalogue, as at first boot.

### 2026-11-21 — bkjob: stanza-create, backup and check; the data-directory pre-check
internal/bkjob, inside a job container (data directory read-only at /var/lib/postgresql/data,
socket, /spool, /repo). Dispatched by `supapaced job stanza-create|backup|check`.
- StanzaCreate(ctx, in) / Check(ctx, in) (jobio.CheckJobResult) and Backup(ctx, in)
  (jobio.BackupResult): pre-check, the tool, then a final Push whose result is the `push`
  member (never nil on success). check and backup run a push loop beside the tool (a pass,
  then 0.5 s): the tool waits for its WAL in the repository. The loop is stopped by a flag
  between passes and waited for before the final push, so two pushes never overlap.
  stanza-create has no loop (no stanza yet): one push after it.
- Backup refuses any in.Type but "full". The set is read from `info --output=json` (its own
  read bound of 8 MiB, about 650 bytes a set): exactly one stanza of in.Stanza, the newest
  label; label ^[0-9]{8}-[0-9]{6}F$, type full, segments of 24 hex digits on one timeline
  1..2^31-1, LSNs, times from the tool's unix seconds in UTC with stop >= start > 0.
- Codes (bkjob.Codes, the same five for the three kinds): login (exit 56 or 27 with the tool's
  "unable to check pg1: [DbConnectError]" warning line), archive_timeout (exit 82; the message
  names the loop's last push failure, else a late lane), pgbackrest (any other tool failure,
  a failure of the final push with the push's code in the message, a backup type other than
  full, an info answer out of shape), tablespace, symlink. A push's own codes never pass out.
- Messages: the passphrase replaced, cleaned with pgsock.Sanitize, at most 256 bytes.
- precheck(root): walks from directory descriptors, opening only directories with
  O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK from the parent's descriptor; any link is symlink, any
  entry of pg_tblspc is tablespace; a directory replaced by a link or a non-directory before
  its open is symlink; an entry gone is skipped; FIFOs, sockets, devices and files are passed
  over (the tool skips special files itself). Bounds: depth 64, 2^24 entries; past either,
  or a directory that cannot be listed, is symlink ("not walked whole").
- Known limits: the pre-check is a best effort — a link made after the walk is stored by the
  tool; the controls are the job's mounts and absent network, and the restore job, which
  refuses a set whose manifest holds a link. Entries a loop pass set aside are listed only
  when the job succeeds (the failure document has no push; the message counts them). An entry
  whose type the listing does not give is symlink ("not walked whole"), never looked up by
  a path. An info answer at its bound fails the backup (pgbackrest: too many sets). check takes
  no lock in pgBackRest
  2.58; stanza-create and backup exit 50 on an unwritable lock path (pgbackrest).

### 2026-11-21 — bkjob: restore, serve and seed jobs
The restore, serve and seed programs of internal/bkjob, dispatched by supapaced job KIND.
- Restore(ctx, in): restores set in.Set into the empty data directory. First it reads the
  set's manifest with the tool's repo-get backup/<stanza>/<label>/backup.manifest (only that
  path, the job's environment, never --raw), streamed: at most bklimit.SetFileMax bytes and
  1 MiB a line, the tool stopped at the verdict. Refused before anything is written:
  any pg_tblspc entry or link (code tablespace); a [backup:target] entry other than pg_data
  of type path, a [target:file]/[target:path] key outside walname's set-file form, a
  malformed or oversized manifest, any repo-get failure (code set_invalid).
  Then restore --set=<label> --type=none, or --type=standby --target-timeline=<n>.
  On success: none writes recovery.signal (O_EXCL|O_NOFOLLOW); standby renames the tool's
  standby.signal (a regular file) to recovery.signal. Result {"ok","mode"}.
  Codes: tablespace; history_mismatch (exit 58); set_invalid (75, a signal, a manifest
  refusal); pgbackrest (anything else, a data directory that is not empty). A failed job
  leaves the tool's files and no recovery.signal; the caller wipes before the next restore.
  Messages never hold the passphrase or the set's key (also a key cut at 256 bytes).
- Serve(ctx, in, rspool): answers the archive binary's requests until ctx ends (SIGTERM),
  then exit 0 with {"ok","served","none","refused","last","last_none","last_segment"}.
  req/ and out/ are opened once without following links; a non-directory there is
  replaced; failure code rspool. A request must be a regular file of in.UID named as
  walname.Request; anything else is unlinked unread (directories stay). Each pass answers
  at most 8 requests without a waiting answer, newest ctime first. A name answered
  in.MaxAnswers times (cap bklimit.ServeMaxAnswers) is removed unanswered, so the server
  times out and stops instead of promoting. An unadmitted timeline is answered <name>.none
  without the tool; archive-get exit 1 is <name>.none; other failures retry. A file answer
  is checked against SegmentMax/SmallMax and copied to out/.tmp-<name>-<16 hex> (exclusive,
  no link), fsynced and renamed. Old .tmp- entries in out/ are removed at start.
  last_segment: highest segment number answered with a file. none: last 64 names.
  A kill (deadline) leaves no result line.
- Seed(ctx, repo, fetch): checks all of fetch/ first (directories and regular files only,
  names [A-Za-z0-9_.+-]{1,255}, at most 32 levels; failure leaves repo/ untouched), then
  empties repo/ (rmtree.Remove per directory, unlink otherwise; repo/ is a mount) and copies
  by descriptor: directories 0750, files 0640, exclusive and unfollowed; each file is synced
  before it is closed, each directory after its walk, repo/ last. Result
  {"ok","files","bytes"}; failure code seed. A failed copy leaves repo/ partial; running
  the job again over the same fetch/ is correct. A fetch/ carrying pgBackRest's latest
  link is refused.
- The manifest check also reads backup.manifest.copy when the repository holds one, by the
  same rules; two manifests with different keys are set_invalid. Serve's listing returns
  after the current batch once its context ends.
- Known limits: Serve's per-name counts reset past 65,536 names.

### 2026-11-21 — agent: job containers, the backup network, two node-check rows
- `RunJob(ctx, JobSpec) (JobResult, error)` runs one job of a subject (a project ref or `cp`)
  in the worker image and returns its exit code, its result line and the tail of its standard
  error. Kinds: push, stanza-create, backup, check, restore, serve, seed (no network, the
  subject's ids) and replicate, fetch, probe (the backup network, 65530:65530, for replicate
  and fetch with the subject's group). Every kind: no capability, no new privileges, the
  platform's seccomp profile, read-only root, a private /tmp, `--ipc none` (no /dev/shm),
  memory = swap, a pids limit, one CPU, `GOMEMLIMIT` 32 MiB under the memory limit (it does
  not cover a tool the program starts); entrypoint `/supapaced`, command `job <kind>` or
  `replicate <mode>` (copy or rebuild from the input, fetch, probe).
- Mounts per kind, nothing else: push spool, repo; stanza-create, backup, check data (ro),
  sock, spool, repo; restore data, repo (ro); serve data (ro), rspool, repo (ro); seed repo,
  fetch (ro); replicate repo (ro), the index file (ro), /cred (ro); fetch fetch, /cred (ro);
  probe /cred (ro). Always the daemon's executable at /supapaced (ro) and the job's directory
  at /job (ro: input.json and the spec's files, 0444 in a 0755 directory).
- Limits: 512m/256 pids/128m tmpfs for the six worker kinds, 128m/64/16m for seed, 256m/64/64m
  for fetch and probe, `MemMB` (default 256, at least 128) for replicate.
- Name `job-<subject>-<kind>`, labels supapace.role=job, supapace.ref, supapace.job,
  supapace.kind. A probe: `Subject` is the bucket role (`projects` or `cp`), name
  `job-probe-<role>`, ref label and files `probe-<role>`, id may be 0, ids unused.
- Refused before anything is created: an unknown kind and `recover`; a subject that is no ref,
  ids outside the project range (`cp`: 70:70); no id or deadline; an input whose kind, subject
  or job differ from the spec's; a replicate input without mode copy or rebuild; a passphrase
  for another kind than the six, any other secret name; a credential for a worker, none for a
  networked kind, or one that is not exactly 2 lines (probe 4) without a final newline or an
  empty field; `MemMB` on another kind; an `Env` name outside `^SUPAPACE_[A-Z0-9_]{1,100}$`
  (and, for a networked kind, one holding PASS, SECRET, KEY or TOKEN) or a value that is not
  one printable line; a file name outside `[a-z0-9][a-z0-9._-]{0,63}` or `input.json`. A
  networked job is refused with ErrContainment while containment has failed or the `backup`
  network is not the platform's. `JobSpec.Addrs` is not read: a program's address list is its
  `SUPAPACE_S3_ADDRS`, and what a job can reach is the node ruleset's set.
- Source check (`ErrHostState`, match with errors.Is; nothing launched or made): every mount
  source must exist, not be a link, be a directory (the index file and the executable: a
  regular file) and be owned uid and gid by the subject (data, sock, spool, rspool, repo), by
  65530:<gid> (fetch, made by root when absent, after the other sources passed), by root
  (index, executable, job directory) or by 65530:65530 (the credential file). The daemon's
  executable must be root's: a daemon run from a binary of another owner starts no job.
- Secrets: `Env` and `SecretEnv` go through `<jobs>/<id>.env` (root 0600), removed as soon as
  `docker run -d` returns; from then the passphrase is in Docker's record of the container
  (root and the socket's group) until the container is removed. `Cred` is written to
  `<jobs>/<id>.cred` (65530:65530 0400, jobs directory root 0700) and mounted at /cred; it and
  the job's directory are removed with the container. The index file must be readable by
  65530 (0444).
- Lifecycle: every job container of the subject is removed first, whatever its kind and
  state — if one stays, nothing is started; the container runs detached and is polled every
  second; at `Deadline` it is killed and removed (`TimedOut`); when ctx ends it is stopped
  (`docker stop -t 10`) and its result read as after any exit — ctx's error is returned only
  when no line was read. The calls after a job (stop, output, removal) have 60 s from the
  job's end. A removal that fails after the job ended is logged and the result returned; the
  leftover goes before the subject's next job or at the next daemon start. Callers must not
  run two jobs of one subject at once: the launcher has no lock.
- Result: the last newline-terminated line of the whole standard output, at most 1 MiB; more
  than 4 MiB of output, no terminated line or a longer line give an empty result. `Stderr` is
  the last 4 KiB of the first 64 KiB, sanitised.
- `KillJobs(ctx, subject)`: the subject's job containers and files (`probe-projects` and
  `probe-cp` name the probes); "" removes every job container, every container labelled
  supapace.phase=R and everything under the jobs directory. Each removal has its own 60 s.
- `SetReplicatorQuota(ctx, mb)`: uid 65530's quota on the repository filesystem; 0 clears it.
- `EnsureBackupNetwork(ctx)`: bridge `spb0` on the node's backup subnet, IPv6 off, no other
  option; a network `backup` with anything else is refused, never changed; a create that
  loses a race checks the network the other made. Leaving it is the node ruleset's: the
  declared store addresses only, nothing between members, nothing to or from the node. A
  job's resolver is 192.0.2.1: no lookup leaves the node.
- Node check: `repo-filesystem` (blocking everywhere): the repository root is the topmost mount
  at its path, XFS, mounted usrquota,nosuid,nodev,noexec, and on another device than the
  projects directory; `protected-hardlinks` (informational on a development node):
  fs.protected_hardlinks is 1; `docker-networks` accepts `backup`.
- internal/backup: a mount-source refusal is matched with errors.Is(err, agent.ErrHostState).
- Test node: the host's build is mounted read-only at /opt/supapace/build; node-init.sh
  installs root-owned 0755 copies into /opt/supapace/bin at boot and on
  `docker exec <node> /usr/local/bin/node-init.sh install-bins`. `make reach`, `reach-dash`,
  `reach-reboot` and `harness-test` install first; after any other rebuild on a running node
  (a test binary built into bin/, an experiment script) run install-bins before using it. A
  binary that did not change keeps its file, so a running daemon's /proc/<pid>/exe still names
  it; one that changed is replaced by rename — the daemon then runs its old program, its jobs
  the new one, and the suite, which finds the daemon by that link, needs the daemon restarted.
- Known limits: a job at a project's uid runs beside that project's cluster with shared
  directories but separate pid, mount and IPC namespaces; a daemon killed mid-job leaves the
  container and its files until its next start; the environment file is synced to the
  platform filesystem before it is removed.
- Node tests (reach tag, bare node with the object-store stand-in, as root):
  `go test -c -tags reach ./internal/agent`, run `-test.run '^TestJobReach_'`; the test
  binary is the job's program there, and the node's installed daemon binary for one test.

### 2026-11-21 — test hardening, second part
- Gateway tests: serve a test server with goServe, never a bare go Serve. It counts the running
  handlers. A cleanup that restores a package global (a seam, the limits) calls stopServers(t)
  first: it closes the test's own servers and waits (20 s at most) for the handlers of those and
  of its parent tests' servers. A handler may still read the global until it returns.
- Bootstrap static tests read the package source embedded at build time (the source variable,
  go:embed *.go), not the working directory: a checkout under a running binary changes nothing.
  Use parseSource and fs.Glob(source, "*.go"), never parser.ParseFile on a path.
- A control session in bootstrap tests sends only the startup parameters it needs (rawDial);
  to leave a role's statement_timeout out of its own query, set only that one to 0.
- The shared test database of a package lives 4 h as a backstop (the watchdog removes it when the
  test process ends); a -count run outlives 30 min. Use 14400 in a new package's startDB.
- A process killed with its group counts as ended when it is gone or a zombie: its new parent
  (init or a subreaper) may reap it late. Wait with waitDead (10 s), not a short loop.
- Search a stored key set for the quoted member name ("x5u"), not bare letters: a random key's
  base64 may contain them.
- A helper that repeats is stopped after N runs have ended, bounded at 30 s, not after a sleep.

### 2026-11-21 — saga: the restore operation

internal/saga/restore.go, restore_submit.go. A restore replaces a project's data in place with a
backup set and the archive after it: to a time, a WAL position, or the end of the archive; from
the project's repository or from the off-site store.

Submit
- Runner.Submit(ctx, "restore", ref, params): params are exactly {"to","timeline","from"}.
  to: "latest", an RFC 3339 time, or "lsn:<hex>/<hex>". timeline: 0 = the newest recorded one.
  from: "" = the default (local), "local", "offsite".
- The timeline followed is the one named, else the newest recorded; it is rendered as its decimal
  for every target, the end of the archive included ("latest" is never rendered: the server
  would follow the newest history the archive holds, a branch no restore finished included).
- Rules run before the store is touched, in this order: target (pgconf.RecoveryPins), window,
  source, disk quota, repository quota, replication pause. Nothing is written on a refusal.
- Errors: a target outside the backups' window is a *store.WindowError (errors.As); a target the
  recovery pins refuse wraps pgconf.ErrGUCValue and store.ErrConflict (the admin API answers 400
  bad_request); every other refusal wraps store.ErrConflict with its reason (409 conflict).
- The set is chosen from the recorded sets, never from repository files: the newest that stopped
  at or before the target on the lineage of the timeline followed. Lineage of timeline k: the
  sets on k, plus — when the restore that recorded k is known (the timeline row names its
  operation, whose parameters name its set L) — the lineage of L's timeline up to L's stop, down
  the chain. A timeline whose restore is not known contributes its own sets only.
- The source becomes off-site without being asked on a node that has no state file of the
  project, and for a set that stopped before the repository's seed time; off-site needs the store
  declared and a set recorded as replicated and listed.
- Also refused: the repository quota full by the last push's quota report or by the newest push
  job's code (not on a node without a state file, where the figure is stale); with the store
  declared, a replication paused for its budget (a restore replicates before it wipes).

Steps (operation.step), in order
- T1 target rendered again (refusal: final, invalid_target, nothing changed); on a node without a
  state file of the project: directories, network and rendered files, no first boot.
- T2 project restoring, route draining, PostgREST stopped. T3 cluster stopped and removed.
- T4p slot taken; push jobs until one reports the spool empty (bound: bklimit.PushLoopMax, then
  final push_incomplete). T4r replication, then what the repository holds is recorded and compared
  with the timeline rows; a difference sends the restore off-site.
- T5a (off-site): only after a copy job of T4r in the same pass ended complete (mode copy, not
  stopped, not skipped) — else back to T4p; then the fetch directory emptied and the fetch job.
- T5b (off-site): the seed time is recorded, then the seed job, which empties the repository
  and copies the fetched range in; the held histories are then the fetch plan's.
- T5 "wiped" recorded, then the data directory wiped: the first step that changes it.
- T6 restore job, mode none; after a history_mismatch one standby retry with the timeline
  followed when the set lies on it, else the off-site store. tablespace is final. The job's
  reported mode must be the one asked.
- T7 the timeline this recovery will create is chosen, then the recover job. T8 re-key with the
  spec the recovery start was given, the new timeline confirmed (t8_done in the same
  transaction); the recovery start is stopped on every outcome.
- T9 normal start and check. T10p, T10r, T10c, T10b, T10s: push, replicate, check, full backup,
  replicate; a check or backup that ends tablespace or symlink is final.
- T11 PostgREST, route active, fetch directory removed, done and slot freed in one transaction.

Re-entry and attempts
- A step reads only jobs above the operation's job floor; every rewind and every op retry raises
  it, so the steps passed again submit fresh jobs. A step that needs an earlier step's job of the
  same pass and finds none goes back to that step (T4r to T4p, T5a to T4p, T5b to T5a, T6 with an
  unseeded off-site source to T5a).
- Failed or interrupted job at T6: back to T5 (wipe first). At T7, and any failure of T8 before
  t8_done: back to T3. A seed that finds no fetch directory: back to T5a.
- A rewind costs an attempt unless a job that was already counted caused it; cancelled and
  interrupted jobs are not counted at their end, so their rewind is. Five attempts, then failed
  with the cause's code.
- T8 with t8_done set only stops the cluster: no second re-key.
- A failed restore leaves the project restoring, its route draining; op retry continues it, a
  new restore or a delete supersedes it. Its last_error ends with the state it leaves — data
  directory unchanged or replaced, or nothing on the node yet — the commands that leave it, the
  way back to the state before ("--to latest --timeline n") once the directory was wiped, and
  the first reason the source became the off-site store.

Shortfall (end-of-archive restores only)
- Compared by segment number: the highest segment the serve job handed out against the newest
  segment of the timeline followed as the last T4p push reported it (the off-site record's on a
  node that held nothing). Below it: the result's shortfall object and notice restore-shortfall;
  the restore still completes. A missing figure, or no serve result: "not checked" and the notice.
- The figure is what was handed to the recovering server, not what it replayed.

Result document (operation.result of a done restore)
- to, from, set, mode, reached_segment, new_timeline, previous_timeline,
  previous_newest_segment, seeded, shortfall (null, an object, or "not checked"), steps
  (seconds per step, parked waits included). A failed restore has none.

Parameters the steps add (operation.params; written member by member, others kept)
- set, set_start_segment, replaced, n, n_newest_segment, reached_segment, histories, newest,
  t7_started, t8_done, standby_tried, fetch_extra, seeded, shortfall, mode, times, clock, decided,
  wiped, switched.

Job parameters written
- recover: {"target":{"timeline", "time"?, "lsn"?}}, timeline a decimal;
  restore: {"set","mode","target_timeline"}; fetch: {"set","to","timeline","extra"}.

Codes of its own
- Final: invalid_target, push_incomplete, fetch_too_large, set_not_offsite,
  offsite_not_declared, tablespace, symlink, and internal for a stored job result out of shape.
  Counted: timeline_conflict, timeline_mismatch (notice timeline-mismatch).

Touches outside the package
- pgconf.RecoveryPins: with no target the timeline is "latest" or a decimal id (the end of that
  timeline's archive); with a time or a position, "current" or a decimal id, as before.
- adminapi: an error wrapping pgconf.ErrGUCValue answers 400 bad_request.

Caller rules
- SetJobs and SetRecoverer before Run: without them a restore fails with code internal.
- Every stored job result is checked for shape and bounds before use.

Known limits
- Nothing lifts a replication pause before its time; the refusal says when the pause ends.
- The stop after the re-key runs within what is left of the step's deadline (5 s at least); the
  step's own parameter writes have a bound of their own, so a re-key out of time rewinds.
- symlink at T10c/T10b is final also when the data directory could not be walked whole.
- Without a named timeline a restore follows the newest recorded one — also the timeline of a
  restore that failed after its re-key. After a control-plane recovery that lost a recorded
  timeline's row, that timeline is abandoned and is not followed.
- A restore job's refusal of a set (tablespace, link) comes after the wipe.
- A restore to a time after the last commit fails target_not_reached, five passes.
- Nothing here has run on a node yet.

### 2026-11-21 — Control-plane database: archiving, its move, the recovery start

internal/agent/platform.go. The control-plane database (container sp-cp-db, uid and gid
nodecfg.ControlPlaneUID = 70, no network, peer authentication over its socket only) archives
like a project's cluster, lives on the projects filesystem under quotas, and can be restored.

Where things are
- CPProjectDir()/{data,spool,rspool/{req,out}}: 70:70 0700; CPProjectDir() itself root 0700.
- CPDir()/sock (70:70) and CPDir()/etc (pg_hba.conf, pg_ident.conf, root 0444): unchanged.
- RepoDir("cp")/repo: 70:70 0750; RepoDir("cp")/fetch: 65530:70 2750, only during a restore.
- ToolsDir()/supapace-arch: root 0555, copied from beside the daemon's executable; its
  digest is part of the container's configuration label.
- CPDir()/initialised: the stamp, root 0444, empty. CPDir()/restoring: the restore marker,
  root 0600, empty. CPDir()/data.moved: the old tree after a move; this package never
  removes it.

Exported
- EnsureControlPlaneDB(ctx) error: refuses while the marker exists; sets uid 70's two
  quotas (nodecfg.CPQuotas) first and at every call, so a filesystem without enforced
  quotas stops it before anything is written; moves a database from an older build's
  CPDir()/data; stamps the node; starts or adopts sp-cp-db, re-creating it when its label
  differs. Command line adds archive_mode=on, archive_command=pgconf.ArchiveCommand (with
  its marker word, without which a backup is refused), restore_command=
  pgconf.RestoreCommand, archive_timeout=300; environment adds
  POSTGRES_INITDB_ARGS=--data-checksums (acts on an empty data directory only).
- EnsureControlPlaneRecovery(ctx, pgconf.RecoveryTarget) error: sp-cp-recovery, the same
  arguments without a restart policy and without the initialisation variable, role label
  cp-recovery, the recovery settings last. Only while the marker exists and sp-cp-db does
  not; an earlier sp-cp-recovery is removed first. On an empty data directory it exits 1.
- StopControlPlaneRecovery(ctx) error: stops (30 s grace) and removes it; absent is done.
- PrepareControlPlaneRestore(ctx) error: starts nothing. Refuses while sp-cp-db exists and
  while CPDir()/data exists. A first call (no marker) also refuses a non-empty data
  directory or repository, then writes the marker, makes the trees with their quotas and
  empties spool and rspool. A call that finds the marker also empties data and repo/ and
  removes fetch/. A removal task that fails is an error.
- ControlPlaneRecoveryState(ctx) (promoted, exited bool, systemID string, err error):
  exited is true for an absent or stopped container, and then no session is opened; a
  server that does not accept a session yet is promoted=false with no error; systemID is
  the database system identifier as an unsigned decimal, set once promoted.
- FinishControlPlaneRestore(ctx) error: stops the recovery start, removes fetch/, and
  last the marker.

The move (once, at the first ensure that finds CPDir()/data)
- Order: the old tree is checked (directories and regular files only), sp-cp-db is stopped
  and removed, the tree is copied to data.part with owners and modes, the projects
  filesystem is synced (syncfs on a descriptor opened before the copy; its error stops the
  move), CPDir()/data is renamed to data.moved, data.part is renamed to data.
- Resume by names alone: data.moved + data.part finishes with one rename; data.moved +
  data is done; the old tree alone (with or without data.part) copies again.
- Refused: data.moved alone; the old and the new data without data.moved.
- The copy does not watch the context: a deadline that passes during it fails the call
  after the move is complete, and the next call starts the container.

The stamp
- Written once the data directory holds PG_VERSION. A stamped node whose data directory
  holds no database is refused with a message naming the path, the stamp and the mount to
  check: no new database is ever created over an empty or wrong projects filesystem.
- Anything at the stamp's path counts as the stamp (it is not opened). It is part of the
  container's configuration label.
- Only a start on an unstamped node carries the image's initialisation variable; without
  it the image refuses to initialise an empty directory.
- A fresh node's first ensure therefore starts the database twice: once to initialise it,
  then — when it answers and the node is stamped — again without the variable; it returns
  when the second answers. An ensure waits for an answer (3 min at most; a stopped
  container or another session error ends it at once) only when it stamps the node in that
  call; on a stamped node it never waits.

Caller rules
- The archive binary must lie beside the daemon's executable at every ensure.
- EnsureImageFiles before EnsureControlPlaneRecovery and before a second
  PrepareControlPlaneRestore (the removal tasks need the seccomp profile).
- No job container of subject "cp" may run during PrepareControlPlaneRestore or
  FinishControlPlaneRestore; no daemon may run during a restore (the recovery start
  listens on the daemon's socket path).
- repo/ and fetch/ are emptied only by tasks at their owners' ids (70:70, 65530:70) on the
  control-plane image; root empties data, spool and rspool.

Errors
- All refusals are plain errors with fixed wording; none is exported for matching. The
  marker refusal contains "a control-plane restore is marked".

Known limits
- The quotas are set from the configuration at every ensure: a quota changed by hand is
  put back within a repair round. Change cp_disk_quota_mb or cp_repo_quota_mb instead.
- At uid 70's quota a write that needs WAL space stops the server; while recovery cannot
  write, Docker restarts it at its back-off. Committed rows are kept. Nothing reports the
  state in the node check yet.
- Nothing pushes the control plane's spool yet: it grows by one 16 MiB segment every five
  minutes at least.
- A daemon that dies during a fresh node's first start waits, when it comes back, until
  that start has answered; only then is the node stamped and the container made again
  without the initialisation variable.
- The suite's quota test keeps the node file's bytes in node.json.reach-orig while the
  quota is lowered and restores only from that copy; without a copy it changes nothing.
- A build older than this one must never run on a moved node; docs/operations.md has the
  four steps back.
- A database moved from an older build has no page checksums; a new one has.
- internal/agent/sys_linux_amd64.go and sys_linux_arm64.go hold the syncfs call number;
  another architecture needs its own file.

### 2026-11-21 — Studio: the request guard; how the server reads a path; a path ending in a space
Patches 0011-0013 (topic guard). The first request middleware of the dashboard's server
(start.ts), ahead of every other and listed once; it covers route handlers, server functions
and pages.
- lib/api/self-hosted/assertion.ts: verifyAssertion(text, now?) - the header
  X-Supapace-Assertion, checked as internal/dashtok checks it, on the same vectors: size,
  envelope (strict unpadded base64url), Ed25519 with <SUPAPACE_DASH_KEYS>/assert.pub (43
  base64url characters, at most one line end), a fatal UTF-8 decode, types and domains, the
  payload's bytes against their re-serialisation, times, SUPAPACE_NODE_ID. Every refusal is
  401 bad_assertion with one message. checkAssertionSettings() reads the two settings now.
- lib/api/self-hosted/request-guard.ts: guardRequest(ctx, getRouter), readPath(router,
  pathname) -> {segments, route, methods}, checkStart(). Order: assertion (401); the path it
  is handed - never the request's own URL - read with the router's decoder and matcher: first
  two segments api + ai|mcp: 404; a segment with the shape of a ref that is not the
  assertion's, any letter case: 404; under /api, no exact route with handlers: 404, no handler
  for the method: 405 with Allow (HEAD follows GET); then resolve, and the rest of the request
  inside the project's context. A ProjectError from any of it, or thrown further down, is
  answered {code, message}.
- lib/api/apiWrapper.ts rethrows an error named ProjectError (the module is shared with the
  browser's bundle: it must import nothing of self-hosted/).
- lib/api/self-hosted/start-check.ts: a server plugin (vite.config.ts, nitro plugins); at
  process start it calls checkStart(): limits, the control-plane client's settings, the
  assertion's. A server without one exits 1 before it listens, with one log line and no
  other: "supapace: <reason>; the server stops". The plugin is bundled into the server entry
  with its own copies of those modules: module state exists twice; a start hook proves
  settings and warms nothing for requests.
What the assertion binds: node, principal, project, role, purpose - not the request. Accepted:
exp > now, iat <= now + 5 s, 0 < exp - iat <= 60 s, whole seconds, no leeway. One assertion is
accepted again within its life, for any route of its project.
Answered before the guard, never by a handler: a GET or HEAD of an existing public file; a
path beginning // (308 to the same path with one slash); a path under /_serverFn/ without a
function id, and what normalises to one (the framework's 500 with its fixed body, no detail);
the HTTP parser's 400 and 431; 400 for an invalid percent sequence.
The build's prerender starts the server with TSS_PRERENDERING=true and no setting of a node,
and asks for the shell (GET, header X-TSS_SHELL: true). In that mode only a page passes: GET,
that header with the value true, no assertion, no path under /_serverFn/, first segment not
api in any case, no server handler on the matched route - all judged on the handed path.
Everything else is 401 and no setting is read. A process with the switch and any of
SUPAPACE_NODE_ID, _DASH_SOCKET, _DASH_KEYS, _DASH_DATA, _PGCAP, _PGMETA, _LIMITS exits 1 (the
test of _PGMETA is of its presence; the guard never reads its value). No request and no node
can choose the mode.
Caller rules:
- Every request to a built image needs an assertion; a container needs the node's settings
  and both key files or it exits at start (studio/build.sh gives its measured containers
  test settings and waits for a 401).
- The project comes from the context alone: never from a path parameter (the framework
  decodes parameter values once more than the path), a query, a body or a function's payload.
- Code that catches every error under the guard must rethrow a ProjectError. No secret,
  connection string or path in an Error message: upstream's 500 bodies and a server
  function's error answer carry the message.
- A setting added later is read by checkSettings() or checkAssertionSettings() - or it is
  checked at first use only - and joins the prerender stop's list and env.tsv.
- A route whose handlers are not an object of methods is answered 405 for every method.
studio/prove (run by build.sh prove; each `bash F IMAGE`; hosts need openssl 3 and curl):
- stand-ins.bash (sourced): the image as a node runs it, sp-dashstub socket and pgmeta, three
  projects, a key pair of the run; tok REF SUB ROLE [PURPOSE [IAT_OFFSET [LIFETIME]]];
  PROVE_PREFIX names what it starts. Answer times come from the clock.
- context.sh (72 rows): each request answered for its assertion's project (single,
  interleaved, one kept-alive connection, pipelined); refusals; the chain's order; start-up
  without settings; the prerender mode.
- manifest.sh (2,045 rows at this pin): from the image's own route tree (paths.mjs --routes,
  which must equal the non-deleted rows of routes.tsv): 401 without an assertion for every
  route, page and server function; 404 for another project's ref in every $ref position; 404
  for the routes not served; the guard's 404 for every deleted row, every method, with and
  without a slash; 405 with Allow; then the controls, the last on a server whose own project
  settings are marked: no page's HTML holds a marked value of the control plane or of the
  process, and a route that still answers a process value shows that the search finds one.
  It fails when a started row left no line. A release checks the build record's proofs member.
- paths.mjs SRV <paths.in >paths.json: reads its input first, starts the built server
  in-process, replaces the request-middleware chain by an observer, and records for each raw
  path {raw, href, segments, route}: the URL as the server's parser left it (null: answered
  400 unread), the segments the router matched on (null: no router asked), the route's full
  path. paths.in holds the fixed lines. Derived from the built route tree: for every route its
  mechanical forms (dot segments, capitals, slashes, another project's ref, encodings, a
  trailing space alone, doubled, before an empty and a non-empty query, as a segment, behind
  a dot segment), and every octet %00-%ff at eight places of three routes chosen from the
  tree. 15,846 vectors at this pin. It fails when the guard's readPath disagrees with the
  router, when a /_serverFn/ path reaches the route tree, or when a route's plain, dot-dot or
  capitals form does not match.
- Gate 45-paths: the generator's output, given 600 s, must be studio/prove/paths.json byte
  for byte. After a change of the pin or of a route: build.sh paths, commit, run
  TestDashPaths_ServerVectors.
- The build record has no pages_with_project_data and no pages_fetched; gate 55-record holds
  bypass, mcp_chunk_importers and listener.
internal/gateway TestDashPaths_ServerVectors: seven assertions over every vector, no
exception; among them that what the gateway forwards, the router matched on the segments the
gateway read, and that a path ending in an encoded space is answered 400.
Gateway, the first path rule (internal/gateway/dashpath.go; the sign-in model's ruleZero): a
path whose last segment, percent-decoded, ends in a space is refused, 400 bad_request,
whatever the query - counted with that rule's refusals, not forwarded, on project hosts and
the sign-in host. The server parses the decoded path as a URL a second time; a URL parser
drops a space that ends it and then resolves a dot segment it hid, so /project/<ref>%20,
/api/mcp%20? and /api/parse-query/x/..%20 were routed without the space. A return path of
the sign-in follows the same rule (it becomes /). A space elsewhere in a segment, or in the
query, is an ordinary character.
How the server reads a path (pin: router-core 1.171, start-server-core 1.169, Nitro 3 beta,
Node 24): the HTTP parser refuses a raw space, control and byte above 0x7e and accepts a raw
#; the request URL is parsed once (dot segments, backslash); the path is decoded once -
%25, %5C and the URL delimiters ; / ? : @ & = + $ , # stay encoded, controls are re-encoded -
and parsed as a URL again; the router decodes the same way again (no change), trims trailing
slashes and matches without regard to case. Path segments are never decoded twice.
Known limits:
- A route parameter value that ends in a space cannot be addressed: the gateway refuses the
  path (with an empty query the server dropped the space itself).
- Server functions are dispatched by the prefix /_serverFn/, not through the route tree; the
  vectors do not cover their handlers, the guard and manifest.sh do.
- A page's body streams after the guard's next() returned; a read of the context from a
  callback the response's consumer drives may find none (500, fail closed). No page reads the
  context yet.
- The assertion is not bound to a method or a path; it lives 30 s as minted.
- Studio has no request-body bound of its own; the gateway's caps are the only ones.
- manifest.sh's control for process values needs a route that still answers one.
- paths.mjs depends on the bundle exporting getRouter, startInstance and readPath by name.

### 2026-11-24 — pgsock guard uses the shared wire checks
- guard.go no longer reads lengths, subtypes or counts itself; it calls internal/pgwire:
  Header (backend and client message headers), AuthSubtype and the Auth* constants,
  ScramIterations (shape of the server-first message and its count).
- The guard keeps: the salt compare (constant time, against the platform's salt), the exact
  count 4096, the SASL mechanism list split, taking the payload after the subtype (b[4:]),
  and its own refusal of a negative body length.
- Refusals are unchanged: ErrScramParams, ErrNotScram, ErrCleartextRequested, ErrBudget keep
  their meaning; a non-canonical count now reads "malformed server-first message".
- Caller rule: keep the order in checkServerFirst: ScramIterations first, then the salt is
  read from field two (safe only after that shape check).
- guard_test.go: a source test forbids length, subtype and count parsing in guard.go.
  It reads guard.go only and is a tripwire; the behaviour tests are the proof.
- pgwire.Header and ScramIterations refuse a stated length or count that does not fit an
  int, so a 32-bit build cannot see a negative length or a wrapped count.
- Known limit: one test of the wire proxy (the largest stated length streams without an
  allocation) cannot hold on a 32-bit int; 64-bit builds only are tested.

## 2026-11-24 — control-plane tests on a host run

- The restore-marker test and the quota test of the control-plane suite skip, as their first
  statement, when the suite runs against a host (SUPAPACE_HOST=1): on a host the daemon is a
  system unit that logs to the journal and restarts outside the harness's hold, so these two
  tests would read a log file that does not exist and restart the daemon under other tests.
- The read-only control-plane test (data moved, socket stays) runs on both kinds of run.

### 2026-11-24 — Reach suite: off-site tests (test/reach/offsite_test.go)
Written ahead of the daemon's backup wiring: on a layout-1 node all three tests skip; with
SUPAPACE_BACKUP=1 they fail at once naming the layout (needBackups), and without a declared
object-store stand-in they skip, or fail with SUPAPACE_STANDIN=1 (needStandin). They need a full
node with the stand-in (make node-up; make reach exports SUPAPACE_STANDIN=1).
- TestReach24_RepositoryScope: A's push and replication jobs mount nothing of B; the replication
  job's /repo is A's, read-only; its /cred is the projects' write pair. Planted in A's repository:
  files under B's stanza name, a top directory named for B's ref, links into B's tree; none reaches
  the store under any key; every key beginning with A's ref is below "<ref>/" and names a path of
  A's stanza (control: a forged file at a valid name of A's stanza is uploaded). Known limit,
  logged: on the stand-in the write pair places delete markers; locked versions stay. A's set
  restored by hand with B's passphrase fails (control: with A's it restores).
- TestReach25_ObjectLock: a locked version is not removed by the admin keys, nor with the
  governance-bypass header (control: the same request without a version places a marker); forged
  empty overwrites of a segment and the info files become current; a restore --from offsite still
  completes from the recorded versions and a row written before it is present.
- TestReach29_Replicator: walk (links out, to the root and into B; a FIFO; a 100 GB sparse file;
  5,000 names of a timeline never admitted; a file of another uid; 14 levels; a name swapped for a
  link) — nothing planted is uploaded, the copy's notice detail counts every entry; write_once
  (history-rewritten, one version kept); copy_order (a set without backup.manifest is not uploaded);
  history_first (failpoint restore:T10r with the supervisor hold: timeline 2 stays local while its
  history is unreadable, segment-without-history, no info version; then both go up); budgets
  (upload_objects_per_day=1 pauses until 00:00 UTC, the notice gives a fill time, pushes and B go
  on); offsite_outage (the replication jobs' packets dropped in the inet supapace forward chain:
  pushes continue, last_ok and lag show it, the stand-in still answers the suite, catch-up after);
  repository_quota_full (1 GiB repository filled: segments stay spooled, B and the control plane
  push on, a restart with a larger disk_quota_mb recovers).
- Keys are read as "<ref>/<path>" (the harness declares no bucket prefix). Long bounds: a restore
  45 min; history_first up to about 105 min. The outage holds the drift tick, refreshed per push.
- Helpers local to the file: versionsAt/objectsOf/inStore (sp-probe s3 versions/head), waitKey,
  waitRepl, noticeCount, noticeEntries, waitNotice, archiveDir, plantRepo, segPath, handRestore,
  s3Client, s3Delete (signed DELETE with an optional bypass header), restoreLong.

### 2026-11-24 — test/reach: restore tests and the restore drill
test/reach/restore_test.go (tag reach): TestReach30_Restore, TestReach31_RestoreDrill,
TestReach32_Switch. Written ahead of the daemon's backup and restore wiring: not yet run.
- Reach30: refusals of a restore request (out of the window, an unrecorded timeline, a full
  disk); the recovery start (no network, phase R, removed by a daemon restart); a daemon killed
  at restore:T7 and restore:T8; time and position targets; a spool of more than one push job's
  worth pushed empty before the wipe, and the shortfall; restored settings and restored content
  (role settings, a login trigger, a password check, a scheduled job) that must not delay, stop
  or observe the re-key; failed restores: exactly five passes, restart refused, delete, op
  retry, superseded. Sub-test offsite: the off-site source, a stray history, two off-site
  fetches at once.
- Reach31: the restore drill, both sources, with durations logged. Reach32: the switch of a
  layout-1 project by one restart, and one whose first backup failed.
- After every restore to a time or a position, archiveClean: pg_stat_archiver.failed_count is 0
  and pg_wal/ holds no .partial file two minutes on.
- Each test skips on a node at layout 1 and fails at once naming the layout when
  SUPAPACE_BACKUP=1. The sub-tests offsite need the object-store stand-in (needStandin).
- Needs a development node (failpoints, --layout 1), the daemon running backup jobs and
  restores, and about 3 GiB free on the projects filesystem (one case spools ~1.9 GiB).
- restoreScratch: the scratch fixture of a test that restores. Its clean-up waits for an open
  restore and deletes a project left restoring before the scratch clean-up runs.
- holdQuiet: holds the daemon while no push of the project is queued or running. The spool case
  repeats a pass (at most 3) whose restore did not stop the project being served within one push
  interval of the hold's end.
- hide(): redaction plus password verifiers, for every printed error and statement.
- concurrent_fetches writes forged rows into the off-site record through the store. They stay
  until the project's off-site purge.
- Bounds: a restore 45 minutes, replication 15, a forced full 10. Estimated 5 to 6.5 hours for
  the file at layout 2; split it over several node jobs.
- Known limits: a restore still open at 45 minutes leaves its project restoring for the suite's
  own clean-up. The password check's counterpart for logins (pg_tle clientauth) is not covered.

## 2026-11-24 — browser tests: a return path that ends in an encoded space

- The browser test of return paths from another site expects a path ending in an encoded space
  to land on /, as the gateway and the flow model have answered since the first path rule; a path
  with an encoded space inside a segment is still kept. It also fails when any request reaches a
  path that ends in a space.
- The test's path lists are literals and the binary runs only in a node: after a change of the
  sign-in vectors or of either return-path function, run `make browser-test`, not only a compile.

## 2026-11-24 — worker image: the zstd pin follows Alpine

- Alpine moved zstd from 1.5.7-r2 to 1.6.0-r0 in the pinned release, so `apk add` refused both
  pins in deploy/worker/Dockerfile and every node build in CI failed. Both pins are bumped; the
  image builds, pgBackRest starts and links the new library. Nothing else in the list moved.
- A pinned package that Alpine replaces fails the build with "unable to select packages": bump
  that pin (the release keeps one version of a package), rebuild, and let the node suite run.

### 2026-11-24 — The wiped-node recovery drill (TestReach27_WipedNode)
test/reach/recovery_test.go. Written ahead of `supapaced recover`, `escrow show` and their wiring
in the daemon; it has not run end to end yet.
What it covers, in order (each phase's duration is logged as `drill: <phase>: <d>`):
- the escrow set shown in two parts and kept in the test's temporary directory; the key, stanza,
  bucket and read-only credential checked against the node;
- untrusted store content: another control-plane database's objects under another stanza name, a
  far higher history, an unusable object at the key of a segment not yet uploaded, and 5,000
  objects of a non-existent set in A's prefix;
- a deleted project whose purge waits, a finished create, a create held at step 12b with the
  stand-in paused, and a restore parked on a paused push;
- recover refused on a node that still has its control-plane database, and refused for a key part
  of another key before anything is written; a serve job killed mid-recovery: no promotion;
- the wipe: every container, network and volume of the node's Docker, /etc/supapace, and all of
  /var/lib/supapace except the two filesystems, which are emptied;
- recover stops at the shortfall naming the newest fetched segment and the end of replay;
  --accept-shortfall finishes; init; the daemon released;
- before `offsite set`: create refused "partly declared", no project path made; after it: a new
  epoch, open operations failed (a provisioning create aborted) with "recovered", the purge still
  pending and then done with the keys destroyed; A restored from the store to a time between two
  markers (a Vault secret decrypts); the finished create and B restored to the end of their
  archives.
How it skips and fails: it skips off the test node (no /run/sp-node-ready, or SUPAPACE_HOST=1);
then needBackups and needStandin as every backup test; then it needs SUPAPACE_WIPE_NODE=1. Without
the switch it skips, or fails when SUPAPACE_BACKUP=1. A full run therefore passes
-test.skip '^TestReach27_WipedNode$' and runs it afterwards alone with SUPAPACE_WIPE_NODE=1.
It destroys the node's state by design. After a failure past the plant or the wipe, recreate the
node and its stand-in (make node-down, node-up): the planted objects stay locked for a day.
Needs: the harness's stand-in, the worker image under its default name, dev mode (failpoints) and
the hold-file supervisor.
Known limits: images, kernel tables, quota limits and /run survive the wipe (the image archive
option of recover is not exercised); the epoch check sees two calls in one run, not a call by a
stopped run.

### 2026-11-24 — The read-only login's platform password, and the clean-up of its scheduled jobs

What it provides
- `bootstrap.Secrets.ReadOnlyPassword`, with the salt key `supabase_read_only_user` in
  `ScramSalts`. Empty: nothing is sent or expected for that login. Set: `Run` and `Rekey` send a
  fourth password statement after supabase_admin, postgres and authenticator (in a re-key before
  the pooler manager's). The four passwords must differ.
- `Rekey` skips the read-only login's statement, like the pooler manager's, when the server
  answers that the role does not exist (SQLSTATE 42704). For the three platform roles, and in
  `Run` for all four, that answer is an error. Nothing reports a skip; a missing role is drift.
- `bootstrap.SetReadOnlyVerifier(ctx, conn, Secrets) error`: that one statement as the session's
  first, in the form and through the check of the other password statements.
- `bootstrap.AssertReadOnlyVerifier(ctx, conn, Secrets) ([]nodecfg.CheckResult, error)`: the
  check `service-passwords` for this login. No stored password passes. With `ReadOnlyPassword`
  set, only the platform's verifier passes ("differs from the platform's"); without it any stored
  password is a finding ("present without a platform secret"). At most 512 characters of the
  stored value are read and compared as a whole, in constant time; nothing read is parsed. The
  login is no longer in the list of roles that must have no password. The agent's assertion runs
  the check at a create's two blocking assertions and in the drift check.
- `bootstrap.DeleteReadOnlyJobs(ctx, conn) error`: ends every session and worker of the login and
  deletes its rows of the scheduler's job table. One pass is one transaction of seven constant
  statements sent as one query: begin; end the login's backends; lock the job table; delete the
  login's rows; clear the session's activity snapshot (the server reads its activity view once
  in a transaction); end the login's backends again; commit. Passes repeat 0.1 s apart until a
  clean one: the lock granted, no row deleted, no backend other than a client session ended at
  either ending, and begun at least 3 s after the answers of the last pass that ended such a
  backend or deleted a row. It returns no count.
- `(*agent.Agent).SetReadOnlyLogin(ctx, Spec) error`: one superuser session, the verifier, then
  the statement-statistics reset (best effort, logged). `saga.Agent` has the method.
- `(*agent.Agent).DropReadOnlyJobs(ctx, Spec) error`: `DeleteReadOnlyJobs` in a superuser session
  with `lock_timeout` 2 s and `statement_timeout` 10 s, triggers on, under 15 s of its own.
  `saga.Agent` does not have it.
- `pgsock.Target.LockTimeout` and `StatementTimeout`: above zero they are sent at startup in
  place of the list's 0, in milliseconds rounded up; they hold against role and database
  settings.
- Saga: create step 2 makes the secret `pg.supabase_read_only_user.password`; a specification
  carries the password exactly when the secret exists (a secret that cannot be read fails the
  specification); restart step `R6`, last and at every layout, gives a project without the
  secret its verifier and then stores the secret.

Caller rules
- Use `DropReadOnlyJobs` on a cluster started for service. Its outcome is "ran" or "failed" and
  nothing more: what the cluster answers decides only whether a pass is repeated.
- A lock not granted (55P03 at the lock) is repeated. No job table or schema (42P01 or 3F000, as
  the lock's answer only) ends the run without error, after the first ending. Any other error
  ends the run at once.
- A deadline is worded by its cause and matches `context.DeadlineExceeded`: `no clean pass
  within 15 s` with the last pass's reason (the lock was not granted, a worker was ended, a row
  was deleted); `the caller's deadline passed before a clean pass`; `a pass ran out of its
  statement budget`. A failed run is safe to run again.
- A run that ended a worker or deleted a row lasts at least 3 s; one that finds nothing ends
  after one pass. The 3 s cover one loop of the scheduler (at most 1 s) and a worker's launch.
- `R6` writes nothing to the operation's parameters: the secret's existence is the record. A
  stop between verifier and secret leaves no secret, and the next attempt sets a fresh password.
  A refused verifier fails the step and stores nothing.
- A statement of the clean-up is a package constant sent through `pipeSQL`; the two
  constant-statement tests admit that wrapper beside `execSQL` and `querySQL`.
- Tests of the clean-up on the pinned image go through the platform's own session (its budget
  included), not a bare driver connection.

Known limits
- The delete is by the login's name; rows under any other name are not touched.
- A session of another role that holds a lock on the job table makes every run fail at its
  deadline. The delete has the statement timeout as its only bound on the number of rows.
- "No job table" is the cluster's word, as every answer is: it does not prove that no job runs.
- A project made before this has no read-only password until its next completed restart, and a
  failing `R6` ends a restart failed after its configuration is in force.
- `pgsock.Target`'s printers do not show the two timeouts.

### 2026-11-27 — Studio: per-project configuration, version and state from the request context
Patches 0014-0018 (topic config). What upstream read once from the process for its one project
is read for the request's project from its context; the per-project constants and their
defaults are deleted, so an importer left behind stops the build.
- lib/api/self-hosted/util.ts: checkHeaderKey() - postgres-meta's key for the
  x-connection-encrypted header, the file <SUPAPACE_DASH_KEYS>/crypto.key: exactly 64 base64url
  characters and at most one line end (^[A-Za-z0-9_-]{64}\n?$), used byte for byte, the line end
  included. Read by checkStart() at process start and by the request path at its first use;
  never re-read. A missing, unreadable or malformed file, or a key directory that is not an
  absolute path, stops the process ("supapace: the header key file ...; the server stops"); the
  message never holds the key. encryptString() uses it. There is no other key: upstream's
  PG_META_CRYPTO_KEY setting and its built-in key are deleted.
- lib/api/self-hosted/project-values.ts: projectUrls() {restUrl, endpoint, protocol, dbHost}
  from the context's api_url; dataApi() {schemas, extraSearchPath (comma-joined), maxRows
  (number or null)}; contextProject() - upstream's project shape with the context's ref, name,
  status (active ACTIVE_HEALTHY, restarting RESTARTING, restoring RESTORING) and dbVersion (the
  answer's db_version); PROJECT_DB_PORT = 5432. Each throws outside a request
  (no_project_context): there is no default.
- Routes answering from them: projects/, projects/$ref/, props/project/$ref/ and /api,
  projects/$ref/{databases,settings,config/,config/postgrest,run-lints}, organizations/,
  profile/, type generation (included_schemas = the project's schemas, URL-encoded); the
  opt-in MCP files compile against them. The organisation bears the project's name; the
  profile's one project is the request's. max_rows is null when the project sets no limit.
- No project answer asks the project's database: the version is the control plane's.
- studio/build.sh test single-quotes each test path for the build container's shell, so a
  test file under a directory named $ref runs.
Caller rules:
- Read every per-project value through these helpers, synchronously, before the first await
  of the handler; never from the path's $ref, the process or a module variable.
- postgres-meta must receive the header key BY FILE: CRYPTO_KEY_FILE naming the same bytes (it
  reads the file untrimmed); CRYPTO_KEY as an environment value cannot carry a line end. The
  pinned postgres-meta falls back silently to its built-in key when the setting is missing or
  empty, so a node checks that a header sealed with the file is accepted. A new key needs
  Studio and postgres-meta restarted together.
- A container needs crypto.key beside assert.pub and cache.key or it exits at start (the
  measured containers of build.sh and the proofs' stand-ins write a throwaway one).
- Patch 0016 is exported with one line of context (upstream's stub lines beside it hold e-mail
  literals the content gate refuses); `build.sh export` writes default context, so re-export it
  with -U1 until the gate exempts context lines. Patch 0015 builds only with 0016 after it.
studio/prove/config.sh (28 rows): two projects with different names, Data API settings,
versions and states, every converted route interleaved; no postgres-meta request for a project
answer; no start without the key file or with one of another form; the key with and without a
line end against postgres-meta's stand-in.
What the next packages inherit:
- Keys: the API keys and the JWT secret are still answered from the process and upstream's
  defaults (settings, props/project/$ref/api, the key routes, jwt_secret of config/ and
  config/postgrest, apiKey sent to postgres-meta) - release-blocking until the keys come from
  the control plane; manifest.sh's process-value control then moves. The edits of this patch
  set in settings.ts and props/project/$ref/api.ts are local (imports, two consts, values).
- Stores: no shared file; nothing to rebase.
- Query: generate-types.ts sends included_schemas from dataApi(); keep it when the request goes
  through the one postgres-meta caller; STUDIO_PG_META_URL is still in the proofs' stand-ins
  and manifest.sh's marked list.
Known limits:
- LOGFLARE_URL (analytics) is still a process value; only opt-in and deleted routes reach it.
- The UI's edge-function URL for hooks and cron jobs is upstream's fixed internal address.
- The Data API settings form rejects a null row limit; the pooling route is a fixed stub.

### 2026-11-27 — The worker image pins versions, not Alpine's package revisions

- Alpine replaced two more package revisions inside the pinned release (libxml2 -r3 to -r5, zstd
  -r0 to -r1) three days after the last bump; every node build failed again at `apk add`.
- deploy/worker/Dockerfile now pins each package as `name~version` (apk's prefix match): the
  upstream version stays fixed, the revision Alpine rebuilds in place is taken as it comes.
- This replaces the earlier rule "bump the pin; do not unpin". Still do not drop a pin: a build
  that fails with "unable to select packages" now means a version moved. Look at what changed,
  bump that pin, rebuild, and let the node suite run.
- The base image stays pinned by digest in internal/nodecfg/images.lock.

### 2026-11-27 — The dashboard node side: keys, Studio, postgres-meta, data volume, gateway files
internal/agent/dash.go. Nothing here acts on a node without a studio domain: no directory, no
file, no image, no Docker call, no row.
- EnsureDashboardFiles(ctx): calls dashcfg.For first; a refusal makes it do nothing (nil) and
  becomes the failing row dashboard-config. Creates the keys once in KeyDir (root 0700, each
  file root 0600, never replaced): assert.key and assert.pub (dashtok.GenerateKey), cache.key
  (32 random bytes: 43 base64url and one line end), crypto.key (48 random bytes: exactly 64
  base64url characters, no line end - the one form Studio's reader and postgres-meta's file read
  take alike). Then the copies, each written by nodefs.WriteFile (temporary name, no link
  followed, rename) only when not in place in content, mode and owner:
  StudioKeys assert.pub root 0444, cache.key and crypto.key Studio's uid 0400;
  <platform dir>/dash/pgmeta/crypto.key postgres-meta's uid 0400 (directory root 0755);
  GatewayDash assert.key gateway uid 0400 and domain root 0444 (one line);
  GatewayStudioTLS key.pem gateway uid 0400, cert.pem root 0444 (from StudioTLS).
  SocketDir root, group Studio's uid, 0750. Starts no container.
- Refused and left as found: a KeyDir file that is not a regular file of mode 0600 owned by the
  daemon, a link, a key not in its form, a public half not matching assert.key, a public half
  without its key (a key without its public half gets one). Errors name the path, never a key.
- EnsureDashboard(ctx): EnsureDashboardFiles, then Studio's user quota (Limits.StudioVolumeMB) on
  the projects filesystem before DataDir (<projects dir>/dash, Studio's uid 0700) is handed
  over, then sp-studio, sp-pgmeta-0, sp-pgmeta-1. Each is adopted only at its configuration
  label, alone on platform at its address (started when stopped), else removed and made
  again. The label covers options, command, image id, the seccomp profile and the keys read at
  start (Studio: its three copies; postgres-meta: KeyDir's crypto.key). A failing
  dashcfg.Limits.Check renders nothing.
- Every dashboard container (dashHardening): cap-drop ALL, no-new-privileges, the node's
  seccomp profile, read-only root, core 0, no healthcheck, restart unless-stopped, ipc
  private, the two sysctls, one network (platform) at a fixed address, a supapace.role label
  (studio, pgmeta).
- sp-studio: StudioImage, Studio's uid, 896 MiB (swap the same), 256 pids, tmpfs /tmp; SocketDir
  at /run/dash ro, StudioKeys at /etc/dash ro, DataDir at /var/lib/dash rw. Environment:
  dashcfg.StudioEnv with the image label supapace.studio.env (a JSON object of strings); a label
  StudioEnv refuses, a missing label, or an image ENV naming a listener name, a fixed name or
  ENABLED_FEATURES_* fails the creation naming the image.
- sp-pgmeta-0/1: nodecfg.PgMetaImage() (the lock's "pgmeta"), postgres-meta's uid, 768 MiB, one
  CPU, 128 pids, tmpfs /tmp; dashcfg.PgMetaEnv plus CRYPTO_KEY_FILE=/etc/pgmeta/crypto.key, the
  copy's directory mounted read-only there: the key is in no container configuration. The
  image falls back to a built-in key when that file is missing or empty, so postgres-meta is
  rendered only while the copy is in place. Refused: any libpq name (PG followed by a letter) in
  the image's ENV or the arguments; CRYPTO_KEY or CRYPTO_KEY_FILE in the image's own ENV.
- CheckDashboard(ctx) []nodecfg.CheckResult: nil without a studio domain; dashboard-config alone
  when dashcfg.For refuses; else dashboard-config, dashboard-files (KeyDir root 0700 and its
  files, every copy, DataDir Studio's 0700), and one row per container: exists, runs, carries
  this daemon's label, at its address - and fails while Docker restarts it or when it has
  restarted and its last start is under a minute old (Docker reports it running meanwhile),
  with its last log line cut at 256 bytes on a character boundary and quoted.
- The gateway's label also covers dash/domain, KeyDir's assert.pub and the studio certificate,
  only with a studio domain (a node without one keeps its label).
- nodefs SetQuotaAt and QuotaUsage accept dashcfg.StudioUID. scripts/cache-images.sh handles
  the lock key pgmeta only with SP_DASH=1, in both modes, saved under dash/.
For the wiring that calls these:
- Call EnsureDashboardFiles before the daemon's first EnsureGateway (it starts nothing).
  EnsureImageFiles (the seccomp profile) and EnsurePlatformNetworks must have run before
  EnsureDashboard; nothing checks that order. The images are not pulled: Studio's image and
  the pinned postgres-meta must be in the node's store.
- Every row above is containment-blocking under Blocking() as it stands (only control-plane-db
  and gateway are exempt); a later package may exempt the three container rows, never
  dashboard-config or dashboard-files (a wrong key file is an exposure, not an outage).
- The purge of a project's data directory (<DataDir>/<ref>) is the wiring's: DataDir is
  writable by Studio's uid, so remove it relative to DataDir without following links (Go's
  os.RemoveAll on Linux does), only for a valid ref, after the project has left the
  dashboard file.
- A further dashboard container reuses dashHardening, ensureDashContainer and the row pattern.
  Known limits: a crash loop whose crashes are more than a minute apart passes the restart rule
  outside the minute after each restart; a postgres-meta that restarted while root had removed
  its key copy keeps the built-in key until it is made again.

### 2026-11-27 — Studio: no secret in settings responses; keys from the control plane
The secrets patches of the Studio series. What a dashboard answer may hold of a project's keys:
- `settings`, `config`, `config/postgrest`: no `jwt_secret` member; the server holds no JWT
  secret. `settings.service_api_keys` names the anon and service_role keys with empty values;
  the props route has no `defaultApiKey`/`serviceApiKey`. These routes ask the control plane
  for no key, so they answer while it is silent.
- `GET /api/v1/projects/<ref>/api-keys` and `…/api-keys/<id>`: one `keys` call per request with
  the request's own assertion (`projectKeys()` in `lib/api/self-hosted/api-keys.ts`), nothing
  kept. The list holds the anon key; `service_role` is listed only when the query is exactly
  `reveal=true` AND the control plane answered the key, which the client module accepts only
  for an owner under the purpose `reveal`. Unknown id: `404` `API key not found`. Both answer
  `Cache-Control: no-store`.
- `GET …/config/auth/signing-keys`: the control plane's public keys in its order, each
  `{id: kid, algorithm, status: "in_use", public_jwk: {kty, kid, alg, n, e}}`, no dates.
- Refusals are the control plane client's: its five passed-on codes, else
  `503 project_unavailable`; no key in an error body or a log line.
- postgres-meta receives `Content-Type` and `x-connection-encrypted` (the request project's,
  never the caller's) beside the HTTP client's own headers; type generation also sends a
  request id its sender makes.
- Key page: the anon key from the key list; `Reveal` sends `…/api-keys/service_role?reveal=true`
  once, on the click. JWT keys page: a read-only table of the signing keys.
Caller rules: call `projectKeys()` in the request's own flow; only the two key routes pass on
`service_role_key`; an answer that can hold a key is `no-store`. Removed: the self-hosted
constants file, `AUTH_JWT_SECRET` and the four `SUPABASE_*` key names (an importer or a read
fails the build).
Known limits: three client components still fetch the revealed list on load (an owner's page
load fetches the key; others get the anon key alone); the `Reveal` button shows for every role;
pages that read the anon key from `settings` show none. Proof: `studio/prove/secrets.sh`.

### 2026-11-27 — test-container watchdog, node-test lock, content-gate patch rule, serve order
- internal/testdocker (tests only): Labels(t) returns --label supapace.test=1 and
  --label supapace.test.owner=<random per process>; the first call starts a watchdog in its own
  session that waits until the process (pid and /proc start time) is gone, then removes every
  container and volume of that owner value at once, after 5 s and after 30 s. Never by name, age
  or the shared label. Bounded(image, cmd...) runs cmd as pid 1 and sends it SIGINT after 4 h;
  cmd must end on SIGINT (postgres does). Callers: pass Labels to every docker run/create and
  volume create of a test; give Bounded the image's own entrypoint and command explicitly.
  Known limit: a docker run still under way 30 s after the process is gone is not removed.
- Node tests on one node run one at a time: reach, reach-dash, reach-reboot and node-proof hold a
  host lock file named after the node ($TMPDIR/sp-node-tests-<node>.lock, flock) over everything
  they do to the node (node-proof from building its test binary, reach-reboot from the restart).
  A docker exec ended by ^C leaves its process in the node after the lock is released. By hand:
  one package at a time (go test -tags reach -p 1).
- make reach, reach-dash, reach-reboot pass SUPAPACE_BACKUP into the node only when it is set.
- The reach suite's TestMain requires a dial of the admin socket to succeed within 30 s.
- bkjob serve: a request is answered only when no answer of its name waits in out/, checked
  before the request itself; with the archive binary removing the request before the answer,
  no request is answered twice. A refused request (not a regular file, wrong owner) whose answer
  still waits is refused on the first pass after the answer is taken.
- check-public: new rule "short code", two letters of one case and two digits standing as a
  token or a name's start (not after a letter or digit, not followed by a digit or a letter of
  its case, not two hex letters such as fe80). An exact token in scripts/public-allow.txt passes
  this rule; the deny-list ignores the allow file. Name test containers by meaning
  (sp-test-logs-..., sp-test-job-...), never by an id.
- check-public: in studio/patches/*.patch the context and removed lines of a hunk, counted as
  git applies them and only after the patch's first diff --git line (never in the commit
  message), are exempt from the generic e-mail and host-name rules only; the deny-list,
  IPv4/IPv6, home-path and short-code rules apply to every line, and headers, message, file and
  hunk headers, added lines and the trailer are judged in full. A context line is taken as
  written; the apply gate of the Studio build shows whether upstream holds it.
- Test helpers wait for a final state, not a first sign: the wake socket's mode 0660, a relay's
  end before its test ends, a bound of 30 s on every wait for a child process in sp-probe.

### 2026-11-27 — Studio: snippets private per member, shared per project
Patches 0025-0027 (topic stores). The module is
lib/api/self-hosted/member-store.ts. The process-wide snippets folder (SNIPPETS_MANAGEMENT_FOLDER)
is gone; a remaining importer fails the build.
- Store calls: listSnippets(params), getSnippet(id), putSnippet(body), deleteSnippets(ids),
  countSnippets(name?), listFolders(), createFolder(name), deleteFolders(ids).
- Checks and names: checkId, checkName, NAME_BYTES (200), principalDir(iss, sub),
  sharedId(author, name).
- Read slots: sqlAnswer(fn), acquireRead(ref), readsHeld(ref?), READ_SLOTS (4),
  READ_SLOTS_PROJECT (2), READ_WAITING (32), READ_WAITING_PROJECT (8).
- Types: Snippet, SnippetMetadata, Folder, ListParams.
- The five content routes under /api/platform/projects/$ref/content call these; their wire shapes
  are upstream's.
- Project, member and role come from getProjectContext() alone; nothing in the path, query or
  body names a directory. Ids are checked to the lower-case UUID form and names are checked.
On disk, under SUPAPACE_DASH_DATA (directories 0700, files 0600, every write by rename):
  <ref>/snippets/<P>/<name>.sql            a member's own, at the root
  <ref>/snippets/<P>/<folder>/<name>.sql   in one of its folders (one level)
  <ref>/snippets/shared/<P>/<name>.sql     shared by member P
  .<16 hex>.tmp                            a write in progress; leftovers removed at a write
<P> = lower-case hex SHA-256 of u32be(len iss) iss u32be(len sub) sub. The file holds the SQL only.
- Ids. An own id is upstream's, derived by the editor from folder and name (a 32-bit hash). A write
  whose id another own snippet already has is refused 409 exists. A shared id is SHA-256 of author
  and name. A share or unshare moves the file and changes the id; the client follows the answer.
- Names. A create replaces a snippet of its name. A rename, move, share or unshare onto a taken
  name is refused 409 exists, and so is a folder whose name a file uses.
- owner_id (and owner.id) is 1, the profile stub's id, for the asking member's own snippets and 0
  for another member's; the editor then shows another's shared snippet read-only.
- Names are 1-200 UTF-8 bytes: no leading dot, no / \ NUL or control character, no half surrogate.
Bounds:
- Per project, all members together: snippet_entries (2,000 snippets, folders and any other names
  below a member's directory) and snippet_bytes (64 MiB of SQL). They are checked against the disk
  and written under one in-process lock per project; other projects do not wait.
- One snippet, and the SQL of one listing answer, are at most result_bytes (8 MiB). A larger
  snippet is refused 413 too_large. A listing past it ends with a cursor, the base64url JSON of
  [sort key, id] of its last snippet; the next page holds the snippets strictly after that place.
- An answer that carries SQL (content/ GET and PUT, item/$id) holds one of READ_SLOTS slots of the
  process, at most READ_SLOTS_PROJECT for one project. It holds the slot until the server has taken
  its body, the client has gone, or handover_ms has passed; at handover_ms the answer is cut.
- A request that finds no slot waits at most slot_wait_ms, behind at most READ_WAITING requests in
  the process and READ_WAITING_PROJECT of its project; otherwise it is answered 429 busy.
Refusals ({code, message}, no path):
- 400: bad_id, bad_name, bad_request (also a cursor not of this listing);
- 403: read_only (every write of a read_only member), not_author (another member's shared
  snippet);
- 404 not_found; 409 exists; 413 too_large; 429 busy; 507 store_full;
- 503 store_unavailable: every file-system failure; the log line names the ref and the errno code
  only.
Caller rules:
- Exactly one Studio process writes a data directory: the lock and the slots are in the process.
- A route whose answer carries SQL returns sqlAnswer(...) unbuffered. A wrapper that reads, clones
  or buffers the body frees the slot early.
- Keep the gateway's body deadline below handover_ms.
- A purge removes <data>/<ref> whole without following links.
Known limits:
- The bounds are shared: one member can fill the project's bounds for all, and a 507 shows a
  member the project's total use.
- A removed member's private snippets count until the purge; nobody can delete their shared ones.
- The byte count stops at the entry bound: with more entries on disk than the bound, bytes are
  under-counted.
- The slot caps are per project, not per principal: a member of two projects can hold all four
  slots for handover_ms.
- Every PUT takes a slot; many writes at once in one project get 429 busy.
- A snippet rewritten or renamed while a listing pages can move past the cursor and be missed in
  that pass.
- Every write walks the project's tree (about 80 ms at 2,000 entries).
- Favourites are not stored; the folder PATCH changes nothing.
- Unit tests: studio/build.sh test (member-store.test.ts, member-store.hostile.test.ts).

### 2026-11-27 — reach: "served" means the gateway's current route generation

- reach: a 200 through the gateway is no proof of the current routes. After a daemon start the
  routes are drained, then re-activated per project about a second later, and the gateway reads
  the route file once a second. `gatewayCurrent` (the file shows the projects active and the
  gateway's /-/health reports that generation or later) gates `cpBack` and `waitServed`.
- New test TestControlPlane_BackMeansServedAfterADaemonRestart: restart, cpBack, then 3 s of 200s.
- Tenants see 503 project_restarting for that adoption window on every daemon restart (about one
  to two seconds with a few projects; four adoptions run at a time). The drain is the deliberate
  fail-closed order of a start; whether a start may keep serving shown-contained projects is open.

### 2026-11-27 — supapaced recover, escrow show|ack, offsite check, offsite rebuild-continue

cmd/supapaced: recovercmd.go, escrowcmd.go, offsitecheck.go, offsiterebuild.go. Root only; exit 0
done, 1 refused or stopped (one line on stderr, prefixed with the command's name), 2 usage.

recover --escrow F [--escrow F2] [--worker-image-archive F] [--accept-shortfall]
- Brings the control-plane database back from the escrow set and the object store, on a node
  that holds none. Runs with nodecfg.Defaults(); a node.json left on the node is named in one
  line and not read, except its uid range (where a surviving owner is looked for).
- Refused before any write: a key part that is not the document's; a newer document or schema;
  another control-plane image; a key file, sealed passphrase or declaration that is not the
  document's (another key, or another endpoint, region, addressing style, CA, bucket or prefix
  of the control plane); container sp-cp-db; a database at the old data path; a data directory
  or repository that holds anything without the restore marker; /etc/supapace that is a link,
  a file, another owner's or group/other writable; an executable that is not root's or no
  supapace-arch beside it; the worker image absent, or of another id, without an archive.
- Worker image: with an archive it is loaded when the image is absent or has another id, and
  the id compared again; an inspection that fails otherwise is "could not be inspected".
- Holds the daemon's lock (serve.lock) for the whole run: no daemon and no second recover.
- Order: key 0400 with its marker, passphrase sealed, a partial declaration (the control
  plane's bucket, read-only credential; the node's own full declaration of the same location
  is kept); EnsureImageFiles; KillJobs("cp"); PrepareControlPlaneRestore;
  SetReplicatorQuota(2 x repository quota); backup network; resolve and nft.InstallSet; jobs
  1-4 of subject cp through Agent.RunJob: fetch (list_current, max_bytes and deadline from the
  repository quota), seed, restore, serve beside EnsureControlPlaneRecovery(latest) until
  promotion; the checks; Migrate, ListProjects, EnterNewEpoch once; KillJobs("cp");
  FinishControlPlaneRestore; the report.
- The restore job runs in mode standby with a target timeline: the highest fetched history
  that is not above the newest fetched segment's timeline, else 1.
- A fetched history of the timeline just above the newest fetched segment's stops the run
  before the seed; no flag passes it. A node lost after its promotion's history was uploaded
  and before a segment of that timeline leaves this state, and is refused like any other.
- After promotion the newest history in the data directory (that of the new timeline N) must
  name the timelines 1 to N-1, each once, in order, spelled as numbers; otherwise the run
  stops as a denial. This is what judges which histories replay followed: the names the store
  lists do not.
- "Reached" is the segment holding the byte before that history's last switch point (16 MiB
  segments). Reached below the fetch's newest segment by number, or no serve result: a
  shortfall — exit 1, or accepted with the flag. Segment names in the store beyond what replay
  reaches show as a shortfall, whatever put them there.
- A recovery start that exits before promotion, a failed restore job, a fetch without a
  segment, a promoted history out of order: a denial ("the store denies this recovery"); the
  flag does not pass it. The message names the last request the serve job answered: what the
  server asked for next is what could not be read.
- The restored database's system identifier must be the document's incarnation.
- Nothing is written to the restored database before all of these have passed.
- Every line is scrubbed of the passphrase, the read-only pair and the key, and of any
  beginning of one of at least 8 bytes.
- SIGTERM, SIGINT or a closed output end the run "interrupted by a signal". A run that does
  not finish removes the control plane's job containers and the recovery start and keeps the
  marker; the next run starts from emptied trees. Every stop exits 1.
- Report lines: "recovered point: set L, reached segment S, new epoch N"; "memberships,
  session revocations and service keys are as of the recovered point"; per project that was
  still being created (layout 2) "… what is under R/ below the projects bucket's prefix";
  "next: run supapaced init, …".

escrow show [--part kek|rest] / escrow ack
- nodeEscrow(ctx, paths, cfg, key, store, at) builds the document from the node's state for
  show, ack and any other reader; refused until the store is declared and the control plane's
  stanza exists. A missing passphrase file is an error, never made.
- show prints the whole document or one part on standard output.
- ack prints the rest part unless its hash is the acknowledged one, refuses the null device,
  and writes Paths.EscrowAcked() only after a display that succeeded: offsite.EscrowRestHash,
  64 hex digits, no newline, 0600.

openCPStore / dialCPStore (escrowcmd.go)
- openCPStore: the control-plane database for a command run by hand; refuses an environment
  with PG* variables and a node whose restore is marked ("finish supapaced recover first").
  Used by escrow show, escrow ack and offsite rebuild-continue.
- dialCPStore: the same without the marker's refusal; recover's own.

offsite check
- Resolve, nft.InstallSet, backup network, one probe job per bucket (kind probe, subject the
  bucket's role, write pair then read pair, the other bucket's name only when it differs).
- Record at Paths.OffsiteCheck(), 0600 by rename, and the same bytes on standard output:
  {"at","endpoint","rows":[{"bucket","name","ok","detail"}]}. A probe without a result is one
  row named "probe" with ok null; a refused result (unparsable, more than 32 rows, a malformed,
  reserved or repeated name) or a failure document is "probe" with ok false. Details are
  cleaned and cut to 256 bytes.
- Exit 1 with "not passed: N of M rows are not ok" unless every row is true; the record is
  written either way. Passed = every row true and the record's endpoint the declared one.
- A signal stops the running probe and writes no record.

offsite rebuild-continue --subject <ref|cp>
- Store.ContinueRebuild(ctx, subject, bklimit.RebuildMaxPages): one statement sets the page
  count to 0 for a subject at the cap whose record is not rebuilt for the epoch and returns
  the old count; store.ErrConflict otherwise (also for a cap below 1), store.ErrNotFound for an
  unknown subject. Then ClearAlert(subject, "rebuild-page-cap"). The markers stay.
- internal/backup: a launch past the cap raises the notice rebuild-page-cap ("<n> pages
  merged") and the alert of that code, severity page, figures {"pages": n}.
- Store.EnterNewEpoch empties every subject's rebuild markers and page count.
- store.SchemaVersion() is the schema version this build migrates to.

Tests
- The job command's tests put every PG* variable back (keepToolEnv); a test that opens the
  store through openCPStore still clears them first (cleanPGEnv).
- The fakes of a recovery bound their waits: a wrong ordering fails in a named test.

Known limits
- The check of the promoted history assumes this database's timelines arise one per recovery,
  at the end of its archive. A tool that restores it to an earlier point must restate it.
- The new epoch is the restored epoch plus one.
- Agent.RunJob carries a launch through when its context ends during it, then stops and
  removes the job.
- recover killed outright (SIGKILL) leaves the recovery start and the serve job running; the
  marker stays, a daemon start is refused on it, and the next recover run removes both.
- Killed between the marker's removal and the report, the report is lost; the undone creates
  are the projects left aborted with an off-site purge due.
- Two offsite checks at once remove each other's probe; both end "not passed".
- The quotas and the ruleset are the defaults' until the daemon's first start.
- The version the escrow document names is fixed unless the build sets main.supapacedVersion.
- A store that leaves objects out of its listings offers an older state unseen.

### 2026-11-27 — Studio: one bounded, audited path to postgres-meta
Patches 0028-0032 (topic query; 0032 holds further tests). Every statement and type generation
of the dashboard's server reaches postgres-meta through one function. Upstream's address
constant (PG_META_URL) and getPgMetaRedirectUrl are deleted.
- lib/api/self-hosted/pg-meta.ts:
  - callPgMeta(call) -> {status, text}; call is {kind:'query', sql, parameters?, readOnly?} or
    {kind:'typegen', schemas}. In order: the connection string of the request's project (the
    read-only one whenever the member's role is read_only or the call site asks); the request
    body built and bounded; a slot; the audit record, flushed; the request to the instance the
    control plane names (pg_meta 0 or 1) with Content-Type and x-connection-encrypted and nothing
    a caller handed in; the answer read under a deadline and a byte bound. One connection per
    call, closed after it; no redirect is followed.
  - handOver(request, next): called by the request guard around next(). A request holds at most
    one slot and its calls run one after the other on it. The slot is kept until the response
    has been handed to the client in pieces of 64 KiB, the client has gone, or handover_ms have
    passed since postgres-meta's last answer (the body is then cut).
  - parserSlot(fn): parser_slots parses at a time per project (POST /api/parse-query).
  - checkPgMetaSettings(): reads SUPAPACE_PGMETA and the limits; checkStart() calls it.
- SUPAPACE_PGMETA is exactly http://<IPv4>:<port>,http://<IPv4>:<port> in instance order, as
  dashcfg.StudioEnv renders it. Anything else stops the server at start ("supapace:
  SUPAPACE_PGMETA is not http://<address>:<port>,http://<address>:<port>; the server stops").
  The request guard no longer tests its presence in the prerender mode (six settings do).
- Refusals, thrown as ProjectError and answered by the guard as {code, message}:
  403 no_read_only_login (no read-only string for a read_only member or a read-only call site);
  400 bad_request (a statement that is no text); 413 body_too_large (the serialised body above
  meta_body_bytes; before a slot, on no record); 429 busy (the project's project_waiting places
  taken, or slot_wait_ms waited); 503 audit_unavailable; 504 query_deadline (meta_call_ms from
  the send); 400 result_too_large (more than result_bytes, announced or counted; reading stops);
  499 client_gone; 500 no_project_context outside a guarded request. postgres-meta giving no
  usable answer (no connection, not HTTP, a short body, not UTF-8, a head above 8 KiB) is a
  plain Error with a fixed text and no address; the client gets 500 {"error":{}}.
- Slots: instance_calls in flight per instance, project_calls per project; a project's second
  slot only while two are free; waiting projects are granted in turn. A slot is freed on every
  end: the answer handed over, an error, the deadline, a bound, the client gone.
- A login the database refuses is an answer that is not 2xx and holds either code 28P01 with
  severity FATAL (a password refused when the connection is made), or no code and a message
  that begins "SASL: SCRAM-SERVER-FINAL-MESSAGE: " (the database client's own report that the
  server did not prove it holds the password). An error a statement raises is neither. Then:
  one log line "supapace: security: the database of <ref> at port <port> did not take the
  login: <reason>", dropProject(ref), one resolve; the call is sent once more only if the
  control plane now names another connection string, never a third time. Sent again to another
  instance, it gives the first instance's slot back and takes one of the other's.
- lib/api/self-hosted/audit.ts: writeAudit(record), MAX_LINE_BYTES = 4096. The file is
  <SUPAPACE_DASH_DATA>/<ref>/audit.log (0600; its directory 0700): one JSON line per request SENT
  to postgres-meta, members in this order, each a string:
  {"t","ref","iss","sub","role","login","kind","sql_sha256"} - t is UTC with milliseconds; kind
  is query or typegen; sql_sha256 is the hex SHA-256 of the statement's text, absent for typegen.
  Written after the slot is granted; appended and flushed (the directory too for a new file)
  before the request leaves; the file becomes audit.log.1 (one generation) before a line would
  take it past audit_file_bytes. It is opened for reading and writing, never through a link and
  never waiting: a file that does not end in a line end (a write the machine did not finish)
  gets one first, so the fragment is a line of its own. Not written: 503 audit_unavailable,
  nothing sent, one log line "supapace: the audit record of <ref> could not be written
  (<errno>)". A statement refused before it is sent (403, 400, 413, 429, a client that left
  while waiting) is on no record; a statement sent twice is on record twice; a record does not
  say that the statement ran.
- SUPAPACE_LIMITS has exactly fifteen members, in this order: socket_call_ms, slot_wait_ms,
  meta_call_ms, handover_ms, result_bytes, instance_calls, project_calls, project_waiting,
  parser_slots, resolve_memory_s, resolve_disk_days, snippet_bytes, snippet_entries,
  audit_file_bytes, meta_body_bytes. dashcfg.LimitSet.StudioJSON() renders the last one from
  MetaBodyMB x 2^20, the figure postgres-meta's own body limit is rendered from; there is no
  second field. This server stops at start on fourteen members ("meta_body_bytes is missing") and
  a server built before this change stops on fifteen ("unknown member"): the daemon and the
  image must come from the same commit.
- studio/gates/85-single-caller.sh (eight seeds): the name SUPAPACE_PGMETA occurs in no source
  file of the build tree but pg-meta.ts and unit tests (*.test.ts, *.test.tsx); pg-meta.ts
  exports exactly PgMetaAnswer, PgMetaCall, callPgMeta, checkPgMetaSettings, handOver,
  parserSlot; no file that is no unit test imports a module named *.test. It is a tripwire for
  the setting's name, not a proof: an address written into the code, the container's name, an
  escaped identifier, a glob import of test modules, or a change inside the wrapper pass it.
  A patch that touches the path to postgres-meta is read with that in mind.
- studio/prove/stand-ins.bash: two postgres-meta stand-ins, `pgmeta [stub args]` (containers
  <prefix>-pgmeta-0 and -1), named to the server by address through SUPAPACE_PGMETA, which
  `studio` appends from $META; `seen [0|1]` counts both instances or one, 0 before a first
  request. No proof names a single postgres-meta host any more. STUDIO_PG_META_URL is gone from
  the stand-ins, from manifest.sh's planted list (four values) and marked list (which looks for
  the instances' addresses instead) and from env.tsv, with PLATFORM_PG_META_URL; turbo.jsonc
  lost both names. secrets.sh rows 5.x read the request count and the headers at the project's
  instance; type generation carries the same two headers as a statement. The measured
  containers of build.sh are given SUPAPACE_PGMETA.
- studio/prove/bounds.sh IMAGE (55 rows, about five minutes; the pinned postgres-meta image must
  be loaded, it is never pulled): the instance and the record; no record, no send; the byte
  bounds of an answer and of a body; the slot wait, the deadline, clients leaving; the hand-over
  and its bound; the connection-string vectors read by the pinned image's parser as they arrive
  and as that image rewrites them (row 6.0.1 fails when its rewrite changes), the refused ones
  never sent.
- studio/test-patches/0001-early-release.patch: never part of the product; `build.sh image
  --variant early-release` builds supapace-studio:early-release and leaves the product's tag,
  archive and record as they were. It frees the slot at postgres-meta's answer; bounds.sh then
  fails rows 5.3, 5.5, 5.7, 5.8, 5.9.7, 5.9.8, 5.10 and no other.
Caller rules:
- Reach postgres-meta only through executeQuery, generateTypescriptTypes or callPgMeta; never
  read or write its address elsewhere; a new export of pg-meta.ts must join the gate's list.
- callPgMeta runs inside a guarded request, in the request's own flow: a callback the response's
  consumer drives has no context (500 no_project_context).
- A handler that asks postgres-meta answers with a Response that has a body; otherwise its slot
  ends when the handler returns.
- Headers handed to executeQuery or generateTypescriptTypes are ignored.
What the next work inherits:
- The node's dashboard wiring: SUPAPACE_PGMETA exactly as rendered; the image and the daemon
  from one commit (a mismatch of the limits is a start loop with one log line - show it in the
  node check); Studio's data directory writable by its uid, or every statement is 503; the
  volume sized for every project's snippets, two audit generations and cache together (a full
  volume refuses every project's statements). To confirm on a node: a wrong password through
  the wire proxy reaches the server as severity FATAL, code 28P01, and the security line is
  logged. The severity is the database server's localised word: pin the cluster's message
  language (lc_messages=C on its command line); today the image's own file sets it. With
  another word a refused password is not seen: nothing is dropped, and a member with a rotated
  password in its kept answer gets the database's refusal for at most resolve_memory_s.
  The audit's reader: the eight members, lines up to 4 KiB, "sent" (possibly twice), not "ran".
  The limits test's control image is supapace-studio:early-release.
- Pages and the shell: a loader or a stream callback has no project context; a route that asks
  postgres-meta returns its Response from the handler.
- The hidden surfaces: the opt-in AI and MCP files call executeQuery from stream callbacks and
  fail closed there; MCP passes parameters, which the record's hash does not cover.
Known limits:
- The record holds the hash of the statement's text, not its parameters; no served route passes
  any.
- Any member, a read_only one too, can roll its own project's two audit generations out with
  statements of its own, and can hold its project's slots.
- A login that really is refused costs, per statement, the project's kept entries and one
  question of the control plane, against that project's budget there.
- result_bytes bounds the bytes of an answer, not what parsing it allocates. Three projects can
  hold an instance's four slots.
- One Studio process writes a data volume: one writer per project's audit file is a rule of the
  process.
- A request whose client leaves costs eleven log lines of the server framework's own.

### 2026-11-27 — Experiments e20–e28 on the platform's own code (ag/exp.go, ag/lab.sh)
- Files: `test/harness/experiments/e20.sh` … `e28.sh`, `lib-agent.sh` (sourced after
  `lib-backup.sh`), `ag/lab.sh` (host runner, bash) and `ag/exp.go` (build tag `supapace_exp`).
- Run, from a checkout with Go and Docker: `make images`, `make node-bare NODE=sp-x`
  (with the object-store stand-in; never `SP_OFFSITE=0`), then
  `test/harness/experiments/ag/lab.sh sp-x test/harness/experiments/eNN.sh`; `make node-down
  NODE=sp-x` at the end. One script per node at a time.
- lab.sh builds `supapaced` from the tree with one more command, `supapaced exp …`: `go build
  -overlay` puts `ag/exp.go` into `cmd/supapaced` as `zz_exp.go`, with `-tags supapace_exp`.
  No product build or test build contains it; `go build -tags supapace_exp ./...` fails
  on purpose (the file is a fragment of `cmd/supapaced`). `make check-exp` (a step of CI's unit
  job) vets it through the same overlay and shellchecks the scripts; nothing of the kit runs in
  CI. It calls internal/agent, nft, s3x, store, jobio, pgsock and walname.
- The binary and the node's `supapace-arch` go to `/var/lib/sp-exp/ag/bin` in the node (root,
  0755): every job, task and archive-binary copy runs the platform's programs, because RunJob
  mounts the daemon's own executable. `exp` refuses a non-root caller; lab secrets are derived
  from a random seed in the kit directory (0700) and never printed.
- lab.sh refuses a node where the daemon runs or the kit directory exists; on TERM, INT or HUP it
  stops the run by its recorded pid (60 s, then KILL) and removes the lab: `exp downall`
  (projects, control-plane database, platform networks, ruleset, quotas, by name) and
  `lab_down`. After a KILL of lab.sh, run `make node-down`.
- Output: PASS / FAIL / CONTROL / RECORDED lines, then one `VERDICT ENN: confirmed — …` line;
  exit 0 confirmed, 1 a criterion failed (`unknown`), 3 a lab error (the EXIT trap prints an
  `unknown` line naming the step).
- Questions: e20 the replicator's group read of repo/ and hostile entries; e21 the repository
  quota at push and backup, fetch/ charged to the replicator, a disk-quota stop with and without
  the runbook; e22 conditional create and versions on the stand-in, the probe job; e23 the backup
  network's egress with the off-site set, F7, no lookup, a set change in flight, the drift check;
  e24 the re-key against hostile restored settings and content; e25 recovery leftovers (target
  beyond the archive, a seeded repository, an altered segment, a stop between promotion and
  re-key, a self-promoted cluster); e26 the control-plane stanza end to end; e27 idle WAL and a
  segment archived again after a crash; e28 the `.partial` rule under the real server.
- Durations on a loaded workstation: e20 2–3 min, e21 5–8, e22 <1, e23 3, e24 2, e25 15–18,
  e26 2–3, e27 ~28 (25 of them idle sampling at `archive_timeout` 300 s), e28 2–3.
- Stand-ins left in the lab: the fetch plan is built from the store's listing (`exp` xPlan), the
  record of timelines is shell state (the serve job admits `SERVE_TL`, default 1,2,3), single
  connection probes and the slow reader are sp-probe containers, and pgBackRest's verify, info
  and expire run in a plain worker container.
- Limits: the stand-in keeps every object a day on a 512 MiB tmpfs; one round of all nine uses
  about 111 MiB, so about four rounds fit one node. e20's repository holds about half the
  replication job's file cap (1037 of 2048 files). Re-run e24 at every image
  bump of the cluster image (the platform session's startup list is one image's).

### 2026-11-27 — check-exp under an older shellcheck

- The CI runner's shellcheck (0.9.0) reports a function reached only through a trap as SC2317;
  newer versions report it as SC2329. ag/lab.sh's EXIT-trap handler disables both by directive.
- A lint step must pass under the runner's tool version, not only the workstation's: print the
  version in the step (CI does) and prefer a directive with a reason over a global exclusion.

### 2026-11-27 — Browser harness: a cookie barrier the engine keeps

- run.mjs setCookie: the page reads its cookies back after writing the cookie and a host-only
  mark; the mark is waited for in the jar when the page holds it, else the cookie, else the jar
  is read once after the page's read. WebKit keeps no cookie, the mark included, on a host that
  is itself a listed suffix, so a wait for the mark there can only time out.
- A barrier cookie must be one the engine keeps on that host; a refused barrier is not a delay.

### 2026-11-27 — Node network: exact members of a project network; no forwarding on two networks
internal/agent (gate.go, nodecheck.go, postgrest.go, platform.go), internal/dashcfg (env.go).
- dashcfg.NoForwardArgs(): the docker arguments that keep a container on two networks from
  forwarding between them - six --sysctl pairs, in this order: net.ipv4.ip_forward=0,
  net.ipv4.conf.all.rp_filter=1, net.ipv4.conf.default.rp_filter=1,
  net.ipv4.conf.all.arp_ignore=1, net.ipv4.conf.default.arp_ignore=1,
  net.ipv6.conf.all.disable_ipv6=1. sp-gateway and every postgrest-<ref> are created with them
  (a PostgREST after its own options; the IPv6 setting is there once); the wire proxy must be.
- Why the conf.default pair: for the reverse-path filter and arp_ignore the kernel takes the
  larger of conf.all and the interface's own value, and an interface starts with its
  namespace's default, which a new namespace takes from the host - often 2, the loose filter.
  With conf.all=1 alone every interface stayed loose. With both, the first interface, one
  connected before the start and one attached after it are strict. The arp_ignore default
  changes nothing in effect (conf.all=1 already gives 1); it keeps each interface's value at 1.
- The settings are part of the configuration label of the gateway and of each PostgREST. At
  the first daemon start after the upgrade the gateway is made again (log: "re-creating
  sp-gateway: its configuration changed") and each PostgREST at its adoption; clusters are not
  touched. Measured with two projects: about 1 s of refused connections, then about 3 s of 503
  on each project. Later starts make nothing again. Changing the list changes every label.
- Start gate, condition 7 (CheckContainment, CheckAdopted) - the member rule: proj-<ref> holds
  at most pg-<ref> at ClusterAddr(i), postgrest-<ref> at PostgRESTAddr(i) and, only on a node
  whose dashboard is configured (a studio domain and a configuration dashcfg.For accepts),
  sp-pgcap at dashcfg.ProxyAddr(cfg, i). Any other member, one of the three at another address
  (the reserved host included), or one created without a configured address refuses the start,
  whatever its capabilities. Fewer members are not refused. It covers every container the gate
  reads: the running members of the three networks and the two tenant containers by name,
  running or created. Text (match on "member rule"):
    proj-<ref>: member rule: <container> is on it at "<address>"; it may hold only
    pg-<ref> at <a>, postgrest-<ref> at <b>[, sp-pgcap at <c>]
  It names nothing of another network and no label. A completed finding: ErrContainment, never
  ErrCheckIncomplete. An operation ends as final with containment_failed; a refused restart
  leaves the project restarting with its route draining until the member is removed and
  'supapace op retry <id>' is run. Other projects start and serve meanwhile.
- Start gate, fixed addresses: each of the dashboard's four addresses on platform
  (dashcfg.Static, on every node) may be held only by its own container - sp-studio,
  sp-pgmeta-0, sp-pgmeta-1, sp-pgcap. Another holder, running or created, refuses every start:
    <container> holds <address> on platform, the address of <owner>
  A stranger elsewhere on platform does not refuse a start; the node check reports it.
- ctrConf.Sysctls: Docker's record of a container's sysctls, read with
  index .HostConfig "Sysctls" - Docker leaves the key out of a container that has none, and a
  field reference then fails the read of every container in the call.
- Node check rows, all blocking under Blocking():
  - platform-members also accepts the dashboard's four containers, each at its address with
    its role label (studio, pgmeta, pgmeta, pgcap), only on a node whose dashboard is
    configured; elsewhere each is "foreign member <name>". A mismatch reads
    "<name> at <address>: not at <want> with the role label <role>".
  - project-addresses: every network named proj-*, its members read as the gate reads them,
    held to the member rule; the slice is the number in the bridge name spp<i>, confirmed by
    the subnet. A member on such a network that is no slice of the node:
    "<network>: member rule: <container> is on it, and it is not a slice of this node".
    It passes with a member missing, a network empty or gone since the listing, an endpoint key
    that resolves within the re-reads; it fails on any read error and on a key that stays.
    Cost: three Docker calls a project network (about 50 ms each network on a test node).
  - forwarding: Docker's record of sp-gateway, of every container labelled
    supapace.role=postgrest (running or not) and of any container named sp-pgcap holds each
    setting at its value, else "<container> was not created with <key>=<value>". The gateway
    and a PostgREST are judged only when they carry the configuration label this daemon
    computes now (a PostgREST's from its own ref, generation and epoch labels, its platform
    address and postgrest.conf on disk): one with another label is not adopted, is made again
    by its next ensure, and the rows gateway and rest-container report it - so a daemon start
    after an upgrade does not stop the node's projects. sp-pgcap is always judged, whatever
    its label, state or networks.
- Caller rules:
  - Attach a container to a project network only with --ip; a connect without one takes the
    first free address, and from then on every start of that project is refused.
  - Create the proxy with NoForwardArgs from its first version, with no capability, the role
    label pgcap, at its platform address. On a node whose dashboard is no longer configured
    remove it, with its attachments, before the node check of a daemon start: left there,
    platform-members and project-addresses fail and every project is stopped until it is gone
    (the node then recovers by itself within seconds). The same holds for sp-studio and
    sp-pgmeta-*.
  - A package that exempts dashboard container rows in Blocking() leaves project-addresses
    and forwarding blocking.
- Known limits: Docker lists only running containers as members, so a stopped stranger
  configured on a project network is seen when it runs (the two tenant containers are read
  created or stopped). The row forwarding reads Docker's record, not the namespace; the node
  test TestNode_ForwardingDefaultsAndApplied reads the namespace, per interface. The gate
  accepts sp-pgcap on a project network by name and address alone; its settings are the row's.
  A container on one project's network fails project-addresses for the node: at the next
  daemon start every project is stopped, not only that one.
- Tests: TestGate_ProjectNetworkMembers, TestGate_FixedPlatformAddressUnderAnotherName,
  TestGate_TransientEndpointIsReadAgain, TestNodeCheck_ProjectAddresses,
  TestNodeCheck_Forwarding, TestNodeCheck_PlatformMembers_AcceptsTheFour_OnlyWithAStudioDomain;
  on a node (make node-proof PKG=internal/agent) TestNode_ForwardingDefaultsAndApplied and
  TestNode_GateProjectNetworkMembers. A test that needs a scratch member for the capability
  rule puts it on the platform network, never on a project's.

### 2026-11-28 — The wire proxy on the node: container, table, attachments, two node-check rows

One container per node, `sp-pgcap`, carries the dashboard's SQL connections. It sits on the
platform network at `dashcfg.Addrs.Pgcap` and at host 4 of every project network it serves, and
reads one table, `<platform dir>/dash/pgcap/pgcap.json`. `internal/agent/dashnet.go` makes the
container, writes the table and attaches and detaches the proxy. `EnsureProxy`, `AttachProxy`
and `DetachProxy` do nothing on a node without a studio domain, or on one whose configuration
`dashcfg.For` refuses.

Provided (methods of `*agent.Agent`):
- `EnsureProxy(ctx, list func(context.Context) ([]Spec, error)) error` — takes the table's
  lock, calls `list` once for the live projects, then: the table with this daemon's classes
  and the slices of the listed projects it is attached to; `sp-pgcap` running with this
  daemon's configuration (made again when its label, its platform membership or its address
  differ, and then started from a table without slices); attached at host 4 of every listed
  project whose network exists; detached from every other network but `platform`. Every
  project is tried and the errors are joined: after a failed attach a project keeps its slice
  and attachment only where the proxy already held the slice's own address, and a network that
  has not the slice's shape is never kept. An error of `list` is returned with nothing
  changed; a nil `list` is refused.
- `AttachProxy(ctx, s Spec) error` — a create's step `7a`: attach at host 4, then add the slice
  with `dashcfg.Limits.Proxy.ConnsPerProject`. Makes the container when the node has none, from
  the table on disk (one without slices when there is no file). Starts a stopped proxy.
  Idempotent. An absent project network is an error.
- `DetachProxy(ctx, ref string) error` — remove the slice from the table, then detach. Called
  by `RemoveNetwork` first; a failure there leaves the network. Idempotent; nil when the network
  is absent. The slice is read from the network itself.
- `RemoveProxy(ctx) error` — on any node, under the table's lock: removes `sp-pgcap`, and with
  it its attachments, only under its exact name with the role label `pgcap`, by the id that was
  inspected. Nil when there is none. A container of that name without the label is left and is
  an error naming it. The table stays: with no proxy `proxy-networks` passes, `proxy` reports
  the absence, and `EnsureProxy` makes the proxy again and attaches the listed projects.
- `RemoveDashboard(ctx) error` — only on a node whose dashboard is NOT configured: removes
  `sp-studio`, `sp-pgmeta-0`, `sp-pgmeta-1` (each under its exact name with its own role label,
  by the inspected id; one without its label is left silently) and the proxy as `RemoveProxy`
  does (so a container named `sp-pgcap` that is not the platform's is an error here), then the
  proxy's table. Keys and Studio's data stay. Every container is tried; the errors are joined.
  The daemon calls it at a start, before the node check, and logs its error
  (`cmd/supapaced/boot.go`, asserted at use): what it left is for the member rows to judge.
- `saga.Agent` gained `AttachProxy(context.Context, agent.Spec) error`. Step `7a` follows `7`
  in every create and completes at once where the agent does nothing. It has no compensation of
  its own: `RemoveNetwork` (delete D4, abort C6) undoes it.

The table:
- `pgcap.Table.Marshal`'s bytes, written whole by rename, root `0444` in a root `0755`
  directory (every write puts the directory's mode back), at most 1 MiB, never read through a
  link, not rewritten when already in place.
- One lock (`proxyMu`) from the read of the file to the last Docker call of each method; the
  node check's read, `RemoveProxy` and `RemoveDashboard` take it too.
- Two orders, everywhere: a slice enters the table after the proxy holds its address on that
  network; it leaves the table before the proxy leaves the network.
- Refused before anything is attached or written: a table `pgcap.ParseTable` refuses (terms
  above the ceiling among its rules), one above 1 MiB, one whose terms at their class's cost
  plus 16 MiB pass 80 % of the container's memory. The step that asked fails with that reason.
- A file that is no table (not canonical, a link, too large) makes attach and detach fail and
  change nothing; only `EnsureProxy` replaces it.
- A network of a project's name that has not this node's shape for the slice is never joined
  (`ErrContainment`).

A proxy the runtime holds between two restarts: the runtime then refuses to connect or
disconnect it. Every call that changes an attachment goes through one helper (`proxyNetwork`):
when the call fails and the runtime reports the proxy restarting, the proxy is stopped, the
call made once more, and the proxy started again — so a create, a delete or an abort does not
wait for the proxy to be well. A proxy that runs, or whose state cannot be read, is never
stopped for a failing call.

The container: image `supapace-pgcap:local` (it must be in the node's store; nothing is
pulled), uid 65529, the dashboard containers' hardening and the settings against forwarding,
64 MiB memory and swap, 64 pids, `nofile` from the table (1,216 on a default node), the table's
directory read-only at `/etc/pgcap`, `GOMEMLIMIT` at half the memory limit, the command
`/pgcap /etc/pgcap/pgcap.json`, role label `pgcap`. Its configuration label covers the options,
the command, the image id, the seccomp profile and the table's shape (listen, block, slice
prefix, ceiling; per class its name, port base, peers, pool and buffer sizes). A change of any
of them re-creates the container and cuts every dashboard SQL connection of the node — so does
a changed per-peer cap, which enters `nofile`. A changed rate, allowance or deadline rewrites
the file only.

Node check, on a configured node only (`NodeCheck` appends both rows itself):
- `proxy-networks` — BLOCKING. Fails when the proxy, running or not, is attached to a network
  that is neither `platform` nor a project network of this node (named `proj-<ref>`, with a
  slice's bridge, subnet, internal flag and isolated gateway); when the table holds a slice for
  which no such network exists; when the proxy or one of its networks cannot be read. A table
  that cannot be read or parsed does not fail it: the attachments are then judged alone, and
  the file is the row `proxy`'s to report. Passes when there is no proxy.
- `proxy` — reported, not blocking (`agent.Blocking` exempts it as it does `gateway`). Fails
  when `sp-pgcap` is absent, stopped, of another configuration or at another address, or caught
  by the restart rule; when the table is absent, unreadable or no table; when a slice of the
  table lacks the proxy at host 4; when an attachment has no slice; when the proxy's log of
  the last five seconds names a port of the table it could not open.
- One restart rule (`dashRestarting`) for `sp-studio`, `sp-pgmeta-0`, `sp-pgmeta-1` and
  `sp-pgcap`: the runtime is restarting the container, or it restarted and its last start is
  under a minute old, or its restart count grew since the last check of that name. A count
  below the one last seen counts from nought: the runtime counts anew at a start by hand, and
  at the agent's own start of a stopped or held proxy.
- `platform-members` and `project-addresses` read a project network's slice by the same strict
  rule (`sliceOf`): a member on a `proj-…` network that is not internal with an isolated gateway
  fails both rows.

Rules for whoever wires this into the daemon:
- Call `EnsureProxy` at every daemon start and in the repair round; `list` returns the placed
  projects that are not deleting or later. Nothing else starts a stopped proxy, attaches a
  project created before the node had a studio domain, or re-attaches one whose network was
  made again by a recovery.
- `list` runs with the table's lock held, so no create's attach falls between the reading of
  the list and the work. Every attach, detach, removal and node check waits behind it: it must
  return promptly (give it a deadline), and it must not take or wait for a project's own lock
  or anything else a saga step holds across its agent call — those steps are waiting for it.
- What `proxy-networks` reports is repaired by `EnsureProxy`, by `RemoveProxy` (which starts
  nothing, so it may run on a node that is not contained) or by hand. A start's node check
  runs before the store is open: a row that fails there stops the tenants first.
- `EnsureImageFiles` and `EnsurePlatformNetworks` come first. One agent per process: the lock
  and the restart counts are package state.

Known limits:
- The restart count is the daemon's memory. Its first check of a name compares nothing, so at
  a start the count never fails a row; a container made again counts from nought; a growth is
  reported once, to the caller that reads it.
- After `make reach-reboot DASH=1` the proxy is stopped (the harness stops nested containers by
  hand, which the restart policy does not undo): `bridge_members_d` is red on a dashboard node
  until the daemon calls `EnsureProxy` at a start. `make reach DASH=1`, and both targets on a
  node without a dashboard, pass.
- The agent has no list of projects. A network made by hand with exactly a slice's shape under
  a project-like name passes `proxy-networks`; the row `proxy` reports the attachment.
- With a table that cannot be parsed the blocking row cannot judge the table's slices; the
  proxy itself keeps the last table it read.
- The row `proxy` asks the runtime for the last five seconds of log and judges what one call
  returns (64 KiB): on a node of about a hundred slices that all log every second, a line past
  that bound is not seen.
- If the daemon's context ends between the helper's stop and its start, a proxy that was held
  between two restarts stays stopped until the next attach or ensure starts it.
- The blocking row `forwarding` judges whatever container is named `sp-pgcap`, on any node, by
  that name alone: one that is not the platform's and was not created with the settings fails
  it. `RemoveDashboard` and `RemoveProxy` leave such a container and say so; it is removed by
  hand.
- The public resolver's leg of the hostile-cluster node proof runs only when
  `SUPAPACE_PUBLIC_RESOLVER` names one in the proof's environment.

### 2026-11-28 — A pooler node: node file, init, image lock and cache, harness

A node has a pooler when its node file names a pooler label. This entry is what the node file,
`supapaced init`, the image lock, the image cache and the test harness provide for such a node.
No container, ruleset or daemon wiring is part of it: a labelled node runs as any other until
those arrive.

Node file (`internal/nodecfg`) — seven members, all `omitempty`; a file without them is written
byte for byte as before:
- `pooler_label` (`PoolerLabel`): the pooler zone is `<label>.<domain>`, a project's pooler host
  `<ref>.<label>.<domain>`. Empty: no pooler.
- `public_addrs` (`PublicAddrs`): every IPv4 address under which the outside sees the node — what
  its names resolve to, and every source address the provider gives its outbound traffic.
- `egress_subnet` (`EgressSubnet`): the outbound network's subnet. Read it through
  `Config.Egress()`, which returns the member or `10.212.10.0/24`; never read the member.
  `EgressBridge` is `spe0`, `EgressNetwork` is `tenant-egress`.
- `proxy_max_conns`, `rest_idle_stop_s`, `offsite_window_s`, `rekey_settle_s`: figures their users
  resolve; 0 is "the built-in value" (`rest_idle_stop_s` 0: never stopped for idleness).
- `Validate` — and so `Load`, every daemon start and every `init` — refuses, with joined plain
  errors that begin with the member's name and come in one fixed order:
  - a label that is not one DNS label of `[a-z0-9-]` (1 to 63 characters, no hyphen at either
    end), one with a project ref's shape (20 of `[a-z0-9]`), or one under which
    `<ref>.<label>.<domain>` passes 253 characters;
  - a public address that is not dotted IPv4 in canonical form, or is unspecified, broadcast,
    loopback, link-local or multicast, or lies in `0.0.0.0/8` or the reserved block
    `240.0.0.0/4`, or repeats, or lies inside a network of the node (project block, platform,
    ingress, Docker pool, backup, egress); more than 32 of them;
  - an egress subnet, as `Egress()` resolves it, that is not a masked IPv4 network or overlaps
    another network of the node;
  - `rest_idle_stop_s` outside 0 to 86400; a negative `proxy_max_conns`, `offsite_window_s` or
    `rekey_settle_s` (named in that order).
- The label's two patterns are written twice: in `Validate` and in `poolcfg.ValidLabel`
  (`nodecfg` cannot import `poolcfg`); a test holds them equal. Change both together. The 253
  rule is in `Validate` only.
- Upgrade: the default egress subnet now counts among the node's networks. A node file whose
  networks were moved by hand onto `10.212.10.0/24` no longer loads; `init` never wrote one.
- `Paths`: `PoolerSecrets()` `/etc/supapace/pooler`, `PoolerTLS()` `/etc/supapace/tls-pooler`,
  `NftLimitFile()` `/etc/supapace/nftables-limit.nft`, `WakeDir()`
  `/var/lib/supapace/platform/wake`, `ScheduleCache()`
  `/var/lib/supapace/platform/schedule.json`. Paths only: of these `init` creates `tls-pooler`
  alone (root 0700; `cert.pem` and `key.pem` root 0600), on a node with a label.

Images (`internal/nodecfg/images.go`, `images.lock`):
- The lock row `supavisor` holds the tag, the index digest and both platform digests; a test
  holds it equal to the pooler lab's pins file.
- `SupavisorImage()`: `<repository>@<index digest>`; an error when the row or its index digest is
  missing. Never a platform digest.
- `PostgresImages()`: image reference → version, from the row `postgres` and every row
  `postgres@<version>`. Errors: a version that is not dotted digits, a tag that does not end in
  `:<version>`, a row without its index digest, two rows naming one image. The lock has no such
  row yet, and neither the cache script nor the Makefile reads a key with `@` in it: whoever
  adds the first one extends both.

`poolcfg.ValidAllowList` refuses the egress subnet as it refuses the node's other networks, and
a network of the node that does not parse is now an error naming it (it was skipped before).

`supapaced init`:
- `--pooler-label L`: set once — at the first init, or at a later one of a node that has none.
  Another label is refused (exit 1, nothing written); without the flag the stored label stays.
  A labelled node must pass `poolcfg.For` at every init.
- `--pooler-tls-cert F --pooler-tls-key F`: required with the label unless `--dev` is given or a
  pair is stored; refused with `--dev`. The first certificate of the file must match the key, be
  valid now, allow server authentication, and carry the DNS name `*.<label>.<domain>` and no
  other DNS, address, e-mail or URI name (compared as written, lower case). Its common name is
  not looked at. Further certificates of the file are stored as given. Regular files of at most
  1 MiB; a link is followed.
- `--dev` issues the pair from the node's CA; the zone lies under the base domain, which the
  CA's name constraint covers. A development pair — the base one, the studio's, the pooler's —
  is issued again when it cannot be loaded or expires within 30 days, and all of them are
  whenever the CA itself is issued (none was in place): a pair in place is never left under a
  CA that is gone. With the CA in place and the pairs valid a run writes nothing. An operator's
  node has no CA and is never issued a pair; `--dev` cannot be added to it.
- `--public-addr A`, once for each: the flags of one run replace the stored list; a run without
  the flag keeps it; nothing else of the node file moves. To return to declaring none, remove
  `public_addrs` from the node file (the help and the installation document say so). The daemon
  reads the list at its start.
- A node file that carries `offsite_window_s` or `rekey_settle_s` is refused without `--dev`;
  with both, the first is the one named.
- The node file, with the label, is written before the pair. An interrupted run leaves a
  labelled node without its pair: the next init asks for it (operator's node) or issues it
  (development node). Whoever starts the pooler treats a missing pair as a failing check.

`scripts/install-node.sh` passes the new flags to `init`, writes
`/etc/modules-load.d/supapace.conf` (`nf_conntrack_bridge`, `nft_connlimit`; 0644) and, when
either is not under `/sys/module`, prints `modprobe -a nf_conntrack_bridge nft_connlimit` for the
operator to run. It loads no module. `node-init.sh` writes the same file in a test node and
loads none.

Image cache (`scripts/cache-images.sh`):
- `SP_POOLER=1` (`make … POOLER=1` exports it): the row `supavisor` is saved, as every row is,
  into `DIR/pool/supavisor-<12 hex>.tar`, or pulled by its index digest with `--pull-only`.
  Without the variable the row is neither pulled nor saved.
- "Cached" means, for every row: the archive's `index.json` names the lock's index digest as a
  manifest entry's digest and in the image's name. Anything else at the archive's path is
  removed before the pull and saved again; when the pull fails the path stays empty.
- The pooler lab's own archive is saved for one platform and fails that check, so the lab keeps
  it under `pool/lab-supavisor-<12 hex>-<arch>.tar`, which no node loads. A checkout from before
  this change still uses the pooler's name for it: in a cache shared with such a checkout each
  side finds the other's file unusable. One cache for each checkout until all carry the change.

Harness (`Makefile`, `test/harness/node/node-init.sh`):
- `make images POOLER=1`: the pooler's row, and the wire proxy's image built and saved as
  `dash/supapace-pgcap.tar`, as `DASH=1` does (the save line makes `dash/` itself).
- `make node-up POOLER=1` and `make node-bare POOLER=1`: 6 GiB (8 with `DASH=1`; `NODE_MEM`
  overrides); the node container gets `POOLER=1` and `SP_POOLER_LABEL=db`; `node-init.sh` loads
  `/images/pool/*.tar` except `lab-*`, and `dash/supapace-pgcap.tar`, and in full mode gives
  `init` `--pooler-label db` when the binary knows the flag. The zone of a test node is
  `db.sp.test`.
- A node started with `POOLER=1` from a cache whose `pool/` holds no archive but the lab's stops
  before it loads any image, with one line naming `make images POOLER=1`. Without `POOLER=1`
  nothing looks at `pool/`.
- The outside lab, made once the node is up: the network `$(NODE)-out` — internal, without an
  address of the host — on `OUT_SUBNET`, by default `198.51.100.<16·(S3_SLOT mod 15 + 1)>/28`;
  the node at its base + 8; the container `$(NODE)-client` (the control-plane image, sleeping,
  `NET_ADMIN` its one capability) at base + 9; the client's address in `/var/lib/sp/outside` on
  the node. Two nodes whose slots agree mod 15 collide: the second `node-up` stops at the
  network with a line naming `OUT_SUBNET`, its node already running — `make node-down`, then
  `node-up` with another `OUT_SUBNET`.
- `make node-down` always removes `$(NODE)-client` and `$(NODE)-out`, by those exact names and
  without looking at a label: never name a node `<another node>-out` or `<another node>-client`.
- `make reach` and `make reach-dash` pass `SUPAPACE_POOLER=1` when the node file has a label and
  `SUPAPACE_OUTSIDE=1` when `/var/lib/sp/outside` exists; the other node targets pass neither.
- The suite passes on a pooler node: its one test that took a node without a studio domain for
  a 4 GiB node now takes a pooler node for a 6 GiB one.
- A harness script must start with its interpreter line: a line in front of it passes `sh -n`
  and stops the node at its start. A test holds the first line of each.

Known limits:
- Nothing in the node can run a command in the outside client: the client is a container of the
  host's Docker that only sleeps, and the node knows its address alone.
- `init` takes no lock: two runs at once with different labels can both succeed and leave a
  pair that is not the stored label's. One run at a time.
- A development CA issued now replaces every pair in place — also the stored copy of an
  operator's pair, on a node whose node file was removed by hand before `init --dev`.
- The stop looks for the pooler's archive alone: a cache that has it and lacks
  `dash/supapace-pgcap.tar` gives a pooler node without the wire proxy's image, silently.
  `make images POOLER=1` always writes both.
- The "cached" check reads the digest and the name anywhere in `index.json`, not in one
  manifest entry: an archive made by hand with the two in different entries is kept.
- `Validate` puts no bound on the size or kind of the egress subnet beyond "an IPv4 network that
  overlaps no other".
- On a node with a studio domain the row `proxy` fails until the daemon ensures the proxy, so
  `supapace node check` exits 1 there, with or without `POOLER=1`.
- The suite's reset removes nothing of the outside lab; there is nothing of it in the node yet.

### 2026-11-28 — agent: the platform database on a node with a pooler label
internal/agent (platformdb.go; nodecheck.go, gate.go).
- sp-platform-db holds the pooler's registry. Derived state: never backed up; registering the
  projects again rebuilds it.
- (*Agent).EnsurePlatformDB(ctx) error. Without a pooler label: nothing, nil, no Docker call.
  With a label and a configuration poolcfg.For refuses: nothing made, the refusal returned.
  Else, in this order: the node secret; the directories and the two access files; an
  initialisation when there is no database; the container adopted, started or made again; the
  registry role and database over the socket. Idempotent. Never two calls at once (one task
  name, one directory): call it from the daemon's round, before the pooler's ensure.
- (*Agent).CheckPlatformDB(ctx): the node-check row platform-db. It fails when the restart rule
  catches the container ("sp-platform-db is restarting; its last log line: ..."), or when the
  container is absent, stopped, of another configuration or at another address. Not blocking
  (Blocking exempts it). No row without a label; one failing row carrying the refusal when
  poolcfg.For refuses.
- Until the daemon calls the ensure, every node with a label has the failing row
  "sp-platform-db absent" and 'supapace node check' exits 1 there; the node stays contained.
- The container: the control-plane image at uid and gid 65525 (poolcfg.PlatformDBUID; not in
  the image's account file), network platform at poolcfg's PlatformDB address (base + 7) and no
  other, the control-plane database's hardening, 256 MiB, 128 pids, restart unless-stopped, role
  label platform-db, no environment of its own. Settings: listen_addresses=<that address>,
  max_connections=40, password_encryption=scram-sha-256, hba_file and ident_file in /etc/sp.
- Files under /var/lib/supapace/platform/pdb (root 0700): data and sock (65525, 0700 as made;
  the image sets sock to 3775 at each start), etc (root 0755) with pg_hba.conf and
  pg_ident.conf (root 0444), and the stamp "initialised" (root 0444, empty). The access file
  is exactly:
    local all postgres peer map=agent
    host supavisor supavisor_meta <pooler address>/32 scram-sha-256
  and the mapping "agent root postgres". A file found changed on disk is written back and the
  container made again; the row reports "another configuration" until then.
- A database is the stamp and data/PG_VERSION together. The stamp is written last, after the
  initialisation task ended with code 0 and left a version file. Without either: the stamp is
  removed (an error there stops the repair), the server's container and a left-over
  task-pdb-initdb are removed by name, data is emptied, and the task runs again. A task killed
  part-way leaves a version file and no stamp, so it is repaired by the next call.
- The task task-pdb-initdb: same image, uid 65525, no network, the data directory alone
  mounted, the image's initdb with --auth=reject. The superuser has no password. The image's
  entrypoint is never asked to initialise: under the exact access file its own first session is
  refused, and without a password variable it refuses an empty directory.
- The secret /etc/supapace/pooler/meta.password: 64 lower-case hexadecimal characters, root
  0600 in a root 0700 directory, made once and never replaced. It is written under a temporary
  name (.meta.password.*) in that directory, synced and linked into place, so its name never
  holds a partial file; when two makers race, both return the one that was linked first.
  Anything else at the name (a link, a directory, a FIFO, another mode, owner or form) is
  refused before a container is made; the error names the path, never the content. The server
  is given a SCRAM-SHA-256 verifier of it (4096 iterations, a fresh salt at every call).
- Over the socket, as postgres (root maps to it), at every call: role supavisor_meta - login,
  nosuperuser, nocreatedb, nocreaterole, noreplication, connection limit 30, the verifier;
  database supavisor owned by it; CONNECT revoked from PUBLIC on supavisor and on postgres.
  Measured for a call that adopts: about 100 ms, 7 commits, 600 bytes of WAL; sessions stay.
- The wait for the server, tried every second while the container runs: at most 3 minutes when
  this call made or started the container, at most 10 seconds when it found it running - a
  restart loop costs the caller 10 seconds a call. Errors: "stopped before it answered",
  "did not answer within <bound>"; any other session error is returned at once.
- Node check: platform-members accepts sp-platform-db at its address with its role label on a
  node with a label that poolcfg.For accepts; anywhere else it is a foreign member (blocking).
  Start gate, on every node: only sp-platform-db may hold the platform database's address:
    <container> holds <address> on platform, the address of sp-platform-db
- Its log: on standard error (one entrypoint line a start on standard output); lines of about
  150 bytes; driver json-file. A read over the cap on standard error is halved as for the other
  databases.
- Measured: 34 MiB and 7 processes idle, 78 MiB and 37 with 30 sessions.
- Caller rules: read the secret through metaPassword and make it nowhere else; a name in the
  secrets directory that begins with ".meta.password." is not a secret; never mount pdb/sock
  into another container (a process of uid 0 that reaches the socket is the superuser); build
  the argument list with pdbConfig only after the profile and the access files are on disk.
- Known limits:
  - A stamped directory the server cannot start on is not repaired by itself: the row names the
    restart loop; remove pdb/initialised and the next ensure makes the database again.
  - Another image reference makes the container again on the same data; another major version
    needs that removal too.
  - A paused container: each call returns after 10 seconds and the row stays OK.
  - Removing the label by hand, or a configuration poolcfg.For refuses, leaves a foreign member
    that stops every project until the container is removed. Nothing removes it.
  - A temporary name left by a process killed while making the secret is never cleaned.
  - The verifier is written at every call. The two syncs of the secret are not under test.
- Tests: TestPlatformDB_*, TestNodeCheck_PlatformDB*, TestNodeCheck_PlatformServiceRows,
  TestPlatformMembers_PlatformDBOnlyWithALabel,
  TestGate_ForeignHolderOfThePlatformDBAddressRefuses; on a bare node, as root:
  make node-proof PKG=internal/agent RUN='TestPlatformDB_|TestNode_PlatformDB'
  (no CI job runs it).
