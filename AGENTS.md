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
    exchange; queries get no answer), `sasl-iter` (a server-first message with a random
    salt and ten million iterations), `huge` (a header announcing 1 GiB, then its body),
    `flood` (ParameterStatus and NoticeResponse without end), `stall` (nothing), `trickle`
    (the SASL request, one byte per second).
  - Post-authentication modes need `--password-file` and `--salt` (refused for every other
    mode): they complete a real SCRAM-SHA-256 exchange with that password, that salt and
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
