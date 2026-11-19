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
