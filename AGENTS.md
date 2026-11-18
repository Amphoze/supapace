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
  `conn N LEN` + LEN bytes, prints `listening` once bound and logging, never completes
  authentication (clients need their own timeout) and leaves no record for a connection
  that sends nothing.

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
  - PostgREST alone accepts tokens with no `kid`, no `exp`, no `role`, an unknown `crit`
    header, `role = authenticator`, or a duplicate `role`; refusing those is the gateway's
    job.
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
  per project), `unavailable` (503, gateway-wide or draining), `upstream_unavailable` (502),
  `upstream_timeout` (504). The gateway — not the upstream — refuses tokens without `kid`,
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
