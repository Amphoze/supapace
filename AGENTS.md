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
