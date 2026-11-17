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
