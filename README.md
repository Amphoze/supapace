# supapace

Self-hosted, multi-project Supabase-compatible platform. One shared stack serves many
isolated projects; every non-core capability is opt-in per project; the control plane
spans multiple instances and clouds.

**Status: pre-alpha.** Nothing here is deployable yet.

## What it is

Supabase's own components are the runtime. supapace is the control plane, the gateway and
the provisioning model that turn them into a multi-project platform without running a full
stack per project:

| Capability | Shape |
|---|---|
| Database | one database per project on a shared Postgres cluster, isolated roles and grants |
| REST / GraphQL Data API | PostgREST per project (lazy-started), `pg_graphql` in-database |
| Realtime | one shared multi-tenant Realtime, one tenant row per project |
| Storage | one shared multi-tenant Storage, one tenant row per project |
| Edge Functions | one shared Deno runtime, per-project isolates with per-project limits |
| Dashboard | one patched Studio deployment serving every project |
| Pooler | one shared Supavisor fronting every cluster |
| Auth | **no GoTrue.** Any external OIDC issuer; per-project signing keys and JWKS |

## Non-goals

- **GoTrue is out of scope by design.** supapace consumes RS256 tokens from an external
  OIDC provider and keeps `auth.uid()`, `auth.role()` and `auth.jwt()` working against
  them, so existing row-level security carries over unchanged.
- No billing, no org/team model, no cloud-provider-specific primitives.

## Layout

    cmd/        control plane, node agent, gateway, CLI
    internal/   implementation packages
    migrations/ control-plane schema and per-project bootstrap SQL
    deploy/     container images and compose stacks
    studio/     patch series applied to upstream Studio

## Licence

Apache-2.0. See [LICENSE](LICENSE).
