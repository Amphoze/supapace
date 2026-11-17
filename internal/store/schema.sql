create table cp_meta (
  singleton  boolean primary key default true check (singleton),
  epoch      bigint  not null,            -- 1 at first Migrate; bumped by every restore of this database
  schema_ver integer not null
);
create table node (
  id text primary key, project_block cidr not null, slice_prefix integer not null,
  uid_base integer not null, uid_count integer not null,
  next_uid integer not null,                 -- monotonic; advanced in the placement transaction; never decreases
  mem_alloc_mb integer not null, pids_alloc integer not null
);
create table project (
  ref          text primary key check (ref ~ '^[a-z0-9]{20}$'),   -- the row is the tombstone: never deleted
  name         text not null,
  node_id      text not null references node(id),
  state        text not null check (state in
                 ('provisioning','active','restarting','deleting','deleted','purged','aborted')),
  epoch        bigint not null,
  generation   bigint not null default 1,     -- desired
  applied_gen  bigint not null default 0,     -- reported by the agent
  uid          integer,                       -- = gid; set at placement, then kept forever (retired, never reused)
  subnet_index integer,                       -- NULL until placed, and again once purged or aborted
  mem_mb       integer not null, pids integer not null,            -- admission inputs, set by CreateProject:
                                                                    -- mem_mb = config.mem_mb + 256, pids = 512 + 64
  config       jsonb  not null default '{}',  -- store.ProjectConfig: {"disk_quota_mb":8192,"mem_mb":512,"guc":{...}}
  user_roles   text[] not null default '{authenticated}',
  created_at   timestamptz not null default now(),
  deleted_at   timestamptz, purge_after timestamptz
);
create unique index project_uid   on project (node_id, uid)          where uid is not null;
create unique index project_slice on project (node_id, subnet_index) where subnet_index is not null;
create table operation (
  id         bigserial primary key,
  ref        text not null references project(ref),
  kind       text not null check (kind in ('create','restart','delete','purge')),
  state      text not null check (state in ('pending','running','done','aborting','aborted','failed')),
  step       text not null default '',      -- last step COMPLETED (empty = none); the saga's step ids
  attempts   integer not null default 0,
  params     jsonb not null default '{}',
  epoch      bigint not null, generation bigint not null,
  not_before timestamptz not null default now(),
  last_error text,                           -- "<code>: <message>"; the admin API's error codes
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create index operation_open on operation (ref, id) where state in ('pending','running','aborting');
create table project_dek (
  ref text primary key references project(ref), kek_id text not null,
  nonce bytea, wrapped bytea, destroyed_at timestamptz,
  check ((wrapped is null) = (destroyed_at is not null)),
  check ((wrapped is null) = (nonce is null))
);
create table secret (
  ref text not null references project(ref), name text not null,
  nonce bytea not null, ciphertext bytea not null, created_at timestamptz not null default now(),
  primary key (ref, name)
);
create table project_key (
  ref text not null references project(ref), kid text not null,
  class text not null check (class in ('anon','service_role','issuer')),
  jwk jsonb not null, created_at timestamptz not null default now(),
  primary key (ref, kid)                     -- two projects may trust one issuer key
);
