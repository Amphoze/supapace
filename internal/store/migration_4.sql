alter table operation drop constraint operation_kind_check;
alter table operation add constraint operation_kind_check check (kind in
  ('create','restart','delete','purge','restore','settings','rekey-login'));
alter table backup_job drop constraint backup_job_kind_check;
alter table backup_job add constraint backup_job_kind_check check (kind in
  ('push','replicate','stanza-create','backup','check','fetch','seed','restore','recover',
   'expire','verify','drop-spool','offsite-expire'));
create sequence backup_job_launch;                                       -- the order in which jobs went running
alter table backup_job add column launch bigint;                         -- null: launched before this migration; orders before every number
alter table offsite_object add column launch bigint not null default 0;  -- the launch of the job that recorded the row; existing rows: 0
alter table offsite_object alter column launch drop default;             -- from here an insert without the number fails
alter table backup_timeline add column launch bigint not null default 0; -- drawn when a restore's timeline is recorded
alter table backup_timeline alter column launch drop default;
update backup_timeline set launch = nextval('backup_job_launch') where state = 'recorded' and tli > 1;
alter table backup_timeline add constraint backup_timeline_launch_check
  check (state <> 'recorded' or tli = 1 or launch > 0);                  -- a restore's timeline cannot become recorded without its number
alter table node add column conn_alloc integer not null default 2128,
                 add column desc_alloc bigint  not null default 536870912,
                 add column pass_at timestamptz, add column clock_hold_until timestamptz;
alter table project add column conns integer not null default 72,         -- the project's share of the proxy's connections
                    add column settings jsonb not null default '{}',     -- store.ProjectSettings
                    add column read_only_since timestamptz,
                    add column rekey_pending jsonb not null default '[]'; -- [{"login","since"}]
update project set conns = greatest(coalesce((config->'guc'->>'max_connections')::integer, 120) - 50, 0) + 2;
alter table backup_state add column full_due boolean not null default false,
  add column last_check_ok timestamptz, add column last_verify_at timestamptz, add column verify_ok boolean,
  add column last_expire_at timestamptz, add column last_offsite_expire_at timestamptz,
  add column spool_dropped_at timestamptz, add column canary_at timestamptz, add column deadman_at timestamptz,
  add column offsite_purge_seen_at timestamptz;                           -- the pass that first saw offsite_purge
alter table backup_set add column expired_local_at timestamptz, add column offsite_removed_at timestamptz;
alter table backup_notice add column sent_count bigint not null default 0, add column sent_at timestamptz;
create table restore_point (
  ref text not null references project(ref), name text not null check (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  lsn pg_lsn not null, tli integer not null, created_at timestamptz not null default now(),
  primary key (ref, name));
create table alert (
  subject text not null check (subject ~ '^([a-z0-9]{20}|cp|node)$'), code text not null,
  severity text not null check (severity in ('warn','page')),
  count bigint not null default 1, first_at timestamptz not null default now(),
  last_at timestamptz not null default now(), figures jsonb not null default '{}',   -- numbers only
  open boolean not null default true, sent_count bigint not null default 0, sent_at timestamptz,
  primary key (subject, code));
create table issuance (
  id bigserial primary key, ref text not null references project(ref),
  login text not null, role text not null, asked_by text not null, at timestamptz not null default now());
