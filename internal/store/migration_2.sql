alter table project drop constraint project_state_check;
alter table project add constraint project_state_check check (state in
  ('provisioning','active','restarting','restoring','deleting','deleted','purged','aborted'));
alter table project add column slot_op bigint;                     -- operation owning the backup slot
alter table operation drop constraint operation_kind_check;
alter table operation add constraint operation_kind_check check (kind in ('create','restart','delete','purge','restore'));
alter table operation drop constraint operation_state_check;
alter table operation add constraint operation_state_check check (state in
  ('pending','running','waiting_job','done','aborting','aborted','failed','superseded'));
alter table operation add column result jsonb;
drop index operation_open;
create index operation_open on operation (ref, id) where state in ('pending','running','waiting_job','aborting');

create table backup_state (
  subject text primary key check (subject ~ '^([a-z0-9]{20}|cp)$'),
  incarnation text not null default '1',              -- a project: "1"; the control plane: its database system identifier, unsigned decimal
  stanza_created boolean not null default false,
  last_push_ok timestamptz, last_repl_ok timestamptz,
  spool_entries integer, spool_bytes bigint, spool_oldest timestamptz,   -- as the last push job reported them
  disk_used_kb bigint, disk_hard_kb bigint, repo_used_kb bigint, repo_hard_kb bigint, quota_at timestamptz, -- the quota report, host-side
  newest_segment text check (newest_segment ~ '^[0-9A-F]{24}$'),
  forced_full_day date,
  budget_day date, bytes_today bigint not null default 0, objects_today integer not null default 0,
  repl_paused_until timestamptz,
  rebuild_epoch bigint not null default 0,
  rebuild_key_marker text not null default '', rebuild_version_marker text not null default '', rebuild_pages integer not null default 0,
  seeded_at timestamptz,
  offsite_purge boolean not null default false
);
create table backup_job (
  id bigserial primary key,
  subject text not null references backup_state(subject),
  lane text not null check (lane in ('push','backup')),
  kind text not null check (kind in ('push','replicate','stanza-create','backup','check','fetch','seed','restore','recover')),
  state text not null check (state in ('queued','running','done','failed')),
  op_id bigint references operation(id), op_step text not null default '',
  params jsonb not null default '{}', result jsonb, code text, message text,
  runs integer not null default 0, deadline_s integer not null check (deadline_s > 0),
  created_at timestamptz not null default now(), started_at timestamptz, finished_at timestamptz
);
create unique index backup_job_slot  on backup_job (subject) where state = 'running';
create index        backup_job_queue on backup_job (lane, id) where state = 'queued';
create index        backup_job_op    on backup_job (op_id, op_step, id) where op_id is not null;
create index        backup_job_done  on backup_job (finished_at) where state in ('done','failed');
create table backup_set (
  subject text not null references backup_state(subject),
  label text not null check (label ~ '^[0-9]{8}-[0-9]{6}F$'),
  tli integer not null check (tli >= 1),
  start_segment text not null, stop_segment text not null, start_lsn pg_lsn not null, stop_lsn pg_lsn not null,
  start_at timestamptz not null, stop_at timestamptz not null,
  job_id bigint not null references backup_job(id),
  replicated boolean not null default false,        -- every file of the set is in offsite_object
  listed_at timestamptz,                            -- a time the uploaded info files listed it
  primary key (subject, label)
);
create table backup_timeline (
  subject text not null references backup_state(subject),
  tli integer not null check (tli >= 1),
  state text not null check (state in ('recorded','pending','abandoned')),
  op_id bigint references operation(id),
  created_at timestamptz not null default now(),
  primary key (subject, tli)
);
create table backup_gap (
  id bigserial primary key, subject text not null references backup_state(subject),
  cause text not null check (cause in ('quarantine','spool-drop')),   -- 'spool-drop' is reserved; nothing writes it yet
  first_segment text not null, last_segment text not null, detail text not null default '',
  at timestamptz not null default now()
);
create table backup_notice (
  subject text not null references backup_state(subject), code text not null,
  count bigint not null default 1, first_at timestamptz not null default now(),
  last_at timestamptz not null default now(), detail text not null default '',
  primary key (subject, code)
);
create table offsite_object (                        -- the uploaded-key record
  subject text not null references backup_state(subject),
  key text not null,                                 -- relative to <prefix>/<subject>/
  size bigint not null, sha256 bytea,                -- null: row rebuilt from a listing
  ino bigint, ctime_ns bigint,                       -- the local file when uploaded; null when rebuilt
  version_id text, uploaded_at timestamptz not null,
  seen_epoch bigint not null default 0,              -- the last epoch whose rebuild listed the key
  primary key (subject, key)
);
create table offsite_info_version (
  subject text not null references backup_state(subject),
  name text not null check (name in ('archive.info','archive.info.copy','backup.info','backup.info.copy')),
  version_id text not null, sha256 bytea not null, uploaded_at timestamptz not null,
  primary key (subject, name, version_id)
);
