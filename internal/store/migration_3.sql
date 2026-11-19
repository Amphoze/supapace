create table member (
  ref text not null references project(ref),
  issuer  text not null check (length(issuer)  between 1 and 255),
  subject text not null check (length(subject) between 1 and 255),
  role text not null check (role in ('owner','developer','read_only')),
  added_at timestamptz not null default now(),
  primary key (ref, issuer, subject)
);
create index member_principal on member (issuer, subject);
create table principal_revocation (
  issuer text not null, subject text not null, not_before timestamptz not null,
  primary key (issuer, subject)
);
create table dashboard_issuer (
  singleton boolean primary key default true check (singleton),
  issuer text not null, client_id text not null, authorize_url text not null,
  end_session_url text not null default '',
  session_seconds integer not null default 28800 check (session_seconds between 300 and 28800),
  jwks jsonb not null, updated_at timestamptz not null default now()
);
create table slice_hold (
  node_id text not null references node(id),
  subnet_index integer not null check (subnet_index >= 0),
  free_after timestamptz not null,
  primary key (node_id, subnet_index)
);
create table readonly_cleanup (
  ref text primary key references project(ref),
  due timestamptz not null,
  due_fixed boolean not null default false,
  next_try timestamptz not null default now(),
  failures integer not null default 0
);
