-- 0001_core.sql
-- Core tables for batch 1: configuration, inventory, collectors, ingestion and events.
-- Safe to run more than once.

create table if not exists schema_migrations (
  version text primary key,
  applied_at timestamptz not null default now()
);

-- Editable configuration. Nothing the console shows or the API enforces is fixed in code.
create table if not exists settings (
  key text primary key,
  value jsonb not null,
  description text,
  updated_at timestamptz not null default now()
);

-- Every label and line of copy in the console.
create table if not exists copy (
  key text primary key,
  value text not null,
  updated_at timestamptz not null default now()
);

-- The log sources the platform accepts.
create table if not exists sources (
  id text primary key,
  label text not null,
  description text,
  sort_order integer not null default 0,
  enabled boolean not null default true
);

create table if not exists departments (
  id text primary key,
  name text not null,
  zone text not null
);

create table if not exists staff (
  id text primary key,
  display_name text not null,
  role text not null,
  department_id text references departments (id),
  status text not null default 'active' check (status in ('active', 'terminated')),
  updated_at timestamptz not null default now()
);

create table if not exists assets (
  id text primary key,
  kind text not null check (kind in ('workstation', 'server', 'medical_device', 'network')),
  role text not null,
  os text,
  ip inet,
  department_id text references departments (id),
  zone text not null,
  status text not null default 'active' check (status in ('active', 'isolated', 'offline')),
  last_seen_at timestamptz,
  attributes jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
create index if not exists assets_ip_idx on assets (ip);
create index if not exists assets_kind_idx on assets (kind);

-- Registered collectors. Signing secrets are derived from a server side key and are never stored here.
create table if not exists collectors (
  id text primary key,
  name text not null,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz
);

-- One row per accepted batch. The unique pair makes a replayed batch harmless.
create table if not exists ingest_batches (
  id bigint generated always as identity primary key,
  collector_id text not null references collectors (id),
  batch_id uuid not null,
  run_id text,
  received_at timestamptz not null default now(),
  records integer not null default 0,
  accepted integer not null default 0,
  duplicate integer not null default 0,
  rejected integer not null default 0,
  unique (collector_id, batch_id)
);
create index if not exists ingest_batches_run_idx on ingest_batches (run_id);

-- Records that failed normalization, kept for diagnosis.
create table if not exists ingest_rejects (
  id bigint generated always as identity primary key,
  batch_pk bigint not null references ingest_batches (id) on delete cascade,
  record_index integer not null,
  source text,
  reason text not null,
  raw jsonb,
  received_at timestamptz not null default now()
);
create index if not exists ingest_rejects_received_idx on ingest_rejects (received_at desc);

-- The common event schema. Every source is normalized into this shape.
create table if not exists events (
  id bigint generated always as identity primary key,
  batch_pk bigint not null references ingest_batches (id),
  source text not null references sources (id),
  source_event_id text not null,
  occurred_at timestamptz not null,
  ingested_at timestamptz not null default now(),
  category text not null,
  action text not null,
  outcome text not null default 'unknown' check (outcome in ('success', 'failure', 'unknown')),
  severity smallint not null default 0 check (severity between 0 and 3),
  actor_user text,
  host text,
  src_ip inet,
  dst_ip inet,
  dst_port integer,
  protocol text,
  patient_ref text,
  bytes_out bigint,
  bytes_in bigint,
  attributes jsonb not null default '{}'::jsonb,
  raw jsonb not null,
  unique (source, source_event_id)
);
create index if not exists events_occurred_idx on events (occurred_at desc);
create index if not exists events_source_occurred_idx on events (source, occurred_at desc);
create index if not exists events_host_occurred_idx on events (host, occurred_at desc);
create index if not exists events_actor_occurred_idx on events (actor_user, occurred_at desc);
create index if not exists events_patient_occurred_idx on events (patient_ref, occurred_at desc) where patient_ref is not null;
create index if not exists events_batch_idx on events (batch_pk);

insert into schema_migrations (version) values ('0001_core') on conflict do nothing;
