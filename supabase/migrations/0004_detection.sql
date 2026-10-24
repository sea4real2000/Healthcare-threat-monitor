-- 0004_detection.sql
-- Detection: patients, ground truth for scenarios, rules, baselines, models, alerts and incidents.
-- Safe to run more than once.

-- Synthetic patients. The department is the care relationship the record access model uses.
create table if not exists patients (
  ref text primary key,
  department_id text references departments (id),
  flag text check (flag in ('vip', 'staff')),
  updated_at timestamptz not null default now()
);

-- A scripted attack run. Launched from the console or by the evaluation harness.
create table if not exists scenario_runs (
  id bigint generated always as identity primary key,
  scenario text not null,
  status text not null default 'requested' check (status in ('requested', 'running', 'completed', 'contained', 'failed')),
  requested_by text,
  requested_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz,
  first_event_at timestamptz,
  last_event_at timestamptz,
  target jsonb not null default '{}'::jsonb,
  evaluation_run_id bigint,
  note text
);
create index if not exists scenario_runs_status_idx on scenario_runs (status);

-- Which events an attack scenario produced. Detection code never reads this table.
-- It exists only so results can be scored afterwards.
create table if not exists ground_truth (
  source text not null,
  source_event_id text not null,
  scenario_run_id bigint not null references scenario_runs (id) on delete cascade,
  stage text not null,
  primary key (source, source_event_id)
);
create index if not exists ground_truth_run_idx on ground_truth (scenario_run_id);

-- Detection rules are data. An analyst can add, edit or switch one off from the console.
create table if not exists rules (
  id text primary key,
  name text not null,
  description text not null,
  category text not null check (category in ('ransomware', 'access', 'records', 'network', 'devices')),
  kind text not null check (kind in ('match', 'threshold', 'new_value')),
  definition jsonb not null,
  severity smallint not null check (severity between 1 and 3),
  confidence numeric(4, 3) not null check (confidence > 0 and confidence < 1),
  technique_id text,
  technique_name text,
  enabled boolean not null default true,
  load_error text,
  updated_at timestamptz not null default now(),
  updated_by text
);

-- Values each entity is known to use, such as the hosts a medical device normally talks to.
create table if not exists baseline_values (
  scope text not null,
  entity text not null,
  value text not null,
  origin text not null default 'training' check (origin in ('training', 'feedback')),
  first_seen timestamptz not null default now(),
  primary key (scope, entity, value)
);

-- What analyst feedback has taught a detector about one entity.
create table if not exists detector_exceptions (
  id bigint generated always as identity primary key,
  detector_type text not null check (detector_type in ('rule', 'model')),
  detector_id text not null,
  entity text not null,
  kind text not null check (kind in ('suppress', 'threshold')),
  value numeric,
  reason text,
  source_incident bigint,
  created_by text,
  created_at timestamptz not null default now(),
  unique (detector_type, detector_id, entity, kind)
);

create table if not exists models (
  id text primary key,
  name text not null,
  description text not null,
  entity_label text not null,
  window_seconds integer not null,
  features jsonb not null default '[]'::jsonb,
  enabled boolean not null default true,
  version integer not null default 0,
  trained_at timestamptz,
  training_from timestamptz,
  training_to timestamptz,
  training_rows integer,
  threshold numeric,
  score_summary jsonb,
  feature_stats jsonb
);

-- Windows an analyst has ruled on. Confirmed attacks are kept out of training.
-- Windows dismissed as normal are kept, with their features, and weigh heavily in every later training run.
create table if not exists model_training_labels (
  model_id text not null references models (id) on delete cascade,
  entity text not null,
  window_start timestamptz not null,
  label text not null check (label in ('normal', 'attack')),
  features jsonb,
  source_incident bigint,
  created_at timestamptz not null default now(),
  primary key (model_id, entity, window_start)
);

create table if not exists incidents (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  opened_at timestamptz not null,
  last_activity_at timestamptz not null,
  category text not null,
  title text not null,
  status text not null default 'open' check (status in ('open', 'confirmed', 'dismissed')),
  band text not null check (band in ('low', 'medium', 'high')),
  confidence numeric(5, 4) not null,
  severity smallint not null,
  primary_host text,
  primary_user text,
  hosts text[] not null default '{}',
  users text[] not null default '{}',
  sources text[] not null default '{}',
  detectors text[] not null default '{}',
  techniques text[] not null default '{}',
  alert_count integer not null default 0,
  medium_at timestamptz,
  high_at timestamptz,
  decided_by uuid,
  decided_by_name text,
  decided_at timestamptz,
  decision_reason text,
  decision_note text
);
create index if not exists incidents_status_idx on incidents (status, band, last_activity_at desc);
create index if not exists incidents_opened_idx on incidents (opened_at desc);

create table if not exists incident_entities (
  incident_id bigint not null references incidents (id) on delete cascade,
  entity_type text not null check (entity_type in ('host', 'user')),
  entity_value text not null,
  primary key (incident_id, entity_type, entity_value)
);
create index if not exists incident_entities_lookup_idx on incident_entities (entity_type, entity_value);

create table if not exists alerts (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  occurred_at timestamptz not null,
  last_seen_at timestamptz not null,
  detector_type text not null check (detector_type in ('rule', 'model')),
  detector_id text not null,
  category text not null,
  title text not null,
  severity smallint not null,
  confidence numeric(5, 4) not null,
  host text,
  actor_user text,
  entity text not null,
  sources text[] not null default '{}',
  technique_id text,
  technique_name text,
  hits integer not null default 1,
  observed numeric,
  score numeric,
  window_start timestamptz,
  evidence jsonb not null default '[]'::jsonb,
  explanation jsonb not null default '[]'::jsonb,
  baseline jsonb,
  suppressed boolean not null default false,
  incident_id bigint references incidents (id) on delete set null,
  dedupe_key text not null unique
);
create index if not exists alerts_incident_idx on alerts (incident_id);
create index if not exists alerts_detector_idx on alerts (detector_type, detector_id, occurred_at desc);
create index if not exists alerts_occurred_idx on alerts (occurred_at desc);

-- Small pieces of state the detection service keeps between runs, such as its place in the event stream.
create table if not exists engine_state (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz not null default now()
);

select htm_lockdown();

insert into schema_migrations (version) values ('0004_detection') on conflict do nothing;
