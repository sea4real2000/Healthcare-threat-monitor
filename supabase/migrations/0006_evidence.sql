-- 0006_evidence.sql
-- Evidence: evaluation runs and the compliance mapping.
-- Safe to run more than once.

-- One row per run of the evaluation harness, with the measured results.
create table if not exists evaluation_runs (
  id bigint generated always as identity primary key,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  status text not null default 'running' check (status in ('running', 'completed', 'failed')),
  config jsonb not null default '{}'::jsonb,
  metrics jsonb,
  report_markdown text
);

-- How platform functions map to published safeguards. Rows are editable.
create table if not exists compliance_controls (
  id text primary key,
  framework text not null check (framework in ('hipaa', 'nist_csf', 'hhs_405d')),
  citation text not null,
  title text not null,
  contribution text not null,
  evidence_key text,
  url text,
  sort_order integer not null default 0
);

select htm_lockdown();

insert into schema_migrations (version) values ('0006_evidence') on conflict do nothing;
