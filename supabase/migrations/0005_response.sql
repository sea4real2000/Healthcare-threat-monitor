-- 0005_response.sql
-- Response: accounts and sessions, analyst feedback, response actions, forwarding, and the audit log.
-- Safe to run more than once.

-- Analyst and administrator accounts. Visitors need no account and can change nothing.
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique check (email = lower(email)),
  display_name text not null,
  role text not null check (role in ('analyst', 'admin')),
  status text not null default 'invited' check (status in ('invited', 'active', 'disabled')),
  password_hash text,
  totp_secret text,
  totp_last_step bigint not null default 0,
  setup_token_hash text,
  setup_expires_at timestamptz,
  failed_logins integer not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now(),
  created_by text,
  last_login_at timestamptz
);

-- Only a hash of the session token is stored, so a copy of this table cannot be used to sign in.
create table if not exists sessions (
  token_hash text primary key,
  user_id uuid not null references users (id) on delete cascade,
  mfa_passed boolean not null default false,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  expires_at timestamptz not null,
  ip text,
  user_agent text
);
create index if not exists sessions_user_idx on sessions (user_id);

create table if not exists rate_limits (
  bucket text not null,
  window_start timestamptz not null,
  hits integer not null default 0,
  primary key (bucket, window_start)
);

-- What an analyst decided about an incident, and whether the detectors have learned from it yet.
create table if not exists feedback (
  id bigint generated always as identity primary key,
  incident_id bigint not null references incidents (id) on delete cascade,
  verdict text not null check (verdict in ('true_positive', 'false_positive')),
  reason text not null,
  note text,
  created_by uuid,
  created_by_name text,
  created_at timestamptz not null default now(),
  applied_at timestamptz,
  applied jsonb
);
create index if not exists feedback_pending_idx on feedback (id) where applied_at is null;

-- Isolation and release requests. A connector for a real endpoint product reads and acknowledges these.
create table if not exists response_actions (
  id bigint generated always as identity primary key,
  incident_id bigint references incidents (id) on delete set null,
  asset_id text not null references assets (id),
  action text not null check (action in ('isolate', 'release')),
  status text not null default 'requested' check (status in ('requested', 'acknowledged', 'failed')),
  requested_by uuid,
  requested_by_name text not null,
  requested_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  connector text,
  note text
);
create index if not exists response_actions_status_idx on response_actions (status, id);

-- Messages waiting to be forwarded to a SIEM or SOC.
create table if not exists siem_outbox (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  incident_id bigint,
  event_type text not null,
  snapshot jsonb not null,
  status text not null default 'pending' check (status in ('pending', 'sent', 'failed')),
  attempts integer not null default 0,
  sent_at timestamptz,
  webhook_result text,
  syslog_result text,
  last_error text
);
create index if not exists siem_outbox_pending_idx on siem_outbox (id) where status = 'pending';

-- The built in receiver, so a visitor can watch forwarded messages arrive.
create table if not exists siem_inbox (
  id bigint generated always as identity primary key,
  received_at timestamptz not null default now(),
  signature_ok boolean not null,
  event_type text,
  incident_id bigint,
  payload jsonb not null,
  cef text
);
create index if not exists siem_inbox_received_idx on siem_inbox (received_at desc);

create or replace function siem_enqueue(p_incident bigint, p_event text, p_extra jsonb default '{}'::jsonb)
returns void language sql as $$
  insert into siem_outbox (incident_id, event_type, snapshot)
  select i.id, p_event, to_jsonb(i) || coalesce(p_extra, '{}'::jsonb) from incidents i where i.id = p_incident;
$$;

-- The audit log. Each entry stores the hash of the entry before it, so changing or
-- removing any past entry breaks the chain from that point on.
create table if not exists audit_log (
  seq bigint primary key,
  at timestamptz not null,
  at_text text not null,
  actor_type text not null check (actor_type in ('system', 'user', 'connector')),
  actor_id text not null,
  actor_name text not null,
  action text not null,
  subject_type text not null,
  subject_id text not null,
  detail_text text not null,
  prev_hash text not null,
  hash text not null
);
create index if not exists audit_log_subject_idx on audit_log (subject_type, subject_id);
create index if not exists audit_log_action_idx on audit_log (action, seq desc);

-- The exact text that is hashed. Each field is written as its length, a colon, then the field,
-- so no choice of field contents can make two different entries produce the same text.
create or replace function audit_canonical(variadic parts text[]) returns text
language sql immutable as $$
  select string_agg(char_length(p)::text || ':' || p, '|' order by ord) from unnest(parts) with ordinality as t(p, ord);
$$;

create or replace function audit_append(
  p_actor_type text, p_actor_id text, p_actor_name text, p_action text,
  p_subject_type text, p_subject_id text, p_detail jsonb
) returns bigint language plpgsql as $$
declare
  v_seq bigint;
  v_prev text;
  v_at timestamptz := clock_timestamp();
  v_at_text text;
  v_detail text := coalesce(p_detail, '{}'::jsonb)::text;
  v_hash text;
begin
  -- One writer at a time, so two entries can never claim the same place in the chain.
  perform pg_advisory_xact_lock(88442211);
  select seq, hash into v_seq, v_prev from audit_log order by seq desc limit 1;
  v_seq := coalesce(v_seq, 0) + 1;
  v_prev := coalesce(v_prev, repeat('0', 64));
  v_at_text := to_char(v_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
  v_hash := encode(sha256(convert_to(audit_canonical(
    v_prev, v_seq::text, v_at_text, p_actor_type, coalesce(p_actor_id, ''), coalesce(p_actor_name, ''),
    p_action, coalesce(p_subject_type, ''), coalesce(p_subject_id, ''), v_detail), 'UTF8')), 'hex');
  insert into audit_log (seq, at, at_text, actor_type, actor_id, actor_name, action, subject_type, subject_id, detail_text, prev_hash, hash)
  values (v_seq, v_at, v_at_text, p_actor_type, coalesce(p_actor_id, ''), coalesce(p_actor_name, ''), p_action,
          coalesce(p_subject_type, ''), coalesce(p_subject_id, ''), v_detail, v_prev, v_hash);
  return v_seq;
end;
$$;

-- Walks the whole chain. Returns the first entry that does not check out, if any.
create or replace function audit_verify()
returns table (ok boolean, entries bigint, broken_seq bigint, reason text, head_hash text)
language plpgsql as $$
declare
  r record;
  v_prev text := repeat('0', 64);
  v_expect bigint := 1;
  v_count bigint := 0;
  v_hash text;
begin
  for r in select * from audit_log order by seq loop
    if r.seq <> v_expect then
      return query select false, v_count, v_expect, 'entry missing'::text, v_prev; return;
    end if;
    if r.prev_hash <> v_prev then
      return query select false, v_count, r.seq, 'link to previous entry broken'::text, v_prev; return;
    end if;
    v_hash := encode(sha256(convert_to(audit_canonical(
      r.prev_hash, r.seq::text, r.at_text, r.actor_type, r.actor_id, r.actor_name,
      r.action, r.subject_type, r.subject_id, r.detail_text), 'UTF8')), 'hex');
    if v_hash <> r.hash then
      return query select false, v_count, r.seq, 'entry contents changed'::text, v_prev; return;
    end if;
    v_prev := r.hash;
    v_expect := r.seq + 1;
    v_count := v_count + 1;
  end loop;
  return query select true, v_count, null::bigint, null::text, v_prev;
end;
$$;

-- The chain detects tampering. This trigger refuses it in the first place.
create or replace function audit_log_immutable() returns trigger language plpgsql as $$
begin
  raise exception 'the audit log is append only';
end;
$$;

drop trigger if exists audit_log_no_change on audit_log;
create trigger audit_log_no_change before update or delete on audit_log
  for each row execute function audit_log_immutable();
drop trigger if exists audit_log_no_truncate on audit_log;
create trigger audit_log_no_truncate before truncate on audit_log
  for each statement execute function audit_log_immutable();

do $$
declare r text;
begin
  foreach r in array array['anon', 'authenticated', 'public'] loop
    if r = 'public' or exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke execute on function audit_append(text, text, text, text, text, text, jsonb) from %s', r);
      execute format('revoke execute on function audit_verify() from %s', r);
      execute format('revoke execute on function siem_enqueue(bigint, text, jsonb) from %s', r);
    end if;
  end loop;
end;
$$;

select htm_lockdown();

insert into schema_migrations (version) values ('0005_response') on conflict do nothing;
