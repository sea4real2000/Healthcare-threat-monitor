-- 0002_lockdown.sql
-- Default deny. Row level security is switched on for every table and the public
-- Supabase roles lose all table privileges. The console and the APIs reach the
-- database on the server only, so a visitor holding the public key can read nothing
-- and write nothing. Policies for signed in analysts arrive with the sign in batch.
--
-- Call htm_lockdown() at the end of every later migration so new tables are covered.

create or replace function htm_lockdown() returns integer
language plpgsql
as $$
declare
  t record;
  r text;
  n integer := 0;
begin
  for t in
    select c.oid::regclass as tbl
    from pg_class c
    join pg_namespace ns on ns.oid = c.relnamespace
    where ns.nspname = 'public' and c.relkind in ('r', 'p')
  loop
    execute format('alter table %s enable row level security', t.tbl);
    foreach r in array array['anon', 'authenticated'] loop
      if exists (select 1 from pg_roles where rolname = r) then
        execute format('revoke all on table %s from %I', t.tbl, r);
      end if;
    end loop;
    n := n + 1;
  end loop;

  foreach r in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke all on all sequences in schema public from %I', r);
      execute format('revoke execute on function htm_lockdown() from %I', r);
    end if;
  end loop;
  revoke execute on function htm_lockdown() from public;
  return n;
end;
$$;

select htm_lockdown();

insert into schema_migrations (version) values ('0002_lockdown') on conflict do nothing;
