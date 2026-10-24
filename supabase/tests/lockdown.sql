-- Proves that a visitor role can read nothing and write nothing.
-- Run with: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/lockdown.sql
-- The script raises an exception, and psql exits with an error, on the first leak.

do $$
declare
  t record;
  r text;
  leaks text := '';
  n bigint;
begin
  foreach r in array array['anon', 'authenticated'] loop
    if not exists (select 1 from pg_roles where rolname = r) then
      raise exception 'role % does not exist, cannot run the lockdown test', r;
    end if;
    for t in
      select c.relname as name, c.relrowsecurity as rls
      from pg_class c join pg_namespace ns on ns.oid = c.relnamespace
      where ns.nspname = 'public' and c.relkind in ('r', 'p')
    loop
      if not t.rls then
        leaks := leaks || format('[%s has row level security off] ', t.name);
      end if;

      execute format('set local role %I', r);
      begin
        execute format('select count(*) from public.%I', t.name) into n;
        if n > 0 then
          leaks := leaks || format('[%s can read %s rows from %s] ', r, n, t.name);
        end if;
      exception when insufficient_privilege then null;
      end;
      begin
        execute format('delete from public.%I', t.name);
        get diagnostics n = row_count;
        if n > 0 then
          leaks := leaks || format('[%s can delete from %s] ', r, t.name);
        end if;
      exception when insufficient_privilege then null;
      end;
      begin
        execute format('insert into public.%I default values', t.name);
        leaks := leaks || format('[%s can insert into %s] ', r, t.name);
      exception
        when insufficient_privilege then null;
        when others then
          -- Any other error means the insert got past the permission check.
          leaks := leaks || format('[%s passed the permission check on %s] ', r, t.name);
      end;
      reset role;
    end loop;
  end loop;

  if leaks <> '' then
    raise exception 'LOCKDOWN FAILED: %', leaks;
  end if;
  raise notice 'LOCKDOWN OK: visitor roles can read and write nothing';
end;
$$;
