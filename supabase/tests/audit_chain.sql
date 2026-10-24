-- Proves the audit log is append only and that tampering is detected.
-- Run with: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase/tests/audit_chain.sql
-- Everything happens inside one transaction that is rolled back, so the log is left as it was.

begin;

do $$
declare
  v record;
  first_new bigint;
  refused boolean;
begin
  select * into v from audit_verify();
  if not v.ok then
    raise exception 'AUDIT TEST: the chain is already broken at entry %: %', v.broken_seq, v.reason;
  end if;

  first_new := audit_append('system', 'test', 'Audit test', 'test.one', 'test', '1', '{"n": 1}'::jsonb);
  perform audit_append('user', 'u1', 'Name | with: odd, characters', 'test.two', 'test', '2', '{"note": "a|b:c"}'::jsonb);
  perform audit_append('system', 'test', 'Audit test', 'test.three', 'test', '3', null);
  select * into v from audit_verify();
  if not v.ok then raise exception 'AUDIT TEST: chain broken after appending'; end if;

  -- 1. Changes and deletions are refused outright.
  refused := false;
  begin
    update audit_log set action = 'test.changed' where seq = first_new;
  exception when others then refused := true;
  end;
  if not refused then raise exception 'AUDIT TEST: an update was allowed'; end if;
  refused := false;
  begin
    delete from audit_log where seq = first_new;
  exception when others then refused := true;
  end;
  if not refused then raise exception 'AUDIT TEST: a delete was allowed'; end if;

  -- 2. If someone with full database rights removes the guard and edits an entry, the chain shows it.
  alter table audit_log disable trigger audit_log_no_change;
  update audit_log set detail_text = '{"n": 2}' where seq = first_new;
  select * into v from audit_verify();
  if v.ok or v.broken_seq <> first_new then raise exception 'AUDIT TEST: a changed entry was not detected'; end if;
  update audit_log set detail_text = '{"n": 1}' where seq = first_new;

  -- 3. Removing an entry from the middle is detected too.
  delete from audit_log where seq = first_new + 1;
  select * into v from audit_verify();
  if v.ok or v.broken_seq <> first_new + 1 then raise exception 'AUDIT TEST: a removed entry was not detected'; end if;
  alter table audit_log enable trigger audit_log_no_change;

  raise notice 'AUDIT CHAIN OK: changes are refused, and a changed or removed entry is detected';
end;
$$;

rollback;
