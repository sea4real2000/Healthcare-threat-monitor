import { timingSafeEqual } from 'node:crypto';
import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { MIN_MASTER_KEY_LENGTH } from '@/lib/signing';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function tokenMatches(given: string | null): boolean {
  const expected = process.env.DIAGNOSE_TOKEN;
  if (!expected || expected.length < 24 || !given) return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(given);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Plain health check for uptime monitors. Add ?diagnose=1 with the diagnose token
 * header to get a fuller report for debugging a deployment. The report says whether
 * each secret is set. It never returns a secret.
 */
export async function GET(req: Request) {
  const url = new URL(req.url);
  const wantsDiagnose = url.searchParams.get('diagnose') === '1';
  if (wantsDiagnose && !tokenMatches(req.headers.get('x-htm-diagnose-token'))) {
    return NextResponse.json({ ok: false, error: 'diagnose_token_required' }, { status: 401 });
  }

  let database = 'down';
  let migrations: string[] = [];
  let detail: Record<string, unknown> = {};
  let dbError: string | null = null;
  try {
    const sql = db();
    migrations = (await sql<{ version: string }[]>`select version from schema_migrations order by version`).map(
      (r) => r.version,
    );
    database = 'up';
    if (wantsDiagnose) {
      const [counts] = await sql`
        select (select count(*)::int from sources where enabled) as sources_enabled,
               (select count(*)::int from settings) as settings_rows,
               (select count(*)::int from copy) as copy_rows,
               (select count(*)::int from collectors where enabled) as collectors_enabled,
               (select count(*)::int from assets) as assets,
               (select count(*)::int from staff) as staff,
               (select count(*)::int from ingest_batches) as batches,
               (select count(*)::int from ingest_rejects) as rejects,
               (select count(*)::int from events) as events,
               (select max(occurred_at) from events) as newest_event,
               (select max(received_at) from ingest_batches) as newest_batch,
               now() as database_time`;
      const rls = await sql<{ name: string }[]>`
        select c.relname as name from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity`;
      detail = { counts, tables_without_row_level_security: rls.map((r) => r.name) };
    }
  } catch (err) {
    dbError = wantsDiagnose ? String((err as Error)?.message ?? err) : 'unreachable';
  }

  const body: Record<string, unknown> = { ok: database === 'up', database, migrations };
  if (dbError) body.database_error = dbError;
  if (wantsDiagnose) {
    body.environment = {
      DATABASE_URL: Boolean(process.env.DATABASE_URL),
      INGEST_SIGNING_KEY: (process.env.INGEST_SIGNING_KEY ?? '').length >= MIN_MASTER_KEY_LENGTH,
      DATABASE_SSL: process.env.DATABASE_SSL ?? 'auto',
      node: process.version,
    };
    Object.assign(body, detail);
  }
  return NextResponse.json(body, {
    status: database === 'up' ? 200 : 503,
    headers: { 'Cache-Control': 'no-store' },
  });
}
