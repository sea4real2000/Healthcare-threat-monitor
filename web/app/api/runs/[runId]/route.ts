import { NextResponse } from 'next/server';
import { authenticateCollector, deny } from '@/lib/auth';
import { db } from '@/lib/db';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Reports what the database actually holds for one simulator run, per source.
 * The simulator compares this with its own ledger of what it emitted.
 */
export async function GET(req: Request, ctx: { params: Promise<{ runId: string }> }) {
  try {
    const auth = await authenticateCollector(req, '');
    if (!auth.ok) return auth.response;
    const { runId } = await ctx.params;
    if (!/^[A-Za-z0-9_]{1,64}$/.test(runId)) return deny(400, 'bad_run_id');

    const sql = db();
    const [batches] = await sql<{ batches: number; records: number; accepted: number; duplicate: number; rejected: number }[]>`
      select count(*)::int as batches, coalesce(sum(records), 0)::int as records,
             coalesce(sum(accepted), 0)::int as accepted, coalesce(sum(duplicate), 0)::int as duplicate,
             coalesce(sum(rejected), 0)::int as rejected
      from ingest_batches where run_id = ${runId} and collector_id = ${auth.collectorId}`;
    const perSource = await sql<{ source: string; stored: number }[]>`
      select e.source, count(*)::int as stored
      from events e join ingest_batches b on b.id = e.batch_pk
      where b.run_id = ${runId} and b.collector_id = ${auth.collectorId}
      group by e.source order by e.source`;

    return NextResponse.json(
      {
        ok: true,
        run_id: runId,
        ...batches,
        stored: Object.fromEntries(perSource.map((r) => [r.source, r.stored])),
        stored_total: perSource.reduce((sum, r) => sum + r.stored, 0),
      },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch (err) {
    console.error('[runs] failed', err);
    return deny(500, 'internal_error');
  }
}
