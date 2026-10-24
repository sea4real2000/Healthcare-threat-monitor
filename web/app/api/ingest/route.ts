import { NextResponse } from 'next/server';
import { authenticateCollector, deny, readLimitedBody } from '@/lib/auth';
import { ingestRecords } from '@/lib/ingest';
import { numberSetting } from '@/lib/settings';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RUN_ID = /^[A-Za-z0-9_]{1,64}$/;
/**
 * Accepts one signed batch of raw log records, maps each into the common schema
 * and stores it. Sending the same batch twice changes nothing the second time.
 */
export async function POST(req: Request) {
  try {
    const read = await readLimitedBody(req);
    if (!read.ok) return read.response;
    const auth = await authenticateCollector(req, read.body);
    if (!auth.ok) return auth.response;

    let parsed: { batch_id?: unknown; run_id?: unknown; records?: unknown };
    try {
      parsed = JSON.parse(read.body);
    } catch {
      return deny(400, 'body_not_json');
    }
    if (typeof parsed?.batch_id !== 'string' || !UUID.test(parsed.batch_id)) return deny(400, 'bad_batch_id');
    if (parsed.run_id != null && (typeof parsed.run_id !== 'string' || !RUN_ID.test(parsed.run_id))) {
      return deny(400, 'bad_run_id');
    }
    if (!Array.isArray(parsed.records) || parsed.records.length === 0) return deny(400, 'records_missing');
    const maxRecords = await numberSetting('ingest.max_batch_records');
    if (parsed.records.length > maxRecords) return deny(413, 'too_many_records');

    const batchId = parsed.batch_id.toLowerCase();
    const runId = (parsed.run_id as string | undefined) ?? null;
    const total = parsed.records.length;
    const outcome = await ingestRecords(auth.collectorId, batchId, runId, parsed.records);

    return NextResponse.json(
      {
        ok: true,
        batch_id: batchId,
        replayed: outcome.replayed,
        records: total,
        accepted: outcome.accepted,
        duplicate: outcome.duplicate,
        rejected: outcome.rejected,
        rejects: outcome.rejects.slice(0, 20).map((r) => ({ index: r.record_index, source: r.source, reason: r.reason })),
      },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch (err) {
    console.error('[ingest] failed', err);
    return deny(500, 'internal_error');
  }
}
