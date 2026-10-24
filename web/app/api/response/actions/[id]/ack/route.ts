import { NextResponse } from 'next/server';
import { authenticateCollector, deny, readLimitedBody } from '@/lib/auth';
import { db } from '@/lib/db';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * A connector reports that it has carried out an isolation or release.
 * Only now does the asset change status, and the action lands in the audit log.
 */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  try {
    const read = await readLimitedBody(req);
    if (!read.ok) return read.response;
    const auth = await authenticateCollector(req, read.body);
    if (!auth.ok) return auth.response;
    // Carrying out an isolation is a privilege. A collector that only sends logs does not have it.
    if (!auth.canRespond) return deny(403, 'collector_may_not_respond');
    const { id } = await ctx.params;
    if (!/^\d{1,18}$/.test(id)) return deny(400, 'bad_action_id');
    let parsed: { status?: unknown; note?: unknown };
    try {
      parsed = JSON.parse(read.body);
    } catch {
      return deny(400, 'body_not_json');
    }
    const status = parsed.status === 'failed' ? 'failed' : parsed.status === 'acknowledged' ? 'acknowledged' : null;
    if (!status) return deny(400, 'bad_status');
    const note = typeof parsed.note === 'string' ? parsed.note.slice(0, 200) : null;

    const sql = db();
    const result = await sql.begin(async (tx) => {
      const rows = await tx<{ action: string; asset_id: string; incident_id: string | null }[]>`
        update response_actions set status = ${status}, acknowledged_at = now(), connector = ${auth.collectorId}, note = ${note}
        where id = ${id}::bigint and status = 'requested'
        returning action, asset_id, incident_id::text`;
      if (rows.length === 0) return null;
      const action = rows[0];
      const [collector] = await tx<{ name: string }[]>`select name from collectors where id = ${auth.collectorId}`;
      if (status === 'acknowledged') {
        const next = action.action === 'isolate' ? 'isolated' : 'active';
        await tx`update assets set status = ${next}, updated_at = now() where id = ${action.asset_id}`;
        const event = action.action === 'isolate' ? 'asset_isolated' : 'asset_released';
        if (action.incident_id) {
          await tx`select siem_enqueue(${action.incident_id}::bigint, ${event}, ${tx.json({ asset: { id: action.asset_id, status: next } })}::jsonb)`;
        }
      }
      const auditAction = status === 'failed' ? `asset.${action.action}_failed` : action.action === 'isolate' ? 'asset.isolated' : 'asset.released';
      await tx`select audit_append('connector', ${auth.collectorId}, ${collector?.name ?? auth.collectorId}, ${auditAction}, 'asset',
        ${action.asset_id}, ${tx.json({ action_id: id, incident_id: action.incident_id, note })}::jsonb)`;
      return action;
    });
    if (!result) return deny(409, 'action_not_waiting');
    return NextResponse.json({ ok: true, ...result, status }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (err) {
    console.error('[response ack] failed', err);
    return deny(500, 'internal_error');
  }
}
