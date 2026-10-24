import { NextResponse } from 'next/server';
import { authenticateCollector, deny } from '@/lib/auth';
import { db } from '@/lib/db';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Lists isolation and release requests that are waiting to be carried out.
 * This is the contract a connector for a real endpoint product implements:
 * read the requests here, act on the endpoint, then acknowledge each one.
 */
export async function GET(req: Request) {
  try {
    const auth = await authenticateCollector(req, '');
    if (!auth.ok) return auth.response;
    // Carrying out an isolation is a privilege. A collector that only sends logs does not have it.
    if (!auth.canRespond) return deny(403, 'collector_may_not_respond');
    const actions = await db()`
      select a.id::text as id, a.action, a.asset_id, host(s.ip) as asset_ip, s.kind as asset_kind,
             a.incident_id::text as incident_id, a.requested_by_name, a.requested_at
      from response_actions a join assets s on s.id = a.asset_id
      where a.status = 'requested' order by a.id limit 100`;
    return NextResponse.json({ ok: true, actions }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (err) {
    console.error('[response actions] failed', err);
    return deny(500, 'internal_error');
  }
}
