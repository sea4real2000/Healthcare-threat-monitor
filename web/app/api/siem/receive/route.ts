import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { NextResponse } from 'next/server';
import { deny, readLimitedBody } from '@/lib/auth';
import { db } from '@/lib/db';
import { allow, requestAddress } from '@/lib/ratelimit';
import { numberSetting } from '@/lib/settings';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * The built in SIEM receiver. It accepts the same signed webhook a real SIEM
 * would receive, checks the signature, and stores the message so the console
 * can show it arriving. Unsigned or wrongly signed messages are refused.
 */
export async function POST(req: Request) {
  try {
    if (!(await allow(`siem:${requestAddress(req)}`, 'limits.api_per_minute'))) return deny(429, 'too_many_requests');
    const key = process.env.SIEM_WEBHOOK_KEY ?? '';
    if (key.length < 32) return deny(503, 'receiver_key_not_configured');
    const read = await readLimitedBody(req);
    if (!read.ok) return read.response;

    const timestamp = req.headers.get('x-htm-timestamp') ?? '';
    const signature = req.headers.get('x-htm-signature') ?? '';
    const skew = await numberSetting('ingest.max_skew_seconds');
    if (!/^\d{10}$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > skew) return deny(401, 'timestamp_outside_window');
    const bodyHash = createHash('sha256').update(read.body, 'utf8').digest('hex');
    const expected = createHmac('sha256', key)
      .update(['v1', timestamp, 'POST', new URL(req.url).pathname, bodyHash].join(':'), 'utf8')
      .digest();
    const given = /^[0-9a-f]{64}$/.test(signature) ? Buffer.from(signature, 'hex') : Buffer.alloc(0);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) return deny(401, 'signature_mismatch');

    let message: { event_type?: unknown; incident?: { id?: unknown }; cef?: unknown };
    try {
      message = JSON.parse(read.body);
    } catch {
      return deny(400, 'body_not_json');
    }
    const incidentId = Number(message?.incident?.id);
    const sql = db();
    await sql`
      insert into siem_inbox (signature_ok, event_type, incident_id, payload, cef)
      values (true, ${typeof message.event_type === 'string' ? message.event_type.slice(0, 60) : null},
              ${Number.isSafeInteger(incidentId) ? incidentId : null}, ${sql.json(message as never)},
              ${typeof message.cef === 'string' ? message.cef.slice(0, 4000) : null})`;
    return NextResponse.json({ ok: true }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (err) {
    console.error('[siem receive] failed', err);
    return deny(500, 'internal_error');
  }
}
