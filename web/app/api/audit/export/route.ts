import { createHmac } from 'node:crypto';
import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Exports the whole audit log for an outside auditor. Every entry carries the fields that
 * were hashed, so the chain can be checked with scripts/verify_audit_export.py and nothing else.
 * When AUDIT_EXPORT_KEY is set, the file also carries an HMAC SHA256 signature of its entries.
 */
export async function GET() {
  const user = await currentUser();
  if (!user) return NextResponse.json({ ok: false, error: 'sign_in_required' }, { status: 401 });
  const sql = db();
  const entries = await sql`
    select seq::text as seq, at_text, actor_type, actor_id, actor_name, action, subject_type, subject_id, detail_text, prev_hash, hash
    from audit_log order by audit_log.seq`;
  const body = JSON.stringify(entries);
  const key = process.env.AUDIT_EXPORT_KEY ?? '';
  const exported = {
    format: 'htm_audit_export_v1',
    exported_at: new Date().toISOString(),
    exported_by: user.name,
    entry_count: entries.length,
    head_hash: entries.length ? entries[entries.length - 1].hash : null,
    canonical: 'For each entry, join these fields with "|", each written as its length in characters, a colon, then the field: prev_hash, seq, at_text, actor_type, actor_id, actor_name, action, subject_type, subject_id, detail_text. The entry hash is the SHA 256 of that text in UTF 8.',
    signature: key.length >= 32 ? createHmac('sha256', key).update(body, 'utf8').digest('hex') : null,
    entries,
  };
  await sql`select audit_append('user', ${user.id}, ${user.name}, 'audit.exported', 'audit_log', '', ${sql.json({ entries: entries.length })}::jsonb)`;
  return new NextResponse(JSON.stringify(exported, null, 1), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="audit_export_${new Date().toISOString().slice(0, 10)}.json"`,
      'Cache-Control': 'no-store',
    },
  });
}
