import { NextResponse } from 'next/server';
import { db } from './db';
import { allow, requestAddress } from './ratelimit';
import { numberSetting } from './settings';
import { HEADER_KEY_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, verifySignature } from './signing';

export type CollectorAuth =
  | { ok: true; collectorId: string; canRespond: boolean }
  | { ok: false; response: NextResponse };

export function deny(status: number, reason: string): NextResponse {
  return NextResponse.json({ ok: false, error: reason }, { status, headers: { 'Cache-Control': 'no-store' } });
}

/** Checks the request signature, then checks the collector is registered and enabled. */
export async function authenticateCollector(req: Request, body: string): Promise<CollectorAuth> {
  if (!(await allow(`api:${requestAddress(req)}`, 'limits.api_per_minute'))) {
    return { ok: false, response: deny(429, 'too_many_requests') };
  }
  const maxSkewSeconds = await numberSetting('ingest.max_skew_seconds');
  const url = new URL(req.url);
  const result = verifySignature({
    keyId: req.headers.get(HEADER_KEY_ID),
    timestamp: req.headers.get(HEADER_TIMESTAMP),
    signature: req.headers.get(HEADER_SIGNATURE),
    method: req.method,
    path: url.pathname,
    body,
    masterKey: process.env.INGEST_SIGNING_KEY,
    maxSkewSeconds,
  });
  if (!result.ok) return { ok: false, response: deny(result.status, result.reason) };

  const rows = await db()<{ enabled: boolean; can_respond: boolean }[]>`
    select enabled, can_respond from collectors where id = ${result.collectorId}`;
  if (rows.length === 0 || !rows[0].enabled) {
    return { ok: false, response: deny(403, 'collector_not_registered') };
  }
  return { ok: true, collectorId: result.collectorId, canRespond: rows[0].can_respond };
}

/** Reads the body as text and enforces the size limit before anything is parsed. */
export async function readLimitedBody(req: Request): Promise<{ ok: true; body: string } | { ok: false; response: NextResponse }> {
  const maxBytes = await numberSetting('ingest.max_body_bytes');
  const declared = Number(req.headers.get('content-length') ?? '0');
  if (declared > maxBytes) return { ok: false, response: deny(413, 'body_too_large') };
  const body = await req.text();
  if (Buffer.byteLength(body, 'utf8') > maxBytes) return { ok: false, response: deny(413, 'body_too_large') };
  return { ok: true, body };
}
