import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const HEADER_KEY_ID = 'x-htm-key-id';
export const HEADER_TIMESTAMP = 'x-htm-timestamp';
export const HEADER_SIGNATURE = 'x-htm-signature';
export const MIN_MASTER_KEY_LENGTH = 32;

export function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

/** A collector secret is derived from the server key, so no secret is ever stored in the database. */
export function deriveCollectorSecret(masterKey: string, collectorId: string): string {
  return createHmac('sha256', masterKey).update(`collector:${collectorId}`, 'utf8').digest('hex');
}

/** The exact string both sides sign. It binds the time, the method, the path and the body. */
export function canonicalString(timestamp: string, method: string, path: string, body: string): string {
  return ['v1', timestamp, method.toUpperCase(), path, sha256Hex(body)].join(':');
}

export function signRequest(secret: string, timestamp: string, method: string, path: string, body: string): string {
  return createHmac('sha256', secret).update(canonicalString(timestamp, method, path, body), 'utf8').digest('hex');
}

export type VerifyResult =
  | { ok: true; collectorId: string }
  | { ok: false; status: number; reason: string };

export function verifySignature(input: {
  keyId: string | null;
  timestamp: string | null;
  signature: string | null;
  method: string;
  path: string;
  body: string;
  masterKey: string | undefined;
  maxSkewSeconds: number;
  nowMs?: number;
}): VerifyResult {
  const { keyId, timestamp, signature, masterKey } = input;
  if (!masterKey || masterKey.length < MIN_MASTER_KEY_LENGTH) {
    return { ok: false, status: 503, reason: 'signing_key_not_configured' };
  }
  if (!keyId || !timestamp || !signature) {
    return { ok: false, status: 401, reason: 'missing_signature_headers' };
  }
  if (!/^[A-Za-z0-9_]{3,64}$/.test(keyId)) {
    return { ok: false, status: 401, reason: 'bad_key_id' };
  }
  if (!/^\d{10}$/.test(timestamp)) {
    return { ok: false, status: 401, reason: 'bad_timestamp' };
  }
  const now = Math.floor((input.nowMs ?? Date.now()) / 1000);
  if (Math.abs(now - Number(timestamp)) > input.maxSkewSeconds) {
    return { ok: false, status: 401, reason: 'timestamp_outside_window' };
  }
  if (!/^[0-9a-f]{64}$/.test(signature)) {
    return { ok: false, status: 401, reason: 'bad_signature_format' };
  }
  const secret = deriveCollectorSecret(masterKey, keyId);
  const expected = signRequest(secret, timestamp, input.method, input.path, input.body);
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(signature, 'hex');
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { ok: false, status: 401, reason: 'signature_mismatch' };
  }
  return { ok: true, collectorId: keyId };
}
