import { describe, expect, it } from 'vitest';
import { deriveCollectorSecret, signRequest, verifySignature } from '@/lib/signing';

// The same vector is checked in engine/tests, so both languages must agree.
const MASTER = '0123456789abcdef0123456789abcdef';
const COLLECTOR = 'sim_hospital_01';
const SECRET = '4f77f91d662217a01618981516897e90e54d127ebb31ea34545b9e72e8f452f5';
const SIGNATURE = '310a45b5e2aaff8f823736eb10a0a0f7f22e5c2f65aaa9740a1757273a424545';
const TS = '1760000000';
const BODY = '{"a":1}';

function check(over: Record<string, unknown> = {}) {
  return verifySignature({
    keyId: COLLECTOR,
    timestamp: TS,
    signature: SIGNATURE,
    method: 'POST',
    path: '/api/ingest',
    body: BODY,
    masterKey: MASTER,
    maxSkewSeconds: 300,
    nowMs: Number(TS) * 1000,
    ...over,
  });
}

describe('request signing', () => {
  it('matches the shared test vector', () => {
    expect(deriveCollectorSecret(MASTER, COLLECTOR)).toBe(SECRET);
    expect(signRequest(SECRET, TS, 'POST', '/api/ingest', BODY)).toBe(SIGNATURE);
  });

  it('accepts a correct signature', () => {
    expect(check()).toEqual({ ok: true, collectorId: COLLECTOR });
  });

  it('rejects a changed body, path, method or collector', () => {
    expect(check({ body: '{"a":2}' })).toMatchObject({ ok: false, reason: 'signature_mismatch' });
    expect(check({ path: '/api/inventory' })).toMatchObject({ ok: false, reason: 'signature_mismatch' });
    expect(check({ method: 'GET' })).toMatchObject({ ok: false, reason: 'signature_mismatch' });
    expect(check({ keyId: 'other_collector' })).toMatchObject({ ok: false, reason: 'signature_mismatch' });
  });

  it('rejects a stale or future timestamp', () => {
    expect(check({ nowMs: (Number(TS) + 301) * 1000 })).toMatchObject({ ok: false, reason: 'timestamp_outside_window' });
    expect(check({ nowMs: (Number(TS) - 301) * 1000 })).toMatchObject({ ok: false, reason: 'timestamp_outside_window' });
  });

  it('rejects missing or malformed headers', () => {
    expect(check({ signature: null })).toMatchObject({ ok: false, reason: 'missing_signature_headers' });
    expect(check({ signature: 'zz' })).toMatchObject({ ok: false, reason: 'bad_signature_format' });
    expect(check({ timestamp: 'now' })).toMatchObject({ ok: false, reason: 'bad_timestamp' });
    expect(check({ keyId: '../x' })).toMatchObject({ ok: false, reason: 'bad_key_id' });
  });

  it('refuses to run with a missing or short server key', () => {
    expect(check({ masterKey: undefined })).toMatchObject({ ok: false, status: 503 });
    expect(check({ masterKey: 'short' })).toMatchObject({ ok: false, status: 503 });
  });
});
