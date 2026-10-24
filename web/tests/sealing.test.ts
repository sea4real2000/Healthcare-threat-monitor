import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { seal, unseal } from '../lib/crypto';

const vector = JSON.parse(readFileSync(new URL('../../shared/sealed_vector.json', import.meta.url), 'utf8'));

describe('sealing with SOURCES_SECRET', () => {
  it('unseals the vector shared with the background service', () => {
    process.env.SOURCES_SECRET = vector.secret;
    expect(unseal(vector.sealed, vector.purpose, 'SOURCES_SECRET')).toBe(vector.plain);
  });
  it('round trips, and refuses a different key or purpose', () => {
    process.env.SOURCES_SECRET = vector.secret;
    const s = seal('pw', 'record_source', 'SOURCES_SECRET');
    expect(unseal(s, 'record_source', 'SOURCES_SECRET')).toBe('pw');
    expect(() => unseal(s, 'totp', 'SOURCES_SECRET')).toThrow();
    process.env.SOURCES_SECRET = 'another_secret_of_enough_length_0123456789';
    expect(() => unseal(s, 'record_source', 'SOURCES_SECRET')).toThrow();
  });
  it('refuses to seal without the secret', () => {
    delete process.env.SOURCES_SECRET;
    expect(() => seal('pw', 'record_source', 'SOURCES_SECRET')).toThrow(/SOURCES_SECRET/);
  });
});
