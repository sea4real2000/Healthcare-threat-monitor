import { beforeAll, describe, expect, it } from 'vitest';
import { base32Decode, base32Encode, hashPassword, newTotpSecret, seal, totpCode, unseal, verifyPassword, verifyTotp } from '@/lib/crypto';

beforeAll(() => {
  process.env.AUTH_SECRET = 'test_secret_0123456789abcdef0123456789';
});

describe('passwords', () => {
  it('accepts the right password and refuses a wrong one', async () => {
    const stored = await hashPassword('correct horse battery staple');
    expect(stored.startsWith('scrypt$15$8$3$')).toBe(true);
    expect(await verifyPassword('correct horse battery staple', stored)).toBe(true);
    expect(await verifyPassword('correct horse battery stapler', stored)).toBe(false);
  });

  it('gives a different hash each time', async () => {
    expect(await hashPassword('same password here')).not.toBe(await hashPassword('same password here'));
  });

  it('refuses when there is no stored hash', async () => {
    expect(await verifyPassword('anything', null)).toBe(false);
    expect(await verifyPassword('anything', 'not a hash')).toBe(false);
  });
});

describe('one time codes', () => {
  // The published test secret from RFC 6238, "12345678901234567890", in base32.
  const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890'));

  it('matches the RFC 6238 test vectors', () => {
    expect(totpCode(RFC_SECRET, Math.floor(59 / 30))).toBe('287082');
    expect(totpCode(RFC_SECRET, Math.floor(1111111109 / 30))).toBe('081804');
    expect(totpCode(RFC_SECRET, Math.floor(1234567890 / 30))).toBe('005924');
    expect(totpCode(RFC_SECRET, Math.floor(2000000000 / 30))).toBe('279037');
  });

  it('accepts the current code and one step either side', () => {
    const now = 1234567890 * 1000;
    const step = Math.floor(1234567890 / 30);
    expect(verifyTotp(RFC_SECRET, '005924', 0, now)).toBe(step);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step - 1), 0, now)).toBe(step - 1);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 1), 0, now)).toBe(step + 1);
    expect(verifyTotp(RFC_SECRET, totpCode(RFC_SECRET, step + 2), 0, now)).toBeNull();
  });

  it('refuses a code that was already used', () => {
    const now = 1234567890 * 1000;
    const step = Math.floor(1234567890 / 30);
    expect(verifyTotp(RFC_SECRET, '005924', step, now)).toBeNull();
  });

  it('refuses anything that is not six digits', () => {
    for (const bad of ['', '12345', '1234567', 'abcdef', '00592a']) expect(verifyTotp(RFC_SECRET, bad, 0)).toBeNull();
  });

  it('round trips base32 and makes long secrets', () => {
    const secret = newTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Encode(base32Decode(secret))).toBe(secret);
  });
});

describe('sealed secrets', () => {
  it('round trips and never stores the plain text', () => {
    const sealed = seal('JBSWY3DPEHPK3PXP', 'totp');
    expect(sealed).not.toContain('JBSWY3DPEHPK3PXP');
    expect(unseal(sealed, 'totp')).toBe('JBSWY3DPEHPK3PXP');
  });

  it('refuses a changed value, a wrong purpose and a wrong key', () => {
    const sealed = seal('secret value', 'totp');
    const parts = sealed.split('.');
    const body = Buffer.from(parts[3], 'base64');
    body[0] ^= 1;
    expect(() => unseal([parts[0], parts[1], parts[2], body.toString('base64')].join('.'), 'totp')).toThrow();
    expect(() => unseal(sealed, 'other')).toThrow();
    process.env.AUTH_SECRET = 'another_secret_0123456789abcdef0123456789';
    expect(() => unseal(sealed, 'totp')).toThrow();
    process.env.AUTH_SECRET = 'test_secret_0123456789abcdef0123456789';
  });
});
