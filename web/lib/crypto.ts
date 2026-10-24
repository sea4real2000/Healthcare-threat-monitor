import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto';

// Password hashing, one time codes and secret storage. Standard primitives only.

const SCRYPT = { N: 2 ** 15, r: 8, p: 3, keylen: 64, maxmem: 128 * 1024 * 1024 };

function scrypt(password: string, salt: Buffer, N: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password.normalize('NFKC'), salt, SCRYPT.keylen, { N, r, p, maxmem: SCRYPT.maxmem }, (err, key) =>
      err ? reject(err) : resolve(key),
    );
  });
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, SCRYPT.N, SCRYPT.r, SCRYPT.p);
  return ['scrypt', Math.log2(SCRYPT.N), SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$');
}

export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  const parts = (stored ?? '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') {
    // Spend the same time whether or not the account exists, so timing does not reveal which emails are registered.
    await scrypt(password, Buffer.alloc(16), SCRYPT.N, SCRYPT.r, SCRYPT.p);
    return false;
  }
  const expected = Buffer.from(parts[5], 'base64');
  const actual = await scrypt(password, Buffer.from(parts[4], 'base64'), 2 ** Number(parts[1]), Number(parts[2]), Number(parts[3]));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

// Base32, as authenticator apps expect.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of text.toUpperCase().replace(/=+$/, '')) {
    const index = ALPHABET.indexOf(ch);
    if (index < 0) throw new Error('bad base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export const TOTP_PERIOD = 30;

/** One time code for a time step, as RFC 6238 defines it (SHA1, six digits). */
export function totpCode(secretBase32: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', base32Decode(secretBase32)).update(counter).digest();
  const offset = mac[mac.length - 1] & 15;
  const number = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1_000_000).padStart(6, '0');
}

/**
 * Checks a code against the current step and one either side.
 * Returns the matching step, or null. A step at or before `lastStep` is refused, so a code cannot be used twice.
 */
export function verifyTotp(secretBase32: string, code: string, lastStep: number, nowMs = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const current = Math.floor(nowMs / 1000 / TOTP_PERIOD);
  for (const step of [current, current - 1, current + 1]) {
    if (step <= lastStep) continue;
    const expected = Buffer.from(totpCode(secretBase32, step));
    if (timingSafeEqual(expected, Buffer.from(code))) return step;
  }
  return null;
}

export function newTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

function sealKey(purpose: string, envName = 'AUTH_SECRET'): Buffer {
  const secret = process.env[envName] ?? '';
  if (secret.length < 32) throw new Error(`${envName} must be set and at least 32 characters long`);
  return Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), `htm:${purpose}`, 32));
}

/** Encrypts a small secret for storage, with AES 256 in GCM mode. */
export function seal(plain: string, purpose: string, envName = 'AUTH_SECRET'): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', sealKey(purpose, envName), iv);
  const body = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64'), cipher.getAuthTag().toString('base64'), body.toString('base64')].join('.');
}

export function unseal(sealed: string, purpose: string, envName = 'AUTH_SECRET'): string {
  const [version, iv, tag, body] = sealed.split('.');
  if (version !== 'v1') throw new Error('unknown sealed format');
  const decipher = createDecipheriv('aes-256-gcm', sealKey(purpose, envName), Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(body, 'base64')), decipher.final()]).toString('utf8');
}

/** Database passwords for connected record sources are sealed with their own key, which the background service also holds. */
export function sourcesConfigured(): boolean {
  return (process.env.SOURCES_SECRET ?? '').length >= 32;
}

export function authConfigured(): boolean {
  return (process.env.AUTH_SECRET ?? '').length >= 32;
}
