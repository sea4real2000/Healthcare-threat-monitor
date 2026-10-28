// The backup file: everything needed to move an installation to a new one, locked with a passphrase.
//
// Layout:
//   "HTMBACKUP\n"        10 bytes, so the file says what it is
//   format version       1 byte, now 1
//   scrypt cost          1 byte each: log2 of N, r, p
//   salt                 16 bytes, for the key made from the passphrase with scrypt
//   iv                   12 bytes
//   ciphertext           AES 256 GCM of the contents
//   tag                  16 bytes, which proves the passphrase is right and nothing was changed
// The contents: the manifest as JSON (4 byte length, then the text), then each file as a 2 byte name length, the
// name, an 8 byte size and the bytes, then a 2 byte zero to end. Lengths are big endian.
// Used by scripts/backup_service.mjs, which makes and restores backups, and by the console's tests.
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';
import { appendFileSync, closeSync, createReadStream, createWriteStream, openSync, readSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

export const MAGIC = Buffer.from('HTMBACKUP\n');
export const FORMAT = 1;
const HEADER = MAGIC.length + 4 + 16 + 12;
const TAG = 16;
// About a second on an ordinary computer and 128 MB of memory, so guessing passphrases is slow.
const COST = { log2N: 17, r: 8, p: 1 };
const NAME = /^[a-z0-9_.]{1,64}$/;

export class BackupError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function key(passphrase, salt, { log2N, r, p }) {
  const N = 2 ** log2N;
  return new Promise((resolve, reject) =>
    scrypt(passphrase.normalize('NFC'), salt, 32, { N, r, p, maxmem: 128 * N * r * 2 }, (err, k) => (err ? reject(err) : resolve(k))));
}

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

/**
 * Writes an encrypted backup to `out`. `files` is a list of { name, path } or { name, data }.
 * The file only appears under its own name once it is complete.
 */
export async function writeBackup(out, manifest, files, passphrase, cost = COST) {
  for (const f of files) if (!NAME.test(f.name)) throw new BackupError('bad_name', `file name not allowed in a backup: ${f.name}`);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', await key(passphrase, salt, cost), iv);
  const part = `${out}.part`;
  writeFileSync(part, Buffer.concat([MAGIC, Buffer.from([FORMAT, cost.log2N, cost.r, cost.p]), salt, iv]), { mode: 0o600 });
  async function* contents() {
    const m = Buffer.from(JSON.stringify(manifest), 'utf8');
    yield u32(m.length);
    yield m;
    for (const f of files) {
      const name = Buffer.from(f.name, 'utf8');
      const size = f.data ? f.data.length : statSync(f.path).size;
      yield Buffer.concat([u16(name.length), name, u64(size)]);
      if (f.data) yield f.data;
      else for await (const chunk of createReadStream(f.path)) yield chunk;
    }
    yield u16(0);
  }
  await pipeline(Readable.from(contents()), cipher, createWriteStream(part, { flags: 'a' }));
  appendFileSync(part, cipher.getAuthTag());
  renameSync(part, out);
}

/** Reads only the readable header, to say early whether a file is a backup at all. */
export function readHeader(file) {
  const size = statSync(file).size;
  if (size < HEADER + TAG) throw new BackupError('not_a_backup', 'this file is not a Healthcare Threat Monitor backup');
  const fd = openSync(file, 'r');
  try {
    const head = Buffer.alloc(HEADER);
    readSync(fd, head, 0, HEADER, 0);
    if (!head.subarray(0, MAGIC.length).equals(MAGIC)) throw new BackupError('not_a_backup', 'this file is not a Healthcare Threat Monitor backup');
    const at = MAGIC.length;
    if (head[at] !== FORMAT) throw new BackupError('newer_format', 'this backup was made by a newer version. Update this installation first');
    const cost = { log2N: head[at + 1], r: head[at + 2], p: head[at + 3] };
    if (cost.log2N < 14 || cost.log2N > 20 || cost.r < 1 || cost.r > 16 || cost.p < 1 || cost.p > 4) throw new BackupError('not_a_backup', 'this backup\'s header is damaged');
    return { size, cost, salt: head.subarray(at + 4, at + 20), iv: head.subarray(at + 20, at + 32) };
  } finally {
    closeSync(fd);
  }
}

/**
 * Decrypts a backup into `dir` and returns its manifest and the names of its files. Nothing is returned unless
 * the passphrase is right and the file is exactly as it was made.
 */
export async function readBackup(file, passphrase, dir) {
  const { size, cost, salt, iv } = readHeader(file);
  const fd = openSync(file, 'r');
  const tag = Buffer.alloc(TAG);
  readSync(fd, tag, 0, TAG, size - TAG);
  closeSync(fd);
  const decipher = createDecipheriv('aes-256-gcm', await key(passphrase, salt, cost), iv);
  decipher.setAuthTag(tag);
  const plain = join(dir, 'contents.plain');
  try {
    await pipeline(createReadStream(file, { start: HEADER, end: size - TAG - 1 }), decipher, createWriteStream(plain, { mode: 0o600 }));
  } catch {
    try { unlinkSync(plain); } catch { /* not written */ }
    throw new BackupError('wrong_passphrase', 'the passphrase is wrong, or the file was changed or damaged');
  }
  try {
    return unpack(plain, dir);
  } finally {
    unlinkSync(plain);
  }
}

function unpack(plain, dir) {
  const fd = openSync(plain, 'r');
  let pos = 0;
  const take = (n) => {
    const b = Buffer.alloc(n);
    const got = readSync(fd, b, 0, n, pos);
    if (got !== n) throw new BackupError('damaged', 'the backup ends too early');
    pos += n;
    return b;
  };
  try {
    const manifest = JSON.parse(take(take(4).readUInt32BE()).toString('utf8'));
    const names = [];
    for (;;) {
      const length = take(2).readUInt16BE();
      if (length === 0) break;
      const name = take(length).toString('utf8');
      if (!NAME.test(name) || names.includes(name)) throw new BackupError('damaged', `the backup holds a file it should not: ${name}`);
      let left = Number(take(8).readBigUInt64BE());
      const out = openSync(join(dir, name), 'w', 0o600);
      try {
        const chunk = Buffer.alloc(1024 * 1024);
        while (left > 0) {
          const n = readSync(fd, chunk, 0, Math.min(chunk.length, left), pos);
          if (n <= 0) throw new BackupError('damaged', 'the backup ends too early');
          writeSync(out, chunk, 0, n);
          pos += n;
          left -= n;
        }
      } finally {
        closeSync(out);
      }
      names.push(name);
    }
    return { manifest, names };
  } finally {
    closeSync(fd);
  }
}
