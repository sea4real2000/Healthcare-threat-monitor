import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readBackup, readHeader, writeBackup } from '../scripts/backup_format.mjs';

// A low scrypt cost keeps the tests quick. Real backups use the default.
const cheap = { log2N: 14, r: 8, p: 1 };
const dirs: string[] = [];
const temp = () => { const d = mkdtempSync(join(tmpdir(), 'htm-backup-')); dirs.push(d); return d; };
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });

async function made(passphrase = 'correct horse battery staple') {
  const d = temp();
  const big = Buffer.alloc(3 * 1024 * 1024 + 17, 7);
  writeFileSync(join(d, 'database.dump'), big);
  const file = join(d, 'out.htmbackup');
  await writeBackup(file, { product: 'healthcare-threat-monitor', version: '0.9.0' }, [
    { name: 'database.dump', path: join(d, 'database.dump') },
    { name: 'secrets.json', data: Buffer.from('{"auth":"x"}') },
  ], passphrase, cheap);
  return { file, big };
}

describe('backup files', () => {
  it('give back exactly what went in, with the right passphrase', async () => {
    const { file, big } = await made();
    const out = temp();
    const { manifest, names } = await readBackup(file, 'correct horse battery staple', out);
    expect(manifest).toEqual({ product: 'healthcare-threat-monitor', version: '0.9.0' });
    expect(names).toEqual(['database.dump', 'secrets.json']);
    expect(readFileSync(join(out, 'database.dump')).equals(big)).toBe(true);
    expect(readFileSync(join(out, 'secrets.json'), 'utf8')).toBe('{"auth":"x"}');
    expect(readdirSync(out).sort()).toEqual(['database.dump', 'secrets.json']);
  });

  it('are refused with a wrong passphrase, leaving nothing readable behind', async () => {
    const { file } = await made();
    const out = temp();
    await expect(readBackup(file, 'wrong passphrase entirely', out)).rejects.toMatchObject({ code: 'wrong_passphrase' });
    expect(readdirSync(out)).toEqual([]);
  });

  it('are refused when a single byte was changed', async () => {
    const { file } = await made();
    const bytes = readFileSync(file);
    bytes[bytes.length - 100] ^= 1;
    writeFileSync(file, bytes);
    await expect(readBackup(file, 'correct horse battery staple', temp())).rejects.toMatchObject({ code: 'wrong_passphrase' });
  });

  it('do not hold the database or secrets in readable form', async () => {
    const { file } = await made();
    expect(readFileSync(file).includes(Buffer.from('"auth"'))).toBe(false);
    expect(statSync(file).mode & 0o077).toBe(0);
    expect(existsSync(`${file}.part`)).toBe(false);
  });

  it('say plainly when a file is not a backup at all', () => {
    const d = temp();
    writeFileSync(join(d, 'photo.jpg'), Buffer.alloc(500, 1));
    expect(() => readHeader(join(d, 'photo.jpg'))).toThrow(/not a Healthcare Threat Monitor backup/);
  });

  it('refuse file names that could reach outside the folder', async () => {
    const d = temp();
    await expect(writeBackup(join(d, 'x'), {}, [{ name: '../escape', data: Buffer.from('x') }], 'a passphrase here', cheap)).rejects.toMatchObject({ code: 'bad_name' });
  });
});
