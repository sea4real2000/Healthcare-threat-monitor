import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { backupDir, backupServiceRunning, newBackupId, publicStatus, readBackupStatus, readyBackupFile, readyBackups, requestBackupJob, sameOrigin } from '@/lib/backups';

let dir = '';
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'htm-backups-'));
  for (const f of ['requests', 'status', 'ready']) mkdirSync(join(dir, f));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const req = (headers: Record<string, string>) => new Request('http://console:3000/api/backups', { method: 'POST', headers });

describe('the console side of backups', () => {
  it('only offers backups where the backup folder exists', () => {
    process.env.HTM_BACKUP_DIR = join(dir, 'missing');
    expect(backupDir()).toBeNull();
    process.env.HTM_BACKUP_DIR = dir;
    expect(backupDir()).toBe(dir);
    delete process.env.HTM_BACKUP_DIR;
    expect(backupDir()).toBeNull();
  });

  it('says the service is running only when it reported in within 30 seconds', () => {
    expect(backupServiceRunning(dir)).toBe(false);
    writeFileSync(join(dir, 'service.json'), JSON.stringify({ at: new Date(Date.now() - 60_000).toISOString() }));
    expect(backupServiceRunning(dir)).toBe(false);
    writeFileSync(join(dir, 'service.json'), JSON.stringify({ at: new Date().toISOString() }));
    expect(backupServiceRunning(dir)).toBe(true);
  });

  it('writes requests privately, under random ids, and reports them as waiting until picked up', () => {
    const id = newBackupId();
    expect(id).toMatch(/^[a-f0-9]{32}$/);
    expect(newBackupId()).not.toBe(id);
    requestBackupJob(dir, id, { kind: 'backup', passphrase: 'secret words here' });
    const file = join(dir, 'requests', `${id}.json`);
    expect(statSync(file).mode & 0o077).toBe(0);
    expect(JSON.parse(readFileSync(file, 'utf8')).kind).toBe('backup');
    expect(readBackupStatus(dir, id)).toMatchObject({ state: 'working', step: 'waiting' });
  });

  it('refuses ids that are not its own shape, so no path can be reached through one', () => {
    expect(readBackupStatus(dir, '../../etc/passwd')).toBeNull();
    expect(readyBackupFile(dir, '../secrets')).toBeNull();
    expect(readBackupStatus(dir, newBackupId())).toBeNull();
  });

  it('lists finished backups newest first, and tells the browser nothing from the request', () => {
    const older = newBackupId();
    const newer = newBackupId();
    for (const [id, made] of [[older, '2026-10-01T10:00:00Z'], [newer, '2026-10-02T10:00:00Z']]) {
      writeFileSync(join(dir, 'status', `${id}.json`), JSON.stringify({ id, kind: 'backup', state: 'done', made_at: made, at: made, passphrase: 'never shown' }));
      writeFileSync(join(dir, 'ready', `${id}.htmbackup`), 'HTMBACKUP\n');
    }
    expect(readyBackups(dir).map((b) => b.id)).toEqual([newer, older]);
    expect(readyBackupFile(dir, newer)?.size).toBe(10);
    const shown = publicStatus(readBackupStatus(dir, newer)!);
    expect(JSON.stringify(shown)).not.toContain('never shown');
    expect(shown.madeAt).toBe('2026-10-02T10:00:00Z');
  });

  it('accepts requests only from the installation\'s own pages', () => {
    expect(sameOrigin(req({ origin: 'https://10.0.0.5', 'x-forwarded-host': '10.0.0.5' }))).toBe(true);
    expect(sameOrigin(req({ origin: 'https://another.example', 'x-forwarded-host': '10.0.0.5' }))).toBe(false);
    expect(sameOrigin(req({ 'x-forwarded-host': '10.0.0.5' }))).toBe(false);
    expect(sameOrigin(req({ origin: 'not a url', host: '10.0.0.5' }))).toBe(false);
  });
});
