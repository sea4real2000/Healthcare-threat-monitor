import { randomBytes } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

// Backups with clicks. The console only asks: it writes a request into the folder it shares with the hospital
// installation's backup service (scripts/backup_service.mjs), which does the work and reports back in the same
// folder. Installations without that service, such as the demo, have no HTM_BACKUP_DIR and offer no backups.

export const BACKUP_ID = /^[a-f0-9]{32}$/;

export type BackupStatus = {
  id: string;
  kind: 'backup' | 'restore';
  state: 'working' | 'done' | 'failed';
  step?: string;
  code?: string;
  message?: string;
  bytes?: number;
  made_at?: string;
  at: string;
};

export function backupDir(): string | null {
  const dir = process.env.HTM_BACKUP_DIR;
  return dir && existsSync(dir) ? dir : null;
}

export function newBackupId(): string {
  return randomBytes(16).toString('hex');
}

/** True when the backup service has reported in within the last 30 seconds. */
export function backupServiceRunning(dir: string): boolean {
  try {
    const { at } = JSON.parse(readFileSync(join(dir, 'service.json'), 'utf8')) as { at: string };
    return Date.now() - Date.parse(at) < 30_000;
  } catch {
    return false;
  }
}

/** Hands a request to the backup service. The file is private and appears whole, never half written. */
export function requestBackupJob(dir: string, id: string, request: Record<string, unknown>): void {
  const file = join(dir, 'requests', `${id}.json`);
  writeFileSync(`${file}.part`, JSON.stringify(request), { mode: 0o600 });
  renameSync(`${file}.part`, file);
}

export function readBackupStatus(dir: string, id: string): BackupStatus | null {
  if (!BACKUP_ID.test(id)) return null;
  try {
    return JSON.parse(readFileSync(join(dir, 'status', `${id}.json`), 'utf8')) as BackupStatus;
  } catch {
    // Asked for but not picked up yet.
    return existsSync(join(dir, 'requests', `${id}.json`)) ? { id, kind: 'backup', state: 'working', step: 'waiting', at: new Date().toISOString() } : null;
  }
}

/** The finished backup file for this id, if it is still there to download. */
export function readyBackupFile(dir: string, id: string): { path: string; size: number } | null {
  if (!BACKUP_ID.test(id)) return null;
  const path = join(dir, 'ready', `${id}.htmbackup`);
  return existsSync(path) ? { path, size: statSync(path).size } : null;
}

/** Finished backups still waiting to be downloaded, newest first. */
export function readyBackups(dir: string): BackupStatus[] {
  const list: BackupStatus[] = [];
  for (const f of readdirSync(join(dir, 'ready'))) {
    const id = f.replace(/\.htmbackup$/, '');
    const status = readBackupStatus(dir, id);
    if (status?.state === 'done' && status.kind === 'backup') list.push(status);
  }
  return list.sort((a, b) => (b.made_at ?? b.at).localeCompare(a.made_at ?? a.at));
}

/** What the browser is told about a job: never anything from the request itself. */
export function publicStatus(status: BackupStatus) {
  const { id, kind, state, step, code, message, bytes, made_at: madeAt, at } = status;
  return { id, kind, state, step, code, message, bytes, madeAt, at };
}

/**
 * True when the request comes from the installation's own pages: its Origin names this host. Browsers always send
 * Origin on these requests, so a missing one is refused too.
 */
export function sameOrigin(req: Request): boolean {
  const origin = req.headers.get('origin');
  const host = req.headers.get('x-forwarded-host') ?? req.headers.get('host');
  if (!origin || !host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}
