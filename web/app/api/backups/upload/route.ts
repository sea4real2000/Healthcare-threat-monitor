import { createWriteStream, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { NextResponse } from 'next/server';
import { deny } from '@/lib/auth';
import { backupActor } from '@/lib/backupAccess';
import { backupDir, backupServiceRunning, newBackupId, sameOrigin } from '@/lib/backups';
import { numberSetting } from '@/lib/settings';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Receives a backup file to restore, as the request body, straight onto the disk so a large backup never sits in
 * memory. Nothing is restored yet: that needs the passphrase and a confirmation, sent next to /api/backups/restore.
 */
export async function POST(req: Request) {
  if (!sameOrigin(req)) return deny(403, 'wrong_origin');
  const who = await backupActor(req, true);
  if (!who.ok) return who.response;
  const dir = backupDir();
  if (!dir) return deny(404, 'backups_not_available');
  if (!backupServiceRunning(dir)) return deny(503, 'backup_service_not_running');
  const limit = (await numberSetting('backups.max_upload_mb')) * 1024 * 1024;
  if (Number(req.headers.get('content-length') ?? '0') > limit) return deny(413, 'upload_too_large');
  if (!req.body) return deny(400, 'no_file');
  const upload = newBackupId();
  const path = join(dir, 'incoming', upload);
  let seen = 0;
  const counter = new Transform({
    transform(chunk: Buffer, _enc, done) {
      seen += chunk.length;
      done(seen > limit ? new Error('too_large') : null, chunk);
    },
  });
  try {
    await pipeline(Readable.fromWeb(req.body as never), counter, createWriteStream(`${path}.part`, { mode: 0o600 }));
  } catch (err) {
    rmSync(`${path}.part`, { force: true });
    return deny((err as Error).message === 'too_large' ? 413 : 400, (err as Error).message === 'too_large' ? 'upload_too_large' : 'upload_failed');
  }
  if (seen === 0) {
    rmSync(`${path}.part`, { force: true });
    return deny(400, 'no_file');
  }
  renameSync(`${path}.part`, path);
  return NextResponse.json({ ok: true, upload, bytes: seen }, { headers: { 'Cache-Control': 'no-store' } });
}
