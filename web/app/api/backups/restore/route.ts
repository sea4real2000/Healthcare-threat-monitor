import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { NextResponse } from 'next/server';
import { audit } from '@/lib/actionHelpers';
import { deny } from '@/lib/auth';
import { backupActor } from '@/lib/backupAccess';
import { BACKUP_ID, backupDir, backupServiceRunning, newBackupId, requestBackupJob, sameOrigin } from '@/lib/backups';
import { textSetting } from '@/lib/settings';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Asks the backup service to replace everything in this installation with an uploaded backup. */
export async function POST(req: Request) {
  if (!sameOrigin(req)) return deny(403, 'wrong_origin');
  const who = await backupActor(req, true);
  if (!who.ok) return who.response;
  const dir = backupDir();
  if (!dir) return deny(404, 'backups_not_available');
  if (!backupServiceRunning(dir)) return deny(503, 'backup_service_not_running');
  const body = (await req.json().catch(() => ({}))) as { upload?: unknown; passphrase?: unknown; confirm?: unknown };
  const upload = typeof body.upload === 'string' ? body.upload : '';
  const passphrase = typeof body.passphrase === 'string' ? body.passphrase.slice(0, 500) : '';
  if (!BACKUP_ID.test(upload) || !existsSync(join(dir, 'incoming', upload))) return deny(400, 'no_upload');
  if (!passphrase) return deny(400, 'passphrase_missing');
  // The word to type is a setting, like all the console's wording.
  if (String(body.confirm ?? '').trim() !== (await textSetting('backups.restore_confirm_word'))) return deny(400, 'not_confirmed');
  const id = newBackupId();
  // Written to the audit log before the restore replaces it, and again by the backup service afterwards.
  await audit(who.actor, 'backup.restore_requested', 'backup', id, { via: who.actor.via });
  requestBackupJob(dir, id, { kind: 'restore', upload, passphrase, by: who.actor });
  return NextResponse.json({ ok: true, id }, { headers: { 'Cache-Control': 'no-store' } });
}
