import { NextResponse } from 'next/server';
import { audit } from '@/lib/actionHelpers';
import { deny } from '@/lib/auth';
import { backupActor } from '@/lib/backupAccess';
import { backupDir, backupServiceRunning, newBackupId, requestBackupJob, sameOrigin } from '@/lib/backups';
import { numberSetting } from '@/lib/settings';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Asks the backup service for a new backup, locked with the administrator's passphrase. */
export async function POST(req: Request) {
  if (!sameOrigin(req)) return deny(403, 'wrong_origin');
  const who = await backupActor(req, false);
  if (!who.ok) return who.response;
  const dir = backupDir();
  if (!dir) return deny(404, 'backups_not_available');
  if (!backupServiceRunning(dir)) return deny(503, 'backup_service_not_running');
  const body = (await req.json().catch(() => ({}))) as { passphrase?: unknown };
  const passphrase = typeof body.passphrase === 'string' ? body.passphrase : '';
  if (passphrase.length < (await numberSetting('backups.passphrase_min_length')) || passphrase.length > 500) return deny(400, 'passphrase_too_short');
  const id = newBackupId();
  requestBackupJob(dir, id, { kind: 'backup', passphrase, by: who.actor });
  await audit(who.actor, 'backup.requested', 'backup', id, {});
  return NextResponse.json({ ok: true, id }, { headers: { 'Cache-Control': 'no-store' } });
}
