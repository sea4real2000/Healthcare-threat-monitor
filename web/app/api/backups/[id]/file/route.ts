import { createReadStream } from 'node:fs';
import { Readable } from 'node:stream';
import { audit } from '@/lib/actionHelpers';
import { deny } from '@/lib/auth';
import { backupDir, readBackupStatus, readyBackupFile } from '@/lib/backups';
import { currentUser } from '@/lib/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Downloads a finished backup. Administrators only. The file is locked with its passphrase. */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await currentUser();
  if (!user) return deny(401, 'sign_in_required');
  if (user.role !== 'admin') return deny(403, 'admin_only');
  const { id } = await params;
  const dir = backupDir();
  if (!dir) return deny(404, 'backups_not_available');
  const file = readyBackupFile(dir, id);
  if (!file) return deny(404, 'not_found');
  const made = (readBackupStatus(dir, id)?.made_at ?? new Date().toISOString()).slice(0, 16).replace(/[:T]/g, '-');
  await audit(user, 'backup.downloaded', 'backup', id, { bytes: file.size });
  return new Response(Readable.toWeb(createReadStream(file.path)) as ReadableStream, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(file.size),
      'Content-Disposition': `attachment; filename="htm-backup-${made}.htmbackup"`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
