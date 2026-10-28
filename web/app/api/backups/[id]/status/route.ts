import { NextResponse } from 'next/server';
import { deny } from '@/lib/auth';
import { backupDir, publicStatus, readBackupStatus } from '@/lib/backups';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * How a backup or restore is going. The job's id is 32 random characters known only to whoever asked for it, so it
 * is enough to read this: a restore signs everyone out part way through, and the page must still see it finish.
 * Nothing from the backup itself is ever in the answer.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const dir = backupDir();
  if (!dir) return deny(404, 'backups_not_available');
  const status = readBackupStatus(dir, id);
  if (!status) return deny(404, 'not_found');
  return NextResponse.json({ ok: true, ...publicStatus(status) }, { headers: { 'Cache-Control': 'no-store' } });
}
