import { NextResponse } from 'next/server';
import { deny } from '@/lib/auth';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';
import { numberSetting } from '@/lib/settings';
import { buildInstaller, rootCertificate } from '@/lib/windowsInstaller';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * The installer for one group of Windows computers. It carries the group's secret, so only a signed in
 * administrator can download it, and every download is written to the audit log.
 */
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await currentUser();
  if (!user || user.role !== 'admin') return deny(403, 'admin_only');
  const { id } = await params;
  if (!/^win_[a-z0-9]{10}$/.test(id)) return deny(404, 'not_found');
  const sql = db();
  const [group] = await sql<{ id: string; name: string; enabled: boolean }[]>`
    select id, name, enabled from collectors where id = ${id} and kind = 'windows'`;
  if (!group) return deny(404, 'not_found');
  if (!group.enabled) return deny(409, 'group_disabled');
  // Computers send to the same address the administrator is using now.
  const host = req.headers.get('x-forwarded-host') ?? req.headers.get('host');
  const proto = req.headers.get('x-forwarded-proto') ?? new URL(req.url).protocol.replace(':', '');
  if (!host || !/^[A-Za-z0-9.:\-\[\]]{1,255}$/.test(host)) return deny(400, 'bad_host');
  const apiUrl = `${proto === 'http' ? 'http' : 'https'}://${host}`;
  const root = await rootCertificate();
  const script = buildInstaller({ collectorId: id, groupName: group.name, apiUrl, root, intervalMinutes: await numberSetting('windows.interval_minutes') });
  await sql`select audit_append('user', ${user.id}, ${user.name}, 'windows.installer_downloaded', 'collector', ${id},
    ${sql.json({ api_url: apiUrl, pinned_root: root?.fingerprint ?? null } as never)}::jsonb)`;
  const slug = group.name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '').slice(0, 40) || 'computers';
  return new NextResponse(script, {
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="install_healthcare_threat_monitor_${slug}.ps1"`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
