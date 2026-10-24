import { NextResponse } from 'next/server';
import { deny } from '@/lib/auth';
import { currentUser } from '@/lib/session';
import { rootCertificate } from '@/lib/windowsInstaller';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * The installation's own certificate authority, for hospital computers to trust so browsers stop warning.
 * A certificate is not a secret, but it is only offered to signed in staff, to keep the installation quiet
 * to anyone else on the network.
 */
export async function GET() {
  const user = await currentUser();
  if (!user) return deny(401, 'sign_in_required');
  const root = await rootCertificate();
  if (!root) return deny(404, 'not_found');
  return new NextResponse(root.pem, {
    headers: {
      'Content-Type': 'application/x-x509-ca-cert',
      'Content-Disposition': 'attachment; filename="htm-root.crt"',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
