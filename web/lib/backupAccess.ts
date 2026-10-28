import type { NextResponse } from 'next/server';
import { deny } from './auth';
import { firstRunPending, setupCodeMatches } from './firstRun';
import { allow, requestAddress } from './ratelimit';
import { currentUser } from './session';

export type BackupActor = { id: string; name: string; via: 'admin' | 'setup_code' };

/**
 * Who may make or restore a backup: a signed in administrator, or, on a new installation nobody has set up yet,
 * whoever has the setup code from its screen, so a backup can be restored straight onto a new installation.
 */
export async function backupActor(req: Request, allowSetupCode: boolean): Promise<{ ok: true; actor: BackupActor } | { ok: false; response: NextResponse }> {
  const user = await currentUser();
  if (user?.role === 'admin') return { ok: true, actor: { id: user.id, name: user.name, via: 'admin' } };
  const code = req.headers.get('x-setup-code');
  if (allowSetupCode && code && (await firstRunPending())) {
    if (!(await allow(`firstrun:${requestAddress(req)}`, 'limits.signin_per_minute'))) return { ok: false, response: deny(429, 'too_many_requests') };
    if (await setupCodeMatches(code)) return { ok: true, actor: { id: 'first_visit', name: 'First visit', via: 'setup_code' } };
    return { ok: false, response: deny(403, 'wrong_code') };
  }
  return { ok: false, response: deny(user ? 403 : 401, 'admin_only') };
}
