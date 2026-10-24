import { cache } from 'react';
import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { db } from './db';
import { randomToken, sha256Hex } from './crypto';
import { allow } from './ratelimit';
import { flagSetting, numberSetting } from './settings';

export const SESSION_COOKIE = 'htm_session';

export interface SessionUser {
  id: string;
  email: string;
  name: string;
  role: 'analyst' | 'admin' | 'demo';
  mfaPassed: boolean;
}

export async function clientAddress(): Promise<string> {
  const h = await headers();
  return (h.get('x-forwarded-for') ?? '').split(',')[0].trim() || 'unknown';
}

export async function startSession(userId: string, mfaPassed: boolean, minutes?: number): Promise<void> {
  const token = randomToken();
  const hours = minutes === undefined ? await numberSetting('auth.session_hours') : minutes / 60;
  const h = await headers();
  await db()`
    insert into sessions (token_hash, user_id, mfa_passed, expires_at, ip, user_agent)
    values (${sha256Hex(token)}, ${userId}::uuid, ${mfaPassed}, now() + make_interval(secs => ${Math.round(hours * 3600)}::int),
            ${await clientAddress()}, ${(h.get('user-agent') ?? '').slice(0, 200)})`;
  (await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' && process.env.ALLOW_INSECURE_COOKIES !== '1',
    sameSite: 'lax',
    path: '/',
    maxAge: Math.round(hours * 3600),
  });
}

export async function endSession(): Promise<void> {
  const jar = await cookies();
  const token = jar.get(SESSION_COOKIE)?.value;
  if (token) await db()`delete from sessions where token_hash = ${sha256Hex(token)}`;
  jar.delete(SESSION_COOKIE);
}

/** The session behind this request, whether or not the second factor has been passed yet. */
export const anySession = cache(async (): Promise<SessionUser | null> => {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token || token.length > 100) return null;
  const idle = await numberSetting('auth.idle_minutes');
  const rows = await db()<{ id: string; email: string; display_name: string; role: SessionUser['role']; mfa_passed: boolean }[]>`
    update sessions s set last_seen_at = now()
    from users u
    where s.token_hash = ${sha256Hex(token)} and u.id = s.user_id and u.status = 'active'
      and s.expires_at > now() and s.last_seen_at > now() - make_interval(mins => ${idle}::int)
    returning u.id, u.email, u.display_name, u.role, s.mfa_passed`;
  if (rows.length === 0) return null;
  const r = rows[0];
  return { id: r.id, email: r.email, name: r.display_name, role: r.role, mfaPassed: r.mfa_passed };
});

/**
 * The signed in analyst or administrator, or null. A session that has not passed the second factor
 * counts as a visitor, and so does the public demo visitor: every page and action that uses this
 * treats the demo exactly like an anonymous visitor.
 */
export async function currentUser(): Promise<SessionUser | null> {
  const user = await anySession();
  return user?.mfaPassed && user.role !== 'demo' ? user : null;
}

/** The public demo visitor, while the demo is switched on. Null for everyone else. */
export async function demoVisitor(): Promise<SessionUser | null> {
  const user = await anySession();
  if (!user || user.role !== 'demo' || !user.mfaPassed) return null;
  return (await flagSetting('demo.enabled')) ? user : null;
}

/**
 * For the few actions the demo visitor may take: launching a scenario and isolating or releasing a machine.
 * A real account passes straight through. The demo visitor is also held to a per address rate limit.
 */
export async function requireActor(): Promise<SessionUser | { limited: true }> {
  const user = await currentUser();
  if (user) return user;
  const demo = await demoVisitor();
  if (!demo) redirect('/signin');
  if (!(await allow(`demo:${await clientAddress()}`, 'limits.demo_per_minute'))) return { limited: true };
  return demo;
}

/** For server actions: returns the user or sends the browser to the sign in page. */
export async function requireUser(role?: 'admin'): Promise<SessionUser> {
  const user = await currentUser();
  if (!user) redirect('/signin');
  if (role === 'admin' && user.role !== 'admin') redirect('/console?error=admin_only');
  return user;
}
