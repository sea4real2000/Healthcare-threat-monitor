import { createHash, timingSafeEqual } from 'node:crypto';
import { db } from './db';

// The first visit to a new hospital installation sets up its administrator. It needs the setup code shown on the
// installation's own screen, so only someone who can see that screen can do it.

/** True while the installation has a setup code and no active administrator yet. */
export async function firstRunPending(): Promise<boolean> {
  const [row] = await db()<{ pending: boolean }[]>`
    select exists (select 1 from engine_state where key = 'first_run')
      and not exists (select 1 from users where role = 'admin' and status = 'active') as pending`;
  return Boolean(row?.pending);
}

export function normaliseCode(code: string): string {
  return code.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
}

/** Compares a typed code with the stored hash in constant time. */
export async function setupCodeMatches(code: string): Promise<boolean> {
  const [row] = await db()<{ hash: string | null }[]>`select value->>'hash' as hash from engine_state where key = 'first_run'`;
  if (!row?.hash || !/^[0-9a-f]{64}$/.test(row.hash)) return false;
  const typed = createHash('sha256').update(normaliseCode(code), 'utf8').digest();
  return timingSafeEqual(typed, Buffer.from(row.hash, 'hex'));
}
