import { db } from './db';
import { numberSetting } from './settings';

/**
 * Counts one request against a bucket for the current minute.
 * Returns false once the bucket is over its limit. Limits live in the settings table.
 */
export async function allow(bucket: string, settingKey: string): Promise<boolean> {
  const limit = await numberSetting(settingKey);
  const [row] = await db()<{ hits: number }[]>`
    insert into rate_limits (bucket, window_start, hits) values (${bucket.slice(0, 120)}, date_trunc('minute', now()), 1)
    on conflict (bucket, window_start) do update set hits = rate_limits.hits + 1
    returning hits`;
  return row.hits <= limit;
}

export function requestAddress(req: Request): string {
  return (req.headers.get('x-forwarded-for') ?? '').split(',')[0].trim() || 'unknown';
}
