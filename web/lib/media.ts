import { db } from './db';

export type SiteImage = { slot: string; src: string; alt: string; width: number; height: number };

/** The landing page pictures that have been uploaded, keyed by the place they appear. */
export async function siteImages(): Promise<Record<string, SiteImage>> {
  const rows = await db()<{ slot: string; sha256: string; alt: string; width: number; height: number }[]>`
    select slot, sha256, alt, width, height from site_images where bytes is not null`;
  return Object.fromEntries(rows.map((r) => [r.slot, { slot: r.slot, src: `/api/media/${r.slot}?v=${r.sha256.slice(0, 16)}`, alt: r.alt, width: r.width, height: r.height }]));
}
