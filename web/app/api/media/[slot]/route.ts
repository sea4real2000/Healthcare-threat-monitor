import { db } from '@/lib/db';

export const dynamic = 'force-dynamic';

/**
 * Serves one landing page picture. Public, because the landing page is public.
 * The address carries the picture's hash, so a browser may keep it for a year and a new upload gets a new address.
 */
export async function GET(req: Request, { params }: { params: Promise<{ slot: string }> }) {
  const { slot } = await params;
  if (!/^[a-z_]{2,30}$/.test(slot)) return new Response(null, { status: 404 });
  const [row] = await db()<{ bytes: Buffer; content_type: string; sha256: string }[]>`
    select bytes, content_type, sha256 from site_images where slot = ${slot} and bytes is not null`;
  if (!row) return new Response(null, { status: 404, headers: { 'Cache-Control': 'no-store' } });
  const etag = `"${row.sha256}"`;
  const pinned = new URL(req.url).searchParams.get('v') === row.sha256.slice(0, 16);
  const headers = {
    ETag: etag,
    'Cache-Control': pinned ? 'public, max-age=31536000, immutable' : 'public, max-age=0, must-revalidate',
  };
  if (req.headers.get('if-none-match') === etag) return new Response(null, { status: 304, headers });
  return new Response(new Uint8Array(row.bytes), {
    headers: {
      ...headers,
      'Content-Type': row.content_type,
      'Content-Length': String(row.bytes.length),
      'Content-Disposition': 'inline',
      'Content-Security-Policy': "default-src 'none'; sandbox",
    },
  });
}
