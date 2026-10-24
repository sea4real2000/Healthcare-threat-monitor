import { toCsv } from '@/lib/csv';
import { KINDS, TEMPLATES, type Kind } from '@/lib/inventoryFiles';

/** A spreadsheet template for the setup wizard, with two example rows to replace. */
export async function GET(_req: Request, { params }: { params: Promise<{ kind: string }> }) {
  const kind = (await params).kind.replace(/\.csv$/, '') as Kind;
  if (!KINDS.includes(kind)) return new Response(null, { status: 404 });
  return new Response('﻿' + toCsv(TEMPLATES[kind]), {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${kind}_template.csv"`,
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
