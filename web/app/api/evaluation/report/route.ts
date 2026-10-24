import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** The latest completed evaluation report, as the harness wrote it. */
export async function GET() {
  const rows = await db()<{ id: string; report_markdown: string | null }[]>`
    select id::text as id, report_markdown from evaluation_runs
    where status = 'completed' and report_markdown is not null order by evaluation_runs.id desc limit 1`;
  if (rows.length === 0) return NextResponse.json({ ok: false, error: 'no_report' }, { status: 404 });
  return new NextResponse(rows[0].report_markdown, {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Content-Disposition': `attachment; filename="evaluation_report_${rows[0].id}.md"`,
      'Cache-Control': 'no-store',
    },
  });
}
