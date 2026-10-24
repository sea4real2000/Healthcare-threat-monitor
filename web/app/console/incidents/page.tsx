import Link from 'next/link';
import { Band, Flash, percent } from '@/components/ui';
import { Status } from '@/components/Status';
import { db } from '@/lib/db';
import { formatAgo, formatNumber } from '@/lib/format';
import { getCopy, numberSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const VIEWS = ['queue', 'decided', 'low', 'all'] as const;
const STATUS_TONE = { open: 'warn', confirmed: 'crit', dismissed: 'quiet' } as const;

interface Row {
  id: string;
  title: string;
  status: 'open' | 'confirmed' | 'dismissed';
  band: string;
  confidence: string;
  sources: string[];
  alert_count: number;
  hosts: string[];
  users: string[];
  opened_at: Date;
  last_activity_at: Date;
  now: Date;
}

export default async function IncidentsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const params = await searchParams;
  const requested = Array.isArray(params.view) ? params.view[0] : params.view;
  const view = VIEWS.find((v) => v === requested) ?? 'queue';
  const [t, limit] = await Promise.all([getCopy(), numberSetting('console.incidents_page_limit')]);
  const sql = db();
  const [counts] = await sql<{ queue: number; decided: number; low: number; total: number }[]>`
    select count(*) filter (where status = 'open' and band <> 'low')::int as queue,
           count(*) filter (where status <> 'open')::int as decided,
           count(*) filter (where band = 'low' and status = 'open')::int as low,
           count(*)::int as total
    from incidents`;
  const rows = await sql<Row[]>`
    select id::text as id, title, status, band, confidence::text as confidence, sources, alert_count, hosts, users, opened_at, last_activity_at, now() as now
    from incidents
    where case ${view}::text
      when 'queue' then status = 'open' and band <> 'low'
      when 'decided' then status <> 'open'
      when 'low' then band = 'low' and status = 'open'
      else true end
    order by (case band when 'high' then 0 when 'medium' then 1 else 2 end), last_activity_at desc
    limit ${limit}::int`;
  const tabCount = { queue: counts.queue, decided: counts.decided, low: counts.low, all: counts.total };

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('incidents.title')}</h1>
          <p className="lede">{t('incidents.lede', { queue: formatNumber(counts.queue) })}</p>
        </div>
      </header>
      <Flash params={params} t={t} scope="incidents" />
      <nav className="tabs" aria-label={t('incidents.views')}>
        {VIEWS.map((v) => (
          <Link key={v} href={v === 'queue' ? '/console/incidents' : `/console/incidents?view=${v}`} aria-current={v === view ? 'page' : undefined}>
            {t(`incidents.view.${v}`)} ({formatNumber(tabCount[v])})
          </Link>
        ))}
      </nav>
      <section className="panel">
        {rows.length === 0 ? (
          <p className="empty">{t(`incidents.empty.${view}`)}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('incidents.col.incident')}</th>
                  <th>{t('incidents.col.band')}</th>
                  <th className="right">{t('incidents.col.confidence')}</th>
                  <th className="right">{t('incidents.col.sources')}</th>
                  <th className="right">{t('incidents.col.alerts')}</th>
                  <th>{t('incidents.col.last')}</th>
                  <th>{t('incidents.col.status')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="linked">
                    <td className="wrap">
                      <Link className="row-link" href={`/console/incidents/${r.id}`}>
                        {r.title}
                      </Link>
                      <span className="sub">
                        {t('incidents.number', { id: r.id })} {[...r.hosts, ...r.users].slice(0, 4).join(', ')}
                      </span>
                    </td>
                    <td>
                      <Band band={r.band} label={t(`band.${r.band}`)} />
                    </td>
                    <td className="right num">{percent(r.confidence)}</td>
                    <td className="right num">{r.sources.length}</td>
                    <td className="right num">{formatNumber(r.alert_count)}</td>
                    <td className="num">{formatAgo(r.last_activity_at, r.now, t)}</td>
                    <td>
                      <Status tone={STATUS_TONE[r.status]} label={t(`incident_status.${r.status}`)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
