import Link from 'next/link';
import { Flash } from '@/components/ui';
import { Status, type Tone } from '@/components/Status';
import { requestResponse } from '@/lib/actions';
import { currentUser, demoVisitor } from '@/lib/session';
import { formatAgo, formatNumber } from '@/lib/format';
import { loadAssets } from '@/lib/queries';
import { getCopy, numberSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const KINDS = ['workstation', 'server', 'medical_device', 'network'];
const STATUSES = ['active', 'isolated', 'offline'];
const STATUS_TONE: Record<string, Tone> = { active: 'good', isolated: 'crit', offline: 'quiet' };

function one(v: string | string[] | undefined): string {
  return (Array.isArray(v) ? v[0] : v)?.slice(0, 80).trim() ?? '';
}

export default async function AssetsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const filters = {
    q: one(params.q),
    kind: KINDS.includes(one(params.kind)) ? one(params.kind) : '',
    status: STATUSES.includes(one(params.status)) ? one(params.status) : '',
    department: one(params.department).toUpperCase(),
  };
  const [t, user, demo, windowMinutes, limit] = await Promise.all([
    getCopy(),
    currentUser(),
    demoVisitor(),
    numberSetting('console.overview_window_minutes'),
    numberSetting('console.assets_page_limit'),
  ]);
  const data = await loadAssets(filters, windowMinutes, limit);
  const filtered = Boolean(filters.q || filters.kind || filters.status || filters.department);

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('assets.title')}</h1>
          <p className="lede">
            {t('assets.summary', {
              total: formatNumber(data.counts.total),
              workstations: formatNumber(data.counts.workstation),
              servers: formatNumber(data.counts.server),
              devices: formatNumber(data.counts.medical_device),
              network: formatNumber(data.counts.network),
              isolated: formatNumber(data.counts.isolated),
            })}
          </p>
        </div>
      </header>

      <Flash params={params} t={t} scope="incident" />
      <section className="panel" aria-labelledby="assets-list">
        <div className="panel-head">
          <h2 id="assets-list">{t('assets.list.title')}</h2>
          <p className="panel-note num">
            {t('assets.list.shown', { shown: formatNumber(data.rows.length), total: formatNumber(data.counts.total) })}
          </p>
        </div>
        <form className="filters" method="get" action="/console/assets">
          <label>
            {t('assets.filter.search')}
            <input type="search" name="q" defaultValue={filters.q} maxLength={80} />
          </label>
          <label>
            {t('assets.filter.kind')}
            <select name="kind" defaultValue={filters.kind}>
              <option value="">{t('assets.filter.any')}</option>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {t(`kind.${k}`)}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t('assets.filter.department')}
            <select name="department" defaultValue={filters.department}>
              <option value="">{t('assets.filter.any')}</option>
              {data.departments.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t('assets.filter.status')}
            <select name="status" defaultValue={filters.status}>
              <option value="">{t('assets.filter.any')}</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {t(`asset_status.${s}`)}
                </option>
              ))}
            </select>
          </label>
          <div className="actions">
            <button className="button button-primary" type="submit">
              {t('assets.filter.apply')}
            </button>
            {filtered && (
              <Link className="button" href="/console/assets">
                {t('assets.filter.clear')}
              </Link>
            )}
          </div>
        </form>

        {data.rows.length === 0 ? (
          <p className="empty">{data.counts.total === 0 ? t('assets.none') : t('assets.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('assets.col.asset')}</th>
                  <th>{t('assets.col.kind')}</th>
                  <th>{t('assets.col.department')}</th>
                  <th>{t('assets.col.zone')}</th>
                  <th>{t('assets.col.address')}</th>
                  <th>{t('assets.col.status')}</th>
                  <th>{t('assets.col.last_seen')}</th>
                  <th className="right">{t('assets.col.events', { minutes: windowMinutes })}</th>
                </tr>
              </thead>
              <tbody>
                {data.rows.map((a) => (
                  <tr key={a.id}>
                    <td>
                      {a.id}
                      <span className="sub">
                        {a.role.replaceAll('_', ' ')}
                        {a.os ? `, ${a.os}` : ''}
                      </span>
                    </td>
                    <td>{t(`kind.${a.kind}`)}</td>
                    <td>{a.department ?? ''}</td>
                    <td>{a.zone}</td>
                    <td className="num">{a.ip ?? ''}</td>
                    <td>
                      <Status tone={STATUS_TONE[a.status] ?? 'quiet'} label={t(`asset_status.${a.status}`)} />
                      {(user || demo) && a.status === 'isolated' && (
                        <form action={requestResponse} style={{ marginTop: 6 }}>
                          <input type="hidden" name="asset_id" value={a.id} />
                          <input type="hidden" name="action" value="release" />
                          <button className="button" type="submit">
                            {t('incident.machines.release', { asset: a.id })}
                          </button>
                        </form>
                      )}
                    </td>
                    <td className="num">{formatAgo(a.last_seen_at, data.now, t)}</td>
                    <td className="right num">{formatNumber(a.events)}</td>
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
