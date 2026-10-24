import { SettingsTabs } from '@/components/SettingsTabs';
import { Flash } from '@/components/ui';
import { saveCopy } from '@/lib/actions';
import { db } from '@/lib/db';
import { requireUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function CopyPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, params] = await Promise.all([getCopy(), searchParams]);
  const q = ((Array.isArray(params.q) ? params.q[0] : params.q) ?? '').slice(0, 80).trim();
  const like = `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
  const rows = await db()<{ key: string; value: string }[]>`
    select key, value from copy where ${q}::text = '' or key ilike ${like}::text or value ilike ${like}::text order by key limit 60`;
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('settings.title')}</h1>
          <p className="lede">{t('settings.copy.lede')}</p>
        </div>
      </header>
      <SettingsTabs t={t} current="copy" admin />
      <Flash params={params} t={t} scope="settings" />
      <section className="panel">
        <div className="panel-head">
          <h2>{t('settings.tab.copy')}</h2>
          <p className="panel-note">{t('settings.copy.note', { shown: rows.length })}</p>
        </div>
        <form className="filters" method="get" action="/console/settings/copy">
          <label>
            {t('settings.copy.search')}
            <input type="search" name="q" defaultValue={q} maxLength={80} />
          </label>
          <div className="actions">
            <button className="button button-primary" type="submit">
              {t('assets.filter.apply')}
            </button>
          </div>
        </form>
        <div className="table-wrap">
          <table>
            <tbody>
              {rows.map((r) => (
                <tr key={r.key}>
                  <td className="mono">{r.key}</td>
                  <td style={{ width: '65%' }}>
                    <form action={saveCopy} className="inline-form">
                      <input type="hidden" name="key" value={r.key} />
                      <input type="hidden" name="q" value={q} />
                      <input name="value" defaultValue={r.value} aria-label={r.key} maxLength={2000} required />
                      <button className="button" type="submit">
                        {t('settings.save')}
                      </button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
