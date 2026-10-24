import { SettingsTabs } from '@/components/SettingsTabs';
import { Flash } from '@/components/ui';
import { saveSetting } from '@/lib/actions';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function SettingsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, user, params] = await Promise.all([getCopy(), currentUser(), searchParams]);
  const admin = user?.role === 'admin';
  const rows = await db()<{ key: string; value: unknown; description: string | null }[]>`select key, value, description from settings order by key`;
  const groups = [...new Set(rows.map((r) => r.key.split('.')[0]))];
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('settings.title')}</h1>
          <p className="lede">{t(admin ? 'settings.lede.admin' : 'settings.lede.read_only')}</p>
        </div>
      </header>
      <SettingsTabs t={t} current="settings" admin={admin} />
      <Flash params={params} t={t} scope="settings" />
      {groups.map((g) => (
        <section className="panel" key={g} aria-label={g}>
          <div className="panel-head">
            <h2>{t(`settings.group.${g}`)}</h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('settings.col.setting')}</th>
                  <th>{t('settings.col.value')}</th>
                </tr>
              </thead>
              <tbody>
                {rows
                  .filter((r) => r.key.split('.')[0] === g)
                  .map((r) => (
                    <tr key={r.key}>
                      <td className="wrap">
                        {r.description}
                        <span className="sub">{r.key}</span>
                      </td>
                      <td>
                        {admin ? (
                          <form action={saveSetting} className="inline-form">
                            <input type="hidden" name="key" value={r.key} />
                            {typeof r.value === 'boolean' ? (
                              <select name="value" defaultValue={String(r.value)} aria-label={r.key}>
                                <option value="true">{t('settings.on')}</option>
                                <option value="false">{t('settings.off')}</option>
                              </select>
                            ) : (
                              <input name="value" defaultValue={String(r.value)} aria-label={r.key} inputMode={typeof r.value === 'number' ? 'decimal' : 'text'} maxLength={2000} />
                            )}
                            <button className="button" type="submit">
                              {t('settings.save')}
                            </button>
                          </form>
                        ) : (
                          <span className="num">{typeof r.value === 'boolean' ? t(r.value ? 'settings.on' : 'settings.off') : String(r.value) || t('settings.empty')}</span>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </>
  );
}
