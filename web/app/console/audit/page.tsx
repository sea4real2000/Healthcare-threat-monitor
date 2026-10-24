import { pretty } from '@/components/ui';
import { db } from '@/lib/db';
import { formatNumber } from '@/lib/format';
import { currentUser } from '@/lib/session';
import { getCopy, numberSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const GROUPS = ['', 'incident', 'alert', 'asset', 'isolation', 'release', 'rule', 'user', 'setting', 'scenario', 'models', 'feedback', 'setup', 'source', 'upload', 'learning', 'receiver', 'windows'];

interface Entry {
  seq: string;
  at_text: string;
  actor_type: string;
  actor_name: string;
  action: string;
  subject_type: string;
  subject_id: string;
  detail_text: string;
  hash: string;
}

export default async function AuditPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, user, params, limit] = await Promise.all([getCopy(), currentUser(), searchParams, numberSetting('console.audit_page_limit')]);
  const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v) ?? '';
  const group = GROUPS.includes(one(params.group)) ? one(params.group) : '';
  const subject = one(params.subject).slice(0, 64).trim();
  const sql = db();
  const [[check], entries] = await Promise.all([
    sql<{ ok: boolean; entries: string; broken_seq: string | null; reason: string | null; head_hash: string }[]>`
      select ok, entries::text as entries, broken_seq::text as broken_seq, reason, head_hash from audit_verify()`,
    sql<Entry[]>`
      select seq::text as seq, at_text, actor_type, actor_name, action, subject_type, subject_id, detail_text, hash
      from audit_log
      where (${group}::text = '' or action like ${group + '.%'}::text)
        and (${subject}::text = '' or subject_id = ${subject}::text)
      order by audit_log.seq desc limit ${limit}::int`,
  ]);

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('audit.title')}</h1>
          <p className="lede">{t('audit.lede')}</p>
        </div>
        {user && (
          <a className="button" href="/api/audit/export">
            {t('audit.export')}
          </a>
        )}
      </header>

      <div className={`verify ${check.ok ? '' : 'verify-bad'}`} role="status">
        <strong>{check.ok ? t('audit.verify.ok') : t('audit.verify.broken')}</strong>
        <span className="num">
          {check.ok
            ? t('audit.verify.ok_detail', { entries: formatNumber(Number(check.entries)) })
            : t('audit.verify.broken_detail', { seq: check.broken_seq ?? '', reason: check.reason ?? '', entries: formatNumber(Number(check.entries)) })}
        </span>
        <span className="mono">{t('audit.verify.head', { hash: check.head_hash })}</span>
      </div>

      <section className="panel" aria-labelledby="entries">
        <div className="panel-head">
          <h2 id="entries">{t('audit.entries.title')}</h2>
          <p className="panel-note">{t('audit.entries.note', { shown: formatNumber(entries.length) })}</p>
        </div>
        <form className="filters" method="get" action="/console/audit">
          <label>
            {t('audit.filter.group')}
            <select name="group" defaultValue={group}>
              {GROUPS.map((g) => (
                <option key={g} value={g}>
                  {g ? t(`audit.group.${g}`) : t('assets.filter.any')}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t('audit.filter.subject')}
            <input name="subject" defaultValue={subject} maxLength={64} />
          </label>
          <div className="actions">
            <button className="button button-primary" type="submit">
              {t('assets.filter.apply')}
            </button>
          </div>
        </form>
        {entries.length === 0 ? (
          <p className="empty">{t('audit.entries.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="right">{t('audit.col.seq')}</th>
                  <th>{t('audit.col.time')}</th>
                  <th>{t('audit.col.actor')}</th>
                  <th>{t('audit.col.action')}</th>
                  <th>{t('audit.col.subject')}</th>
                  <th>{t('audit.col.detail')}</th>
                  <th>{t('audit.col.hash')}</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.seq}>
                    <td className="right num">{e.seq}</td>
                    <td className="num">{e.at_text.slice(0, 19).replace('T', ' ')}</td>
                    <td>{e.actor_type === 'user' && !user ? t('audit.actor_hidden') : e.actor_name}</td>
                    <td>{pretty(e.action.replace('.', ': '))}</td>
                    <td>
                      {pretty(e.subject_type)} {e.subject_type === 'user' && !user ? '' : e.subject_id}
                    </td>
                    <td className="mono wrap">{e.detail_text === '{}' ? '' : e.detail_text.slice(0, 160)}</td>
                    <td className="mono">{e.hash.slice(0, 12)}</td>
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
