import Link from 'next/link';
import { Flash, percent, pretty } from '@/components/ui';
import { Status } from '@/components/Status';
import { removeException } from '@/lib/actions';
import { db } from '@/lib/db';
import { formatNumber } from '@/lib/format';
import { currentUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

interface RuleRow {
  id: string;
  name: string;
  category: string;
  kind: string;
  severity: number;
  confidence: string;
  technique_id: string | null;
  enabled: boolean;
  load_error: string | null;
  alerts: number;
  decided: number;
  dismissed: number;
}

export default async function RulesPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, user, params] = await Promise.all([getCopy(), currentUser(), searchParams]);
  const sql = db();
  const [rules, exceptions, [learned]] = await Promise.all([
    sql<RuleRow[]>`
      select r.id, r.name, r.category, r.kind, r.severity, r.confidence::text as confidence, r.technique_id, r.enabled, r.load_error,
             coalesce(s.alerts, 0)::int as alerts, coalesce(s.decided, 0)::int as decided, coalesce(s.dismissed, 0)::int as dismissed
      from rules r
      left join (
        select a.detector_id, count(*) as alerts,
               count(*) filter (where i.status <> 'open') as decided,
               count(*) filter (where i.status = 'dismissed') as dismissed
        from alerts a left join incidents i on i.id = a.incident_id
        where a.detector_type = 'rule' group by 1
      ) s on s.detector_id = r.id
      order by r.category, r.id`,
    sql<{ id: string; detector_type: string; detector_id: string; entity: string; kind: string; value: string | null; created_by: string | null }[]>`
      select id::text as id, detector_type, detector_id, entity, kind, value::text as value, created_by
      from detector_exceptions order by detector_exceptions.id desc limit 200`,
    sql<{ n: number }[]>`select count(*)::int as n from baseline_values where origin = 'feedback'`,
  ]);
  const categories = [...new Set(rules.map((r) => r.category))];

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('rules.title')}</h1>
          <p className="lede">{t('rules.lede', { total: rules.length, enabled: rules.filter((r) => r.enabled).length })}</p>
        </div>
        {user && (
          <Link className="button button-primary" href="/console/rules/new">
            {t('rules.add')}
          </Link>
        )}
      </header>
      <Flash params={params} t={t} scope="rules" />
      {categories.map((category) => (
        <section className="panel" key={category} aria-label={t(`category.${category}`)}>
          <div className="panel-head">
            <h2>{t(`category.${category}`)}</h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('rules.col.rule')}</th>
                  <th>{t('rules.col.kind')}</th>
                  <th>{t('rules.col.technique')}</th>
                  <th className="right">{t('rules.col.confidence')}</th>
                  <th className="right">{t('rules.col.alerts')}</th>
                  <th className="right">{t('rules.col.dismissed')}</th>
                  <th>{t('rules.col.state')}</th>
                </tr>
              </thead>
              <tbody>
                {rules
                  .filter((r) => r.category === category)
                  .map((r) => (
                    <tr key={r.id} className="linked">
                      <td className="wrap">
                        <Link className="row-link" href={`/console/rules/${r.id}`}>
                          {r.name}
                        </Link>
                        <span className="sub">{r.id}</span>
                      </td>
                      <td>{t(`rule_kind.${r.kind}`)}</td>
                      <td>{r.technique_id ?? ''}</td>
                      <td className="right num">{percent(r.confidence)}</td>
                      <td className="right num">{formatNumber(r.alerts)}</td>
                      <td className="right num">{r.decided > 0 ? percent(r.dismissed / r.decided) : ''}</td>
                      <td>
                        {r.load_error ? (
                          <Status tone="crit" label={t('rules.state.error')} />
                        ) : (
                          <Status tone={r.enabled ? 'good' : 'quiet'} label={t(r.enabled ? 'rules.state.on' : 'rules.state.off')} />
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}

      <section className="panel" aria-labelledby="learned">
        <div className="panel-head">
          <h2 id="learned">{t('rules.learned.title')}</h2>
          <p className="panel-note">{t('rules.learned.note', { values: formatNumber(learned.n) })}</p>
        </div>
        {exceptions.length === 0 ? (
          <p className="empty">{t('rules.learned.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('rules.learned.col.detector')}</th>
                  <th>{t('rules.learned.col.entity')}</th>
                  <th>{t('rules.learned.col.change')}</th>
                  <th>{t('rules.learned.col.by')}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {exceptions.map((e) => (
                  <tr key={e.id}>
                    <td>{pretty(e.detector_id)}</td>
                    <td>{e.entity}</td>
                    <td>{e.kind === 'suppress' ? t('rules.learned.suppress') : t('rules.learned.threshold', { value: Number(e.value) })}</td>
                    <td>{user ? (e.created_by ?? '') : t('audit.actor_hidden')}</td>
                    <td className="right">
                      {user && (
                        <form action={removeException}>
                          <input type="hidden" name="exception_id" value={e.id} />
                          <input type="hidden" name="return_to" value="/console/rules" />
                          <button className="button" type="submit">
                            {t('rules.learned.remove')}
                          </button>
                        </form>
                      )}
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
