import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Band, Flash, percent, pretty } from '@/components/ui';
import { Status } from '@/components/Status';
import { decideIncident, requestResponse } from '@/lib/actions';
import { db } from '@/lib/db';
import { formatClock, formatNumber } from '@/lib/format';
import { currentUser, demoVisitor } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

interface Evidence {
  id: number;
  at: string;
  source: string;
  action: string;
  outcome: string;
  user: string | null;
  host: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  detail: string | null;
}

interface AlertRow {
  id: string;
  detector_type: string;
  detector_id: string;
  title: string;
  confidence: string;
  severity: number;
  technique_id: string | null;
  technique_name: string | null;
  hits: number;
  observed: string | null;
  occurred_at: Date;
  evidence: Evidence[];
  explanation: { label: string; value: number; typical: number; beyond_training?: boolean }[];
  description: string | null;
}

function stamp(d: Date): string {
  return `${d.toISOString().slice(0, 10)} ${formatClock(d, true)}`;
}

export default async function IncidentPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { id } = await params;
  if (!/^\d{1,18}$/.test(id)) notFound();
  const [t, user, demo, query] = await Promise.all([getCopy(), currentUser(), demoVisitor(), searchParams]);
  // The demo visitor may isolate and release, like an analyst, but may not decide the incident.
  const responder = Boolean(user || demo);
  const sql = db();
  const [incident] = await sql`
    select id::text as id, title, category, status, band, confidence::text as confidence, severity, opened_at, last_activity_at, medium_at, high_at,
           hosts, users, sources, techniques, alert_count, decided_by_name, decided_at, decision_reason, decision_note
    from incidents where id = ${id}::bigint`;
  if (!incident) notFound();

  const [alerts, assets, actions, feedback, sourceLabels, scenario] = await Promise.all([
    sql<AlertRow[]>`
      select a.id::text as id, a.detector_type, a.detector_id, a.title, a.confidence::text as confidence, a.severity, a.technique_id, a.technique_name,
             a.hits, a.observed::text as observed, a.occurred_at, a.evidence, a.explanation,
             coalesce(r.description, m.description) as description
      from alerts a
      left join rules r on a.detector_type = 'rule' and r.id = a.detector_id
      left join models m on a.detector_type = 'model' and m.id = a.detector_id
      where a.incident_id = ${id}::bigint order by a.occurred_at, a.id limit 400`,
    sql<{ id: string; kind: string; role: string; status: string; waiting: string | null }[]>`
      select s.id, s.kind, s.role, s.status,
             (select action from response_actions ra where ra.asset_id = s.id and ra.status = 'requested' limit 1) as waiting
      from assets s where s.id = any(${incident.hosts as string[]}) order by s.id`,
    sql<{ id: string; action: string; asset_id: string; status: string; requested_by_name: string; requested_at: Date; acknowledged_at: Date | null }[]>`
      select id::text as id, action, asset_id, status, requested_by_name, requested_at, acknowledged_at
      from response_actions where incident_id = ${id}::bigint order by response_actions.id`,
    sql<{ applied: { detector: string; entity: string; change?: string; value?: number; learned_value?: string; normal_for_all?: boolean }[] | null; applied_at: Date | null }[]>`
      select applied, applied_at from feedback where incident_id = ${id}::bigint order by id desc limit 1`,
    sql<{ id: string; label: string }[]>`select id, label from sources`,
    sql<{ id: string; scenario: string; requested_by: string | null }[]>`
      select id::text as id, scenario, requested_by from scenario_runs
      where first_event_at <= ${incident.last_activity_at as Date} and coalesce(last_event_at, now()) >= ${incident.opened_at as Date}::timestamptz - interval '1 minute'
        and (target->'hosts' ?| ${incident.hosts as string[]} or target->'users' ?| ${incident.users as string[]})
      order by scenario_runs.id limit 1`,
  ]);
  const sourceName = new Map(sourceLabels.map((s) => [s.id, s.label]));

  // Group alerts by the detector that raised them, strongest first.
  const groups = new Map<string, AlertRow[]>();
  for (const a of alerts) groups.set(a.detector_id, [...(groups.get(a.detector_id) ?? []), a]);
  const detectors = [...groups.values()].sort(
    (x, y) => Math.max(...y.map((a) => Number(a.confidence))) - Math.max(...x.map((a) => Number(a.confidence))),
  );

  // One timeline from every alert's evidence, each event once.
  const seen = new Map<number, Evidence>();
  for (const a of alerts) for (const e of a.evidence) seen.set(e.id, e);
  const timeline = [...seen.values()].sort((a, b) => a.at.localeCompare(b.at));
  const shown = timeline.slice(0, 120);
  const canAct = Boolean(user) && incident.status === 'open';
  const learned = feedback[0]?.applied ?? null;

  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/incidents">{t('incidents.title')}</Link> / {t('incidents.number', { id: incident.id as string })}
          </p>
          <h1>{incident.title as string}</h1>
          <div className="meta">
            <Band band={incident.band as string} label={t(`band.${incident.band}`)} />
            <span>{t('incident.confidence', { value: percent(incident.confidence as string) })}</span>
            <span>{t(`incident_status.${incident.status}`)}</span>
            <span>{t('incident.sources_agree', { n: (incident.sources as string[]).length })}</span>
          </div>
        </div>
      </header>
      <Flash params={query} t={t} scope="incident" />
      {scenario[0] && (
        <p className="flash">
          {t('incident.scenario_note', { scenario: pretty(scenario[0].scenario), run: scenario[0].id, by: scenario[0].requested_by ?? '' })}
        </p>
      )}

      <div className="split">
        <div>
          <section className="panel" aria-labelledby="why">
            <div className="panel-head">
              <h2 id="why">{t('incident.why.title')}</h2>
              <p className="panel-note">{t('incident.why.note', { detectors: detectors.length, alerts: formatNumber(alerts.length) })}</p>
            </div>
            {detectors.map((group) => {
              const top = group.reduce((a, b) => (Number(b.confidence) > Number(a.confidence) ? b : a));
              const hits = group.reduce((n, a) => n + a.hits, 0);
              return (
                <div className="detector" key={top.detector_id}>
                  <h3>{top.title}</h3>
                  {top.description && <p>{top.description}</p>}
                  <div className="meta">
                    <span>{t(`detector.${top.detector_type}`)}</span>
                    <span>{t('incident.detector.confidence', { value: percent(top.confidence) })}</span>
                    <span>{t('incident.detector.hits', { alerts: group.length, events: formatNumber(hits) })}</span>
                    {top.technique_id && (
                      <a href={`https://attack.mitre.org/${top.technique_id.startsWith('TA') ? 'tactics' : 'techniques'}/${top.technique_id.replace('.', '/')}/`} rel="noreferrer" target="_blank">
                        {top.technique_id} {top.technique_name}
                      </a>
                    )}
                  </div>
                  {top.explanation.length > 0 && (
                    <ul>
                      {top.explanation.map((x) => (
                        <li key={x.label}>
                          {t(x.beyond_training ? 'incident.feature.beyond' : 'incident.feature', { label: x.label, value: formatNumber(x.value), typical: formatNumber(x.typical) })}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              );
            })}
          </section>

          <section className="panel" aria-labelledby="timeline">
            <div className="panel-head">
              <h2 id="timeline">{t('incident.timeline.title')}</h2>
              <p className="panel-note">{t('incident.timeline.note', { shown: shown.length, total: timeline.length })}</p>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t('incident.timeline.col.time')}</th>
                    <th>{t('incident.timeline.col.source')}</th>
                    <th>{t('incident.timeline.col.action')}</th>
                    <th>{t('incident.timeline.col.who')}</th>
                    <th>{t('incident.timeline.col.detail')}</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((e) => (
                    <tr key={e.id}>
                      <td className="num">{formatClock(new Date(e.at), true)}</td>
                      <td>{sourceName.get(e.source) ?? e.source}</td>
                      <td>
                        {pretty(e.action)}
                        {e.outcome === 'failure' && <span className="sub">{t('outcome.failure')}</span>}
                      </td>
                      <td>
                        {e.host ?? e.src_ip ?? ''}
                        <span className="sub">{e.user ?? ''}</span>
                      </td>
                      <td className="mono">{e.detail ?? (e.dst_ip ? `${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ''}` : '')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <div>
          <section className="panel" aria-labelledby="facts">
            <div className="panel-head">
              <h2 id="facts">{t('incident.facts.title')}</h2>
            </div>
            <dl className="facts">
              <dt>{t('incident.facts.opened')}</dt>
              <dd className="num">{stamp(incident.opened_at as Date)} UTC</dd>
              <dt>{t('incident.facts.last')}</dt>
              <dd className="num">{stamp(incident.last_activity_at as Date)} UTC</dd>
              <dt>{t('incident.facts.sources')}</dt>
              <dd>{(incident.sources as string[]).map((s) => sourceName.get(s) ?? s).join(', ')}</dd>
              <dt>{t('incident.facts.people')}</dt>
              <dd>{(incident.users as string[]).join(', ') || t('incident.none')}</dd>
              <dt>{t('incident.facts.techniques')}</dt>
              <dd>{(incident.techniques as string[]).join(', ') || t('incident.none')}</dd>
            </dl>
          </section>

          <section className="panel" aria-labelledby="machines">
            <div className="panel-head">
              <h2 id="machines">{t('incident.machines.title')}</h2>
            </div>
            {assets.length === 0 ? (
              <p className="empty">{t('incident.machines.none')}</p>
            ) : (
              <div className="stack">
                {assets.map((a) => (
                  <div key={a.id}>
                    <strong>{a.id}</strong> <span className="sub">{pretty(a.role)}</span>
                    <div className="meta">
                      <Status tone={a.status === 'isolated' ? 'crit' : a.status === 'active' ? 'good' : 'quiet'} label={t(`asset_status.${a.status}`)} />
                      {a.waiting && <span>{t(`incident.machines.waiting.${a.waiting}`)}</span>}
                    </div>
                    {responder && !a.waiting && a.status === 'active' && incident.band === 'high' && incident.status !== 'dismissed' && (
                      <form action={requestResponse} style={{ marginTop: 8 }}>
                        <input type="hidden" name="incident_id" value={incident.id as string} />
                        <input type="hidden" name="asset_id" value={a.id} />
                        <input type="hidden" name="action" value="isolate" />
                        <button className="button button-danger" type="submit">
                          {t('incident.machines.isolate', { asset: a.id })}
                        </button>
                      </form>
                    )}
                    {responder && !a.waiting && a.status === 'isolated' && (
                      <form action={requestResponse} style={{ marginTop: 8 }}>
                        <input type="hidden" name="incident_id" value={incident.id as string} />
                        <input type="hidden" name="asset_id" value={a.id} />
                        <input type="hidden" name="action" value="release" />
                        <button className="button" type="submit">
                          {t('incident.machines.release', { asset: a.id })}
                        </button>
                      </form>
                    )}
                  </div>
                ))}
                {incident.band !== 'high' && <p className="panel-note">{t('incident.machines.not_eligible')}</p>}
                {!responder && incident.band === 'high' && <p className="panel-note">{t('incident.sign_in_to_act')}</p>}
              </div>
            )}
          </section>

          <section className="panel" aria-labelledby="decision">
            <div className="panel-head">
              <h2 id="decision">{t('incident.decision.title')}</h2>
            </div>
            {incident.status !== 'open' ? (
              <>
                <dl className="facts">
                  <dt>{t('incident.decision.outcome')}</dt>
                  <dd>{t(`incident_status.${incident.status}`)}</dd>
                  <dt>{t('incident.decision.by')}</dt>
                  <dd>{user ? (incident.decided_by_name as string) : t('audit.actor_hidden')}</dd>
                  <dt>{t('incident.decision.at')}</dt>
                  <dd className="num">{incident.decided_at ? `${stamp(incident.decided_at as Date)} UTC` : ''}</dd>
                  <dt>{t('incident.decision.reason')}</dt>
                  <dd>{t(`reason.${incident.decision_reason}`)}</dd>
                  {incident.decision_note && (
                    <>
                      <dt>{t('incident.decision.note')}</dt>
                      <dd>{incident.decision_note as string}</dd>
                    </>
                  )}
                </dl>
                {learned && (
                  <div className="stack">
                    <strong>{t('incident.learned.title')}</strong>
                    {learned.length === 0 ? (
                      <span className="panel-note">{t('incident.learned.nothing')}</span>
                    ) : (
                      learned.map((c, i) => (
                        <span className="panel-note" key={i}>
                          {c.learned_value
                            ? t(c.normal_for_all ? 'incident.learned.value_all' : 'incident.learned.value', { detector: pretty(c.detector), entity: c.entity, value: c.learned_value })
                            : c.change === 'suppress'
                              ? t('incident.learned.suppress', { detector: pretty(c.detector), entity: c.entity })
                              : t('incident.learned.threshold', { detector: pretty(c.detector), entity: c.entity, value: c.value ?? '' })}
                        </span>
                      ))
                    )}
                  </div>
                )}
              </>
            ) : canAct ? (
              <>
                <form action={decideIncident} className="stack">
                  <input type="hidden" name="incident_id" value={incident.id as string} />
                  <input type="hidden" name="verdict" value="confirm" />
                  <label>
                    {t('incident.decision.confirm_reason')}
                    <select name="reason" defaultValue="confirmed_attack">
                      <option value="confirmed_attack">{t('reason.confirmed_attack')}</option>
                      <option value="policy_violation">{t('reason.policy_violation')}</option>
                    </select>
                  </label>
                  <label>
                    {t('incident.decision.note')}
                    <input name="note" maxLength={1000} />
                  </label>
                  <button className="button button-primary" type="submit">
                    {t('incident.decision.confirm')}
                  </button>
                </form>
                <hr className="divider" />
                <form action={decideIncident} className="stack">
                  <input type="hidden" name="incident_id" value={incident.id as string} />
                  <input type="hidden" name="verdict" value="dismiss" />
                  <label>
                    {t('incident.decision.dismiss_reason')}
                    <select name="reason" defaultValue="expected_activity">
                      <option value="expected_activity">{t('reason.expected_activity')}</option>
                      <option value="not_enough_evidence">{t('reason.not_enough_evidence')}</option>
                      <option value="duplicate">{t('reason.duplicate')}</option>
                      <option value="test_activity">{t('reason.test_activity')}</option>
                    </select>
                  </label>
                  <label>
                    {t('incident.decision.note')}
                    <input name="note" maxLength={1000} />
                  </label>
                  <button className="button" type="submit">
                    {t('incident.decision.dismiss')}
                  </button>
                  <span className="panel-note">{t('incident.decision.teach_note')}</span>
                </form>
              </>
            ) : (
              <p className="empty">{t('incident.sign_in_to_act')}</p>
            )}
          </section>

          {actions.length > 0 && (
            <section className="panel" aria-labelledby="actions">
              <div className="panel-head">
                <h2 id="actions">{t('incident.actions.title')}</h2>
              </div>
              <div className="stack">
                {actions.map((a) => (
                  <span key={a.id} className="panel-note">
                    {t(`incident.actions.${a.action}.${a.status}`, {
                      asset: a.asset_id,
                      by: user ? a.requested_by_name : t('audit.actor_hidden'),
                      time: formatClock(a.acknowledged_at ?? a.requested_at, true),
                    })}
                  </span>
                ))}
              </div>
            </section>
          )}
        </div>
      </div>
    </>
  );
}
