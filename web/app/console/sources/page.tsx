import Link from 'next/link';
import { Status } from '@/components/Status';
import { SourceStatus } from '@/components/SourceStatus';
import { Flash } from '@/components/ui';
import { sourcesConfigured } from '@/lib/crypto';
import { db } from '@/lib/db';
import { dayOf, formatAgo, formatNumber, formatWhen } from '@/lib/format';
import { finishLearning, learnAgain } from '@/lib/connectActions';
import { currentUser } from '@/lib/session';
import { flagSetting, getCopy, numberSetting, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function SourcesPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, user, params, demoOn, simulated, learningDays, zone] = await Promise.all([
    getCopy(), currentUser(), searchParams, flagSetting('demo.enabled'), flagSetting('engine.simulate'), numberSetting('learning.days'), textSetting('hospital.timezone'),
  ]);
  const admin = user?.role === 'admin';
  const sql = db();
  const [databases, uploads, logs, learning, senders, [windows]] = await Promise.all([
    sql<{ id: string; name: string; kind: string; host: string; state: string; pending: string | null; last_error: string | null; last_ok_at: Date | null; total_rows: string; rejected_rows: string; now: Date }[]>`
      select id::text as id, name, kind, coalesce(host, base_url) as host, state, pending, last_error, last_ok_at, total_rows::text, rejected_rows::text, now() as now
      from record_sources order by id`,
    sql<{ id: string; filename: string; status: string; row_count: number; accepted: number; rejected: number; uploaded_at: Date; now: Date }[]>`
      select id::text as id, filename, status, row_count, accepted, rejected, uploaded_at, now() as now
      from record_uploads where status <> 'discarded' order by id desc limit 10`,
    sql<{ id: string; name: string; enabled: boolean; last: Date | null; day: number; now: Date }[]>`
      select s.id, s.label as name, s.enabled, x.last, coalesce(x.day, 0)::int as day, now() as now
      from sources s left join lateral (
        select max(occurred_at) as last, count(*) filter (where occurred_at > now() - interval '24 hours') as day
        from events e where e.source = s.id and e.occurred_at > now() - interval '7 days') x on true
      order by s.sort_order, s.id`,
    sql<{ source: string; name: string; started_at: Date; ends_at: Date; finished_at: Date | null; finished_by: string | null; events: string; values_learned: string; now: Date }[]>`
      select l.source, s.label as name, l.started_at, l.ends_at, l.finished_at, l.finished_by, l.events::text, l.values_learned::text, now() as now
      from learning_periods l join sources s on s.id = l.source
      order by l.finished_at is not null, s.sort_order`,
    sql<{ id: string; label: string; state: string; format: string | null; last_seen_at: Date | null; stored: string; now: Date }[]>`
      select id::text as id, coalesce(nullif(name, ''), host(address)) as label, state, format, last_seen_at, stored::text, now() as now
      from log_senders where state <> 'blocked' order by state = 'pending' desc, last_seen_at desc nulls last limit 20`,
    sql<{ groups: number; computers: number }[]>`
      select (select count(*)::int from collectors where kind = 'windows' and enabled) as groups,
        (select count(distinct e.host)::int from events e join ingest_batches b on b.id = e.batch_pk join collectors c on c.id = b.collector_id
          where c.kind = 'windows' and e.occurred_at > now() - interval '7 days') as computers`,
  ]);
  const waiting = senders.filter((s) => s.state === 'pending').length;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('sources.title')}</h1>
          <p className="lede">{t('sources.lede')}</p>
        </div>
        {admin && (
          <div className="head-actions">
            <Link className="button button-primary" href="/console/sources/database/new">
              {t('sources.connect')}
            </Link>
            <Link className="button" href="/console/sources/fhir/new">
              {t('sources.connect_fhir')}
            </Link>
            <Link className="button" href="/console/sources/upload">
              {t('sources.upload')}
            </Link>
          </div>
        )}
      </header>
      <Flash params={params} t={t} scope="sources" />
      {admin && !sourcesConfigured() && <p className="flash flash-error">{t('error.sources.sources_not_configured')}</p>}
      {admin && demoOn && <p className="flash">{t('sources.demo_note')}</p>}

      <section className="panel">
        <div className="panel-head">
          <h2>{t('sources.databases.title')}</h2>
        </div>
        {databases.length === 0 ? (
          <p className="empty">{t('sources.databases.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('sources.col.name')}</th>
                  <th>{t('sources.col.status')}</th>
                  <th>{t('sources.col.last')}</th>
                  <th className="right">{t('sources.col.entries')}</th>
                  <th className="right">{t('sources.col.unreadable')}</th>
                </tr>
              </thead>
              <tbody>
                {databases.map((d) => (
                  <tr key={d.id} className="linked">
                    <td>
                      {admin ? (
                        <Link className="row-link" href={`/console/sources/${d.kind === 'fhir' ? 'fhir' : 'database'}/${d.id}`}>
                          {d.name}
                        </Link>
                      ) : (
                        d.name
                      )}
                      <span className="sub">
                        {t(`source_kind.${d.kind}`)}
                        {admin ? `, ${d.host}` : ''}
                      </span>
                    </td>
                    <td className="wrap">
                      <SourceStatus s={d} t={t} />
                      {admin && d.last_error && <span className="sub">{d.last_error}</span>}
                    </td>
                    <td>{d.last_ok_at ? formatAgo(d.last_ok_at, d.now, t) : t('sources.never')}</td>
                    <td className="right num">{formatNumber(Number(d.total_rows))}</td>
                    <td className="right num">{formatNumber(Number(d.rejected_rows))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {!simulated && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('sources.receiver.title')}</h2>
            {admin && (
              <Link className="button" href="/console/sources/receiver">
                {t(senders.length ? 'sources.receiver.manage' : 'sources.receiver.connect')}
              </Link>
            )}
          </div>
          {admin && waiting > 0 && <p className="flash">{t('sources.receiver.waiting', { n: waiting })}</p>}
          {senders.length === 0 ? (
            <p className="empty">{t('sources.receiver.empty')}</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t('receiver.col.device')}</th>
                    <th>{t('sources.col.status')}</th>
                    <th>{t('sources.col.last')}</th>
                    <th className="right">{t('receiver.col.stored')}</th>
                  </tr>
                </thead>
                <tbody>
                  {senders.map((d) => (
                    <tr key={d.id}>
                      <td>
                        {d.label}
                        <span className="sub">{d.format ?? t('receiver.format_unknown')}</span>
                      </td>
                      <td>
                        <Status tone={d.state === 'accepted' ? 'good' : 'warn'} label={t(`receiver.state.${d.state}`)} />
                      </td>
                      <td>{formatAgo(d.last_seen_at, d.now, t)}</td>
                      <td className="right num">{formatNumber(Number(d.stored))}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {!simulated && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('sources.windows.title')}</h2>
            {admin && (
              <Link className="button" href="/console/sources/windows">
                {t(windows.groups ? 'sources.windows.manage' : 'sources.windows.connect')}
              </Link>
            )}
          </div>
          <p className="panel-body">
            {windows.computers > 0 ? t('sources.windows.summary', { computers: windows.computers, groups: windows.groups }) : t('sources.windows.empty')}
          </p>
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>{t('sources.uploads.title')}</h2>
        </div>
        {uploads.length === 0 ? (
          <p className="empty">{t('sources.uploads.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('sources.col.file')}</th>
                  <th>{t('sources.col.status')}</th>
                  <th>{t('sources.col.when')}</th>
                  <th className="right">{t('sources.col.rows')}</th>
                  <th className="right">{t('sources.col.stored')}</th>
                  <th className="right">{t('sources.col.unreadable')}</th>
                </tr>
              </thead>
              <tbody>
                {uploads.map((u) => (
                  <tr key={u.id} className="linked">
                    <td>
                      {admin ? (
                        <Link className="row-link" href={`/console/sources/upload/${u.id}`}>
                          {u.filename}
                        </Link>
                      ) : (
                        u.filename
                      )}
                    </td>
                    <td>
                      <Status tone={u.status === 'imported' ? 'good' : 'warn'} label={t(`upload_status.${u.status}`)} />
                    </td>
                    <td>{formatAgo(u.uploaded_at, u.now, t)}</td>
                    <td className="right num">{formatNumber(u.row_count)}</td>
                    <td className="right num">{formatNumber(u.accepted)}</td>
                    <td className="right num">{formatNumber(u.rejected)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {!simulated && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('learning.title')}</h2>
            <p className="panel-note">{learningDays > 0 ? t('learning.note', { days: learningDays }) : t('learning.off')}</p>
          </div>
          {learning.length === 0 ? (
            <p className="empty">{t('learning.empty')}</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t('sources.col.source')}</th>
                    <th>{t('sources.col.status')}</th>
                    <th className="right">{t('learning.col.events')}</th>
                    {admin && <th />}
                  </tr>
                </thead>
                <tbody>
                  {learning.map((l) => {
                    const { day, days } = dayOf(l.started_at, l.ends_at, l.now);
                    const finishing = !l.finished_at && l.ends_at <= l.now;
                    return (
                      <tr key={l.source}>
                        <td>{l.name}</td>
                        <td className="wrap">
                          {l.finished_at ? (
                            <Status tone="good" label={t('learning.status.done')} />
                          ) : (
                            <Status tone="warn" label={finishing ? t('learning.status.finishing') : t('learning.status.learning', { day, days })} />
                          )}
                          <span className="sub">
                            {l.finished_at
                              ? t('learning.finished_on', { when: formatWhen(l.finished_at, zone) })
                              : t('learning.until', { when: formatWhen(l.ends_at, zone) })}
                          </span>
                        </td>
                        <td className="right num">{formatNumber(Number(l.events))}</td>
                        {admin && (
                          <td className="right">
                            {l.finished_at ? (
                              learningDays > 0 && (
                                <form action={learnAgain}>
                                  <input type="hidden" name="source" value={l.source} />
                                  <button className="button button-quiet" type="submit">{t('learning.again')}</button>
                                </form>
                              )
                            ) : (
                              !finishing && (
                                <form action={finishLearning}>
                                  <input type="hidden" name="source" value={l.source} />
                                  <button className="button button-quiet" type="submit">{t('learning.finish')}</button>
                                </form>
                              )
                            )}
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2>{t('sources.logs.title')}</h2>
          <p className="panel-note">{t('sources.logs.note')}</p>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('sources.col.source')}</th>
                <th>{t('sources.col.status')}</th>
                <th>{t('sources.col.last')}</th>
                <th className="right">{t('sources.col.day')}</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l) => {
                const fresh = l.last && l.now.getTime() - l.last.getTime() < 2 * 3600 * 1000;
                return (
                  <tr key={l.id}>
                    <td>{l.name}</td>
                    <td>
                      <Status
                        tone={!l.enabled ? 'quiet' : fresh ? 'good' : l.last ? 'warn' : 'quiet'}
                        label={t(!l.enabled ? 'log_status.off' : fresh ? 'log_status.reporting' : l.last ? 'log_status.quiet' : 'log_status.never')}
                      />
                    </td>
                    <td>{l.last ? formatAgo(l.last, l.now, t) : t('sources.never')}</td>
                    <td className="right num">{formatNumber(l.day)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
