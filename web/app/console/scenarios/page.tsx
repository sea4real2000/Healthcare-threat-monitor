import Link from 'next/link';
import { AutoRefresh } from '@/components/AutoRefresh';
import { Flash, pretty } from '@/components/ui';
import { Status, type Tone } from '@/components/Status';
import { launchScenario } from '@/lib/actions';
import { db } from '@/lib/db';
import { formatAgo, formatClock } from '@/lib/format';
import { currentUser, demoVisitor } from '@/lib/session';
import { flagSetting, getCopy, numberSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const SCENARIOS = ['ransomware', 'record_snooping', 'device_compromise'];
const TONE: Record<string, Tone> = { requested: 'quiet', running: 'warn', completed: 'good', contained: 'good', failed: 'crit' };

interface Run {
  id: string;
  scenario: string;
  status: string;
  requested_by: string | null;
  requested_at: Date;
  target: { hosts?: string[]; users?: string[] };
  note: string | null;
  incident_id: string | null;
  band: string | null;
  now: Date;
}

export default async function ScenariosPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, user, demo, params, refresh, simulated] = await Promise.all([getCopy(), currentUser(), demoVisitor(), searchParams, numberSetting('console.refresh_seconds'), flagSetting('engine.simulate')]);
  const sql = db();
  const runs = await sql<Run[]>`
    select r.id::text as id, r.scenario, r.status, r.requested_by, r.requested_at, r.target, r.note, now() as now, i.id::text as incident_id, i.band
    from scenario_runs r
    left join lateral (
      select id, band from incidents
      where opened_at <= coalesce(r.last_event_at, now()) + interval '15 minutes' and last_activity_at >= r.first_event_at - interval '1 minute'
        and (r.target->'hosts' ?| hosts or r.target->'users' ?| users)
      order by confidence desc limit 1
    ) i on r.first_event_at is not null
    where r.evaluation_run_id is null
    order by r.id desc limit 25`;
  const busy = runs.some((r) => r.status === 'requested' || r.status === 'running');
  const [heartbeat] = await sql<{ fresh: boolean }[]>`
    select coalesce((select updated_at > now() - interval '2 minutes' from engine_state where key = 'heartbeat'), false) as fresh`;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('scenarios.title')}</h1>
          <p className="lede">{t('scenarios.lede')}</p>
        </div>
        <AutoRefresh seconds={refresh} updatedText={t('refresh.updated', { time: formatClock(new Date(), true) })} pauseLabel={t('refresh.pause')} resumeLabel={t('refresh.resume')} />
      </header>
      <Flash params={params} t={t} scope="scenarios" />
      {!simulated && <p className="flash">{t('scenarios.no_simulation')}</p>}
      {simulated && !heartbeat.fresh && <p className="flash flash-error">{t('scenarios.service_down')}</p>}
      <div className="cards">
        {SCENARIOS.map((s) => (
          <div className="card" key={s}>
            <h2>{t(`scenario.${s}.name`)}</h2>
            <p>{t(`scenario.${s}.description`)}</p>
            <p className="panel-note">{t(`scenario.${s}.expect`)}</p>
            {simulated && (user || demo) ? (
              <form action={launchScenario}>
                <input type="hidden" name="scenario" value={s} />
                <button className="button button-primary" type="submit" disabled={busy}>
                  {t('scenarios.launch')}
                </button>
              </form>
            ) : (
              <span className="panel-note">{t('scenarios.sign_in')}</span>
            )}
          </div>
        ))}
      </div>
      <section className="panel" aria-labelledby="runs">
        <div className="panel-head">
          <h2 id="runs">{t('scenarios.runs.title')}</h2>
          <p className="panel-note">{t('scenarios.runs.note')}</p>
        </div>
        {runs.length === 0 ? (
          <p className="empty">{t('scenarios.runs.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('scenarios.col.run')}</th>
                  <th>{t('scenarios.col.status')}</th>
                  <th>{t('scenarios.col.target')}</th>
                  <th>{t('scenarios.col.requested')}</th>
                  <th>{t('scenarios.col.incident')}</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td>
                      {t(`scenario.${r.scenario}.name`)}
                      <span className="sub">{t('scenarios.run_number', { id: r.id })}</span>
                    </td>
                    <td>
                      <Status tone={TONE[r.status] ?? 'quiet'} label={t(`scenario_status.${r.status}`)} />
                    </td>
                    <td>{[...(r.target.hosts ?? []), ...(r.target.users ?? [])].join(', ')}</td>
                    <td>
                      {formatAgo(r.requested_at, r.now, t)}
                      <span className="sub">{user ? (r.requested_by ?? '') : ''}</span>
                    </td>
                    <td>
                      {r.incident_id ? (
                        <Link href={`/console/incidents/${r.incident_id}`}>{t('scenarios.incident_link', { id: r.incident_id, band: pretty(r.band ?? '') })}</Link>
                      ) : (
                        t('scenarios.no_incident')
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
