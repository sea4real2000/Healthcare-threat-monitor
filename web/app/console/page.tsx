import Link from 'next/link';
import { AutoRefresh } from '@/components/AutoRefresh';
import { RateChart } from '@/components/RateChart';
import { Spark } from '@/components/Spark';
import { Status, type Tone } from '@/components/Status';
import { db } from '@/lib/db';
import { formatAgo, formatClock, formatNumber, formatRate, formatWhen } from '@/lib/format';
import { loadOverview } from '@/lib/queries';
import { getCopy, numberSetting, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const OUTCOME_TONE: Record<string, Tone> = { success: 'good', failure: 'warn', unknown: 'quiet' };

export default async function OverviewPage() {
  const [t, windowMinutes, silentAfter, refreshSeconds, recentLimit] = await Promise.all([
    getCopy(),
    numberSetting('console.overview_window_minutes'),
    numberSetting('console.source_silent_after_minutes'),
    numberSetting('console.refresh_seconds'),
    numberSetting('console.recent_events_limit'),
  ]);
  const data = await loadOverview(windowMinutes, silentAfter, recentLimit);
  const [watch] = await db()<{ high: number; medium: number; isolated: number; fresh: boolean; trained: boolean }[]>`
    select count(*) filter (where status = 'open' and band = 'high')::int as high,
           count(*) filter (where status = 'open' and band = 'medium')::int as medium,
           (select count(*)::int from assets where status = 'isolated') as isolated,
           coalesce((select updated_at > now() - interval '2 minutes' from engine_state where key = 'heartbeat'), false) as fresh,
           coalesce((select (value->>'trained')::boolean from engine_state where key = 'heartbeat'), false) as trained
    from incidents`;
  const [learning] = await db()<{ n: number; until: Date | null }[]>`
    select count(*)::int as n, max(ends_at) as until from learning_periods where finished_at is null`;
  const zone = await textSetting('hospital.timezone');
  const silentBefore = data.now.getTime() - silentAfter * 60000;
  const points = data.totals.map((value, i) => ({
    time: formatClock(new Date(data.windowStart.getTime() + i * 60000)),
    value,
  }));

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('overview.title')}</h1>
          <p className="lede">
            {t('overview.summary', {
              reporting: data.reporting,
              total: data.sources.length,
              events: formatNumber(data.totalEvents),
              minutes: windowMinutes,
            })}
          </p>
        </div>
        <AutoRefresh
          seconds={refreshSeconds}
          updatedText={t('refresh.updated', { time: formatClock(data.now, true) })}
          pauseLabel={t('refresh.pause')}
          resumeLabel={t('refresh.resume')}
        />
      </header>

      {learning.n > 0 && learning.until && (
        <p className="flash">
          {t('learning.banner', { until: formatWhen(learning.until, zone) })} <Link href="/console/sources">{t('learning.banner_link')}</Link>
        </p>
      )}

      <dl className="figures">
        <div>
          <dt>{t('overview.figure.events', { minutes: windowMinutes })}</dt>
          <dd className="num">{formatNumber(data.totalEvents)}</dd>
        </div>
        <div>
          <dt>{t('overview.figure.sources')}</dt>
          <dd className="num">
            {data.reporting} <small>{t('overview.figure.of', { total: data.sources.length })}</small>
          </dd>
        </div>
        <div>
          <dt>{t('overview.figure.assets', { minutes: windowMinutes })}</dt>
          <dd className="num">
            {formatNumber(data.assetsSeen)} <small>{t('overview.figure.of', { total: formatNumber(data.assetsTotal) })}</small>
          </dd>
        </div>
        <div>
          <dt>{t('overview.figure.rejects', { minutes: windowMinutes })}</dt>
          <dd className="num">{formatNumber(data.rejects)}</dd>
        </div>
      </dl>

      <section className="panel" aria-labelledby="watch-title">
        <div className="panel-head">
          <h2 id="watch-title">{t('overview.watch.title')}</h2>
          <Status
            tone={watch.fresh ? (watch.trained ? 'good' : 'warn') : 'crit'}
            label={t(watch.fresh ? (watch.trained ? 'overview.watch.running' : 'overview.watch.learning') : 'overview.watch.stopped')}
          />
        </div>
        <div className="panel-body">
          <div className="meta" style={{ fontSize: 'var(--step-2)', color: 'var(--ink)' }}>
            <span>{t('overview.watch.high', { n: watch.high })}</span>
            <span>{t('overview.watch.medium', { n: watch.medium })}</span>
            <span>{t('overview.watch.isolated', { n: watch.isolated })}</span>
            <Link href="/console/incidents">{t('overview.watch.open_queue')}</Link>
          </div>
        </div>
      </section>

      <section className="panel" aria-labelledby="rate-title">
        <div className="panel-head">
          <h2 id="rate-title">{t('overview.rate.title')}</h2>
          <p className="panel-note">{t('overview.rate.note')}</p>
        </div>
        <div className="panel-body">
          {data.totalEvents === 0 ? (
            <p className="empty">{t('empty.events')}</p>
          ) : (
            <RateChart
              points={points}
              ariaLabel={t('overview.rate.aria', { events: formatNumber(data.totalEvents), minutes: windowMinutes })}
              tipTemplate={t('overview.rate.tip')}
              tableLabel={t('overview.rate.table')}
              minuteHeading={t('overview.rate.col.minute')}
              eventsHeading={t('overview.rate.col.events')}
            />
          )}
        </div>
      </section>

      <section className="panel" aria-labelledby="sources-title">
        <div className="panel-head">
          <h2 id="sources-title">{t('overview.sources.title')}</h2>
          <p className="panel-note">{t('overview.sources.note')}</p>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('overview.sources.col.source')}</th>
                <th>{t('overview.sources.col.status')}</th>
                <th className="right">{t('overview.sources.col.events')}</th>
                <th className="right">{t('overview.sources.col.rate')}</th>
                <th>{t('overview.sources.col.last')}</th>
                <th>{t('overview.sources.col.trend', { minutes: windowMinutes })}</th>
              </tr>
            </thead>
            <tbody>
              {data.sources.map((s) => {
                const tone: Tone = !s.last_at ? 'quiet' : s.last_at.getTime() >= silentBefore ? 'good' : 'warn';
                const label = !s.last_at ? t('status.never') : tone === 'good' ? t('status.reporting') : t('status.silent');
                return (
                  <tr key={s.id}>
                    <td className="wrap">
                      {s.label}
                      <span className="sub">{s.description}</span>
                    </td>
                    <td>
                      <Status tone={tone} label={label} />
                    </td>
                    <td className="right num">{formatNumber(s.events)}</td>
                    <td className="right num">{formatRate(s.events / windowMinutes)}</td>
                    <td className="num">{formatAgo(s.last_at, data.now, t)}</td>
                    <td>
                      <Spark
                        values={s.buckets}
                        label={t('overview.sources.trend_aria', {
                          source: s.label,
                          peak: formatNumber(Math.max(...s.buckets, 0)),
                        })}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel" aria-labelledby="recent-title">
        <div className="panel-head">
          <h2 id="recent-title">{t('overview.recent.title')}</h2>
        </div>
        {data.recent.length === 0 ? (
          <p className="empty">{t('empty.events')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('overview.recent.col.time')}</th>
                  <th>{t('overview.recent.col.source')}</th>
                  <th>{t('overview.recent.col.action')}</th>
                  <th>{t('overview.recent.col.outcome')}</th>
                  <th>{t('overview.recent.col.user')}</th>
                  <th>{t('overview.recent.col.host')}</th>
                </tr>
              </thead>
              <tbody>
                {data.recent.map((e) => (
                  <tr key={e.id}>
                    <td className="num">{formatClock(e.occurred_at, true)}</td>
                    <td>{e.source_label}</td>
                    <td>{e.action.replaceAll('_', ' ')}</td>
                    <td>
                      <Status tone={OUTCOME_TONE[e.outcome] ?? 'quiet'} label={t(`outcome.${e.outcome}`)} />
                    </td>
                    <td>{e.actor_user ?? ''}</td>
                    <td>{e.host ?? ''}</td>
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
