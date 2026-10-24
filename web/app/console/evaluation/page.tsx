import { percent, pretty } from '@/components/ui';
import { db } from '@/lib/db';
import { formatNumber } from '@/lib/format';
import { getCopy } from '@/lib/settings';
import type { Translate } from '@/lib/settings';

export const dynamic = 'force-dynamic';

interface ScenarioStats {
  runs: number;
  detected: number;
  reached_high: number;
  median_seconds_to_detect: number | null;
  median_seconds_to_high: number | null;
}

interface Phase {
  hours: number;
  events: number;
  scenario_runs: number;
  detected: number;
  detection_rate: number | null;
  false_incidents: number;
  false_incidents_per_day: number;
  false_incidents_high: number;
  precision: number | null;
  low_band_incidents: number;
  false_by_category: Record<string, number>;
  per_scenario: Record<string, ScenarioStats>;
  detectors: Record<string, { alerts: number; on_attack: number }>;
}

interface Metrics {
  config: { baseline_hours: number; phase_hours: number; per_kind: number; seed: number };
  finished_at: string;
  analyst: { confirmed: number; dismissed: number };
  phase_a: Phase;
  phase_b: Phase;
  events_total: number;
}

function duration(seconds: number | null, t: Translate): string {
  if (seconds === null || seconds === undefined) return t('evaluation.not_reached');
  if (seconds < 1) return t('evaluation.under_second');
  return seconds < 120 ? t('evaluation.seconds', { n: Math.round(seconds) }) : t('evaluation.minutes', { n: (seconds / 60).toFixed(1) });
}

export default async function EvaluationPage() {
  const t = await getCopy();
  const [run] = await db()<{ id: string; metrics: Metrics }[]>`
    select id::text as id, metrics from evaluation_runs where status = 'completed' and metrics is not null order by evaluation_runs.id desc limit 1`;

  if (!run) {
    return (
      <>
        <header className="page-head">
          <div>
            <h1>{t('evaluation.title')}</h1>
            <p className="lede">{t('evaluation.lede')}</p>
          </div>
        </header>
        <section className="panel">
          <p className="empty">{t('evaluation.empty')}</p>
          <p className="empty mono">python -m evaluate</p>
        </section>
      </>
    );
  }

  const m = run.metrics;
  const { phase_a: a, phase_b: b } = m;
  const scenarios = Object.keys(a.per_scenario).sort();
  const categories = [...new Set([...Object.keys(a.false_by_category), ...Object.keys(b.false_by_category)])].sort();
  const detectors = [...new Set([...Object.keys(a.detectors), ...Object.keys(b.detectors)])].sort();
  const none = { alerts: 0, on_attack: 0 };

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('evaluation.title')}</h1>
          <p className="lede">
            {t('evaluation.summary', {
              baseline: m.config.baseline_hours,
              phase: m.config.phase_hours,
              attacks: a.scenario_runs,
              events: formatNumber(m.events_total),
              finished: m.finished_at,
            })}
          </p>
        </div>
        <a className="button" href="/api/evaluation/report">
          {t('evaluation.download')}
        </a>
      </header>
      <p className="flash">{t('evaluation.caveat')}</p>

      <dl className="figures">
        <div>
          <dt>{t('evaluation.figure.detected')}</dt>
          <dd className="num">
            {b.detected} <small>{t('overview.figure.of', { total: b.scenario_runs })}</small>
          </dd>
        </div>
        <div>
          <dt>{t('evaluation.figure.false_before')}</dt>
          <dd className="num">{a.false_incidents_per_day.toFixed(1)}</dd>
        </div>
        <div>
          <dt>{t('evaluation.figure.false_after')}</dt>
          <dd className="num">{b.false_incidents_per_day.toFixed(1)}</dd>
        </div>
        <div>
          <dt>{t('evaluation.figure.precision')}</dt>
          <dd className="num">{b.precision === null ? '' : percent(b.precision)}</dd>
        </div>
      </dl>

      <section className="panel" aria-labelledby="headline">
        <div className="panel-head">
          <h2 id="headline">{t('evaluation.headline.title')}</h2>
          <p className="panel-note">{t('evaluation.headline.note', { confirmed: m.analyst.confirmed, dismissed: m.analyst.dismissed })}</p>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('evaluation.col.measure')}</th>
                <th className="right">{t('evaluation.col.before')}</th>
                <th className="right">{t('evaluation.col.after')}</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>{t('evaluation.row.detected')}</td>
                <td className="right num">{t('evaluation.of', { n: a.detected, total: a.scenario_runs })}</td>
                <td className="right num">{t('evaluation.of', { n: b.detected, total: b.scenario_runs })}</td>
              </tr>
              <tr>
                <td>{t('evaluation.row.false_per_day')}</td>
                <td className="right num">{a.false_incidents_per_day.toFixed(1)}</td>
                <td className="right num">{b.false_incidents_per_day.toFixed(1)}</td>
              </tr>
              <tr>
                <td>{t('evaluation.row.false_high')}</td>
                <td className="right num">{a.false_incidents_high}</td>
                <td className="right num">{b.false_incidents_high}</td>
              </tr>
              <tr>
                <td>{t('evaluation.row.precision')}</td>
                <td className="right num">{a.precision === null ? '' : percent(a.precision)}</td>
                <td className="right num">{b.precision === null ? '' : percent(b.precision)}</td>
              </tr>
              <tr>
                <td>{t('evaluation.row.low')}</td>
                <td className="right num">{formatNumber(a.low_band_incidents)}</td>
                <td className="right num">{formatNumber(b.low_band_incidents)}</td>
              </tr>
              <tr>
                <td>{t('evaluation.row.events')}</td>
                <td className="right num">{formatNumber(a.events)}</td>
                <td className="right num">{formatNumber(b.events)}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel" aria-labelledby="by-attack">
        <div className="panel-head">
          <h2 id="by-attack">{t('evaluation.attacks.title')}</h2>
          <p className="panel-note">{t('evaluation.attacks.note')}</p>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('evaluation.col.attack')}</th>
                <th>{t('evaluation.col.phase')}</th>
                <th className="right">{t('evaluation.col.detected')}</th>
                <th className="right">{t('evaluation.col.high')}</th>
                <th className="right">{t('evaluation.col.ttd')}</th>
                <th className="right">{t('evaluation.col.tth')}</th>
              </tr>
            </thead>
            <tbody>
              {scenarios.flatMap((s) =>
                ([['before', a], ['after', b]] as const).map(([label, phase]) => {
                  const x = phase.per_scenario[s];
                  return x ? (
                    <tr key={`${s}-${label}`}>
                      <td>{label === 'before' ? t(`scenario.${s}.name`) : ''}</td>
                      <td>{t(`evaluation.col.${label}`)}</td>
                      <td className="right num">{t('evaluation.of', { n: x.detected, total: x.runs })}</td>
                      <td className="right num">{t('evaluation.of', { n: x.reached_high, total: x.runs })}</td>
                      <td className="right num">{duration(x.median_seconds_to_detect, t)}</td>
                      <td className="right num">{duration(x.median_seconds_to_high, t)}</td>
                    </tr>
                  ) : null;
                }),
              )}
            </tbody>
          </table>
        </div>
      </section>

      <>
        <section className="panel" aria-labelledby="false-by">
          <div className="panel-head">
            <h2 id="false-by">{t('evaluation.false.title')}</h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('evaluation.col.category')}</th>
                  <th className="right">{t('evaluation.col.before')}</th>
                  <th className="right">{t('evaluation.col.after')}</th>
                </tr>
              </thead>
              <tbody>
                {categories.map((c) => (
                  <tr key={c}>
                    <td>{t(`category.${c}`)}</td>
                    <td className="right num">{a.false_by_category[c] ?? 0}</td>
                    <td className="right num">{b.false_by_category[c] ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <section className="panel" aria-labelledby="by-detector">
          <div className="panel-head">
            <h2 id="by-detector">{t('evaluation.detectors.title')}</h2>
            <p className="panel-note">{t('evaluation.detectors.note')}</p>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('evaluation.col.detector')}</th>
                  <th className="right">{t('evaluation.col.before')}</th>
                  <th className="right">{t('evaluation.col.after')}</th>
                </tr>
              </thead>
              <tbody>
                {detectors.map((d) => {
                  const x = a.detectors[d] ?? none;
                  const y = b.detectors[d] ?? none;
                  return (
                    <tr key={d}>
                      <td>{pretty(d)}</td>
                      <td className="right num">{t('evaluation.on_attack', { alerts: x.alerts, real: x.on_attack })}</td>
                      <td className="right num">{t('evaluation.on_attack', { alerts: y.alerts, real: y.on_attack })}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      </>
    </>
  );
}
