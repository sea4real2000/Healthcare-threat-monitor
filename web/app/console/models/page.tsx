import { Flash } from '@/components/ui';
import { Status } from '@/components/Status';
import { requestRetrain } from '@/lib/actions';
import { db } from '@/lib/db';
import { formatAgo, formatNumber } from '@/lib/format';
import { currentUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

interface ModelRow {
  id: string;
  name: string;
  description: string;
  entity_label: string;
  window_seconds: number;
  features: { key: string; label: string }[];
  enabled: boolean;
  version: number;
  trained_at: Date | null;
  training_rows: number | null;
  threshold: string | null;
  score_summary: { histogram: number[]; edges: number[]; p50: number; p99: number; max: number } | null;
  feature_stats: Record<string, { median: number; p99: number; max: number }> | null;
  alerts: number;
  taught: number;
  now: Date;
}

function Histogram({ summary, threshold, label }: { summary: NonNullable<ModelRow['score_summary']>; threshold: number; label: string }) {
  const W = 520;
  const H = 120;
  const pad = 22;
  const bins = summary.histogram;
  // A log scale, because nearly every window sits in the first few bars.
  const top = Math.log10(Math.max(...bins) + 1);
  const step = (W - 8) / bins.length;
  const lo = summary.edges[0];
  const hi = summary.edges[summary.edges.length - 1];
  const x = (v: number) => 4 + ((v - lo) / (hi - lo || 1)) * (W - 8);
  return (
    <svg className="histogram" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} style={{ width: '100%', maxWidth: W, height: 'auto' }}>
      {bins.map((n, i) => {
        const h = n === 0 ? 0 : Math.max((Math.log10(n + 1) / top) * (H - pad - 6), 2);
        return <rect key={i} className={summary.edges[i] >= threshold ? 'over' : ''} x={4 + i * step + 1} y={H - pad - h} width={step - 2} height={h} rx="2" />;
      })}
      <line x1={x(threshold)} x2={x(threshold)} y1="2" y2={H - pad} />
      <text x="4" y={H - 6}>
        {lo.toFixed(2)}
      </text>
      <text x={W - 4} y={H - 6} textAnchor="end">
        {hi.toFixed(2)}
      </text>
    </svg>
  );
}

export default async function ModelsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, user, params] = await Promise.all([getCopy(), currentUser(), searchParams]);
  const models = await db()<ModelRow[]>`
    select m.*, m.threshold::text as threshold, now() as now,
           (select count(*)::int from alerts a where a.detector_type = 'model' and a.detector_id = m.id) as alerts,
           (select count(*)::int from model_training_labels l where l.model_id = m.id and l.label = 'normal' and l.features is not null) as taught
    from models m order by m.id`;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('models.title')}</h1>
          <p className="lede">{t('models.lede')}</p>
        </div>
        {user && (
          <form action={requestRetrain}>
            <button className="button button-primary" type="submit">
              {t('models.retrain')}
            </button>
          </form>
        )}
      </header>
      <Flash params={params} t={t} scope="models" />
      {models.map((m) => (
        <section className="panel" key={m.id} aria-labelledby={`model-${m.id}`}>
          <div className="panel-head">
            <h2 id={`model-${m.id}`}>{m.name}</h2>
            <Status tone={m.trained_at ? 'good' : 'quiet'} label={m.trained_at ? t('models.trained', { ago: formatAgo(m.trained_at, m.now, t) }) : t('models.untrained')} />
          </div>
          <div className="panel-body">
            <p className="lede" style={{ marginTop: 0 }}>
              {m.description}
            </p>
            <div className="meta">
              <span>{t('models.watches', { entity: m.entity_label, minutes: Math.round(m.window_seconds / 60) })}</span>
              <span>{t('models.training_rows', { rows: formatNumber(m.training_rows ?? 0) })}</span>
              <span>{t('models.taught', { rows: formatNumber(m.taught) })}</span>
              <span>{t('models.alerts', { alerts: formatNumber(m.alerts) })}</span>
              <span>{t('models.version', { version: m.version })}</span>
            </div>
          </div>
          {m.score_summary && m.threshold && (
            <div className="panel-body">
              <p className="panel-note">{t('models.histogram.note')}</p>
              <Histogram summary={m.score_summary} threshold={Number(m.threshold)} label={t('models.histogram.aria', { name: m.name })} />
            </div>
          )}
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('models.col.feature')}</th>
                  <th className="right">{t('models.col.typical')}</th>
                  <th className="right">{t('models.col.p99')}</th>
                  <th className="right">{t('models.col.max')}</th>
                </tr>
              </thead>
              <tbody>
                {m.features.map((f) => {
                  const s = m.feature_stats?.[f.key];
                  return (
                    <tr key={f.key}>
                      <td>{f.label}</td>
                      <td className="right num">{s ? formatNumber(Math.round(s.median * 100) / 100) : ''}</td>
                      <td className="right num">{s ? formatNumber(Math.round(s.p99 * 100) / 100) : ''}</td>
                      <td className="right num">{s ? formatNumber(Math.round(s.max * 100) / 100) : ''}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </>
  );
}
