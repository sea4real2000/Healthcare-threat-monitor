import Link from 'next/link';
import { redirect } from 'next/navigation';
import './landing.css';
import { db } from '@/lib/db';
import { firstRunPending } from '@/lib/firstRun';
import { formatNumber } from '@/lib/format';
import { siteImages, type SiteImage } from '@/lib/media';
import { flagSetting, getCopy, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const ICONS: Record<string, React.ReactNode> = {
  lock: <path d="M7 10V7a5 5 0 0 1 10 0v3h1a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1Zm2 0h6V7a3 3 0 0 0-6 0Z" />,
  record: <path d="M6 2h9l5 5v14a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1Zm8 1.5V8h4.5ZM8 12v2h8v-2Zm0 4v2h6v-2Z" />,
  device: <path d="M3 12h4l2-5 4 10 2-5h6v2h-4.6L13 20 9 10l-.6 4H3Z" />,
  key: <path d="M14 3a7 7 0 0 0-6.7 9L2 17.3V22h4.7v-2.4h2.4v-2.4h2.2l1.2-1.2A7 7 0 1 0 14 3Zm2.5 6.5a2 2 0 1 1 0-4 2 2 0 0 1 0 4Z" />,
  person: <path d="M12 12a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9Zm-8 9a8 8 0 0 1 16 0Z" />,
  chain: (
    <path d="M10.6 13.4a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.6l-1.1 1 1.4 1.5 1.1-1a2 2 0 1 1 2.9 2.8l-3 3a2 2 0 0 1-2.9 0Zm2.8-2.8a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.6l1.1-1-1.4-1.5-1.1 1a2 2 0 1 1-2.9-2.8l3-3a2 2 0 0 1 2.9 0Z" />
  ),
  open: <path d="M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6Zm-1 13.5-3.5-3.5L9 10.5l2 2 4-4 1.5 1.5Z" />,
};

function Icon({ name, size = 24 }: { name: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      {ICONS[name]}
    </svg>
  );
}

/** A picture an administrator uploaded under Settings, Images. Cropped by its frame, so any shape fits. */
function Photo({ image, className, eager = false }: { image: SiteImage; className: string; eager?: boolean }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img className={className} src={image.src} alt={image.alt} width={image.width} height={image.height} loading={eager ? 'eager' : 'lazy'} decoding="async" />
  );
}

function seconds(v: number | null | undefined): string {
  if (v === null || v === undefined) return '';
  return v < 120 ? `${Math.round(v)} s` : `${(v / 60).toFixed(1)} min`;
}

export default async function Landing() {
  // The landing page describes the simulated demo. A hospital's own installation opens straight on its console.
  if (!(await flagSetting('engine.simulate'))) redirect((await firstRunPending()) ? '/welcome' : '/console');
  const [t, images, name, repo, contact] = await Promise.all([
    getCopy(),
    siteImages(),
    textSetting('platform.name'),
    textSetting('platform.repository_url'),
    textSetting('platform.contact_email'),
  ]);
  const sql = db();
  const [[live], buckets, [evaluation]] = await Promise.all([
    sql<
      {
        events: number;
        sources: number;
        total_sources: number;
        open: number;
        rules: number;
        models: number;
        decided: number;
        audit: number;
        fresh: boolean;
        retained: number;
      }[]
    >`
      select (select count(*)::int from events where occurred_at >= now() - interval '60 minutes') as events,
             (select count(distinct source)::int from events where occurred_at >= now() - interval '10 minutes') as sources,
             (select count(*)::int from sources where enabled) as total_sources,
             (select count(*)::int from incidents where status = 'open' and band <> 'low') as open,
             (select count(*)::int from rules where enabled) as rules,
             (select count(*)::int from models where enabled) as models,
             (select count(*)::int from incidents where status <> 'open') as decided,
             (select count(*)::int from audit_log) as audit,
             (select count(*)::int from events) as retained,
             coalesce((select updated_at > now() - interval '2 minutes' from engine_state where key = 'heartbeat'), false) as fresh`,
    sql<{ bucket: number; n: number }[]>`
      select floor(extract(epoch from (occurred_at - (now() - interval '60 minutes'))) / 60)::int as bucket, count(*)::int as n
      from events where occurred_at >= now() - interval '60 minutes' and occurred_at <= now() group by 1`,
    sql<
      {
        metrics: {
          phase_a: Record<string, never>;
          phase_b: Record<string, never>;
        } | null;
      }[]
    >`
      select metrics from evaluation_runs where status = 'completed' and metrics is not null order by evaluation_runs.id desc limit 1`,
  ]);
  const series = new Array<number>(60).fill(0);
  for (const b of buckets) if (b.bucket >= 0 && b.bucket < 60) series[b.bucket] = b.n;
  const peak = Math.max(...series, 1);
  const a = evaluation?.metrics?.phase_a as { false_incidents_per_day: number } | undefined;
  const b = evaluation?.metrics?.phase_b as
    | {
        detected: number;
        scenario_runs: number;
        false_incidents_per_day: number;
        per_scenario: Record<string, { median_seconds_to_detect: number | null }>;
      }
    | undefined;

  return (
    <div className="land">
      <div className="wrap">
        <header className="land-top">
          <Link className="land-brand" href="/">
            <Icon name="open" size={28} />
            {name}
          </Link>
          <div className="land-top-facts">
            <span>
              {t('landing.top.license_label')}
              <strong>{t('landing.top.license')}</strong>
            </span>
            {contact && (
              <span>
                {t('landing.top.contact_label')}
                <strong>{contact}</strong>
              </span>
            )}
            <Link className="pill" href="/console">
              {t('landing.cta.demo')}
            </Link>
          </div>
        </header>
        <nav className="land-nav" aria-label={t('landing.nav.label')}>
          <a href="#top">{t('landing.nav.home')}</a>
          <a href="#watches">{t('landing.nav.watches')}</a>
          <a href="#how">{t('landing.nav.how')}</a>
          <a href="#results">{t('landing.nav.results')}</a>
          <Link href="/console/compliance">{t('landing.nav.compliance')}</Link>
          {repo && <a href={repo}>{t('landing.nav.code')}</a>}
        </nav>
      </div>

      <section className="hero" id="top">
        <div className="wrap hero-grid">
          <div className={images.hero ? 'hero-visual has-photo' : 'hero-visual'}>
            {images.hero && <Photo image={images.hero} className="hero-photo" eager />}
            <div className="monitor" aria-label={t('landing.monitor.aria')}>
              <div className="monitor-head">
                <span>{t('landing.monitor.title')}</span>
                <span className={`monitor-live ${live.fresh ? '' : 'off'}`}>
                  <i />
                  {t(live.fresh ? 'landing.monitor.live' : 'landing.monitor.paused')}
                </span>
              </div>
              <svg
                viewBox="0 0 480 120"
                role="img"
                aria-label={t('landing.monitor.chart', {
                  events: formatNumber(live.events),
                })}
              >
                {series.map((n, i) => {
                  const h = n === 0 ? 0 : Math.max((n / peak) * 112, 2);
                  return <rect key={i} x={i * 8 + 1} y={120 - h} width="6" height={h} rx="2" />;
                })}
              </svg>
              <dl>
                <div>
                  <dt>{t('landing.monitor.events')}</dt>
                  <dd>{formatNumber(live.events)}</dd>
                </div>
                <div>
                  <dt>{t('landing.monitor.sources')}</dt>
                  <dd>
                    {live.sources}/{live.total_sources}
                  </dd>
                </div>
                <div>
                  <dt>{t('landing.monitor.open')}</dt>
                  <dd>{formatNumber(live.open)}</dd>
                </div>
              </dl>
            </div>
          </div>
          <div className="hero-copy">
            <span className="tag">{t('landing.hero.tag')}</span>
            <h1>
              {t('landing.hero.title_one')}
              <span>{t('landing.hero.title_two')}</span>
            </h1>
            <p>{t('landing.hero.body')}</p>
            <div className="hero-actions">
              <Link className="pill" href="/console">
                {t('landing.cta.demo')}
              </Link>
              {repo ? (
                <a className="pill pill-ghost" href={repo}>
                  {t('landing.cta.code')}
                </a>
              ) : (
                <Link className="pill pill-ghost" href="/console/evaluation">
                  {t('landing.cta.results')}
                </Link>
              )}
            </div>
          </div>
        </div>
      </section>

      <div className="wrap feature-band">
        <div className="feature-band-inner">
          {(['person', 'chain', 'open'] as const).map((icon, i) => (
            <div key={icon}>
              <span className="icon">
                <Icon name={icon} />
              </span>
              <h3>{t(`landing.feature.${i + 1}.title`)}</h3>
              <p>{t(`landing.feature.${i + 1}.body`)}</p>
            </div>
          ))}
        </div>
      </div>

      <section className="land-section wrap" id="watches">
        <div className="section-head">
          <div>
            <span className="tag">{t('landing.watches.tag')}</span>
            <h2>
              {t('landing.watches.title_one')}
              <span>{t('landing.watches.title_two')}</span>
            </h2>
          </div>
          <p>{t('landing.watches.body')}</p>
          <Link className="pill" href="/console/rules">
            {t('landing.watches.cta')}
          </Link>
        </div>
        <div className={images.watches ? 'watch-layout has-photo' : 'watch-layout'}>
          {images.watches && (
            <div className="watch-photo">
              <Photo image={images.watches} className="fill" />
            </div>
          )}
          <div className="watch-grid">
            {(['lock', 'record', 'device', 'key'] as const).map((icon, i) => (
              <div className="watch-card" key={icon}>
                <span className="icon">
                  <Icon name={icon} />
                </span>
                <h3>{t(`landing.watch.${i + 1}.title`)}</h3>
                <p>{t(`landing.watch.${i + 1}.body`)}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="land-section wrap" id="how">
        <div className="section-head center">
          <span className="tag">{t('landing.how.tag')}</span>
          <h2>
            {t('landing.how.title_one')}
            <span>{t('landing.how.title_two')}</span>
          </h2>
          <p>{t('landing.how.body')}</p>
        </div>
        <div className="how-grid">
          <ol className="steps">
            {[1, 2, 3, 4, 5].map((n) => (
              <li key={n}>
                <h3>{t(`landing.step.${n}.title`)}</h3>
                <p>{t(`landing.step.${n}.body`)}</p>
              </li>
            ))}
          </ol>
          <div className="how-side">
            {images.how && <Photo image={images.how} className="how-photo" />}
            <aside className="glance">
              <h3>{t('landing.glance.title')}</h3>
              <p>{t('landing.glance.body')}</p>
              <dl>
                <div>
                  <dt>{t('landing.glance.sources')}</dt>
                  <dd>{live.total_sources}</dd>
                </div>
                <div>
                  <dt>{t('landing.glance.rules')}</dt>
                  <dd>{live.rules}</dd>
                </div>
                <div>
                  <dt>{t('landing.glance.models')}</dt>
                  <dd>{live.models}</dd>
                </div>
                <div>
                  <dt>{t('landing.glance.response')}</dt>
                  <dd>{t('landing.glance.response_value')}</dd>
                </div>
              </dl>
            </aside>
          </div>
        </div>
      </section>

      <section className="land-section wrap">
        <dl className="stat-band">
          <div>
            <dd>{formatNumber(live.retained)}</dd>
            <dt>{t('landing.stat.events')}</dt>
          </div>
          <div>
            <dd>{formatNumber(live.rules)}</dd>
            <dt>{t('landing.stat.rules')}</dt>
          </div>
          <div>
            <dd>{formatNumber(live.decided)}</dd>
            <dt>{t('landing.stat.decided')}</dt>
          </div>
          <div>
            <dd>{formatNumber(live.audit)}</dd>
            <dt>{t('landing.stat.audit')}</dt>
          </div>
        </dl>
      </section>

      <section className="land-section wrap" id="results">
        <div className="section-head">
          <div>
            <span className="tag">{t('landing.results.tag')}</span>
            <h2>
              {t('landing.results.title_one')}
              <span>{t('landing.results.title_two')}</span>
            </h2>
          </div>
          <p>{t('landing.results.body')}</p>
          <Link className="pill" href="/console/evaluation">
            {t('landing.results.cta')}
          </Link>
        </div>
        {a && b ? (
          <div className="results">
            <div className="result">
              <strong>
                {t('landing.results.detected_value', {
                  n: b.detected,
                  total: b.scenario_runs,
                })}
              </strong>
              <span>{t('landing.results.detected')}</span>
            </div>
            <div className="result">
              <strong>
                {t('landing.results.false_value', {
                  before: a.false_incidents_per_day.toFixed(0),
                  after: b.false_incidents_per_day.toFixed(0),
                })}
              </strong>
              <span>{t('landing.results.false')}</span>
            </div>
            <div className="result">
              <strong>{seconds(b.per_scenario?.ransomware?.median_seconds_to_detect)}</strong>
              <span>{t('landing.results.ttd')}</span>
            </div>
          </div>
        ) : (
          <p className="fineprint">{t('landing.results.none')}</p>
        )}
        <p className="fineprint">{t('landing.results.caveat')}</p>
      </section>

      <section className="land-section wrap">
        <div className={images.close ? 'cta has-photo' : 'cta'}>
          {images.close && <Photo image={images.close} className="cta-photo" />}
          <div>
            <h2>
              {t('landing.close.title_one')}
              <span>{t('landing.close.title_two')}</span>
            </h2>
            <p>{t('landing.close.body')}</p>
          </div>
          <Link className="pill pill-light" href="/console/scenarios">
            {t('landing.close.cta')}
          </Link>
        </div>
      </section>

      <footer className="land-foot">
        <div className="wrap">
          <p>{t('landing.foot.disclaimer')}</p>
          <p>
            {t('landing.foot.license')} {repo && <a href={repo}>{t('landing.nav.code')}</a>} <Link href="/signin">{t('auth.sign_in')}</Link>
          </p>
        </div>
      </footer>
    </div>
  );
}
