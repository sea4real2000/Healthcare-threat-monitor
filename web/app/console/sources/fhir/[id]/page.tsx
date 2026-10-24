import Link from 'next/link';
import { notFound } from 'next/navigation';
import { AutoRefresh } from '@/components/AutoRefresh';
import { FhirForm } from '@/components/FhirForm';
import { SourceStatus } from '@/components/SourceStatus';
import { Flash } from '@/components/ui';
import { checkFhirSource, startFhirSource, updateFhirSource } from '@/lib/connectActions';
import { db } from '@/lib/db';
import { formatAgo, formatNumber, formatWhen } from '@/lib/format';
import { requireUser } from '@/lib/session';
import { removeRecordSource, setRecordSourceState } from '@/lib/setupActions';
import { getCopy, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

interface FhirSource {
  id: string;
  name: string;
  base_url: string;
  auth_kind: string;
  client_id: string | null;
  token_url: string | null;
  scope: string | null;
  ca_certificate: string | null;
  encrypt: boolean;
  public_jwk: Record<string, string> | null;
  state: string;
  pending: string | null;
  preview: { time: string | null; user: string | null; patient: string | null; action: string | null }[];
  last_error: string | null;
  last_ok_at: Date | null;
  total_rows: string;
  rejected_rows: string;
  now: Date;
}

export default async function FhirSourcePage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, { id }, query, zone] = await Promise.all([getCopy(), params, searchParams, textSetting('hospital.timezone')]);
  if (!/^\d{1,18}$/.test(id)) notFound();
  const [s] = await db()<FhirSource[]>`
    select id::text as id, name, base_url, auth_kind, client_id, token_url, scope, ca_certificate, encrypt, public_jwk, state, pending, preview,
      last_error, last_ok_at, total_rows::text, rejected_rows::text, now() as now
    from record_sources where id = ${id}::bigint and kind = 'fhir'`;
  if (!s) notFound();
  const checked = Boolean(s.last_ok_at) && !s.last_error;
  const step = s.state !== 'setup' ? 'running' : checked ? 'preview' : 'connect';
  const jwks = s.public_jwk ? JSON.stringify({ keys: [s.public_jwk] }, null, 2) : null;

  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/sources">{t('sources.title')}</Link>
          </p>
          <h1>{s.name}</h1>
          <p className="lede">
            <SourceStatus s={s} t={t} /> {t('source_kind.fhir')}, {s.base_url}
          </p>
        </div>
        {s.pending && <AutoRefresh seconds={3} updatedText={t('connect.working')} pauseLabel={t('refresh.pause')} resumeLabel={t('refresh.resume')} />}
      </header>
      <Flash params={query} t={t} scope="sources" />
      {s.pending && <p className="flash">{t(`fhir.pending.${s.pending}`)}</p>}
      {s.last_error && (
        <div className="flash flash-error" role="alert">
          <strong>{t('connect.problem')}</strong> {s.last_error}
        </div>
      )}

      <ol className="setup-steps" aria-label={t('setup.progress')}>
        {(['connect', 'preview', 'running'] as const).map((x, i, all) => (
          <li key={x} className={all.indexOf(step) > i || (x === 'running' && step === 'running') ? 'done' : ''}>
            <span>{t(`fhir.step.${x}`)}</span>
          </li>
        ))}
      </ol>

      {jwks && step === 'connect' && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('fhir.key.title')}</h2>
          </div>
          <div className="panel-body">
            <p>{t('fhir.key.body', { client: s.client_id ?? '' })}</p>
            <pre className="mono ask">{jwks}</pre>
            <p>
              <a className="button" href={`data:application/json;charset=utf-8,${encodeURIComponent(jwks)}`} download={`healthcare_threat_monitor_${s.id}_jwks.json`}>
                {t('fhir.key.download')}
              </a>
            </p>
          </div>
        </section>
      )}

      {step === 'connect' && !s.pending && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('fhir.check.title')}</h2>
          </div>
          <form action={checkFhirSource} className="panel-body">
            <input type="hidden" name="id" value={s.id} />
            <p>{t('fhir.check.body')}</p>
            <button className="button button-primary" type="submit">
              {t('fhir.check')}
            </button>
          </form>
        </section>
      )}

      {step === 'preview' && !s.pending && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('fhir.preview.title')}</h2>
            <p className="panel-note">{t('fhir.preview.note')}</p>
          </div>
          {s.preview.length === 0 ? (
            <p className="empty">{t('fhir.preview.empty')}</p>
          ) : (
            <div className="table-wrap">
              <table className="preview">
                <thead>
                  <tr>
                    <th>{t('fhir.col.time')}</th>
                    <th>{t('fhir.col.user')}</th>
                    <th>{t('fhir.col.patient')}</th>
                    <th>{t('fhir.col.action')}</th>
                  </tr>
                </thead>
                <tbody>
                  {s.preview.map((p, i) => (
                    <tr key={i}>
                      <td className="num">{p.time && !Number.isNaN(Date.parse(p.time)) ? formatWhen(new Date(p.time), zone) : p.time}</td>
                      <td>{p.user}</td>
                      <td className="num">{p.patient}</td>
                      <td>{p.action && 'CRUDE'.includes(p.action) ? t(`fhir.action.${p.action}`) : p.action}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <form action={startFhirSource} className="form-grid">
            <input type="hidden" name="id" value={s.id} />
            <label>
              {t('connect.backfill')}
              <select name="backfill_days" defaultValue="7">
                {[0, 1, 7, 30].map((d) => (
                  <option key={d} value={d}>
                    {t(`connect.backfill.${d}`)}
                  </option>
                ))}
              </select>
            </label>
            <div className="wide">
              <button className="button button-primary" type="submit">
                {t('connect.start')}
              </button>
            </div>
          </form>
        </section>
      )}

      {step === 'running' && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('connect.running.title')}</h2>
          </div>
          <dl className="facts panel-body">
            <dt>{t('connect.running.last')}</dt>
            <dd>{s.last_ok_at ? formatAgo(s.last_ok_at, s.now, t) : t('sources.never')}</dd>
            <dt>{t('connect.running.entries')}</dt>
            <dd className="num">{formatNumber(Number(s.total_rows))}</dd>
            <dt>{t('connect.running.unreadable')}</dt>
            <dd className="num">{formatNumber(Number(s.rejected_rows))}</dd>
          </dl>
          <div className="panel-body row-actions">
            <form action={setRecordSourceState}>
              <input type="hidden" name="id" value={s.id} />
              <input type="hidden" name="to" value={s.state === 'active' ? 'paused' : 'active'} />
              <button className="button" type="submit">
                {t(s.state === 'active' ? 'connect.pause' : 'connect.resume')}
              </button>
            </form>
          </div>
        </section>
      )}

      <section className="panel">
        <details open={step === 'connect' && !s.pending && Boolean(s.last_error)}>
          <summary className="panel-head">
            <h2>{t('connect.details')}</h2>
          </summary>
          <FhirForm
            t={t}
            action={updateFhirSource}
            editing
            values={{ id: s.id, name: s.name, base_url: s.base_url, auth_kind: s.auth_kind, client_id: s.client_id ?? '', token_url: s.token_url ?? '',
              scope: s.scope ?? '', ca_certificate: s.ca_certificate ?? '', encrypt: s.encrypt }}
          />
          <p className="panel-note panel-body">{t('connect.change_note')}</p>
        </details>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>{t('connect.remove.title')}</h2>
        </div>
        <form action={removeRecordSource} className="panel-body">
          <input type="hidden" name="id" value={s.id} />
          <p>{t('fhir.remove.body')}</p>
          <button className="button button-danger" type="submit">
            {t('connect.remove')}
          </button>
        </form>
      </section>
    </>
  );
}
