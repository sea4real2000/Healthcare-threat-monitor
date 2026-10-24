import Link from 'next/link';
import { notFound, redirect } from 'next/navigation';
import { AutoRefresh } from '@/components/AutoRefresh';
import { ConnectionForm } from '@/components/ConnectionForm';
import { SourceStatus } from '@/components/SourceStatus';
import { Flash } from '@/components/ui';
import { db } from '@/lib/db';
import { formatAgo, formatNumber } from '@/lib/format';
import { chooseSourceTable, removeRecordSource, setRecordSourceState, startRecordSource, updateRecordSource } from '@/lib/setupActions';
import { requireUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const FIELDS = ['order', 'time', 'user', 'patient', 'action', 'outcome', 'workstation'] as const;
const REQUIRED = new Set(['order', 'time', 'user', 'patient']);

/** Guesses which column is which from its name, so most hospitals only need to check the choices. */
const GUESS: Record<string, RegExp> = {
  order: /^(log_?id|audit_?id|event_?id|id|seq|sequence|entry_?id|row_?id)$/i,
  time: /(time|date|_at$|^ts$|when|accessed|logged)/i,
  user: /(user|staff|login|operator|clinician|employee|actor|by$)/i,
  patient: /(patient|mrn|hospital_?n(o|umber)|chart|subject)/i,
  action: /(action|event|activity|what|operation|type)/i,
  outcome: /(outcome|result|status|success|ok$|allowed)/i,
  workstation: /(workstation|terminal|pc$|computer|device|host|ip|machine|station)/i,
};

interface Source {
  id: string;
  name: string;
  kind: string;
  host: string;
  port: number;
  database_name: string;
  username: string;
  encrypt: boolean;
  timezone: string;
  day_first: boolean;
  state: string;
  pending: string | null;
  tables: string[];
  table_name: string | null;
  columns: { name: string; type: string }[];
  preview: Record<string, string>[];
  mapping: Record<string, string>;
  backfill_days: number;
  last_error: string | null;
  last_ok_at: Date | null;
  last_rows: number;
  total_rows: string;
  rejected_rows: string;
  created_by: string | null;
  now: Date;
}

export default async function ConnectionPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [{ id }, query, t] = await Promise.all([params, searchParams, getCopy()]);
  if (!/^\d{1,18}$/.test(id)) notFound();
  const [s] = await db()<Source[]>`
    select id::text as id, name, kind, host, port, database_name, username, encrypt, timezone, day_first, state, pending, tables, table_name,
      columns, preview, mapping, backfill_days, last_error, last_ok_at, last_rows, total_rows::text, rejected_rows::text, created_by, now() as now
    from record_sources where id = ${id}::bigint`;
  if (!s) notFound();
  if (s.kind === 'fhir') redirect(`/console/sources/fhir/${s.id}`);
  const used = new Set<string>();
  const guess = (f: string) => {
    if (s.mapping[f]) return s.mapping[f];
    const hit = s.columns.find((c) => GUESS[f].test(c.name) && !used.has(c.name));
    if (hit) used.add(hit.name);
    return hit?.name ?? '';
  };
  const choices = Object.fromEntries(FIELDS.map((f) => [f, guess(f)]));
  const step = s.state !== 'setup' ? 'running' : s.columns.length > 0 ? 'match' : s.tables.length > 0 ? 'table' : 'connect';

  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/sources">{t('sources.title')}</Link>
          </p>
          <h1>{s.name}</h1>
          <p className="lede">
            <SourceStatus s={s} t={t} /> {t(`source_kind.${s.kind}`)}, {s.host}:{s.port}, {s.database_name}
          </p>
        </div>
        {s.pending && <AutoRefresh seconds={3} updatedText={t('connect.working')} pauseLabel={t('refresh.pause')} resumeLabel={t('refresh.resume')} />}
      </header>
      <Flash params={query} t={t} scope="sources" />
      {s.pending && <p className="flash">{t(`connect.pending.${s.pending}`)}</p>}
      {s.last_error && (
        <div className="flash flash-error" role="alert">
          <strong>{t('connect.problem')}</strong> {s.last_error}
        </div>
      )}

      <ol className="setup-steps" aria-label={t('setup.progress')}>
        {(['connect', 'table', 'match', 'running'] as const).map((x, i, all) => (
          <li key={x} className={all.indexOf(step) > i || (x === 'running' && step === 'running') ? 'done' : ''}>
            <span>{t(`connect.step.${x}`)}</span>
          </li>
        ))}
      </ol>

      {step === 'running' && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('connect.running.title')}</h2>
          </div>
          <dl className="facts panel-body">
            <dt>{t('connect.running.table')}</dt>
            <dd className="mono">{s.table_name}</dd>
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

      {step === 'table' && !s.pending && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('connect.table.title')}</h2>
          </div>
          <form action={chooseSourceTable} className="form-grid">
            <input type="hidden" name="id" value={s.id} />
            <label className="wide">
              {t('connect.table.label')}
              <select name="table" defaultValue={s.table_name ?? s.tables.find((x) => /audit|access|log/i.test(x)) ?? s.tables[0]}>
                {s.tables.map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </select>
              <span className="sub">{t('connect.table.hint')}</span>
            </label>
            <div className="wide">
              <button className="button button-primary" type="submit">
                {t('connect.table.submit')}
              </button>
            </div>
          </form>
        </section>
      )}

      {step === 'match' && !s.pending && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('connect.match.title')}</h2>
            <p className="panel-note">{t('connect.match.note', { table: s.table_name ?? '' })}</p>
          </div>
          {s.preview.length > 0 && (
            <div className="table-wrap preview">
              <table>
                <thead>
                  <tr>
                    {s.columns.map((c) => (
                      <th key={c.name}>
                        {c.name}
                        <span className="sub">{c.type}</span>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {s.preview.map((r, i) => (
                    <tr key={i}>
                      {s.columns.map((c) => (
                        <td key={c.name} className="mono">
                          {r[c.name]}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <form action={startRecordSource} className="form-grid">
            <input type="hidden" name="id" value={s.id} />
            {FIELDS.map((f) => (
              <label key={f}>
                {t(`match.${f}`)}
                {REQUIRED.has(f) ? '' : ` ${t('match.optional')}`}
                <select name={f} defaultValue={choices[f]} required={REQUIRED.has(f)}>
                  <option value="">{t('match.none')}</option>
                  {s.columns.map((c) => (
                    <option key={c.name} value={c.name}>
                      {c.name}
                    </option>
                  ))}
                </select>
                <span className="sub">{t(`match.${f}.hint`)}</span>
              </label>
            ))}
            <label>
              {t('connect.backfill')}
              <select name="backfill_days" defaultValue={String(s.backfill_days)}>
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

      <section className="panel">
        <details open={step === 'connect' && !s.pending && Boolean(s.last_error)}>
          <summary className="panel-head">
            <h2>{t('connect.details')}</h2>
          </summary>
          <ConnectionForm t={t} action={updateRecordSource} zones={Intl.supportedValuesOf('timeZone')} editing values={s} />
          <p className="panel-note panel-body">{t('connect.change_note')}</p>
        </details>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>{t('connect.remove.title')}</h2>
        </div>
        <form action={removeRecordSource} className="panel-body">
          <input type="hidden" name="id" value={s.id} />
          <p>{t('connect.remove.body')}</p>
          <button className="button button-danger" type="submit">
            {t('connect.remove')}
          </button>
        </form>
      </section>
    </>
  );
}
