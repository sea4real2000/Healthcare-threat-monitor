import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Flash } from '@/components/ui';
import { db } from '@/lib/db';
import { formatAgo, formatNumber } from '@/lib/format';
import { discardUpload, importUpload } from '@/lib/setupActions';
import { requireUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const FIELDS = ['time', 'user', 'patient', 'action', 'outcome', 'workstation', 'record_id'] as const;
const REQUIRED = new Set(['time', 'user', 'patient']);
const GUESS: Record<string, RegExp> = {
  time: /(time|date|when|accessed|logged)/i,
  user: /(user|staff|login|operator|clinician|employee|actor|by$)/i,
  patient: /(patient|mrn|hospital.?n(o|umber)|chart|subject)/i,
  action: /(action|event|activity|what|operation)/i,
  outcome: /(outcome|result|status|success|allowed)/i,
  workstation: /(workstation|terminal|pc$|computer|device|host|ip|machine|station)/i,
  record_id: /^(id|log.?id|audit.?id|event.?id|entry|entry.?(id|no|number)|row.?id|record.?(id|no)|ref|reference)$/i,
};

interface Upload {
  id: string;
  filename: string;
  status: string;
  headers: string[];
  preview: string[][];
  row_count: number;
  mapping: Record<string, string>;
  timezone: string;
  accepted: number;
  duplicate: number;
  rejected: number;
  problems: { row: number; reason: string }[];
  uploaded_by: string | null;
  uploaded_at: Date;
  imported_at: Date | null;
  now: Date;
}

export default async function UploadDetailPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [{ id }, query, t] = await Promise.all([params, searchParams, getCopy()]);
  if (!/^\d{1,18}$/.test(id)) notFound();
  const [u] = await db()<Upload[]>`
    select id::text as id, filename, status, headers, preview, row_count, mapping, timezone, accepted, duplicate, rejected, problems,
      uploaded_by, uploaded_at, imported_at, now() as now
    from record_uploads where id = ${id}::bigint`;
  if (!u) notFound();
  const used = new Set<string>();
  const choice = (f: string) => {
    if (u.mapping[f]) return u.mapping[f];
    const hit = u.headers.find((h) => GUESS[f].test(h) && !used.has(h));
    if (hit) used.add(hit);
    return hit ?? '';
  };
  const choices = Object.fromEntries(FIELDS.map((f) => [f, choice(f)]));

  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/sources">{t('sources.title')}</Link>
          </p>
          <h1>{u.filename}</h1>
          <p className="lede">{t('upload.summary', { rows: formatNumber(u.row_count), when: formatAgo(u.uploaded_at, u.now, t), zone: u.timezone })}</p>
        </div>
      </header>
      <Flash params={query} t={t} scope="sources" />

      {u.status === 'imported' && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('upload.result.title')}</h2>
          </div>
          <dl className="facts panel-body">
            <dt>{t('upload.result.stored')}</dt>
            <dd className="num">{formatNumber(u.accepted)}</dd>
            <dt>{t('upload.result.duplicate')}</dt>
            <dd className="num">{formatNumber(u.duplicate)}</dd>
            <dt>{t('upload.result.unreadable')}</dt>
            <dd className="num">{formatNumber(u.rejected)}</dd>
          </dl>
          {u.problems.length > 0 && (
            <div className="panel-body">
              <p>{t('upload.result.problems')}</p>
              <ul className="problems">
                {u.problems.map((p, i) => (
                  <li key={i}>
                    {t('setup.problem.row', { row: p.row })} {t(`row_problem.${p.reason}`)}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="panel-note panel-body">{t('upload.result.deleted')}</p>
        </section>
      )}

      {u.status === 'mapping' && (
        <section className="panel">
          <div className="panel-head">
            <h2>{t('connect.match.title')}</h2>
            <p className="panel-note">{t('upload.match.note')}</p>
          </div>
          <div className="table-wrap preview">
            <table>
              <thead>
                <tr>
                  {u.headers.map((h) => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {u.preview.map((r, i) => (
                  <tr key={i}>
                    {u.headers.map((h, k) => (
                      <td key={h} className="mono">
                        {r[k]}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <form action={importUpload} className="form-grid">
            <input type="hidden" name="id" value={u.id} />
            {FIELDS.map((f) => (
              <label key={f}>
                {t(`match.${f}`)}
                {REQUIRED.has(f) ? '' : ` ${t('match.optional')}`}
                <select name={f} defaultValue={choices[f]} required={REQUIRED.has(f)}>
                  <option value="">{t('match.none')}</option>
                  {u.headers.map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </select>
                <span className="sub">{t(`match.${f}.hint`)}</span>
              </label>
            ))}
            <div className="wide">
              <button className="button button-primary" type="submit">
                {t('upload.import', { rows: formatNumber(u.row_count) })}
              </button>
            </div>
          </form>
          <form action={discardUpload} className="panel-body">
            <input type="hidden" name="id" value={u.id} />
            <button className="button" type="submit">
              {t('upload.discard')}
            </button>
          </form>
        </section>
      )}
    </>
  );
}
