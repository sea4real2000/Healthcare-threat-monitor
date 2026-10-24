import Link from 'next/link';
import { Flash } from '@/components/ui';
import { db } from '@/lib/db';
import { FIELDS, KINDS, type Kind } from '@/lib/inventoryFiles';
import { formatAgo, formatNumber } from '@/lib/format';
import { addInventoryRow, importInventory, saveHospitalDetails } from '@/lib/setupActions';
import { requireUser } from '@/lib/session';
import { getCopy, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const CHOICES: Record<string, string[]> = {
  'assets.kind': ['workstation', 'server', 'medical_device', 'network'],
  'staff.status': ['active', 'terminated'],
  'patients.flag': ['', 'vip', 'staff'],
};

interface Import {
  kind: Kind;
  filename: string | null;
  status: 'imported' | 'refused';
  rows: number;
  problems: { row: number; reason: string; detail?: string }[];
  imported_at: Date;
  now: Date;
}

export default async function SetupPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, params, name, timezone] = await Promise.all([getCopy(), searchParams, textSetting('hospital.name'), textSetting('hospital.timezone')]);
  const sql = db();
  const [counts] = await sql<{ departments: number; staff: number; assets: number; patients: number; sources: number; uploads: number }[]>`
    select (select count(*)::int from departments) as departments, (select count(*)::int from staff) as staff,
           (select count(*)::int from assets) as assets, (select count(*)::int from patients) as patients,
           (select count(*)::int from record_sources where state = 'active') as sources,
           (select count(*)::int from record_uploads where status = 'imported') as uploads`;
  const latest = await sql<Import[]>`
    select distinct on (kind) kind, filename, status, rows, problems, imported_at, now() as now
    from inventory_imports order by kind, id desc`;
  const last = new Map(latest.map((r) => [r.kind, r]));
  const zones = Intl.supportedValuesOf('timeZone');
  const done = {
    hospital: Boolean(name),
    departments: counts.departments > 0,
    staff: counts.staff > 0,
    assets: counts.assets > 0,
    patients: counts.patients > 0,
    records: counts.sources + counts.uploads > 0,
  };
  const steps = ['hospital', ...KINDS, 'records'] as const;
  const focus = typeof params.kind === 'string' ? params.kind : null;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('setup.wizard_title')}</h1>
          <p className="lede">{t('setup.lede')}</p>
        </div>
      </header>
      <ol className="setup-steps" aria-label={t('setup.progress')}>
        {steps.map((s) => (
          <li key={s} className={done[s] ? 'done' : ''}>
            <a href={`#${s}`}>{t(`setup.step.${s}`)}</a>
            <span>{done[s] ? t('setup.done') : s === 'patients' ? t('setup.optional') : t('setup.todo')}</span>
          </li>
        ))}
      </ol>
      <Flash params={params} t={t} scope="setup" />

      <section className="panel" id="hospital">
        <div className="panel-head">
          <h2>{t('setup.step.hospital')}</h2>
        </div>
        <form action={saveHospitalDetails} className="form-grid">
          <label>
            {t('setup.hospital.name')}
            <input name="name" maxLength={120} defaultValue={name} required />
          </label>
          <label>
            {t('setup.hospital.timezone')}
            <input name="timezone" list="zones" defaultValue={timezone} required maxLength={64} />
            <span className="sub">{t('setup.hospital.timezone_hint')}</span>
          </label>
          <datalist id="zones">
            {zones.map((z) => (
              <option key={z} value={z} />
            ))}
          </datalist>
          <div className="wide">
            <button className="button button-primary" type="submit">
              {t('setup.save')}
            </button>
          </div>
        </form>
      </section>

      {KINDS.map((kind) => {
        const imp = last.get(kind);
        return (
          <section className="panel" id={kind} key={kind}>
            <div className="panel-head">
              <h2>{t(`setup.step.${kind}`)}</h2>
              <span className="panel-note">{t('setup.count', { n: formatNumber(counts[kind]) })}</span>
            </div>
            <div className="panel-body setup-kind">
              <p>{t(`setup.${kind}.why`)}</p>
              <ol className="setup-how">
                <li>
                  <a href={`/api/templates/${kind}.csv`} download>
                    {t('setup.template')}
                  </a>{' '}
                  {t('setup.template_hint')}
                </li>
                <li>{t(`setup.${kind}.fill`)}</li>
                <li>{t('setup.upload_hint')}</li>
              </ol>
              {imp && (
                <div className={`flash ${imp.status === 'imported' ? 'flash-ok' : 'flash-error'}`} role={focus === kind ? 'status' : undefined}>
                  {imp.status === 'imported'
                    ? t('setup.last_imported', { rows: imp.rows === 1 ? t('setup.one_row') : t('setup.rows', { n: formatNumber(imp.rows) }), file: imp.filename ?? t('setup.typed_in'), when: formatAgo(imp.imported_at, imp.now, t) })
                    : t('setup.last_refused', { file: imp.filename ?? t('setup.typed_in'), when: formatAgo(imp.imported_at, imp.now, t) })}
                  {imp.status === 'refused' && (
                    <ul className="problems">
                      {imp.problems.map((p, i) => (
                        <li key={i}>
                          {p.row > 0 ? t('setup.problem.row', { row: p.row }) + ' ' : ''}
                          {t(`setup.problem.${p.reason}`, { detail: p.detail ?? '' })}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
              <form action={importInventory} className="inline-upload">
                <input type="hidden" name="inventory" value={kind} />
                <input type="file" name="file" accept=".csv,text/csv" required aria-label={t('setup.file')} />
                <button className="button button-primary" type="submit">
                  {t('setup.upload')}
                </button>
              </form>
              <details>
                <summary>{t('setup.add_one')}</summary>
                <form action={addInventoryRow} className="form-grid">
                  <input type="hidden" name="inventory" value={kind} />
                  {FIELDS[kind].map((f) => (
                    <label key={f.key}>
                      {t(`setup.field.${kind}.${f.key}`)}
                      {CHOICES[`${kind}.${f.key}`] ? (
                        <select name={f.key} defaultValue={CHOICES[`${kind}.${f.key}`][0]}>
                          {CHOICES[`${kind}.${f.key}`].map((c) => (
                            <option key={c} value={c}>
                              {t(`setup.choice.${c || 'none'}`)}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <input name={f.key} required={f.required} maxLength={120} />
                      )}
                    </label>
                  ))}
                  <div className="wide">
                    <button className="button" type="submit">
                      {t('setup.add')}
                    </button>
                  </div>
                </form>
              </details>
            </div>
          </section>
        );
      })}

      <section className="panel" id="records">
        <div className="panel-head">
          <h2>{t('setup.step.records')}</h2>
        </div>
        <div className="panel-body">
          <p>{t('setup.records.why')}</p>
          <p>
            <Link className="button button-primary" href="/console/sources/database/new">
              {t('sources.connect')}
            </Link>{' '}
            <Link className="button" href="/console/sources/upload">
              {t('sources.upload')}
            </Link>
          </p>
        </div>
      </section>
    </>
  );
}
