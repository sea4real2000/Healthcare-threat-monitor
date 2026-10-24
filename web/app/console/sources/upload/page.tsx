import Link from 'next/link';
import { Flash } from '@/components/ui';
import { createUpload } from '@/lib/setupActions';
import { requireUser } from '@/lib/session';
import { getCopy, numberSetting, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function UploadPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, params, tz, limit] = await Promise.all([getCopy(), searchParams, textSetting('hospital.timezone'), numberSetting('uploads.max_bytes')]);
  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/sources">{t('sources.title')}</Link>
          </p>
          <h1>{t('sources.upload')}</h1>
          <p className="lede">{t('upload.lede')}</p>
        </div>
      </header>
      <Flash params={params} t={t} scope="sources" />
      <section className="panel">
        <div className="panel-head">
          <h2>{t('upload.how.title')}</h2>
        </div>
        <ol className="setup-how panel-body">
          <li>{t('upload.how.export')}</li>
          <li>{t('upload.how.columns')}</li>
          <li>{t('upload.how.csv', { limit: Math.round(limit / 1000000) })}</li>
        </ol>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>{t('upload.file.title')}</h2>
        </div>
        <form action={createUpload} className="form-grid">
          <label className="wide">
            {t('upload.file')}
            <input type="file" name="file" accept=".csv,text/csv" required />
          </label>
          <label>
            {t('connect.timezone')}
            <input name="timezone" list="zones" required maxLength={64} defaultValue={tz || 'UTC'} />
            <span className="sub">{t('connect.timezone_hint')}</span>
          </label>
          <datalist id="zones">
            {Intl.supportedValuesOf('timeZone').map((z) => (
              <option key={z} value={z} />
            ))}
          </datalist>
          <label>
            {t('connect.day_first')}
            <select name="day_first" defaultValue="true">
              <option value="true">{t('connect.day_first.true')}</option>
              <option value="false">{t('connect.day_first.false')}</option>
            </select>
          </label>
          <div className="wide">
            <button className="button button-primary" type="submit">
              {t('upload.submit')}
            </button>
          </div>
        </form>
      </section>
    </>
  );
}
