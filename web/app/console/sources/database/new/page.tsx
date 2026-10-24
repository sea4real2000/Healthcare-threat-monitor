import Link from 'next/link';
import { ConnectionForm } from '@/components/ConnectionForm';
import { Flash } from '@/components/ui';
import { createRecordSource } from '@/lib/setupActions';
import { requireUser } from '@/lib/session';
import { getCopy, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function NewConnectionPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, params, tz] = await Promise.all([getCopy(), searchParams, textSetting('hospital.timezone')]);
  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/sources">{t('sources.title')}</Link>
          </p>
          <h1>{t('sources.connect')}</h1>
          <p className="lede">{t('connect.lede')}</p>
        </div>
      </header>
      <Flash params={params} t={t} scope="sources" />
      <section className="panel">
        <div className="panel-head">
          <h2>{t('connect.ask.title')}</h2>
        </div>
        <div className="panel-body">
          <p>{t('connect.ask.body')}</p>
          <pre className="mono ask">{t('connect.ask.request')}</pre>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>{t('connect.details')}</h2>
        </div>
        <ConnectionForm
          t={t}
          action={createRecordSource}
          zones={Intl.supportedValuesOf('timeZone')}
          editing={false}
          values={{ name: t('connect.default_name'), kind: 'postgres', host: '', port: 5432, database_name: '', username: '', encrypt: true, timezone: tz || 'UTC', day_first: true }}
        />
      </section>
    </>
  );
}
