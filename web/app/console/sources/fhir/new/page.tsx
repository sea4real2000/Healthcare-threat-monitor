import Link from 'next/link';
import { FhirForm } from '@/components/FhirForm';
import { Flash } from '@/components/ui';
import { createFhirSource } from '@/lib/connectActions';
import { requireUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function NewFhirPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, params] = await Promise.all([getCopy(), searchParams]);
  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/sources">{t('sources.title')}</Link>
          </p>
          <h1>{t('fhir.title')}</h1>
          <p className="lede">{t('fhir.lede')}</p>
        </div>
      </header>
      <Flash params={params} t={t} scope="sources" />
      <section className="panel">
        <div className="panel-head">
          <h2>{t('connect.ask.title')}</h2>
        </div>
        <div className="panel-body">
          <p>{t('fhir.ask.body')}</p>
          <pre className="mono ask">{t('fhir.ask.request')}</pre>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>{t('connect.details')}</h2>
        </div>
        <FhirForm
          t={t}
          action={createFhirSource}
          editing={false}
          values={{ name: t('fhir.default_name'), base_url: '', auth_kind: 'private_key', client_id: '', token_url: '', scope: 'system/AuditEvent.read', ca_certificate: '', encrypt: true }}
        />
      </section>
    </>
  );
}
