import Link from 'next/link';
import { redirect } from 'next/navigation';
import { RuleForm, RuleHelp } from '@/components/RuleForm';
import { Flash } from '@/components/ui';
import { createRule } from '@/lib/actions';
import { currentUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const STARTER = {
  where: [
    { field: 'category', op: 'eq', value: 'process' },
    { field: 'attributes.process_name', op: 'in', value: ['example.exe'] },
  ],
  entity_field: 'host',
};

export default async function NewRulePage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, user, query] = await Promise.all([getCopy(), currentUser(), searchParams]);
  if (!user) redirect('/signin');
  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/rules">{t('rules.title')}</Link>
          </p>
          <h1>{t('rules.add')}</h1>
        </div>
      </header>
      <Flash params={query} t={t} scope="rule" />
      <section className="panel">
        <div className="panel-head">
          <h2>{t('rule.edit.title')}</h2>
        </div>
        <RuleForm
          rule={{ id: '', name: '', description: '', category: 'network', kind: 'match', severity: 2, confidence: '0.5', technique_id: null, technique_name: null, enabled: true, definition: STARTER }}
          t={t}
          action={createRule}
          creating
          readOnly={false}
        />
      </section>
      <RuleHelp t={t} />
    </>
  );
}
