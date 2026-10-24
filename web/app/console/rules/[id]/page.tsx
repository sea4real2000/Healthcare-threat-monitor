import Link from 'next/link';
import { notFound } from 'next/navigation';
import { RuleForm, RuleHelp, type RuleValues } from '@/components/RuleForm';
import { Flash } from '@/components/ui';
import { saveRule } from '@/lib/actions';
import { db } from '@/lib/db';
import { currentUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function RulePage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const { id } = await params;
  const [t, user, query] = await Promise.all([getCopy(), currentUser(), searchParams]);
  const [rule] = await db()<(RuleValues & { load_error: string | null; updated_by: string | null })[]>`
    select id, name, description, category, kind, severity, confidence::text as confidence, technique_id, technique_name, enabled, definition, load_error, updated_by
    from rules where id = ${id.slice(0, 64)}`;
  if (!rule) notFound();
  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/rules">{t('rules.title')}</Link> / {rule.id}
          </p>
          <h1>{rule.name}</h1>
          <p className="lede">
            {t(`rule_kind.${rule.kind}`)}. {t(`category.${rule.category}`)}.
          </p>
        </div>
      </header>
      <Flash params={query} t={t} scope="rule" />
      {rule.load_error && <p className="flash flash-error">{t('rule.load_error', { error: rule.load_error })}</p>}
      {!user && <p className="flash">{t('rule.read_only')}</p>}
      <section className="panel">
        <div className="panel-head">
          <h2>{t('rule.edit.title')}</h2>
        </div>
        <RuleForm rule={rule} t={t} action={saveRule} creating={false} readOnly={!user} />
      </section>
      <RuleHelp t={t} />
    </>
  );
}
