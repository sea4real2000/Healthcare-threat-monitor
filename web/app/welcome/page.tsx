import { redirect } from 'next/navigation';
import { Flash } from '@/components/ui';
import { claimFirstRun } from '@/lib/actions';
import { firstRunPending } from '@/lib/firstRun';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

/** The first visit to a new hospital installation: whoever can see its screen sets up the administrator. */
export default async function WelcomePage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  if (!(await firstRunPending())) redirect('/signin');
  const [t, params] = await Promise.all([getCopy(), searchParams]);
  return (
    <main className="auth">
      <div className="auth-card">
        <h1>{t('welcome.title')}</h1>
        <p>{t('welcome.lede')}</p>
        <Flash params={params} t={t} scope="welcome" />
        <form action={claimFirstRun} className="stack">
          <label>
            {t('welcome.code')}
            <input name="code" required maxLength={40} autoComplete="off" autoCapitalize="characters" spellCheck={false} placeholder="ABCDE FGHJK" />
            <span className="sub">{t('welcome.code_hint')}</span>
          </label>
          <label>
            {t('welcome.name')}
            <input name="name" required maxLength={80} autoComplete="name" />
          </label>
          <label>
            {t('welcome.email')}
            <input type="email" name="email" required maxLength={200} autoComplete="email" />
            <span className="sub">{t('welcome.email_hint')}</span>
          </label>
          <button className="button button-primary" type="submit">
            {t('welcome.continue')}
          </button>
        </form>
        <p className="sub">{t('welcome.next')}</p>
      </div>
    </main>
  );
}
