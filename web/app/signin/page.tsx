import Link from 'next/link';
import { redirect } from 'next/navigation';
import { Flash } from '@/components/ui';
import { signIn, startDemo } from '@/lib/actions';
import { authConfigured } from '@/lib/crypto';
import { firstRunPending } from '@/lib/firstRun';
import { flagSetting, getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function SignInPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  // A new hospital installation has nobody to sign in yet. Its first visit sets up the administrator.
  if (await firstRunPending()) redirect('/welcome');
  const [t, params, demoOn] = await Promise.all([getCopy(), searchParams, flagSetting('demo.enabled')]);
  return (
    <main className="auth">
      <div className="auth-card">
        <h1>{t('signin.title')}</h1>
        <p>{t('signin.lede')}</p>
        <Flash params={params} t={t} scope="signin" />
        {!authConfigured() && <p className="flash flash-error">{t('error.signin.not_configured')}</p>}
        <form action={signIn} className="stack">
          <label>
            {t('signin.email')}
            <input type="email" name="email" autoComplete="username" required maxLength={200} />
          </label>
          <label>
            {t('signin.password')}
            <input type="password" name="password" autoComplete="current-password" required maxLength={200} />
          </label>
          <button className="button button-primary" type="submit">
            {t('signin.continue')}
          </button>
          <Link href="/console">{t('signin.back')}</Link>
        </form>
        {demoOn && (
          <form action={startDemo} className="stack demo-start">
            <h2>{t('signin.demo.title')}</h2>
            <p>{t('signin.demo.body')}</p>
            <button className="button" type="submit">
              {t('signin.demo.button')}
            </button>
          </form>
        )}
      </div>
    </main>
  );
}
