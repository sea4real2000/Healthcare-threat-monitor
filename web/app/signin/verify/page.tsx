import { redirect } from 'next/navigation';
import { Flash } from '@/components/ui';
import { signOut, verifyCode } from '@/lib/actions';
import { anySession } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function VerifyPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, params, session] = await Promise.all([getCopy(), searchParams, anySession()]);
  if (!session) redirect('/signin');
  if (session.mfaPassed) redirect('/console/incidents');
  return (
    <main className="auth">
      <div className="auth-card">
        <h1>{t('verify.title')}</h1>
        <p>{t('verify.lede')}</p>
        <Flash params={params} t={t} scope="signin" />
        <form action={verifyCode} className="stack">
          <label>
            {t('verify.code')}
            <input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" required autoFocus maxLength={7} />
          </label>
          <button className="button button-primary" type="submit">
            {t('verify.submit')}
          </button>
        </form>
        <form action={signOut} className="stack">
          <button className="button button-quiet" type="submit">
            {t('verify.cancel')}
          </button>
        </form>
      </div>
    </main>
  );
}
