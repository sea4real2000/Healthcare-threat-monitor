import Link from 'next/link';
import { redirect } from 'next/navigation';
import { RailNav } from '@/components/RailNav';
import { signOut } from '@/lib/actions';
import { currentUser, demoVisitor } from '@/lib/session';
import { flagSetting, getCopy, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const SECTIONS = ['overview', 'incidents', 'assets', 'sources', 'rules', 'models', 'scenarios', 'forwarding', 'audit', 'compliance', 'evaluation', 'settings'];

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  let shell: { name: string; hospital: string; simulated: boolean; t: Awaited<ReturnType<typeof getCopy>>; user: Awaited<ReturnType<typeof currentUser>>; demo: Awaited<ReturnType<typeof demoVisitor>> } | null = null;
  let failure: string | null = null;
  try {
    shell = { name: await textSetting('platform.name'), hospital: await textSetting('hospital.name'), simulated: await flagSetting('engine.simulate'), t: await getCopy(), user: await currentUser(), demo: await demoVisitor() };
  } catch (err) {
    console.error('[console] cannot load settings', err);
    failure = (err as Error)?.message ?? 'unknown';
  }

  if (!shell) {
    // Copy lives in the database, so this one message cannot. It is for operators only.
    return (
      <main className="work">
        <div className="notice" role="alert">
          <h1>Database not reachable</h1>
          <p>
            The console could not read its settings. Check DATABASE_URL, confirm the migrations have been applied, then
            open /api/health for detail.
          </p>
          <p className="num">{failure}</p>
        </div>
      </main>
    );
  }

  const { name, hospital, simulated, t, user, demo } = shell;
  // On a real hospital's installation the console shows real staff and patient identifiers, so it is for signed in staff only.
  if (!simulated && !user && !demo) redirect('/signin');
  const person = user ?? demo;
  return (
    <div className="shell">
      <aside className="rail">
        <p className="rail-brand">
          <Link href="/" style={{ color: 'inherit', textDecoration: 'none' }}>
            {name}
          </Link>
        </p>
        <RailNav
          label={t('nav.label')}
          items={[...SECTIONS, ...(user?.role === 'admin' ? ['setup'] : [])].map((s) => ({ href: s === 'overview' ? '/console' : `/console/${s}`, label: t(`nav.${s}`) }))}
        />
        <div className="rail-user">
          {person ? (
            <>
              <strong>{person.name}</strong>
              {t(`role.${person.role}`)}
              <form action={signOut}>
                <button type="submit">{t('auth.sign_out')}</button>
              </form>
            </>
          ) : (
            <>
              {t('auth.visitor')} <Link href="/signin">{t('auth.sign_in')}</Link>
            </>
          )}
          <p className="rail-note">{simulated ? t('banner.simulated') : hospital ? `${hospital}. ${t('banner.real')}` : t('banner.real')}</p>
        </div>
      </aside>
      <main className="work">
        {demo && (
          <p className="flash demo-banner" role="note">
            {t('demo.banner')} {t('demo.release_note')}
          </p>
        )}
        {children}
      </main>
    </div>
  );
}
