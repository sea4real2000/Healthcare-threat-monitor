import Link from 'next/link';
import { redirect } from 'next/navigation';
import { RestoreBackup } from '@/components/BackupPanel';
import { backupText } from '@/lib/backupText';
import { backupDir } from '@/lib/backups';
import { firstRunPending } from '@/lib/firstRun';
import { getCopy, numberSetting, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

/**
 * On a new installation nobody has set up yet: restore a backup from an earlier one instead of starting afresh.
 * This is how an installation moves to a new version or a new computer. It needs the setup code from the screen.
 */
export default async function WelcomeRestorePage() {
  if (!(await firstRunPending()) || !backupDir()) redirect('/welcome');
  const [t, confirmWord, followMinutes] = await Promise.all([getCopy(), textSetting('backups.restore_confirm_word'), numberSetting('backups.follow_minutes')]);
  return (
    <main className="auth">
      <div className="auth-card">
        <h1>{t('backups.welcome_title')}</h1>
        <p>{t('backups.welcome_lede')}</p>
        <RestoreBackup text={backupText(t)} confirmWord={confirmWord} withCode limitMinutes={followMinutes} />
        <p className="sub">
          <Link href="/welcome">{t('backups.welcome_back')}</Link>
        </p>
      </div>
    </main>
  );
}
