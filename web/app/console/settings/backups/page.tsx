import { MakeBackup, RestoreBackup } from '@/components/BackupPanel';
import { SettingsTabs } from '@/components/SettingsTabs';
import { backupText } from '@/lib/backupText';
import { backupDir, backupServiceRunning, readyBackups } from '@/lib/backups';
import { requireUser } from '@/lib/session';
import { getCopy, numberSetting, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

/** Backups with clicks: make one to download, or restore one, which replaces everything on this installation. */
export default async function BackupsPage() {
  await requireUser('admin');
  const [t, minLength, confirmWord, keepHours, followMinutes] = await Promise.all([
    getCopy(), numberSetting('backups.passphrase_min_length'), textSetting('backups.restore_confirm_word'),
    numberSetting('backups.keep_hours'), numberSetting('backups.follow_minutes'),
  ]);
  const dir = backupDir();
  const running = dir ? backupServiceRunning(dir) : false;
  const ready = dir ? readyBackups(dir) : [];
  const text = backupText(t);
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('settings.title')}</h1>
          <p className="lede">{t('backups.lede')}</p>
        </div>
      </header>
      <SettingsTabs t={t} current="backups" admin />
      {!dir ? (
        <p className="flash flash-error" role="status">{t('backups.not_available')}</p>
      ) : (
        <>
          {!running ? <p className="flash flash-error" role="status">{t('backups.service_down')}</p> : null}
          <section className="panel" aria-labelledby="make-backup">
            <div className="panel-head">
              <h2 id="make-backup">{t('backups.make_title')}</h2>
            </div>
            <p>{t('backups.make_lede', { hours: keepHours })}</p>
            <MakeBackup text={text} minLength={minLength} limitMinutes={followMinutes} />
          </section>
          <section className="panel" aria-labelledby="ready-backups">
            <div className="panel-head">
              <h2 id="ready-backups">{t('backups.ready_title')}</h2>
            </div>
            {ready.length === 0 ? (
              <p className="sub">{t('backups.ready_none')}</p>
            ) : (
              <ul>
                {ready.map((b) => (
                  <li key={b.id}>
                    <a href={`/api/backups/${b.id}/file`}>{t('backups.download')}</a>{' '}
                    <span className="sub">{new Date(b.made_at ?? b.at).toLocaleString('en-GB')} · {Math.max(1, Math.round((b.bytes ?? 0) / 1024 / 1024))} MB</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section className="panel" aria-labelledby="restore-backup">
            <div className="panel-head">
              <h2 id="restore-backup">{t('backups.restore_title')}</h2>
            </div>
            <p>{t('backups.restore_lede')}</p>
            <RestoreBackup text={text} confirmWord={confirmWord} withCode={false} limitMinutes={followMinutes} />
          </section>
        </>
      )}
    </>
  );
}
