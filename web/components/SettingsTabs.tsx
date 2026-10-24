import Link from 'next/link';
import type { Translate } from '@/lib/settings';

export function SettingsTabs({ t, current, admin }: { t: Translate; current: string; admin: boolean }) {
  const tabs = admin ? ['settings', 'copy', 'images', 'users'] : ['settings'];
  return (
    <nav className="tabs" aria-label={t('settings.tabs')}>
      {tabs.map((tab) => (
        <Link key={tab} href={tab === 'settings' ? '/console/settings' : `/console/settings/${tab}`} aria-current={tab === current ? 'page' : undefined}>
          {t(`settings.tab.${tab}`)}
        </Link>
      ))}
    </nav>
  );
}
