import type { Metadata } from 'next';
import '@fontsource-variable/inter';
import '@fontsource/poppins/500.css';
import '@fontsource/poppins/600.css';
import '@fontsource/poppins/700.css';
import './globals.css';
import { textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export async function generateMetadata(): Promise<Metadata> {
  try {
    return { title: await textSetting('platform.name'), robots: { index: false } };
  } catch {
    // The database is unreachable. The page body explains why, so the tab stays blank here.
    return { title: '', robots: { index: false } };
  }
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
