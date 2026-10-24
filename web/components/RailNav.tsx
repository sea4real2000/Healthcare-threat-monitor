'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export interface NavItem {
  href: string;
  label: string;
}

export function RailNav({ items, label }: { items: NavItem[]; label: string }) {
  const pathname = usePathname();
  return (
    <nav className="rail-nav" aria-label={label}>
      {items.map((item) => (
        <Link key={item.href} href={item.href} aria-current={(item.href === '/console' ? pathname === item.href : pathname.startsWith(item.href)) ? 'page' : undefined}>
          {item.label}
        </Link>
      ))}
    </nav>
  );
}
