import type { Translate } from './settings';

const numberFormat = new Intl.NumberFormat('en-US');
const rateFormat = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });

export function formatNumber(n: number): string {
  return numberFormat.format(n);
}

export function formatRate(n: number): string {
  return rateFormat.format(n);
}

/** Clock time in UTC, so the server and every viewer print the same thing. */
export function formatClock(date: Date, withSeconds = false): string {
  const iso = date.toISOString();
  return withSeconds ? iso.slice(11, 19) : iso.slice(11, 16);
}

export function formatAgo(date: Date | null, now: Date, t: Translate): string {
  if (!date) return t('time.never');
  const minutes = Math.floor((now.getTime() - date.getTime()) / 60000);
  if (minutes < 1) return t('time.just_now');
  if (minutes < 60) return t('time.minutes_ago', { n: minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return t('time.hours_ago', { n: hours });
  return t('time.days_ago', { n: Math.floor(hours / 24) });
}

/** A day and time in the hospital's own time zone, such as "Thu 29 Oct, 14:05". */
export function formatWhen(date: Date, timeZone: string): string {
  let zone = timeZone;
  try {
    new Intl.DateTimeFormat('en-GB', { timeZone: zone });
  } catch {
    zone = 'UTC';
  }
  return new Intl.DateTimeFormat('en-GB', { timeZone: zone, weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false })
    .format(date)
    .replace(/,? (\d{2}:\d{2})$/, ', $1');
}

/** Which day of a period now falls on, counting from 1, and how many days the period has. */
export function dayOf(start: Date, end: Date, now: Date): { day: number; days: number } {
  const DAY = 86400000;
  const days = Math.max(1, Math.round((end.getTime() - start.getTime()) / DAY));
  const day = Math.min(days, Math.max(1, Math.floor((now.getTime() - start.getTime()) / DAY) + 1));
  return { day, days };
}
