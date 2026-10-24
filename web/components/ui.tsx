import type { Translate } from '@/lib/settings';

const BAND_SHAPE: Record<string, React.ReactNode> = {
  high: <path d="M6 0.5 11.5 11H0.5Z" fill="currentColor" />,
  medium: <rect x="1.5" y="1.5" width="9" height="9" rx="1.5" fill="currentColor" />,
  low: <circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" strokeWidth="2" />,
};

/** The confidence band of an incident. Shape and word carry it, colour only helps. */
export function Band({ band, label }: { band: string; label: string }) {
  return (
    <span className={`band band-${band}`}>
      <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
        {BAND_SHAPE[band] ?? BAND_SHAPE.low}
      </svg>
      {label}
    </span>
  );
}

/** Shows the outcome of the last action, passed back in the address as notice or error. */
export function Flash({ params, t, scope }: { params: Record<string, string | string[] | undefined>; t: Translate; scope: string }) {
  const pick = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v)?.replace(/[^a-z_]/g, '').slice(0, 40);
  const notice = pick(params.notice);
  const error = pick(params.error);
  if (!notice && !error) return null;
  return (
    <p className={`flash ${error ? 'flash-error' : 'flash-ok'}`} role="status">
      {error ? t(`error.${scope}.${error}`) : t(`notice.${scope}.${notice}`)}
    </p>
  );
}

export function percent(value: number | string): string {
  return `${Math.round(Number(value) * 100)}%`;
}

export function pretty(value: string): string {
  return value.replaceAll('_', ' ');
}
