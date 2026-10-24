export type Tone = 'good' | 'warn' | 'crit' | 'quiet';

/** A status is always a shape plus a word. The shape differs by tone so it survives without colour. */
export function Status({ tone, label }: { tone: Tone; label: string }) {
  return (
    <span className={`status status-${tone}`}>
      <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
        {tone === 'good' && <circle cx="6" cy="6" r="5" fill="currentColor" />}
        {tone === 'warn' && <path d="M6 1 11.5 11H0.5Z" fill="currentColor" />}
        {tone === 'crit' && <rect x="1" y="1" width="10" height="10" rx="1.5" fill="currentColor" />}
        {tone === 'quiet' && <circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" strokeWidth="2" />}
      </svg>
      <span>{label}</span>
    </span>
  );
}
