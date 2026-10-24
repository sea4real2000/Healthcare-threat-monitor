import { Status } from './Status';
import type { Translate } from '@/lib/settings';

export interface SourceRow {
  state: string;
  pending: string | null;
  last_error: string | null;
}

/** One plain status for a records database connection: setting up, working, paused or a problem. */
export function sourceStatus(s: SourceRow): 'problem' | 'working' | 'paused' | 'busy' | 'setup' {
  if (s.pending) return 'busy';
  if (s.last_error) return 'problem';
  if (s.state === 'active') return 'working';
  if (s.state === 'paused') return 'paused';
  return 'setup';
}

export function SourceStatus({ s, t }: { s: SourceRow; t: Translate }) {
  const status = sourceStatus(s);
  const tone = status === 'working' ? 'good' : status === 'problem' ? 'crit' : status === 'busy' ? 'warn' : 'quiet';
  return <Status tone={tone} label={t(`source_status.${status}`)} />;
}
