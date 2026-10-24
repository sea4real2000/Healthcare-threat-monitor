import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

// Turns one row of a hospital's own patient record access log into a FHIR AuditEvent, the format
// the platform reads. engine/connectors/records_convert.py does the same for database connections.
// Both are checked against the same examples in their tests.

export const MAPPING_FIELDS = ['time', 'user', 'patient', 'action', 'outcome', 'workstation', 'record_id'] as const;
export type MappingField = (typeof MAPPING_FIELDS)[number];
export const REQUIRED_FIELDS: MappingField[] = ['time', 'user', 'patient'];
export type Mapping = Partial<Record<MappingField, string>>;

export interface ConvertOptions {
  timezone: string;
  dayFirst: boolean;
  sourceName: string;
  idPrefix: string;
  /** Machine name to address, so a workstation given by name can still be matched. */
  assetIps?: Map<string, string>;
}

export class RowError extends Error {}

const SUCCESS = new Set(['1', 'true', 'yes', 'y', 'success', 'succeeded', 'successful', 'ok', 'allowed', 'granted', 'pass', 'passed']);
const FAILURE = new Set(['false', 'no', 'n', 'fail', 'failed', 'failure', 'denied', 'error', 'blocked', 'refused', 'rejected']);

export function actionCode(value: string | undefined): string {
  const v = (value ?? '').trim().toLowerCase();
  if (['r', 'c', 'u', 'd'].includes(v)) return v.toUpperCase();
  if (/creat|insert|add|new|register/.test(v)) return 'C';
  if (/updat|edit|modif|amend|chang|correct/.test(v)) return 'U';
  if (/delet|remov|purg/.test(v)) return 'D';
  return 'R';
}

export function outcomeCode(value: string | undefined): string | null {
  const v = (value ?? '').trim().toLowerCase();
  if (v === '') return null;
  if (SUCCESS.has(v)) return '0';
  if (FAILURE.has(v)) return '8';
  return null;
}

/** The offset of a time zone from UTC, in minutes, at a given moment. */
function zoneOffsetMinutes(timeZone: string, utcMs: number): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(new Date(utcMs));
  const n = (t: string) => Number(parts.find((p) => p.type === t)?.value);
  const asUtc = Date.UTC(n('year'), n('month') - 1, n('day'), n('hour'), n('minute'), n('second'));
  return Math.round((asUtc - utcMs) / 60000);
}

export function validTimezone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return tz.length <= 64;
  } catch {
    return false;
  }
}

/** Wall clock time in a zone to an instant. Two passes settle the offset around daylight saving changes. */
function fromWallClock(y: number, mo: number, d: number, h: number, mi: number, s: number, ms: number, tz: string): number {
  const wall = Date.UTC(y, mo - 1, d, h, mi, s, ms);
  let utc = wall - zoneOffsetMinutes(tz, wall) * 60000;
  utc = wall - zoneOffsetMinutes(tz, utc) * 60000;
  return utc;
}

const ISO = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,6}))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i;
const SLASH = /^(\d{1,4})[/.-](\d{1,2})[/.-](\d{1,4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?\s*(am|pm)?)?$/i;

export function parseTime(value: string | undefined, tz: string, dayFirst: boolean): string {
  const v = (value ?? '').trim();
  if (!v) throw new RowError('missing_time');
  if (/^\d{10}(\.\d+)?$/.test(v)) return new Date(Math.round(Number(v) * 1000)).toISOString();
  if (/^\d{13}$/.test(v)) return new Date(Number(v)).toISOString();
  let m = ISO.exec(v);
  if (m) {
    const [, y, mo, d, h = '0', mi = '0', s = '0', frac = '0', zone] = m;
    const ms = Math.round(Number(`0.${frac}`) * 1000);
    if (zone) {
      const offset = zone.toUpperCase() === 'Z' ? 0 : (zone[0] === '-' ? -1 : 1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(-2)));
      return check(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s, ms) - offset * 60000, +y, +mo, +d);
    }
    return check(fromWallClock(+y, +mo, +d, +h, +mi, +s, ms, tz), +y, +mo, +d);
  }
  m = SLASH.exec(v);
  if (m) {
    const [, a, b, c, hRaw = '0', mi = '0', s = '0', ampm] = m;
    let y: number, mo: number, d: number;
    if (a.length === 4) [y, mo, d] = [+a, +b, +c];
    else if (c.length === 4) [y, mo, d] = dayFirst ? [+c, +b, +a] : [+c, +a, +b];
    else throw new RowError('bad_time');
    let h = +hRaw;
    if (ampm) h = (h % 12) + (ampm.toLowerCase() === 'pm' ? 12 : 0);
    return check(fromWallClock(y, mo, d, h, +mi, +s, 0, tz), y, mo, d);
  }
  throw new RowError('bad_time');
}

function check(utcMs: number, y: number, mo: number, d: number): string {
  const day = new Date(Date.UTC(y, mo - 1, d));
  // A date such as 30 February rolls over silently in JavaScript, so confirm it exists.
  if (!Number.isFinite(utcMs) || day.getUTCMonth() !== mo - 1 || day.getUTCDate() !== d || y < 1970 || y > 2200) throw new RowError('bad_time');
  return new Date(utcMs).toISOString();
}

function clean(value: string | undefined, max = 64): string {
  return (value ?? '').trim().slice(0, max);
}

export function eventId(prefix: string, parts: string[]): string {
  return `${prefix}-${createHash('sha256').update(parts.join('\u001f'), 'utf8').digest('hex').slice(0, 24)}`;
}

export function toAuditEvent(row: Partial<Record<MappingField, string>>, opts: ConvertOptions): { source: 'ehr'; payload: Record<string, unknown> } {
  const recorded = parseTime(row.time, opts.timezone, opts.dayFirst);
  const user = clean(row.user).toLowerCase();
  const patient = clean(row.patient);
  if (!user) throw new RowError('missing_user');
  if (!patient) throw new RowError('missing_patient');
  const action = actionCode(row.action);
  const outcome = outcomeCode(row.outcome);
  const station = clean(row.workstation);
  const address = station && isIP(station) ? station : station ? opts.assetIps?.get(station.toUpperCase()) ?? null : null;
  const recordId = clean(row.record_id, 120);
  const id = recordId ? `${opts.idPrefix}-${recordId}` : eventId(opts.idPrefix, [recorded, user, patient, action, station]);
  const agent: Record<string, unknown> = { who: { identifier: { value: user } }, requestor: true };
  if (address) agent.network = { address, type: '2' };
  const payload: Record<string, unknown> = {
    resourceType: 'AuditEvent',
    id,
    recorded,
    action,
    agent: [agent],
    entity: [{ what: { reference: `Patient/${patient}` } }],
    source: { observer: { display: opts.sourceName.slice(0, 120) } },
  };
  if (outcome) payload.outcome = outcome;
  return { source: 'ehr', payload };
}
