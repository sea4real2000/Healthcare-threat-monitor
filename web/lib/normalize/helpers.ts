import { isIP } from 'node:net';

export type Outcome = 'success' | 'failure' | 'unknown';

/** The common event shape every source is mapped into. Mirrors the events table. */
export interface NormalizedEvent {
  source: string;
  source_event_id: string;
  occurred_at: string;
  category: string;
  action: string;
  outcome: Outcome;
  severity: 0 | 1 | 2 | 3;
  actor_user: string | null;
  host: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  patient_ref: string | null;
  bytes_out: number | null;
  bytes_in: number | null;
  attributes: Record<string, unknown>;
}

export type Raw = Record<string, unknown>;
export type Normalizer = (raw: Raw) => Partial<Omit<NormalizedEvent, 'source' | 'source_event_id' | 'occurred_at'>> & {
  source_event_id: unknown;
  occurred_at: unknown;
  category: string;
  action: string;
};

export class NormalizeError extends Error {}

// Small helpers shared by the source mappers.

export function str(v: unknown): string | null {
  if (typeof v === 'string') return v.trim() === '' ? null : v.trim();
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return null;
}

export function int(v: unknown): number | null {
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : Number.NaN;
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

export function ip(v: unknown): string | null {
  const s = str(v);
  return s && isIP(s) ? s : null;
}

export function obj(v: unknown): Raw {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Raw) : {};
}

export function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

/** Accepts ISO text, epoch seconds or epoch milliseconds. Returns ISO text or null. */
export function toIso(v: unknown): string | null {
  let ms: number;
  if (typeof v === 'number' && Number.isFinite(v)) {
    ms = v > 1e11 ? v : v * 1000;
  } else if (typeof v === 'string' && v.trim() !== '') {
    ms = /^\d+(\.\d+)?$/.test(v.trim()) ? (Number(v) > 1e11 ? Number(v) : Number(v) * 1000) : Date.parse(v);
  } else {
    return null;
  }
  return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

/** Drops empty values so the attributes column stays small. */
export function compact(o: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v !== null && v !== undefined && v !== '') out[k] = v;
  }
  return out;
}
