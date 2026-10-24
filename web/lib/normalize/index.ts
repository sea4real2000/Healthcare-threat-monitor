import { NORMALIZERS } from './sources';
import { compact, str, toIso, NormalizeError, type NormalizedEvent, type Raw } from './helpers';

export * from './helpers';

export const SOURCE_IDS = Object.keys(NORMALIZERS);

const MAX_FUTURE_MS = 10 * 60 * 1000;
const MAX_TEXT = 512;

function clip(v: string | null): string | null {
  return v && v.length > MAX_TEXT ? v.slice(0, MAX_TEXT) : v;
}

/**
 * Maps one raw record into the common schema.
 * Throws NormalizeError with a short machine readable reason when the record cannot be used.
 */
export function normalize(source: unknown, payload: unknown, nowMs: number = Date.now()): NormalizedEvent {
  if (typeof source !== 'string' || !Object.hasOwn(NORMALIZERS, source)) {
    throw new NormalizeError('unknown_source');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new NormalizeError('payload_not_an_object');
  }
  const mapped = NORMALIZERS[source](payload as Raw);

  const id = str(mapped.source_event_id);
  if (!id) throw new NormalizeError('missing_event_id');
  if (id.length > 200) throw new NormalizeError('event_id_too_long');

  const occurred = toIso(mapped.occurred_at);
  if (!occurred) throw new NormalizeError('missing_or_bad_time');
  if (Date.parse(occurred) - nowMs > MAX_FUTURE_MS) throw new NormalizeError('time_in_future');

  const port = mapped.dst_port ?? null;
  return {
    source,
    source_event_id: id,
    occurred_at: occurred,
    category: mapped.category,
    action: mapped.action,
    outcome: mapped.outcome ?? 'unknown',
    severity: mapped.severity ?? 0,
    actor_user: clip(mapped.actor_user?.toLowerCase() ?? null),
    host: clip(mapped.host?.toUpperCase() ?? null),
    src_ip: mapped.src_ip ?? null,
    dst_ip: mapped.dst_ip ?? null,
    dst_port: port !== null && port >= 0 && port <= 65535 ? port : null,
    protocol: clip(mapped.protocol?.toLowerCase() ?? null),
    patient_ref: clip(mapped.patient_ref ?? null),
    bytes_out: mapped.bytes_out != null && mapped.bytes_out >= 0 ? mapped.bytes_out : null,
    bytes_in: mapped.bytes_in != null && mapped.bytes_in >= 0 ? mapped.bytes_in : null,
    attributes: compact(mapped.attributes ?? {}),
  };
}
