import { db } from './db';
import { normalize, NormalizeError, type NormalizedEvent } from './normalize';

const MAX_REJECT_RAW_CHARS = 8000;

export interface Reject {
  record_index: number;
  source: string | null;
  reason: string;
  raw: unknown;
}

export interface IngestOutcome {
  replayed: boolean;
  accepted: number;
  duplicate: number;
  rejected: number;
  rejects: Reject[];
}

/**
 * Maps a batch of raw records into the common event format and stores it, in one transaction.
 * Used by the signed ingest API and by uploads made in the console, so both follow exactly the same path.
 * Sending the same batch twice changes nothing the second time.
 */
export async function ingestRecords(collectorId: string, batchId: string, runId: string | null, records: unknown[]): Promise<IngestOutcome> {
  const sql = db();
  const enabled = new Set((await sql<{ id: string }[]>`select id from sources where enabled`).map((r) => r.id));
  // A collector made for a group of Windows computers may only send Windows events.
  const [limits] = await sql<{ allowed: string[] | null }[]>`select allowed_sources as allowed from collectors where id = ${collectorId}`;
  const allowed = limits?.allowed ? new Set(limits.allowed) : null;
  const hostByIp = new Map((await sql<{ id: string; ip: string }[]>`select id, host(ip) as ip from assets where ip is not null`).map((r) => [r.ip, r.id]));

  const events: (NormalizedEvent & { raw: unknown })[] = [];
  const rejects: Reject[] = [];
  const now = Date.now();
  records.forEach((record: unknown, index: number) => {
    const source = (record as { source?: unknown })?.source;
    const payload = (record as { payload?: unknown })?.payload;
    const sourceText = typeof source === 'string' ? source.slice(0, 64) : null;
    try {
      const event = normalize(source, payload, now);
      if (allowed && !allowed.has(event.source)) throw new NormalizeError('source_not_allowed');
      if (!enabled.has(event.source)) throw new NormalizeError('source_disabled');
      // Network sources know an address, not a machine. Resolve it against the inventory.
      if (!event.host && event.src_ip) event.host = hostByIp.get(event.src_ip) ?? null;
      events.push({ ...event, raw: payload });
    } catch (err) {
      if (!(err instanceof NormalizeError)) throw err;
      const rawText = JSON.stringify(payload ?? null);
      rejects.push({
        record_index: index,
        source: sourceText,
        reason: err.message,
        raw: rawText.length <= MAX_REJECT_RAW_CHARS ? (payload ?? null) : { truncated: true },
      });
    }
  });

  const total = records.length;

  const outcome = await sql.begin(async (tx) => {
    const created = await tx<{ id: string }[]>`
      insert into ingest_batches (collector_id, batch_id, run_id, records)
      values (${collectorId}, ${batchId}::uuid, ${runId}, ${total})
      on conflict (collector_id, batch_id) do nothing
      returning id`;
    if (created.length === 0) {
      const [prev] = await tx<{ accepted: number; duplicate: number; rejected: number }[]>`
        select accepted, duplicate, rejected from ingest_batches
        where collector_id = ${collectorId} and batch_id = ${batchId}::uuid`;
      return { replayed: true, ...prev };
    }
    const batchPk = created[0].id;

    let accepted = 0;
    if (events.length > 0) {
      const inserted = await tx`
        insert into events (batch_pk, source, source_event_id, occurred_at, category, action, outcome, severity,
          actor_user, host, src_ip, dst_ip, dst_port, protocol, patient_ref, bytes_out, bytes_in, attributes, raw)
        select ${batchPk}::bigint, t.source, t.source_event_id, t.occurred_at, t.category, t.action, t.outcome,
          t.severity, t.actor_user, t.host, t.src_ip, t.dst_ip, t.dst_port, t.protocol, t.patient_ref,
          t.bytes_out, t.bytes_in, t.attributes, t.raw
        from jsonb_to_recordset(${tx.json(events as never)}::jsonb) as t(
          source text, source_event_id text, occurred_at timestamptz, category text, action text, outcome text,
          severity smallint, actor_user text, host text, src_ip inet, dst_ip inet, dst_port integer, protocol text,
          patient_ref text, bytes_out bigint, bytes_in bigint, attributes jsonb, raw jsonb)
        on conflict (source, source_event_id) do nothing`;
      accepted = inserted.count;
    }
    if (rejects.length > 0) {
      await tx`
        insert into ingest_rejects (batch_pk, record_index, source, reason, raw)
        select ${batchPk}::bigint, t.record_index, t.source, t.reason, t.raw
        from jsonb_to_recordset(${tx.json(rejects as never)}::jsonb) as t(
          record_index integer, source text, reason text, raw jsonb)`;
    }
    const duplicate = events.length - accepted;
    await tx`
      update ingest_batches set accepted = ${accepted}, duplicate = ${duplicate}, rejected = ${rejects.length}
      where id = ${batchPk}::bigint`;
    await tx`
      update assets a set last_seen_at = greatest(coalesce(a.last_seen_at, 'epoch'::timestamptz), seen.latest)
      from (select host, max(occurred_at) as latest from events
            where batch_pk = ${batchPk}::bigint and host is not null group by host) seen
      where a.id = seen.host`;
    await tx`update collectors set last_seen_at = now() where id = ${collectorId}`;
    return { replayed: false, accepted, duplicate, rejected: rejects.length };
  });
  return { ...outcome, rejects: outcome.replayed ? [] : rejects };
}
