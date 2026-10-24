import Link from 'next/link';
import { AutoRefresh } from '@/components/AutoRefresh';
import { pretty } from '@/components/ui';
import { Status } from '@/components/Status';
import { db } from '@/lib/db';
import { formatAgo, formatClock, formatNumber } from '@/lib/format';
import { getCopy, numberSetting, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function ForwardingPage() {
  const [t, refresh, webhook, syslogHost, syslogPort] = await Promise.all([
    getCopy(),
    numberSetting('console.refresh_seconds'),
    textSetting('siem.webhook_url'),
    textSetting('siem.syslog_host'),
    numberSetting('siem.syslog_port'),
  ]);
  const sql = db();
  const [[counts], outbox, inbox] = await Promise.all([
    sql<{ sent: number; pending: number; failed: number; now: Date }[]>`
      select count(*) filter (where status = 'sent')::int as sent, count(*) filter (where status = 'pending')::int as pending,
             count(*) filter (where status = 'failed')::int as failed, now() as now from siem_outbox`,
    sql<{ id: string; created_at: Date; incident_id: string | null; event_type: string; status: string; webhook_result: string | null; syslog_result: string | null }[]>`
      select id::text as id, created_at, incident_id::text as incident_id, event_type, status, webhook_result, syslog_result
      from siem_outbox order by siem_outbox.id desc limit 20`,
    sql<{ id: string; received_at: Date; signature_ok: boolean; event_type: string | null; incident_id: string | null; cef: string | null; payload: unknown }[]>`
      select id::text as id, received_at, signature_ok, event_type, incident_id::text as incident_id, cef, payload
      from siem_inbox order by siem_inbox.id desc limit 15`,
  ]);

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('forwarding.title')}</h1>
          <p className="lede">{t('forwarding.lede')}</p>
        </div>
        <AutoRefresh seconds={refresh} updatedText={t('refresh.updated', { time: formatClock(counts.now, true) })} pauseLabel={t('refresh.pause')} resumeLabel={t('refresh.resume')} />
      </header>

      <section className="panel" aria-labelledby="destinations">
        <div className="panel-head">
          <h2 id="destinations">{t('forwarding.destinations.title')}</h2>
          <p className="panel-note num">{t('forwarding.counts', { sent: formatNumber(counts.sent), pending: formatNumber(counts.pending), failed: formatNumber(counts.failed) })}</p>
        </div>
        <dl className="facts">
          <dt>{t('forwarding.destinations.webhook')}</dt>
          <dd>{webhook || t('forwarding.destinations.builtin')}</dd>
          <dt>{t('forwarding.destinations.syslog')}</dt>
          <dd>{syslogHost ? `${syslogHost}:${syslogPort}` : t('forwarding.destinations.syslog_off')}</dd>
        </dl>
      </section>

      <section className="panel" aria-labelledby="received">
        <div className="panel-head">
          <h2 id="received">{t('forwarding.inbox.title')}</h2>
          <p className="panel-note">{t('forwarding.inbox.note')}</p>
        </div>
        {inbox.length === 0 ? (
          <p className="empty">{t('forwarding.inbox.empty')}</p>
        ) : (
          inbox.map((m) => (
            <div className="detector" key={m.id}>
              <div className="meta" style={{ marginTop: 0 }}>
                <strong>{pretty(m.event_type ?? '')}</strong>
                <span className="num">{formatClock(m.received_at, true)} UTC</span>
                <Status tone={m.signature_ok ? 'good' : 'crit'} label={t(m.signature_ok ? 'forwarding.signature.ok' : 'forwarding.signature.bad')} />
                {m.incident_id && <Link href={`/console/incidents/${m.incident_id}`}>{t('incidents.number', { id: m.incident_id })}</Link>}
              </div>
              <p className="mono">{m.cef}</p>
              <details className="as-table">
                <summary>{t('forwarding.inbox.json')}</summary>
                <pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(m.payload, null, 2)}
                </pre>
              </details>
            </div>
          ))
        )}
      </section>

      <section className="panel" aria-labelledby="sent">
        <div className="panel-head">
          <h2 id="sent">{t('forwarding.outbox.title')}</h2>
        </div>
        {outbox.length === 0 ? (
          <p className="empty">{t('forwarding.outbox.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('forwarding.col.message')}</th>
                  <th>{t('forwarding.col.incident')}</th>
                  <th>{t('forwarding.col.status')}</th>
                  <th>{t('forwarding.col.webhook')}</th>
                  <th>{t('forwarding.col.syslog')}</th>
                  <th>{t('forwarding.col.created')}</th>
                </tr>
              </thead>
              <tbody>
                {outbox.map((m) => (
                  <tr key={m.id}>
                    <td>{pretty(m.event_type)}</td>
                    <td>{m.incident_id ? <Link href={`/console/incidents/${m.incident_id}`}>{m.incident_id}</Link> : ''}</td>
                    <td>
                      <Status tone={m.status === 'sent' ? 'good' : m.status === 'failed' ? 'crit' : 'warn'} label={t(`forwarding.status.${m.status}`)} />
                    </td>
                    <td>{m.webhook_result ?? ''}</td>
                    <td>{m.syslog_result ?? ''}</td>
                    <td className="num">{formatAgo(m.created_at, counts.now, t)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
