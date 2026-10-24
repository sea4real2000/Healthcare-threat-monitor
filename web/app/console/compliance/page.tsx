import { db } from '@/lib/db';
import { formatNumber } from '@/lib/format';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

const FRAMEWORKS = ['hipaa', 'nist_csf', 'hhs_405d'];

interface Control {
  id: string;
  framework: string;
  citation: string;
  title: string;
  contribution: string;
  evidence_key: string | null;
  url: string | null;
}

export default async function CompliancePage() {
  const t = await getCopy();
  const sql = db();
  const [controls, [e]] = await Promise.all([
    sql<Control[]>`select id, framework, citation, title, contribution, evidence_key, url from compliance_controls order by framework, sort_order, id`,
    // Live counts. Each control names the count that stands as its evidence.
    sql<Record<string, number>[]>`
      select (select count(*)::int from events) as events_monitored,
             (select count(*)::int from sources s where exists (select 1 from events ev where ev.source = s.id)) as sources_reporting,
             (select count(*)::int from incidents where status <> 'open') as incidents_decided,
             (select count(*)::int from incidents where cardinality(sources) >= 2) as multi_source_incidents,
             (select count(*)::int from alerts where category in ('ransomware', 'endpoint')) as malware_alerts,
             (select count(*)::int from alerts where detector_id in ('failed_logon_burst', 'logon_fan_out', 'vpn_new_country')) as logon_alerts,
             (select count(*)::int from alerts where detector_id in ('ransom_mass_file_rename', 'ransom_note_created', 'ransom_shadow_copy_delete')) as integrity_alerts,
             (select count(*)::int from alerts where category = 'records') as record_alerts,
             (select count(*)::int from alerts where category = 'devices') as device_alerts,
             (select count(*)::int from alerts where category = 'network') as network_alerts,
             (select count(*)::int from alerts where detector_id in ('risky_attachment_delivered', 'malicious_email_delivered')) as email_alerts,
             (select count(*)::int from response_actions where action = 'isolate' and status = 'acknowledged') as isolations,
             (select count(*)::int from siem_outbox where status = 'sent') as forwarded,
             (select count(*)::int from audit_log) as audit_entries,
             (select count(*)::int from assets) as assets_tracked`,
  ]);

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('compliance.title')}</h1>
          <p className="lede">{t('compliance.lede')}</p>
        </div>
      </header>
      <p className="flash">{t('compliance.disclaimer')}</p>
      {FRAMEWORKS.map((f) => {
        const rows = controls.filter((c) => c.framework === f);
        if (rows.length === 0) return null;
        return (
          <section className="panel" key={f} aria-labelledby={`fw-${f}`}>
            <div className="panel-head">
              <h2 id={`fw-${f}`}>{t(`compliance.framework.${f}`)}</h2>
              <p className="panel-note">{t(`compliance.framework.${f}.note`)}</p>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t('compliance.col.safeguard')}</th>
                    <th>{t('compliance.col.contribution')}</th>
                    <th>{t('compliance.col.evidence')}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((c) => (
                    <tr key={c.id}>
                      <td className="wrap">
                        {c.title}
                        <span className="sub">
                          {c.url ? (
                            <a href={c.url} target="_blank" rel="noreferrer">
                              {c.citation}
                            </a>
                          ) : (
                            c.citation
                          )}
                        </span>
                      </td>
                      <td className="wrap">{c.contribution}</td>
                      <td className="wrap num">
                        {c.evidence_key && c.evidence_key in e ? t(`compliance.evidence.${c.evidence_key}`, { n: formatNumber(e[c.evidence_key]) }) : ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
    </>
  );
}
