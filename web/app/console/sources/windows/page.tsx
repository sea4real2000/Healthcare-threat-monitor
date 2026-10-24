import Link from 'next/link';
import { Status } from '@/components/Status';
import { Flash } from '@/components/ui';
import { createWindowsGroup, setWindowsGroupEnabled } from '@/lib/connectActions';
import { db } from '@/lib/db';
import { formatAgo, formatNumber } from '@/lib/format';
import { requireUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';
import { rootCertificate, showFingerprint } from '@/lib/windowsInstaller';

export const dynamic = 'force-dynamic';

export default async function WindowsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, params, root] = await Promise.all([getCopy(), searchParams, rootCertificate()]);
  const sql = db();
  const [groups, computers] = await Promise.all([
    sql<{ id: string; name: string; enabled: boolean; created_at: Date; last_seen_at: Date | null; computers: number; now: Date }[]>`
      select c.id, c.name, c.enabled, c.created_at, c.last_seen_at, now() as now,
        (select count(distinct e.host)::int from events e join ingest_batches b on b.id = e.batch_pk
          where b.collector_id = c.id and e.occurred_at > now() - interval '7 days') as computers
      from collectors c where c.kind = 'windows' order by c.created_at`,
    sql<{ host: string; group_name: string; last: Date; day: number; listed: boolean; now: Date }[]>`
      select e.host, c.name as group_name, max(e.occurred_at) as last, now() as now,
        count(*) filter (where e.occurred_at > now() - interval '24 hours')::int as day,
        exists (select 1 from assets a where a.id = e.host) as listed
      from events e join ingest_batches b on b.id = e.batch_pk join collectors c on c.id = b.collector_id
      where c.kind = 'windows' and e.host is not null and e.occurred_at > now() - interval '7 days'
      group by e.host, c.name order by max(e.occurred_at) desc limit 500`,
  ]);
  const fresh = (d: Date | null, now: Date) => Boolean(d && now.getTime() - d.getTime() < 2 * 3600 * 1000);
  const unlisted = computers.filter((c) => !c.listed).length;

  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/sources">{t('sources.title')}</Link>
          </p>
          <h1>{t('windows.title')}</h1>
          <p className="lede">{t('windows.lede')}</p>
        </div>
      </header>
      <Flash params={params} t={t} scope="sources" />

      <section className="panel">
        <div className="panel-head">
          <h2>{t('windows.how.title')}</h2>
        </div>
        <ol className="setup-how panel-body">
          <li>{t('windows.how.group')}</li>
          <li>{t('windows.how.download')}</li>
          <li>
            {t('windows.how.run')}
            <pre className="ask">{t('windows.how.command')}</pre>
          </li>
          <li>{t('windows.how.many')}</li>
          <li>{t('windows.how.appear')}</li>
        </ol>
        <p className="panel-body panel-note">
          {root ? t('windows.trust.pinned', { fingerprint: showFingerprint(root.fingerprint) }) : t('windows.trust.system')}
        </p>
        {root && (
          <p className="panel-body panel-note">
            {t('windows.trust.browsers')}{' '}
            <a href="/api/trust/root" download>
              {t('windows.trust.download')}
            </a>
          </p>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>{t('windows.groups.title')}</h2>
          <p className="panel-note">{t('windows.groups.note')}</p>
        </div>
        <form action={createWindowsGroup} className="inline-form panel-body">
          <input name="name" required maxLength={80} placeholder={t('windows.group.name_placeholder')} aria-label={t('windows.group.name')} />
          <button className="button button-primary" type="submit">
            {t('windows.group.create')}
          </button>
        </form>
        {groups.length === 0 ? (
          <p className="empty">{t('windows.groups.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('windows.col.group')}</th>
                  <th>{t('sources.col.status')}</th>
                  <th>{t('sources.col.last')}</th>
                  <th className="right">{t('windows.col.computers')}</th>
                  <th>{t('receiver.col.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <tr key={g.id} className={params.group === g.id ? 'highlight' : undefined}>
                    <td>
                      {g.name}
                      <span className="sub num">{g.id}</span>
                    </td>
                    <td>
                      <Status
                        tone={!g.enabled ? 'quiet' : fresh(g.last_seen_at, g.now) ? 'good' : g.last_seen_at ? 'warn' : 'quiet'}
                        label={t(!g.enabled ? 'windows.status.off' : fresh(g.last_seen_at, g.now) ? 'windows.status.reporting' : g.last_seen_at ? 'windows.status.quiet' : 'windows.status.waiting')}
                      />
                    </td>
                    <td>{formatAgo(g.last_seen_at, g.now, t)}</td>
                    <td className="right num">{formatNumber(g.computers)}</td>
                    <td className="wrap">
                      <div className="inline-form">
                        {g.enabled && (
                          <a className="button button-primary" href={`/api/collectors/windows/${g.id}`} download>
                            {t('windows.download')}
                          </a>
                        )}
                        <form action={setWindowsGroupEnabled}>
                          <input type="hidden" name="group" value={g.id} />
                          <input type="hidden" name="enabled" value={g.enabled ? 'false' : 'true'} />
                          <button className="button button-quiet" type="submit">
                            {t(g.enabled ? 'windows.switch_off' : 'windows.switch_on')}
                          </button>
                        </form>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>{t('windows.computers.title')}</h2>
          <p className="panel-note">{t('windows.computers.note')}</p>
        </div>
        {unlisted > 0 && <p className="flash">{t('windows.computers.unlisted', { n: unlisted })}</p>}
        {computers.length === 0 ? (
          <p className="empty">{t('windows.computers.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('windows.col.computer')}</th>
                  <th>{t('windows.col.group')}</th>
                  <th>{t('sources.col.status')}</th>
                  <th>{t('sources.col.last')}</th>
                  <th className="right">{t('sources.col.day')}</th>
                </tr>
              </thead>
              <tbody>
                {computers.map((c) => (
                  <tr key={`${c.host}|${c.group_name}`}>
                    <td>
                      {c.host}
                      {!c.listed && <span className="sub">{t('windows.not_listed')}</span>}
                    </td>
                    <td>{c.group_name}</td>
                    <td>
                      <Status tone={fresh(c.last, c.now) ? 'good' : 'warn'} label={t(fresh(c.last, c.now) ? 'windows.status.reporting' : 'windows.status.quiet')} />
                    </td>
                    <td>{formatAgo(c.last, c.now, t)}</td>
                    <td className="right num">{formatNumber(c.day)}</td>
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
