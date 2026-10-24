import { headers } from 'next/headers';
import Link from 'next/link';
import { Status } from '@/components/Status';
import { Flash } from '@/components/ui';
import { decideSender, removeSender, renameSender } from '@/lib/connectActions';
import { db } from '@/lib/db';
import { formatAgo, formatNumber } from '@/lib/format';
import { requireUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

// Devices with a short guide. Each guide's wording lives in the copy table, so it can be corrected without code.
const DEVICES = ['fortigate', 'pfsense', 'opnsense', 'mikrotik', 'cisco_asa', 'openwrt', 'ubiquiti', 'sophos', 'linux'];

interface SenderRow {
  id: string;
  address: string;
  name: string;
  state: 'pending' | 'accepted' | 'blocked';
  format: string | null;
  last_seen_at: Date | null;
  received: string;
  stored: string;
  not_understood: string;
  last_unparsed: string | null;
  now: Date;
}

export default async function ReceiverPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  await requireUser('admin');
  const [t, params, h] = await Promise.all([getCopy(), searchParams, headers()]);
  const sql = db();
  const [senders, [beat]] = await Promise.all([
    sql<SenderRow[]>`
      select id::text as id, host(address) as address, name, state, format, last_seen_at, received::text, stored::text,
        not_understood::text, last_unparsed, now() as now
      from log_senders order by state = 'pending' desc, state = 'accepted' desc, last_seen_at desc nulls last`,
    sql<{ fresh: boolean; gateway: string | null }[]>`
      select updated_at > now() - interval '1 minute' as fresh, value->>'gateway' as gateway from engine_state where key = 'receiver_heartbeat'`,
  ]);
  // The address staff already use to reach the console is the one devices send to.
  const address = (h.get('x-forwarded-host') ?? h.get('host') ?? '').replace(/:\d+$/, '') || t('receiver.this_computer');
  const running = Boolean(beat?.fresh);
  // Docker hides devices' own addresses when it passes traffic on through its proxy. Then every device looks like one.
  const hidden = Boolean(beat?.gateway) && senders.some((s) => s.address === beat?.gateway);

  return (
    <>
      <header className="page-head">
        <div>
          <p className="panel-note">
            <Link href="/console/sources">{t('sources.title')}</Link>
          </p>
          <h1>{t('receiver.title')}</h1>
          <p className="lede">{t('receiver.lede')}</p>
        </div>
      </header>
      <Flash params={params} t={t} scope="sources" />

      <section className="panel">
        <div className="panel-head">
          <h2>{t('receiver.where.title')}</h2>
          <Status tone={running ? 'good' : 'crit'} label={t(running ? 'receiver.running' : 'receiver.not_running')} />
        </div>
        {!running && <p className="flash flash-error">{t('receiver.not_running_note')}</p>}
        {hidden && <p className="flash flash-error">{t('receiver.hidden_addresses', { gateway: beat?.gateway ?? '' })}</p>}
        <dl className="facts">
          <div>
            <dt>{t('receiver.where.address')}</dt>
            <dd className="num">{address}</dd>
          </div>
          <div>
            <dt>{t('receiver.where.port')}</dt>
            <dd className="num">514</dd>
          </div>
          <div>
            <dt>{t('receiver.where.protocol')}</dt>
            <dd>{t('receiver.where.protocol_value')}</dd>
          </div>
        </dl>
        <ol className="setup-how panel-body">
          <li>{t('receiver.how.point', { address })}</li>
          <li>{t('receiver.how.appears')}</li>
          <li>{t('receiver.how.accept')}</li>
        </ol>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>{t('receiver.senders.title')}</h2>
          <p className="panel-note">{t('receiver.senders.note')}</p>
        </div>
        {senders.length === 0 ? (
          <p className="empty">{t('receiver.senders.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('receiver.col.device')}</th>
                  <th>{t('sources.col.status')}</th>
                  <th>{t('sources.col.last')}</th>
                  <th className="right">{t('receiver.col.received')}</th>
                  <th className="right">{t('receiver.col.stored')}</th>
                  <th className="right">{t('receiver.col.unread')}</th>
                  <th>{t('receiver.col.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {senders.map((s) => (
                  <tr key={s.id}>
                    <td className="wrap">
                      {s.name || s.address}
                      <span className="sub">
                        {s.name ? `${s.address}, ` : ''}
                        {s.format ?? t('receiver.format_unknown')}
                      </span>
                      {Number(s.not_understood) > 0 && s.last_unparsed && (
                        <details className="sample">
                          <summary>{t('receiver.sample')}</summary>
                          <pre className="ask">{s.last_unparsed}</pre>
                        </details>
                      )}
                    </td>
                    <td>
                      <Status tone={s.state === 'accepted' ? 'good' : s.state === 'pending' ? 'warn' : 'quiet'} label={t(`receiver.state.${s.state}`)} />
                    </td>
                    <td>{formatAgo(s.last_seen_at, s.now, t)}</td>
                    <td className="right num">{formatNumber(Number(s.received))}</td>
                    <td className="right num">{formatNumber(Number(s.stored))}</td>
                    <td className="right num">{formatNumber(Number(s.not_understood))}</td>
                    <td className="wrap">
                      {s.state !== 'accepted' && (
                        <form action={decideSender} className="inline-form">
                          <input type="hidden" name="sender" value={s.id} />
                          <input type="hidden" name="state" value="accepted" />
                          <input name="name" defaultValue={s.name} placeholder={t('receiver.name_placeholder')} maxLength={80} aria-label={t('receiver.name')} />
                          <button className="button button-primary" type="submit">{t('receiver.accept')}</button>
                        </form>
                      )}
                      {s.state === 'accepted' && (
                        <form action={renameSender} className="inline-form">
                          <input type="hidden" name="sender" value={s.id} />
                          <input name="name" defaultValue={s.name} placeholder={t('receiver.name_placeholder')} maxLength={80} aria-label={t('receiver.name')} />
                          <button className="button button-quiet" type="submit">{t('receiver.rename')}</button>
                        </form>
                      )}
                      <div className="inline-form">
                        {s.state !== 'blocked' && (
                          <form action={decideSender}>
                            <input type="hidden" name="sender" value={s.id} />
                            <input type="hidden" name="state" value="blocked" />
                            <button className="button button-quiet" type="submit">{t('receiver.block')}</button>
                          </form>
                        )}
                        <form action={removeSender}>
                          <input type="hidden" name="sender" value={s.id} />
                          <button className="button button-quiet" type="submit">{t('receiver.remove')}</button>
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
          <h2>{t('receiver.devices.title')}</h2>
          <p className="panel-note">{t('receiver.devices.note')}</p>
        </div>
        <div className="panel-body">
          {DEVICES.map((d) => (
            <details key={d} className="guide">
              <summary>{t(`receiver.device.${d}.name`)}</summary>
              <p>{t(`receiver.device.${d}.how`, { address })}</p>
              {t(`receiver.device.${d}.command`, { address }) !== `receiver.device.${d}.command` && (
                <pre className="ask">{t(`receiver.device.${d}.command`, { address })}</pre>
              )}
            </details>
          ))}
        </div>
      </section>
    </>
  );
}
