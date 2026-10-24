import { cookies, headers } from 'next/headers';
import { SettingsTabs } from '@/components/SettingsTabs';
import { Flash } from '@/components/ui';
import { Status } from '@/components/Status';
import { inviteUser, setUserStatus } from '@/lib/actions';
import { db } from '@/lib/db';
import { formatAgo } from '@/lib/format';
import { requireUser } from '@/lib/session';
import { getCopy } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function UsersPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const admin = await requireUser('admin');
  const [t, params] = await Promise.all([getCopy(), searchParams]);
  const users = await db()<{ id: string; email: string; display_name: string; role: string; status: string; last_login_at: Date | null; now: Date }[]>`
    select id::text as id, email, display_name, role, status, last_login_at, now() as now from users order by created_at`;
  // The invitation link is carried in a short lived cookie so it never appears in an address or a log.
  const invite = (await cookies()).get('htm_invite')?.value;
  const h = await headers();
  const origin = `${h.get('x-forwarded-proto') ?? 'http'}://${h.get('x-forwarded-host') ?? h.get('host')}`;
  const [inviteEmail, inviteToken, inviteMail] = invite ? invite.split('|') : [];
  const emails = await db()<{ id: string; sent_at: Date; recipient: string; status: string; detail: string | null; now: Date }[]>`
    select id::text as id, sent_at, recipient, status, detail, now() as now from email_log order by email_log.id desc limit 10`;

  return (
    <>
      <header className="page-head">
        <div>
          <h1>{t('settings.title')}</h1>
          <p className="lede">{t('settings.users.lede')}</p>
        </div>
      </header>
      <SettingsTabs t={t} current="users" admin />
      <Flash params={params} t={t} scope="settings" />
      {inviteToken && (params.notice === 'invited' || params.notice === 'invited_emailed') && (
        <div className="flash flash-ok">
          {inviteMail === 'sent' ? t('settings.users.link_emailed', { email: inviteEmail }) : t('settings.users.link', { email: inviteEmail })}
          <p className="mono">{`${origin}/setup?token=${inviteToken}`}</p>
          {inviteMail === 'skipped' && <p className="panel-note">{t('settings.users.email_off')}</p>}
        </div>
      )}
      <section className="panel">
        <div className="panel-head">
          <h2>{t('settings.users.invite.title')}</h2>
        </div>
        <form action={inviteUser} className="form-grid">
          <label>
            {t('settings.users.name')}
            <input name="display_name" required maxLength={80} />
          </label>
          <label>
            {t('signin.email')}
            <input type="email" name="email" required maxLength={200} />
          </label>
          <label>
            {t('settings.users.role')}
            <select name="role" defaultValue="analyst">
              <option value="analyst">{t('role.analyst')}</option>
              <option value="admin">{t('role.admin')}</option>
            </select>
          </label>
          <div className="wide">
            <button className="button button-primary" type="submit">
              {t('settings.users.invite.submit')}
            </button>
          </div>
        </form>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>{t('settings.users.list')}</h2>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{t('settings.users.name')}</th>
                <th>{t('settings.users.role')}</th>
                <th>{t('settings.users.status')}</th>
                <th>{t('settings.users.last')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id}>
                  <td>
                    {u.display_name}
                    <span className="sub">{u.email}</span>
                  </td>
                  <td>{t(`role.${u.role}`)}</td>
                  <td>
                    <Status tone={u.status === 'active' ? 'good' : u.status === 'invited' ? 'warn' : 'quiet'} label={t(`user_status.${u.status}`)} />
                  </td>
                  <td>{formatAgo(u.last_login_at, u.now, t)}</td>
                  <td className="right">
                    {u.id !== admin.id && u.status !== 'invited' && (
                      <form action={setUserStatus}>
                        <input type="hidden" name="user_id" value={u.id} />
                        <input type="hidden" name="to" value={u.status === 'active' ? 'disabled' : 'active'} />
                        <button className="button" type="submit">
                          {t(u.status === 'active' ? 'settings.users.disable' : 'settings.users.enable')}
                        </button>
                      </form>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>{t('settings.users.emails.title')}</h2>
        </div>
        {emails.length === 0 ? (
          <p className="empty">{t('settings.users.emails.empty')}</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{t('settings.users.emails.col.when')}</th>
                  <th>{t('settings.users.emails.col.to')}</th>
                  <th>{t('settings.users.emails.col.status')}</th>
                </tr>
              </thead>
              <tbody>
                {emails.map((e) => (
                  <tr key={e.id}>
                    <td>{formatAgo(e.sent_at, e.now, t)}</td>
                    <td>{e.recipient}</td>
                    <td className="wrap">
                      <Status tone={e.status === 'sent' ? 'good' : e.status === 'failed' ? 'crit' : 'quiet'} label={t(`email_status.${e.status}`)} />
                      {e.status === 'failed' && <span className="sub">{e.detail}</span>}
                    </td>
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
