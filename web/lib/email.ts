import { db } from './db';
import { textSetting } from './settings';

const KEEP = 50;

export interface EmailResult {
  status: 'sent' | 'failed' | 'skipped';
  detail: string | null;
}

/**
 * Sends one email through Resend. The key lives in the environment, never in the database.
 * When email is not set up, or the provider refuses, nothing is thrown: the caller falls back
 * to showing the link, and the attempt is recorded. Only the last fifty attempts are kept.
 */
export async function sendEmail(input: { to: string; subject: string; text: string; purpose: string }): Promise<EmailResult> {
  const key = process.env.RESEND_API_KEY ?? '';
  const from = await textSetting('email.from_address');
  const fromName = (await textSetting('email.from_name')) || (await textSetting('platform.name'));
  let result: EmailResult;
  if (!key || !from) {
    result = { status: 'skipped', detail: !key ? 'RESEND_API_KEY is not set' : 'no sender address in settings' };
  } else {
    try {
      const response = await fetch(process.env.RESEND_API_URL ?? 'https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: `${fromName.replace(/[<>"\r\n]/g, '')} <${from}>`, to: [input.to], subject: input.subject, text: input.text }),
        signal: AbortSignal.timeout(10_000),
      });
      result = response.ok
        ? { status: 'sent', detail: null }
        : { status: 'failed', detail: `provider answered ${response.status}: ${(await response.text()).slice(0, 200)}` };
    } catch (err) {
      result = { status: 'failed', detail: String((err as Error)?.message ?? err).slice(0, 200) };
    }
  }
  const sql = db();
  await sql`
    insert into email_log (purpose, recipient, transport, status, detail)
    values (${input.purpose}, ${input.to}, 'resend', ${result.status}, ${result.detail})`;
  await sql`delete from email_log where id <= (select id from email_log order by id desc offset ${KEEP} limit 1)`;
  return result;
}
