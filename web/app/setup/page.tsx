import QRCode from 'qrcode';
import { Flash } from '@/components/ui';
import { setupCode, setupPassword } from '@/lib/actions';
import { sha256Hex, unseal } from '@/lib/crypto';
import { db } from '@/lib/db';
import { getCopy, numberSetting, textSetting } from '@/lib/settings';

export const dynamic = 'force-dynamic';

export default async function SetupPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const [t, params] = await Promise.all([getCopy(), searchParams]);
  const token = (Array.isArray(params.token) ? params.token[0] : params.token) ?? '';
  const wantsCode = params.step === 'code';
  const [user] = token
    ? await db()<{ email: string; display_name: string; totp_secret: string | null; password_hash: string | null }[]>`
        select email, display_name, totp_secret, password_hash from users
        where setup_token_hash = ${sha256Hex(token.slice(0, 100))} and setup_expires_at > now() and status = 'invited'`
    : [];

  if (!user) {
    return (
      <main className="auth">
        <div className="auth-card">
          <h1>{t('setup.title')}</h1>
          <p className="flash flash-error">{t('error.setup.link')}</p>
        </div>
      </main>
    );
  }

  let qr: string | null = null;
  let secret = '';
  if (wantsCode && user.totp_secret && user.password_hash) {
    secret = unseal(user.totp_secret, 'totp');
    const issuer = await textSetting('platform.name');
    const uri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    qr = await QRCode.toDataURL(uri, { margin: 1, width: 400 });
  }

  return (
    <main className="auth">
      <div className="auth-card">
        <h1>{t('setup.title')}</h1>
        <p>{t('setup.welcome', { name: user.display_name })}</p>
        <Flash params={params} t={t} scope="setup" />
        {qr ? (
          <>
            <p>{t('setup.code.lede')}</p>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img className="qr" src={qr} alt={t('setup.code.qr_alt')} />
            <p className="mono">{t('setup.code.manual', { secret: secret.replace(/(.{4})/g, '$1 ').trim() })}</p>
            <form action={setupCode} className="stack">
              <input type="hidden" name="token" value={token} />
              <label>
                {t('verify.code')}
                <input name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]{6,7}" required maxLength={7} />
              </label>
              <button className="button button-primary" type="submit">
                {t('setup.code.submit')}
              </button>
            </form>
          </>
        ) : (
          <form action={setupPassword} className="stack">
            <input type="hidden" name="token" value={token} />
            <label>
              {t('setup.password', { min: await numberSetting('auth.password_min_length') })}
              <input type="password" name="password" autoComplete="new-password" required maxLength={200} />
            </label>
            <label>
              {t('setup.confirm')}
              <input type="password" name="confirm" autoComplete="new-password" required maxLength={200} />
            </label>
            <button className="button button-primary" type="submit">
              {t('setup.password.submit')}
            </button>
          </form>
        )}
      </div>
    </main>
  );
}
