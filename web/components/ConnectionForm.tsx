import type { Translate } from '@/lib/settings';

export interface ConnectionValues {
  id?: string;
  name: string;
  kind: string;
  host: string;
  port: number;
  database_name: string;
  username: string;
  encrypt: boolean;
  timezone: string;
  day_first: boolean;
}

/** The connection details for a records database, used to add one and to change one. */
export function ConnectionForm({ t, action, values, zones, editing }: { t: Translate; action: (f: FormData) => Promise<void>; values: ConnectionValues; zones: string[]; editing: boolean }) {
  return (
    <form action={action} className="form-grid">
      {values.id && <input type="hidden" name="id" value={values.id} />}
      <label>
        {t('connect.name')}
        <input name="name" required maxLength={80} defaultValue={values.name} />
      </label>
      <label>
        {t('connect.kind')}
        <select name="kind" defaultValue={values.kind}>
          <option value="postgres">{t('source_kind.postgres')}</option>
          <option value="mysql">{t('source_kind.mysql')}</option>
        </select>
      </label>
      <label>
        {t('connect.host')}
        <input name="host" required maxLength={255} defaultValue={values.host} placeholder="10.0.0.20" />
        <span className="sub">{t('connect.host_hint')}</span>
      </label>
      <label>
        {t('connect.port')}
        <input name="port" required inputMode="numeric" maxLength={5} defaultValue={String(values.port)} />
        <span className="sub">{t('connect.port_hint')}</span>
      </label>
      <label>
        {t('connect.database')}
        <input name="database" required maxLength={128} defaultValue={values.database_name} />
      </label>
      <label>
        {t('connect.username')}
        <input name="username" required maxLength={128} defaultValue={values.username} autoComplete="off" />
        <span className="sub">{t('connect.username_hint')}</span>
      </label>
      <label>
        {t('connect.password')}
        <input name="password" type="password" required={!editing} maxLength={512} autoComplete="new-password" />
        {editing && <span className="sub">{t('connect.password_keep')}</span>}
      </label>
      <label>
        {t('connect.timezone')}
        <input name="timezone" list="zones" required maxLength={64} defaultValue={values.timezone} />
        <span className="sub">{t('connect.timezone_hint')}</span>
      </label>
      <datalist id="zones">
        {zones.map((z) => (
          <option key={z} value={z} />
        ))}
      </datalist>
      <label>
        {t('connect.day_first')}
        <select name="day_first" defaultValue={values.day_first ? 'true' : 'false'}>
          <option value="true">{t('connect.day_first.true')}</option>
          <option value="false">{t('connect.day_first.false')}</option>
        </select>
      </label>
      <label className="check">
        <input type="checkbox" name="encrypt" defaultChecked={values.encrypt} />
        {t('connect.encrypt')}
      </label>
      <div className="wide">
        <button className="button button-primary" type="submit">
          {t(editing ? 'connect.save' : 'connect.submit')}
        </button>
      </div>
    </form>
  );
}
