import type { Translate } from '@/lib/settings';

export interface FhirValues {
  id?: string;
  name: string;
  base_url: string;
  auth_kind: string;
  client_id: string;
  token_url: string;
  scope: string;
  ca_certificate: string;
  encrypt: boolean;
}

/** The details of a FHIR connection, used to add one and to change one. */
export function FhirForm({ t, action, values, editing }: { t: Translate; action: (f: FormData) => Promise<void>; values: FhirValues; editing: boolean }) {
  return (
    <form action={action} className="form-grid">
      {values.id && <input type="hidden" name="id" value={values.id} />}
      <label>
        {t('connect.name')}
        <input name="name" required maxLength={80} defaultValue={values.name} />
      </label>
      <label>
        {t('fhir.base_url')}
        <input name="base_url" required maxLength={500} defaultValue={values.base_url} placeholder="https://ehr.hospital.local/fhir/R4" />
        <span className="sub">{t('fhir.base_url_hint')}</span>
      </label>
      <label>
        {t('fhir.auth')}
        {editing ? (
          <>
            <input type="hidden" name="auth_kind" value={values.auth_kind} />
            <input value={t(`fhir.auth.${values.auth_kind}`)} disabled />
          </>
        ) : (
          <select name="auth_kind" defaultValue={values.auth_kind}>
            {['private_key', 'client_secret', 'token', 'none'].map((k) => (
              <option key={k} value={k}>
                {t(`fhir.auth.${k}`)}
              </option>
            ))}
          </select>
        )}
        <span className="sub">{t('fhir.auth_hint')}</span>
      </label>
      <label>
        {t('fhir.client_id')}
        <input name="client_id" maxLength={200} defaultValue={values.client_id} autoComplete="off" />
        <span className="sub">{t('fhir.client_id_hint')}</span>
      </label>
      <label>
        {t('fhir.secret')}
        <input name="secret" type="password" maxLength={4000} autoComplete="new-password" />
        <span className="sub">{editing ? t('connect.password_keep') : t('fhir.secret_hint')}</span>
      </label>
      <label>
        {t('fhir.token_url')}
        <input name="token_url" maxLength={500} defaultValue={values.token_url} placeholder="https://ehr.hospital.local/oauth2/token" />
        <span className="sub">{t('fhir.token_url_hint')}</span>
      </label>
      <label>
        {t('fhir.scope')}
        <input name="scope" maxLength={200} defaultValue={values.scope} />
        <span className="sub">{t('fhir.scope_hint')}</span>
      </label>
      <label className="wide">
        {t('fhir.ca')}
        <textarea name="ca_certificate" rows={4} maxLength={20000} defaultValue={values.ca_certificate} placeholder="-----BEGIN CERTIFICATE-----" />
        <span className="sub">{t('fhir.ca_hint')}</span>
      </label>
      <label className="check">
        <input type="checkbox" name="encrypt" defaultChecked={values.encrypt} />
        {t('fhir.encrypt')}
      </label>
      <div className="wide">
        <button className="button button-primary" type="submit">
          {t(editing ? 'connect.save' : 'fhir.submit')}
        </button>
      </div>
    </form>
  );
}
