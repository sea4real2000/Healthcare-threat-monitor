import type { Translate } from '@/lib/settings';

export interface RuleValues {
  id: string;
  name: string;
  description: string;
  category: string;
  kind: string;
  severity: number;
  confidence: string;
  technique_id: string | null;
  technique_name: string | null;
  enabled: boolean;
  definition: unknown;
}

const KINDS = ['match', 'threshold', 'new_value'];
const CATEGORIES = ['ransomware', 'access', 'records', 'network', 'devices'];

/** The rule editor. With `creating` it also asks for the parts of a rule that cannot change later. */
export function RuleForm({ rule, t, action, creating, readOnly }: { rule: RuleValues; t: Translate; action: (form: FormData) => Promise<void>; creating: boolean; readOnly: boolean }) {
  return (
    <form action={action} className="form-grid">
      {creating ? (
        <>
          <label>
            {t('rule.field.id')}
            <input name="id" required pattern="[a-z][a-z0-9_]{2,62}" maxLength={63} />
          </label>
          <label>
            {t('rule.field.kind')}
            <select name="kind" defaultValue={rule.kind}>
              {KINDS.map((k) => (
                <option key={k} value={k}>
                  {t(`rule_kind.${k}`)}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t('rule.field.category')}
            <select name="category" defaultValue={rule.category}>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {t(`category.${c}`)}
                </option>
              ))}
            </select>
          </label>
        </>
      ) : (
        <input type="hidden" name="id" value={rule.id} />
      )}
      <label className={creating ? '' : 'wide'}>
        {t('rule.field.name')}
        <input name="name" defaultValue={rule.name} required maxLength={120} readOnly={readOnly} />
      </label>
      <label className="wide">
        {t('rule.field.description')}
        <input name="description" defaultValue={rule.description} required maxLength={500} readOnly={readOnly} />
      </label>
      <label>
        {t('rule.field.severity')}
        <select name="severity" defaultValue={String(rule.severity)} disabled={readOnly}>
          {[1, 2, 3].map((s) => (
            <option key={s} value={s}>
              {t(`severity.${s}`)}
            </option>
          ))}
        </select>
      </label>
      <label>
        {t('rule.field.confidence')}
        <input name="confidence" type="number" step="0.01" min="0.01" max="0.99" defaultValue={rule.confidence} required readOnly={readOnly} />
      </label>
      <label>
        {t('rule.field.technique_id')}
        <input name="technique_id" defaultValue={rule.technique_id ?? ''} maxLength={12} readOnly={readOnly} />
      </label>
      <label>
        {t('rule.field.technique_name')}
        <input name="technique_name" defaultValue={rule.technique_name ?? ''} maxLength={120} readOnly={readOnly} />
      </label>
      <label className="wide">
        {t('rule.field.definition')}
        <textarea className="code" name="definition" defaultValue={JSON.stringify(rule.definition, null, 2)} spellCheck={false} readOnly={readOnly} />
      </label>
      <label className="check wide">
        <input type="checkbox" name="enabled" defaultChecked={rule.enabled} disabled={readOnly} />
        {t('rule.field.enabled')}
      </label>
      {!readOnly && (
        <div className="wide">
          <button className="button button-primary" type="submit">
            {t(creating ? 'rule.create' : 'rule.save')}
          </button>
        </div>
      )}
    </form>
  );
}

export function RuleHelp({ t }: { t: Translate }) {
  return (
    <section className="panel" aria-labelledby="rule-help">
      <div className="panel-head">
        <h2 id="rule-help">{t('rule.help.title')}</h2>
      </div>
      <div className="stack">
        <span>{t('rule.help.kinds')}</span>
        <span>{t('rule.help.fields')}</span>
        <span className="mono">{t('rule.help.fields_list')}</span>
        <span>{t('rule.help.ops')}</span>
        <span className="mono">{t('rule.help.ops_list')}</span>
        <span>{t('rule.help.options')}</span>
      </div>
    </section>
  );
}
