'use server';

import { createHash, randomBytes } from 'node:crypto';
import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { db } from './db';
import {
  authConfigured,
  hashPassword,
  newTotpSecret,
  randomToken,
  seal,
  sha256Hex,
  unseal,
  verifyPassword,
  verifyTotp,
} from './crypto';
import { sendEmail } from './email';
import { inspectImage } from './image';
import { firstRunPending, setupCodeMatches } from './firstRun';
import { allow } from './ratelimit';
import { anySession, clientAddress, endSession, requireActor, requireUser, startSession } from './session';
import { clearSettingsCache, flagSetting, getCopy, numberSetting, textSetting } from './settings';

// Every change a person can make from the console goes through one of these actions.
// Each one checks who is asking, makes the change and writes the audit entry in a single transaction.

function field(form: FormData, name: string, max = 500): string {
  const v = form.get(name);
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}

function back(path: string, params: Record<string, string>): never {
  const query = new URLSearchParams(params).toString();
  redirect(query ? `${path}?${query}` : path);
}

const DISMISS_REASONS = ['expected_activity', 'not_enough_evidence', 'duplicate', 'test_activity'];
const CONFIRM_REASONS = ['confirmed_attack', 'policy_violation'];
const SCENARIOS = ['ransomware', 'record_snooping', 'device_compromise'];
const RULE_KINDS = ['match', 'threshold', 'new_value'];
const RULE_CATEGORIES = ['ransomware', 'access', 'records', 'network', 'devices'];

// Sign in, in two steps: password, then a code from an authenticator app.

export async function signIn(form: FormData): Promise<void> {
  if (!authConfigured()) back('/signin', { error: 'not_configured' });
  if (!(await allow(`signin:${await clientAddress()}`, 'limits.signin_per_minute'))) back('/signin', { error: 'too_many' });
  const email = field(form, 'email', 200).toLowerCase();
  const password = field(form, 'password', 200);
  const sql = db();
  const [user] = await sql<{ id: string; password_hash: string | null; status: string; locked: boolean; totp_secret: string | null }[]>`
    select id, password_hash, status, coalesce(locked_until > now(), false) as locked, totp_secret from users where email = ${email}`;
  const usable = user && user.status === 'active' && !user.locked && user.totp_secret;
  const ok = await verifyPassword(password, usable ? user.password_hash : null);
  if (!usable || !ok) {
    if (user && user.status === 'active' && !user.locked) await recordFailure(user.id);
    // One message for every failure, so the page never reveals which part was wrong.
    back('/signin', { error: 'invalid' });
  }
  await startSession(user.id, false);
  redirect('/signin/verify');
}

async function recordFailure(userId: string): Promise<void> {
  const max = await numberSetting('auth.max_failed_logins');
  const lock = await numberSetting('auth.lock_minutes');
  const sql = db();
  const [row] = await sql<{ failed_logins: number; display_name: string }[]>`
    update users set failed_logins = failed_logins + 1,
      locked_until = case when failed_logins + 1 >= ${max}::int then now() + make_interval(mins => ${lock}::int) else locked_until end
    where id = ${userId}::uuid returning failed_logins, display_name`;
  if (row && row.failed_logins >= max) {
    await sql`select audit_append('system', 'console', 'Console', 'user.locked', 'user', ${userId}, ${sql.json({ failed: row.failed_logins })}::jsonb)`;
    await sql`update users set failed_logins = 0 where id = ${userId}::uuid`;
  }
}

export async function verifyCode(form: FormData): Promise<void> {
  if (!(await allow(`signin:${await clientAddress()}`, 'limits.signin_per_minute'))) back('/signin/verify', { error: 'too_many' });
  const session = await anySession();
  if (!session || session.role === 'demo') redirect('/signin');
  const sql = db();
  const [user] = await sql<{ totp_secret: string; totp_last_step: string; locked: boolean }[]>`
    select totp_secret, totp_last_step::text, coalesce(locked_until > now(), false) as locked from users where id = ${session.id}::uuid`;
  const step = user && !user.locked ? verifyTotp(unseal(user.totp_secret, 'totp'), field(form, 'code', 10).replace(/\s/g, ''), Number(user.totp_last_step)) : null;
  if (step === null) {
    await recordFailure(session.id);
    back('/signin/verify', { error: 'invalid' });
  }
  const token = (await cookies()).get('htm_session')?.value ?? '';
  await sql.begin(async (tx) => {
    await tx`update users set totp_last_step = ${step}, failed_logins = 0, last_login_at = now() where id = ${session.id}::uuid`;
    await tx`update sessions set mfa_passed = true where token_hash = ${sha256Hex(token)}`;
    await tx`select audit_append('user', ${session.id}, ${session.name}, 'user.signed_in', 'user', ${session.id}, '{}'::jsonb)`;
  });
  redirect('/console/incidents');
}

export async function signOut(): Promise<void> {
  const session = await anySession();
  if (session) {
    const sql = db();
    await sql`select audit_append('user', ${session.id}, ${session.name}, 'user.signed_out', 'user', ${session.id}, '{}'::jsonb)`;
  }
  await endSession();
  redirect('/console');
}

// Account setup from an invitation link: choose a password, then enrol an authenticator app.

async function invited(token: string) {
  if (!token || token.length > 100) return null;
  const [user] = await db()<{ id: string; email: string; display_name: string; password_hash: string | null }[]>`
    select id, email, display_name, password_hash from users
    where setup_token_hash = ${sha256Hex(token)} and setup_expires_at > now() and status = 'invited'`;
  return user ?? null;
}

export async function setupPassword(form: FormData): Promise<void> {
  const token = field(form, 'token', 100);
  if (!authConfigured()) back('/setup', { token, error: 'not_configured' });
  if (!(await allow(`signin:${await clientAddress()}`, 'limits.signin_per_minute'))) back('/setup', { token, error: 'too_many' });
  const user = await invited(token);
  if (!user) back('/setup', { error: 'link' });
  const password = field(form, 'password', 200);
  const min = await numberSetting('auth.password_min_length');
  if (password.length < min) back('/setup', { token, error: 'short' });
  if (password !== field(form, 'confirm', 200)) back('/setup', { token, error: 'mismatch' });
  if (password.toLowerCase().includes(user.email.split('@')[0])) back('/setup', { token, error: 'weak' });
  await db()`
    update users set password_hash = ${await hashPassword(password)}, totp_secret = ${seal(newTotpSecret(), 'totp')}
    where id = ${user.id}::uuid`;
  back('/setup', { token, step: 'code' });
}

export async function setupCode(form: FormData): Promise<void> {
  const token = field(form, 'token', 100);
  if (!(await allow(`signin:${await clientAddress()}`, 'limits.signin_per_minute'))) back('/setup', { token, step: 'code', error: 'too_many' });
  const user = await invited(token);
  if (!user || !user.password_hash) back('/setup', { error: 'link' });
  const sql = db();
  const [row] = await sql<{ totp_secret: string }[]>`select totp_secret from users where id = ${user.id}::uuid`;
  const step = verifyTotp(unseal(row.totp_secret, 'totp'), field(form, 'code', 10).replace(/\s/g, ''), 0);
  if (step === null) back('/setup', { token, step: 'code', error: 'invalid' });
  await sql.begin(async (tx) => {
    await tx`update users set status = 'active', totp_last_step = ${step}, setup_token_hash = null, setup_expires_at = null where id = ${user.id}::uuid`;
    await tx`select audit_append('user', ${user.id}, ${user.display_name}, 'user.activated', 'user', ${user.id}, '{}'::jsonb)`;
  });
  // The person has just proved both factors, so sign them in without asking again.
  await startSession(user.id, true);
  redirect('/console/incidents');
}

// Incidents

export async function decideIncident(form: FormData): Promise<void> {
  const user = await requireUser();
  const id = field(form, 'incident_id', 20);
  const verdict = field(form, 'verdict', 20);
  const reason = field(form, 'reason', 40);
  const note = field(form, 'note', 1000);
  const path = `/console/incidents/${id}`;
  if (!/^\d{1,18}$/.test(id)) redirect('/console/incidents');
  const confirm = verdict === 'confirm';
  if (!(confirm ? CONFIRM_REASONS : DISMISS_REASONS).includes(reason)) back(path, { error: 'reason' });
  const sql = db();
  const done = await sql.begin(async (tx) => {
    const rows = await tx`
      update incidents set status = ${confirm ? 'confirmed' : 'dismissed'}, decided_by = ${user.id}::uuid, decided_by_name = ${user.name},
        decided_at = now(), decision_reason = ${reason}, decision_note = ${note || null}
      where id = ${id}::bigint and status = 'open' returning id`;
    if (rows.length === 0) return false;
    await tx`
      insert into feedback (incident_id, verdict, reason, note, created_by, created_by_name)
      values (${id}::bigint, ${confirm ? 'true_positive' : 'false_positive'}, ${reason}, ${note || null}, ${user.id}::uuid, ${user.name})`;
    await tx`select audit_append('user', ${user.id}, ${user.name}, ${confirm ? 'incident.confirmed' : 'incident.dismissed'}, 'incident', ${id},
      ${tx.json({ reason, note: note || null })}::jsonb)`;
    await tx`select siem_enqueue(${id}::bigint, 'incident_decided')`;
    return true;
  });
  revalidatePath(path);
  back(path, done ? { notice: confirm ? 'confirmed' : 'dismissed' } : { error: 'already_decided' });
}

export async function requestResponse(form: FormData): Promise<void> {
  const actor = await requireActor();
  const assetId = field(form, 'asset_id', 64);
  const action = field(form, 'action', 10);
  const incidentId = field(form, 'incident_id', 20);
  const path = /^\d{1,18}$/.test(incidentId) ? `/console/incidents/${incidentId}` : '/console/assets';
  if ('limited' in actor) back(path, { error: 'too_many' });
  const user = actor;
  if (action !== 'isolate' && action !== 'release') back(path, { error: 'action' });
  const sql = db();
  const result = await sql.begin(async (tx) => {
    const [asset] = await tx<{ status: string }[]>`select status from assets where id = ${assetId} for update`;
    if (!asset) return 'asset';
    if ((action === 'isolate') !== (asset.status === 'active')) return 'state';
    const waiting = await tx`select 1 from response_actions where asset_id = ${assetId} and status = 'requested'`;
    if (waiting.length > 0) return 'waiting';
    if (action === 'isolate') {
      // Isolation is only offered on a high confidence incident that names this machine.
      const [incident] = await tx<{ band: string; status: string; hosts: string[] }[]>`
        select band, status, hosts from incidents where id = ${/^\d{1,18}$/.test(incidentId) ? incidentId : '0'}::bigint`;
      if (!incident || incident.band !== 'high' || incident.status === 'dismissed' || !incident.hosts.includes(assetId)) return 'not_eligible';
    }
    const [row] = await tx<{ id: string }[]>`
      insert into response_actions (incident_id, asset_id, action, requested_by, requested_by_name)
      values (${/^\d{1,18}$/.test(incidentId) ? incidentId : null}::bigint, ${assetId}, ${action}, ${user.id}::uuid, ${user.name})
      returning id::text`;
    await tx`select audit_append('user', ${user.id}, ${user.name}, ${action === 'isolate' ? 'isolation.approved' : 'release.approved'}, 'asset', ${assetId},
      ${tx.json({ action_id: row.id, incident_id: incidentId || null })}::jsonb)`;
    return 'ok';
  });
  revalidatePath(path);
  back(path, result === 'ok' ? { notice: action === 'isolate' ? 'isolation_requested' : 'release_requested' } : { error: result });
}

// Scenarios and models

export async function launchScenario(form: FormData): Promise<void> {
  const actor = await requireActor();
  if ('limited' in actor) back('/console/scenarios', { error: 'too_many' });
  // Scenarios write made up attack records. On a real hospital's installation they would mix with its real data.
  if (!(await flagSetting('engine.simulate'))) back('/console/scenarios', { error: 'no_simulation' });
  const user = actor;
  const scenario = field(form, 'scenario', 40);
  if (!SCENARIOS.includes(scenario)) back('/console/scenarios', { error: 'scenario' });
  const sql = db();
  const started = await sql.begin(async (tx) => {
    const busy = await tx`select 1 from scenario_runs where status in ('requested', 'running') for update`;
    if (busy.length > 0) return false;
    const [row] = await tx<{ id: string }[]>`insert into scenario_runs (scenario, requested_by) values (${scenario}, ${user.name}) returning id::text`;
    await tx`select audit_append('user', ${user.id}, ${user.name}, 'scenario.requested', 'scenario_run', ${row.id}, ${tx.json({ scenario })}::jsonb)`;
    return true;
  });
  revalidatePath('/console/scenarios');
  back('/console/scenarios', started ? { notice: 'launched' } : { error: 'busy' });
}

export async function requestRetrain(): Promise<void> {
  const user = await requireUser();
  const sql = db();
  await sql.begin(async (tx) => {
    await tx`insert into engine_state (key, value) values ('retrain_requested', ${tx.json({ by: user.name })}::jsonb)
      on conflict (key) do update set value = excluded.value, updated_at = now()`;
    await tx`select audit_append('user', ${user.id}, ${user.name}, 'models.retrain_requested', 'models', '', '{}'::jsonb)`;
  });
  back('/console/models', { notice: 'retrain' });
}

// Rules

function parseRule(form: FormData): { values: Record<string, unknown>; error?: string } {
  const name = field(form, 'name', 120);
  const description = field(form, 'description', 500);
  const severity = Number(field(form, 'severity', 2));
  const confidence = Number(field(form, 'confidence', 6));
  const technique = field(form, 'technique_id', 20);
  let definition: unknown;
  try {
    definition = JSON.parse(field(form, 'definition', 8000));
  } catch {
    return { values: {}, error: 'definition_json' };
  }
  if (!name || !description) return { values: {}, error: 'name' };
  if (![1, 2, 3].includes(severity)) return { values: {}, error: 'severity' };
  if (!(confidence > 0 && confidence < 1)) return { values: {}, error: 'confidence' };
  if (!definition || typeof definition !== 'object' || Array.isArray(definition) || !Array.isArray((definition as { where?: unknown }).where)) {
    return { values: {}, error: 'definition_shape' };
  }
  if (technique && !/^T[A0-9.]{3,9}$/.test(technique)) return { values: {}, error: 'technique' };
  return {
    values: {
      name, description, severity, confidence, definition,
      technique_id: technique || null,
      technique_name: field(form, 'technique_name', 120) || null,
      enabled: form.get('enabled') === 'on',
    },
  };
}

export async function saveRule(form: FormData): Promise<void> {
  const user = await requireUser();
  const id = field(form, 'id', 64);
  const path = `/console/rules/${id}`;
  const { values: v, error } = parseRule(form);
  if (error) back(path, { error });
  const sql = db();
  const rows = await sql.begin(async (tx) => {
    const updated = await tx`
      update rules set name = ${v.name as string}, description = ${v.description as string}, severity = ${v.severity as number},
        confidence = ${v.confidence as number}, definition = ${tx.json(v.definition as never)}, technique_id = ${v.technique_id as string | null},
        technique_name = ${v.technique_name as string | null}, enabled = ${v.enabled as boolean}, load_error = null,
        updated_at = now(), updated_by = ${user.name}
      where id = ${id} returning id`;
    if (updated.length > 0) {
      await tx`select audit_append('user', ${user.id}, ${user.name}, 'rule.updated', 'rule', ${id},
        ${tx.json({ enabled: v.enabled, severity: v.severity, confidence: v.confidence } as never)}::jsonb)`;
    }
    return updated;
  });
  if (rows.length === 0) redirect('/console/rules');
  back(path, { notice: 'saved' });
}

export async function createRule(form: FormData): Promise<void> {
  const user = await requireUser();
  const id = field(form, 'id', 64).toLowerCase();
  const kind = field(form, 'kind', 20);
  const category = field(form, 'category', 20);
  const { values: v, error } = parseRule(form);
  if (error) back('/console/rules/new', { error });
  if (!/^[a-z][a-z0-9_]{2,62}$/.test(id)) back('/console/rules/new', { error: 'id' });
  if (!RULE_KINDS.includes(kind) || !RULE_CATEGORIES.includes(category)) back('/console/rules/new', { error: 'kind' });
  const sql = db();
  const created = await sql.begin(async (tx) => {
    const rows = await tx`
      insert into rules (id, name, description, category, kind, definition, severity, confidence, technique_id, technique_name, enabled, updated_by)
      values (${id}, ${v.name as string}, ${v.description as string}, ${category}, ${kind}, ${tx.json(v.definition as never)}, ${v.severity as number},
        ${v.confidence as number}, ${v.technique_id as string | null}, ${v.technique_name as string | null}, ${v.enabled as boolean}, ${user.name})
      on conflict (id) do nothing returning id`;
    if (rows.length > 0) {
      await tx`select audit_append('user', ${user.id}, ${user.name}, 'rule.created', 'rule', ${id}, ${tx.json({ kind, category })}::jsonb)`;
    }
    return rows.length > 0;
  });
  if (!created) back('/console/rules/new', { error: 'exists' });
  back(`/console/rules/${id}`, { notice: 'created' });
}

export async function removeException(form: FormData): Promise<void> {
  const user = await requireUser();
  const id = field(form, 'exception_id', 20);
  const returnTo = field(form, 'return_to', 120);
  const path = returnTo.startsWith('/console/') ? returnTo : '/console/rules';
  if (!/^\d{1,18}$/.test(id)) redirect(path);
  const sql = db();
  await sql.begin(async (tx) => {
    const rows = await tx<{ detector_id: string; entity: string; kind: string }[]>`
      delete from detector_exceptions where id = ${id}::bigint returning detector_id, entity, kind`;
    if (rows.length > 0) {
      await tx`select audit_append('user', ${user.id}, ${user.name}, 'exception.removed', 'detector', ${rows[0].detector_id},
        ${tx.json({ entity: rows[0].entity, kind: rows[0].kind })}::jsonb)`;
    }
  });
  back(path, { notice: 'exception_removed' });
}

// Settings, copy and users. Administrators only.

export async function saveSetting(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const key = field(form, 'key', 100);
  const raw = field(form, 'value', 2000);
  const sql = db();
  const [current] = await sql<{ value: unknown }[]>`select value from settings where key = ${key}`;
  if (!current) back('/console/settings', { error: 'unknown_key' });
  let value: unknown;
  if (typeof current.value === 'number') {
    value = Number(raw);
    if (raw === '' || !Number.isFinite(value as number)) back('/console/settings', { error: 'number', key });
  } else if (typeof current.value === 'boolean') {
    value = raw === 'true';
  } else {
    value = raw;
  }
  await sql.begin(async (tx) => {
    await tx`update settings set value = ${tx.json(value as never)}, updated_at = now() where key = ${key}`;
    await tx`select audit_append('user', ${user.id}, ${user.name}, 'setting.updated', 'setting', ${key},
      ${tx.json({ from: current.value, to: value } as never)}::jsonb)`;
  });
  clearSettingsCache();
  back('/console/settings', { notice: 'saved', key });
}

export async function saveCopy(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const key = field(form, 'key', 100);
  const value = field(form, 'value', 2000);
  const q = field(form, 'q', 80);
  if (!value) back('/console/settings/copy', { error: 'empty', q });
  const sql = db();
  await sql.begin(async (tx) => {
    const rows = await tx`update copy set value = ${value}, updated_at = now() where key = ${key} returning key`;
    if (rows.length > 0) {
      await tx`select audit_append('user', ${user.id}, ${user.name}, 'copy.updated', 'copy', ${key}, '{}'::jsonb)`;
    }
  });
  clearSettingsCache();
  back('/console/settings/copy', { notice: 'saved', q });
}

export async function inviteUser(form: FormData): Promise<void> {
  const admin = await requireUser('admin');
  const email = field(form, 'email', 200).toLowerCase();
  const name = field(form, 'display_name', 80);
  const role = field(form, 'role', 10);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !name || /[\u0000-\u001f]/.test(name)) back('/console/settings/users', { error: 'details' });
  if (role !== 'analyst' && role !== 'admin') back('/console/settings/users', { error: 'details' });
  const token = randomToken();
  const hours = await numberSetting('auth.setup_link_hours');
  const sql = db();
  const created = await sql.begin(async (tx) => {
    const rows = await tx<{ id: string }[]>`
      insert into users (email, display_name, role, setup_token_hash, setup_expires_at, created_by)
      values (${email}, ${name}, ${role}, ${sha256Hex(token)}, now() + make_interval(hours => ${hours}::int), ${admin.name})
      on conflict (email) do update set setup_token_hash = excluded.setup_token_hash, setup_expires_at = excluded.setup_expires_at,
        display_name = excluded.display_name, role = excluded.role
      where users.status = 'invited'
      returning id::text`;
    if (rows.length > 0) {
      await tx`select audit_append('user', ${admin.id}, ${admin.name}, 'user.invited', 'user', ${rows[0].id}, ${tx.json({ role })}::jsonb)`;
    }
    return rows.length > 0;
  });
  if (!created) back('/console/settings/users', { error: 'exists' });
  // Email the link when email is set up. Either way it is also shown once, straight after the invitation,
  // so a failed email never blocks a new account. The token is never stored in readable form.
  const h = await headers();
  const origin = `${h.get('x-forwarded-proto') ?? 'http'}://${h.get('x-forwarded-host') ?? h.get('host')}`;
  const t = await getCopy();
  const vars = { name, platform: await textSetting('platform.name'), role: t(`role.${role}`), hours, link: `${origin}/setup?token=${token}` };
  const mail = await sendEmail({ to: email, subject: t('email.invite.subject', vars), text: t('email.invite.body', vars), purpose: 'invitation' });
  (await cookies()).set('htm_invite', `${email}|${token}|${mail.status}`, { httpOnly: true, sameSite: 'strict', path: '/console/settings/users', maxAge: 120 });
  back('/console/settings/users', { notice: mail.status === 'sent' ? 'invited_emailed' : 'invited' });
}

export async function setUserStatus(form: FormData): Promise<void> {
  const admin = await requireUser('admin');
  const id = field(form, 'user_id', 40);
  const disable = field(form, 'to', 10) === 'disabled';
  if (!/^[0-9a-f-]{36}$/.test(id)) redirect('/console/settings/users');
  if (id === admin.id) back('/console/settings/users', { error: 'self' });
  const sql = db();
  await sql.begin(async (tx) => {
    const rows = await tx`
      update users set status = ${disable ? 'disabled' : 'active'} where id = ${id}::uuid and status in ('active', 'disabled') returning id`;
    if (rows.length > 0) {
      if (disable) await tx`delete from sessions where user_id = ${id}::uuid`;
      await tx`select audit_append('user', ${admin.id}, ${admin.name}, ${disable ? 'user.disabled' : 'user.enabled'}, 'user', ${id}, '{}'::jsonb)`;
    }
  });
  back('/console/settings/users', { notice: 'saved' });
}

// Landing page pictures. The file is checked by its own bytes, never by its name or the type the browser claims.

export async function saveImage(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const path = '/console/settings/images';
  const slot = field(form, 'slot', 30);
  const alt = field(form, 'alt', 300);
  const sql = db();
  const [current] = await sql<{ has: boolean; alt: string }[]>`select bytes is not null as has, alt from site_images where slot = ${slot}`;
  if (!current) back(path, { error: 'slot' });
  const file = form.get('file');
  const upload = file instanceof File && file.size > 0 ? file : null;
  if (!upload && !current.has) back(path, { error: 'missing' });
  if (!alt) back(path, { error: 'alt' });

  if (!upload) {
    await sql.begin(async (tx) => {
      await tx`update site_images set alt = ${alt}, updated_at = now(), updated_by = ${user.name} where slot = ${slot}`;
      await tx`select audit_append('user', ${user.id}, ${user.name}, 'setting.image_described', 'site_image', ${slot},
        ${tx.json({ from: current.alt, to: alt } as never)}::jsonb)`;
    });
    revalidatePath('/');
    back(path, { notice: 'described' });
  }

  const limit = await numberSetting('media.max_bytes');
  if (upload!.size > limit) back(path, { error: 'size' });
  const bytes = Buffer.from(await upload!.arrayBuffer());
  const info = inspectImage(bytes);
  if (!info) back(path, { error: 'type' });
  const digest = createHash('sha256').update(bytes).digest('hex');
  await sql.begin(async (tx) => {
    await tx`update site_images set bytes = ${bytes}, content_type = ${info!.type}, size_bytes = ${bytes.length}, width = ${info!.width},
      height = ${info!.height}, sha256 = ${digest}, alt = ${alt}, updated_at = now(), updated_by = ${user.name} where slot = ${slot}`;
    await tx`select audit_append('user', ${user.id}, ${user.name}, 'setting.image_saved', 'site_image', ${slot},
      ${tx.json({ sha256: digest, bytes: bytes.length, type: info!.type, width: info!.width, height: info!.height } as never)}::jsonb)`;
  });
  revalidatePath('/');
  back(path, { notice: 'saved' });
}

export async function removeImage(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const path = '/console/settings/images';
  const slot = field(form, 'slot', 30);
  const sql = db();
  const [current] = await sql<{ sha256: string | null }[]>`select sha256 from site_images where slot = ${slot}`;
  if (!current) back(path, { error: 'slot' });
  await sql.begin(async (tx) => {
    await tx`update site_images set bytes = null, content_type = null, size_bytes = null, width = null, height = null, sha256 = null,
      alt = '', updated_at = now(), updated_by = ${user.name} where slot = ${slot}`;
    await tx`select audit_append('user', ${user.id}, ${user.name}, 'setting.image_removed', 'site_image', ${slot},
      ${tx.json({ sha256: current.sha256 } as never)}::jsonb)`;
  });
  revalidatePath('/');
  back(path, { notice: 'removed' });
}

// The public demo. One shared account with no password, used only when demo.enabled is on.

export async function startDemo(): Promise<void> {
  if (!(await flagSetting('demo.enabled'))) back('/signin', { error: 'demo_off' });
  if (!(await allow(`demo:${await clientAddress()}`, 'limits.demo_per_minute'))) back('/signin', { error: 'too_many' });
  const [demo] = await db()<{ id: string }[]>`select id::text as id from users where role = 'demo' and status = 'active' limit 1`;
  if (!demo) back('/signin', { error: 'demo_off' });
  await startSession(demo.id, true, await numberSetting('demo.session_minutes'));
  redirect('/console/scenarios');
}

// The first visit to a new hospital installation

export async function claimFirstRun(form: FormData): Promise<void> {
  if (!(await firstRunPending())) back('/signin', {});
  if (!(await allow(`firstrun:${await clientAddress()}`, 'limits.signin_per_minute'))) back('/welcome', { error: 'too_many' });
  const code = field(form, 'code', 40);
  const name = field(form, 'name', 80);
  const email = field(form, 'email', 200).toLowerCase();
  if (!name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) back('/welcome', { error: 'details' });
  if (!(await setupCodeMatches(code))) back('/welcome', { error: 'code' });
  const token = randomBytes(32).toString('base64url');
  const hash = createHash('sha256').update(token, 'utf8').digest('hex');
  const sql = db();
  const rows = await sql<{ id: string }[]>`
    insert into users (email, display_name, role, setup_token_hash, setup_expires_at, created_by)
    values (${email}, ${name}, 'admin', ${hash}, now() + interval '2 hours', 'first visit')
    on conflict (email) do update set setup_token_hash = excluded.setup_token_hash, setup_expires_at = excluded.setup_expires_at,
      display_name = excluded.display_name
    where users.status = 'invited'
    returning id::text as id`;
  if (rows.length === 0) back('/welcome', { error: 'taken' });
  await sql`select audit_append('system', 'first_visit', 'First visit', 'setup.first_admin_claimed', 'user', ${rows[0].id},
    ${sql.json({ email, address: await clientAddress() } as never)}::jsonb)`;
  redirect(`/setup?token=${token}`);
}
