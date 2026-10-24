'use server';

import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { audit, back, field } from './actionHelpers';
import { seal, sourcesConfigured } from './crypto';
import { db } from './db';
import { requireUser } from './session';
import { flagSetting, numberSetting } from './settings';

// Administrator actions for the learning period, the built in log receiver and Windows collectors.
// Each checks who is asking and writes an audit entry, like every other change in the console.

const SOURCE_ID = /^[a-z_]{1,32}$/;

// Learning period

export async function finishLearning(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const source = field(form, 'source', 32);
  if (!SOURCE_ID.test(source)) back('/console/sources', { error: 'learning_unknown' });
  // The background service ends it on its next pass and retrains straight away.
  const rows = await db()`update learning_periods set ends_at = now(), finished_by = ${user.name}
    where source = ${source} and finished_at is null returning source`;
  if (rows.length === 0) back('/console/sources', { error: 'learning_unknown' });
  await audit(user, 'learning.finish_requested', 'source', source, {});
  back('/console/sources', { notice: 'learning_finishing' });
}

export async function learnAgain(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const source = field(form, 'source', 32);
  if (!SOURCE_ID.test(source)) back('/console/sources', { error: 'learning_unknown' });
  const days = await numberSetting('learning.days');
  if (!(days > 0)) back('/console/sources', { error: 'learning_off' });
  const rows = await db()`update learning_periods set started_at = now(), ends_at = now() + make_interval(secs => ${days * 86400}),
      finished_at = null, finished_by = null, events = 0, values_learned = 0
    where source = ${source} returning source`;
  if (rows.length === 0) back('/console/sources', { error: 'learning_unknown' });
  await audit(user, 'learning.restarted', 'source', source, { days });
  back('/console/sources', { notice: 'learning_restarted' });
}

// The built in log receiver

const SENDER_STATES = ['accepted', 'blocked'] as const;

async function senderFor(form: FormData): Promise<{ id: string; address: string }> {
  const id = field(form, 'sender', 20);
  if (!/^\d{1,18}$/.test(id)) back('/console/sources/receiver', { error: 'sender_unknown' });
  const [row] = await db()<{ id: string; address: string }[]>`select id::text as id, host(address) as address from log_senders where id = ${id}::bigint`;
  if (!row) back('/console/sources/receiver', { error: 'sender_unknown' });
  return row;
}

export async function decideSender(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const sender = await senderFor(form);
  const state = field(form, 'state', 20) as (typeof SENDER_STATES)[number];
  if (!SENDER_STATES.includes(state)) back('/console/sources/receiver', { error: 'sender_unknown' });
  const name = field(form, 'name', 80);
  await db()`update log_senders set state = ${state}, name = case when ${name} = '' then name else ${name} end,
      decided_by = ${user.name}, decided_at = now(), updated_at = now()
    where id = ${sender.id}::bigint`;
  await audit(user, state === 'accepted' ? 'receiver.sender_accepted' : 'receiver.sender_blocked', 'log_sender', sender.address, { name });
  back('/console/sources/receiver', { notice: state === 'accepted' ? 'sender_accepted' : 'sender_blocked' });
}

export async function renameSender(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const sender = await senderFor(form);
  const name = field(form, 'name', 80);
  await db()`update log_senders set name = ${name}, updated_at = now() where id = ${sender.id}::bigint`;
  await audit(user, 'receiver.sender_renamed', 'log_sender', sender.address, { name });
  back('/console/sources/receiver', { notice: 'sender_renamed' });
}

export async function removeSender(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const sender = await senderFor(form);
  await db()`delete from log_senders where id = ${sender.id}::bigint`;
  await audit(user, 'receiver.sender_removed', 'log_sender', sender.address, {});
  back('/console/sources/receiver', { notice: 'sender_removed' });
}

// Windows collectors

const GROUP_ID = /^win_[a-z0-9]{10}$/;

export async function createWindowsGroup(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const name = field(form, 'name', 80);
  if (!name) back('/console/sources/windows', { error: 'group_name' });
  const id = `win_${randomBytes(8).toString('hex').slice(0, 10)}`;
  await db()`insert into collectors (id, name, kind, allowed_sources, created_by, can_respond)
    values (${id}, ${name}, 'windows', ${['windows']}, ${user.name}, false)`;
  await audit(user, 'windows.group_created', 'collector', id, { name });
  back('/console/sources/windows', { notice: 'group_created', group: id });
}

export async function setWindowsGroupEnabled(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const id = field(form, 'group', 20);
  const enabled = field(form, 'enabled', 5) === 'true';
  if (!GROUP_ID.test(id)) back('/console/sources/windows', { error: 'group_unknown' });
  const rows = await db()`update collectors set enabled = ${enabled} where id = ${id} and kind = 'windows' returning id`;
  if (rows.length === 0) back('/console/sources/windows', { error: 'group_unknown' });
  await audit(user, enabled ? 'windows.group_enabled' : 'windows.group_disabled', 'collector', id, {});
  back('/console/sources/windows', { notice: enabled ? 'group_enabled' : 'group_disabled' });
}

// FHIR connections

const FHIR_AUTH = ['none', 'token', 'client_secret', 'private_key'] as const;
type FhirAuth = (typeof FHIR_AUTH)[number];

async function fhirAllowed(path: string): Promise<void> {
  if (!sourcesConfigured()) back(path, { error: 'sources_not_configured' });
  if (await flagSetting('demo.enabled')) back(path, { error: 'demo_on' });
}

/** A web address with no user name or password in it, so nothing secret is kept in plain text. */
function webAddress(value: string, path: string, error: string): string {
  if (!value) return '';
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    back(path, { error });
  }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || value.length > 500) back(path, { error });
  return value.replace(/\/+$/, '');
}

function fhirFields(form: FormData, path: string) {
  const auth = field(form, 'auth_kind', 20) as FhirAuth;
  if (!FHIR_AUTH.includes(auth)) back(path, { error: 'fhir_auth' });
  const baseUrl = webAddress(field(form, 'base_url', 500), path, 'fhir_url');
  if (!baseUrl) back(path, { error: 'fhir_url' });
  const tokenUrl = webAddress(field(form, 'token_url', 500), path, 'fhir_token_url');
  const clientId = field(form, 'client_id', 200);
  const scope = field(form, 'scope', 200) || 'system/AuditEvent.read';
  if (!/^[\w/.*:\- ]{1,200}$/.test(scope)) back(path, { error: 'fhir_scope' });
  if ((auth === 'client_secret' || auth === 'private_key') && !clientId) back(path, { error: 'fhir_client_id' });
  const ca = field(form, 'ca_certificate', 20000);
  if (ca && !/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----\s*$/.test(ca)) back(path, { error: 'fhir_ca' });
  return { auth, baseUrl, tokenUrl: tokenUrl || null, clientId: clientId || null, scope, ca: ca || null, name: field(form, 'name', 80) || 'Patient records (FHIR)',
    encrypt: form.get('encrypt') === 'on' };
}

/** A key pair for SMART Backend Services. The vendor registers the public half. The private half is sealed. */
function newKeyPair(): { privatePem: string; jwk: Record<string, string> } {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pub = publicKey.export({ format: 'jwk' }) as { kty: string; n: string; e: string };
  // The key's ID is its RFC 7638 thumbprint, so it identifies exactly this key.
  const kid = createHash('sha256').update(JSON.stringify({ e: pub.e, kty: pub.kty, n: pub.n })).digest('base64url');
  return { privatePem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(), jwk: { kty: pub.kty, n: pub.n, e: pub.e, kid, alg: 'RS384', use: 'sig' } };
}

export async function createFhirSource(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const path = '/console/sources/fhir/new';
  await fhirAllowed(path);
  const f = fhirFields(form, path);
  let sealed: string | null = null;
  let jwk: Record<string, string> | null = null;
  if (f.auth === 'token' || f.auth === 'client_secret') {
    const secret = field(form, 'secret', 4000);
    if (!secret) back(path, { error: 'fhir_secret' });
    sealed = seal(secret, 'record_source', 'SOURCES_SECRET');
  } else if (f.auth === 'private_key') {
    const pair = newKeyPair();
    sealed = seal(pair.privatePem, 'record_source', 'SOURCES_SECRET');
    jwk = pair.jwk;
  }
  // With a key pair, the vendor must register the public key first, so the check waits until the administrator asks.
  const [row] = await db()<{ id: string }[]>`
    insert into record_sources (name, kind, base_url, auth_kind, client_id, token_url, scope, ca_certificate, password_sealed, public_jwk,
      encrypt, timezone, pending, created_by)
    values (${f.name}, 'fhir', ${f.baseUrl}, ${f.auth}, ${f.clientId}, ${f.tokenUrl}, ${f.scope}, ${f.ca}, ${sealed},
      ${jwk ? db().json(jwk) : null}, ${f.encrypt}, 'UTC', ${f.auth === 'private_key' ? null : 'discover'}, ${user.name})
    returning id::text as id`;
  await audit(user, 'source.created', 'record_source', row.id, { kind: 'fhir', base_url: f.baseUrl, auth: f.auth, client_id: f.clientId });
  back(`/console/sources/fhir/${row.id}`, { notice: f.auth === 'private_key' ? 'fhir_register_key' : 'fhir_checking' });
}

async function fhirSourceFor(form: FormData): Promise<{ id: string; path: string; row: Record<string, unknown> }> {
  const id = field(form, 'id', 18);
  if (!/^\d{1,18}$/.test(id)) back('/console/sources', { error: 'source' });
  const [row] = await db()<Record<string, unknown>[]>`select * from record_sources where id = ${id}::bigint and kind = 'fhir'`;
  if (!row) back('/console/sources', { error: 'source' });
  return { id, path: `/console/sources/fhir/${id}`, row };
}

export async function checkFhirSource(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const { id, path } = await fhirSourceFor(form);
  await fhirAllowed(path);
  await db()`update record_sources set pending = 'discover', last_error = null, updated_at = now() where id = ${id}::bigint`;
  await audit(user, 'source.checked', 'record_source', id, {});
  back(path, { notice: 'fhir_checking' });
}

export async function updateFhirSource(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const { id, path, row } = await fhirSourceFor(form);
  await fhirAllowed(path);
  const f = fhirFields(form, path);
  if (f.auth !== row.auth_kind) back(path, { error: 'fhir_auth_change' });
  const secret = field(form, 'secret', 4000);
  const sealed = secret && (f.auth === 'token' || f.auth === 'client_secret') ? seal(secret, 'record_source', 'SOURCES_SECRET') : (row.password_sealed as string | null);
  await db()`update record_sources set name = ${f.name}, base_url = ${f.baseUrl}, client_id = ${f.clientId}, token_url = ${f.tokenUrl},
      scope = ${f.scope}, ca_certificate = ${f.ca}, encrypt = ${f.encrypt}, password_sealed = ${sealed},
      pending = 'discover', last_error = null, updated_at = now()
    where id = ${id}::bigint`;
  await audit(user, 'source.updated', 'record_source', id, { base_url: f.baseUrl, client_id: f.clientId, secret_changed: Boolean(secret) });
  back(path, { notice: 'fhir_checking' });
}

export async function startFhirSource(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const { id, path, row } = await fhirSourceFor(form);
  await fhirAllowed(path);
  if (row.state !== 'setup' || !row.last_ok_at) back(path, { error: 'fhir_not_checked' });
  const backfill = Number(field(form, 'backfill_days', 3));
  if (![0, 1, 7, 30].includes(backfill)) back(path, { error: 'backfill' });
  await db()`update record_sources set backfill_days = ${backfill}, pending = 'activate', last_error = null, updated_at = now() where id = ${id}::bigint`;
  await audit(user, 'source.started', 'record_source', id, { backfill_days: backfill });
  back(path, { notice: 'starting' });
}
