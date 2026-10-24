'use server';

import { randomUUID } from 'node:crypto';
import { revalidatePath } from 'next/cache';
import { audit, back, field } from './actionHelpers';
import { CsvError, parseCsv } from './csv';
import { seal, sourcesConfigured } from './crypto';
import { db } from './db';
import { ingestRecords } from './ingest';
import { unknownDepartments, saveInventory, type Inventory } from './inventory';
import { checkRow, FIELDS, KINDS, readRows, type Kind, type RowProblem } from './inventoryFiles';
import { MAPPING_FIELDS, REQUIRED_FIELDS, RowError, toAuditEvent, validTimezone, type Mapping } from './records';
import { requireUser } from './session';
import { clearSettingsCache, flagSetting, numberSetting } from './settings';

// Everything an administrator does to plug the hospital's own data in: the setup wizard,
// connections to records databases, and uploaded access reports. Each action checks who is
// asking and writes an audit entry, like every other change in the console.

const MAX_PROBLEMS = 50;

async function readFile(form: FormData, path: string): Promise<{ name: string; text: string; size: number; bytes: Buffer }> {
  const file = form.get('file');
  if (!(file instanceof File) || file.size === 0) back(path, { error: 'no_file' });
  if (file.size > (await numberSetting('uploads.max_bytes'))) back(path, { error: 'file_too_large' });
  const bytes = Buffer.from(await file.arrayBuffer());
  return { name: file.name.replace(/[^\w .()-]/g, '_').slice(0, 120) || 'upload.csv', text: bytes.toString('utf8'), size: file.size, bytes };
}

// Setup wizard

export async function saveHospitalDetails(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const name = field(form, 'name', 120);
  const tz = field(form, 'timezone', 64) || 'UTC';
  if (!validTimezone(tz)) back('/console/setup', { error: 'timezone' });
  const sql = db();
  await sql.begin(async (tx) => {
    await tx`update settings set value = ${tx.json(name as never)}, updated_at = now() where key = 'hospital.name'`;
    await tx`update settings set value = ${tx.json(tz as never)}, updated_at = now() where key = 'hospital.timezone'`;
  });
  clearSettingsCache();
  await audit(user, 'setup.hospital_saved', 'setting', 'hospital', { name, timezone: tz });
  back('/console/setup', { notice: 'hospital_saved' });
}

async function store(kind: Kind, rows: unknown[]): Promise<void> {
  const inv: Inventory = { departments: [], staff: [], assets: [], patients: [] };
  (inv[kind] as unknown[]).push(...rows);
  await saveInventory(inv);
}

async function departmentProblems(kind: Kind, rows: unknown[]): Promise<RowProblem[]> {
  if (kind === 'departments') return [];
  const missing = await unknownDepartments(rows.map((r) => (r as { department_id: string | null }).department_id));
  return missing.length > 0 ? [{ row: 0, reason: 'unknown_department', detail: missing.slice(0, 20).join(', ') }] : [];
}

async function record(kind: Kind, filename: string | null, status: 'imported' | 'refused', rows: number, problems: RowProblem[], by: string) {
  await db()`insert into inventory_imports (kind, filename, status, rows, problems, imported_by)
    values (${kind}, ${filename}, ${status}, ${rows}, ${db().json(problems.slice(0, MAX_PROBLEMS) as never)}, ${by})`;
}

export async function importInventory(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const kind = field(form, 'inventory', 20) as Kind;
  if (!KINDS.includes(kind)) back('/console/setup', { error: 'kind' });
  const path = `/console/setup`;
  const file = await readFile(form, path);
  let problems: RowProblem[] = [];
  let rows: unknown[] = [];
  try {
    const result = readRows(kind, parseCsv(file.text));
    rows = result.rows;
    problems = result.problems;
  } catch (err) {
    if (!(err instanceof CsvError)) throw err;
    problems = [{ row: 0, reason: `file_${err.message}` }];
  }
  // Department codes are checked for the rows that are otherwise fine, so every problem is reported at once.
  if (!problems.some((p) => p.row <= 1)) problems = [...(await departmentProblems(kind, rows)), ...problems];
  if (problems.length === 0 && rows.length === 0) problems = [{ row: 0, reason: 'file_empty' }];
  if (problems.length > 0) {
    await record(kind, file.name, 'refused', 0, problems, user.name);
    back(path, { error: 'import_refused', kind });
  }
  await store(kind, rows);
  await record(kind, file.name, 'imported', rows.length, [], user.name);
  await audit(user, 'setup.inventory_imported', 'inventory', kind, { file: file.name, rows: rows.length });
  revalidatePath(path);
  back(path, { notice: 'imported', kind });
}

export async function addInventoryRow(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const kind = field(form, 'inventory', 20) as Kind;
  if (!KINDS.includes(kind)) back('/console/setup', { error: 'kind' });
  const values: Record<string, string> = {};
  for (const f of FIELDS[kind]) values[f.key] = field(form, f.key, 120);
  const checked = checkRow(kind, values);
  const problems: RowProblem[] = checked.ok ? await departmentProblems(kind, [checked.value]) : [{ row: 0, reason: checked.reason }];
  if (problems.length > 0) {
    await record(kind, null, 'refused', 0, problems, user.name);
    back('/console/setup', { error: 'import_refused', kind });
  }
  await store(kind, [checked.ok ? checked.value : null]);
  await record(kind, null, 'imported', 1, [], user.name);
  await audit(user, 'setup.inventory_added', 'inventory', kind, { row: checked.ok ? checked.value : null });
  back('/console/setup', { notice: 'added', kind });
}

// Records database connections

async function canConnect(path: string): Promise<void> {
  if (!sourcesConfigured()) back(path, { error: 'sources_not_configured' });
  if (await flagSetting('demo.enabled')) back(path, { error: 'demo_on' });
}

function connectionFields(form: FormData, path: string) {
  const kind = field(form, 'kind', 20);
  const host = field(form, 'host', 255);
  const port = Number(field(form, 'port', 5));
  const database = field(form, 'database', 128);
  const username = field(form, 'username', 128);
  const name = field(form, 'name', 80) || 'Patient records';
  const timezone = field(form, 'timezone', 64) || 'UTC';
  if (kind !== 'postgres' && kind !== 'mysql') back(path, { error: 'kind' });
  // A host name or address only. No scheme, path or spaces, so the field cannot smuggle in connection options.
  if (!/^[A-Za-z0-9.\-:[\]]{1,255}$/.test(host)) back(path, { error: 'host' });
  if (!Number.isInteger(port) || port < 1 || port > 65535) back(path, { error: 'port' });
  if (!database || !username) back(path, { error: 'details' });
  if (!validTimezone(timezone)) back(path, { error: 'timezone' });
  return { kind, host, port, database, username, name, timezone, encrypt: form.get('encrypt') === 'on', dayFirst: field(form, 'day_first', 5) !== 'false' };
}

export async function createRecordSource(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const path = '/console/sources/database/new';
  await canConnect(path);
  const c = connectionFields(form, path);
  const password = field(form, 'password', 512);
  if (!password) back(path, { error: 'details' });
  const [row] = await db()<{ id: string }[]>`
    insert into record_sources (name, kind, host, port, database_name, username, password_sealed, encrypt, timezone, day_first, pending, created_by)
    values (${c.name}, ${c.kind}, ${c.host}, ${c.port}, ${c.database}, ${c.username}, ${seal(password, 'record_source', 'SOURCES_SECRET')},
      ${c.encrypt}, ${c.timezone}, ${c.dayFirst}, 'discover', ${user.name})
    returning id::text`;
  await audit(user, 'source.created', 'record_source', row.id, { name: c.name, kind: c.kind, host: c.host, port: c.port, database: c.database, username: c.username });
  back(`/console/sources/database/${row.id}`, { notice: 'connecting' });
}

async function sourceFor(form: FormData): Promise<{ id: string; path: string; row: Record<string, unknown> }> {
  const id = field(form, 'id', 18);
  if (!/^\d{1,18}$/.test(id)) back('/console/sources', { error: 'source' });
  const [row] = await db()<Record<string, unknown>[]>`select * from record_sources where id = ${id}::bigint`;
  if (!row) back('/console/sources', { error: 'source' });
  return { id, path: `/console/sources/${row.kind === 'fhir' ? 'fhir' : 'database'}/${id}`, row };
}

export async function updateRecordSource(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const { id, path } = await sourceFor(form);
  await canConnect(path);
  const c = connectionFields(form, path);
  const password = field(form, 'password', 512);
  const sealed = password ? seal(password, 'record_source', 'SOURCES_SECRET') : null;
  await db()`update record_sources set name = ${c.name}, kind = ${c.kind}, host = ${c.host}, port = ${c.port}, database_name = ${c.database},
    username = ${c.username}, password_sealed = coalesce(${sealed}, password_sealed), encrypt = ${c.encrypt}, timezone = ${c.timezone},
    day_first = ${c.dayFirst}, state = 'setup', pending = 'discover', tables = '[]', table_name = null, columns = '[]', preview = '[]',
    last_error = null, updated_at = now() where id = ${id}::bigint`;
  await audit(user, 'source.updated', 'record_source', id, { kind: c.kind, host: c.host, port: c.port, database: c.database, username: c.username, password_changed: Boolean(password) });
  back(path, { notice: 'connecting' });
}

export async function chooseSourceTable(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const { id, path, row } = await sourceFor(form);
  const table = field(form, 'table', 256);
  if (!(row.tables as string[]).includes(table)) back(path, { error: 'table' });
  await db()`update record_sources set table_name = ${table}, pending = 'preview', columns = '[]', preview = '[]', mapping = '{}',
    last_error = null, updated_at = now() where id = ${id}::bigint`;
  await audit(user, 'source.table_chosen', 'record_source', id, { table });
  back(path, { notice: 'reading' });
}

export async function startRecordSource(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const { id, path, row } = await sourceFor(form);
  await canConnect(path);
  const columns = new Set((row.columns as { name: string }[]).map((c) => c.name));
  const mapping: Record<string, string> = {};
  for (const f of ['order', ...MAPPING_FIELDS.filter((x) => x !== 'record_id')]) {
    const v = field(form, f, 128);
    if (v) {
      if (!columns.has(v)) back(path, { error: 'mapping' });
      mapping[f] = v;
    }
  }
  if (!mapping.order || REQUIRED_FIELDS.some((f) => !mapping[f])) back(path, { error: 'mapping_required' });
  const backfill = Number(field(form, 'backfill_days', 3));
  if (![0, 1, 7, 30].includes(backfill)) back(path, { error: 'backfill' });
  await db()`update record_sources set mapping = ${db().json(mapping)}, backfill_days = ${backfill}, pending = 'activate', last_error = null,
    updated_at = now() where id = ${id}::bigint`;
  await audit(user, 'source.started', 'record_source', id, { mapping, backfill_days: backfill });
  back(path, { notice: 'starting' });
}

export async function setRecordSourceState(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const { id, path, row } = await sourceFor(form);
  const to = field(form, 'to', 10);
  if (to === 'paused' && row.state === 'active') {
    await db()`update record_sources set state = 'paused', updated_at = now() where id = ${id}::bigint`;
  } else if (to === 'active' && row.state === 'paused') {
    await db()`update record_sources set state = 'active', last_error = null, updated_at = now() where id = ${id}::bigint`;
  } else back(path, { error: 'state' });
  await audit(user, to === 'paused' ? 'source.paused' : 'source.resumed', 'record_source', id, {});
  back(path, { notice: to === 'paused' ? 'paused' : 'resumed' });
}

export async function removeRecordSource(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const { id, row } = await sourceFor(form);
  await db()`delete from record_sources where id = ${id}::bigint`;
  await audit(user, 'source.removed', 'record_source', id, { name: row.name, host: row.host ?? row.base_url });
  back('/console/sources', { notice: 'removed' });
}

// Uploaded access reports

export async function createUpload(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const path = '/console/sources/upload';
  const file = await readFile(form, path);
  const timezone = field(form, 'timezone', 64) || 'UTC';
  if (!validTimezone(timezone)) back(path, { error: 'timezone' });
  let table;
  try {
    table = parseCsv(file.text, 2000000);
  } catch (err) {
    if (!(err instanceof CsvError)) throw err;
    back(path, { error: `file_${err.message}` });
  }
  if (table.rows.length === 0) back(path, { error: 'file_empty' });
  // A mapping used before for a report with the same columns is offered again.
  const [remembered] = await db()<{ value: Record<string, Mapping> }[]>`select value from engine_state where key = 'upload_mappings'`;
  const signature = table.headers.join('\u001f');
  const mapping = remembered?.value?.[signature] ?? {};
  const [row] = await db()<{ id: string }[]>`
    insert into record_uploads (filename, size_bytes, content, headers, preview, row_count, mapping, timezone, day_first, uploaded_by)
    values (${file.name}, ${file.size}, ${file.bytes}, ${db().json(table.headers)}, ${db().json(table.rows.slice(0, 5))}, ${table.rows.length},
      ${db().json(mapping as never)}, ${timezone}, ${field(form, 'day_first', 5) !== 'false'}, ${user.name})
    returning id::text`;
  await audit(user, 'upload.received', 'record_upload', row.id, { file: file.name, rows: table.rows.length });
  back(`/console/sources/upload/${row.id}`, {});
}

export async function importUpload(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const id = field(form, 'id', 18);
  if (!/^\d{1,18}$/.test(id)) back('/console/sources', { error: 'source' });
  const path = `/console/sources/upload/${id}`;
  const sql = db();
  const [up] = await sql<{ content: Buffer | null; headers: string[]; status: string; timezone: string; day_first: boolean; filename: string }[]>`
    select content, headers, status, timezone, day_first, filename from record_uploads where id = ${id}::bigint`;
  if (!up || up.status !== 'mapping' || !up.content) back('/console/sources', { error: 'source' });
  const mapping: Mapping = {};
  for (const f of MAPPING_FIELDS) {
    const v = field(form, f, 200);
    if (v) {
      if (!up.headers.includes(v)) back(path, { error: 'mapping' });
      mapping[f] = v;
    }
  }
  if (REQUIRED_FIELDS.some((f) => !mapping[f])) back(path, { error: 'mapping_required' });

  const table = parseCsv(up.content.toString('utf8'), 2000000);
  const at = Object.fromEntries(Object.entries(mapping).map(([k, h]) => [k, table.headers.indexOf(h)]));
  const assetIps = new Map((await sql<{ id: string; ip: string }[]>`select id, host(ip) as ip from assets where ip is not null`).map((r) => [r.id, r.ip]));
  const opts = { timezone: up.timezone, dayFirst: up.day_first, sourceName: `Upload: ${up.filename}`.slice(0, 120), idPrefix: 'up', assetIps };
  const problems: RowProblem[] = [];
  const records: unknown[] = [];
  const rowOf: number[] = [];
  table.rows.forEach((r, i) => {
    const row: Record<string, string> = {};
    for (const [k, idx] of Object.entries(at)) row[k] = r[idx] ?? '';
    try {
      records.push(toAuditEvent(row, opts));
      rowOf.push(i + 2);
    } catch (err) {
      if (!(err instanceof RowError)) throw err;
      if (problems.length < MAX_PROBLEMS) problems.push({ row: i + 2, reason: err.message });
    }
  });
  let rejected = table.rows.length - records.length;
  let accepted = 0;
  let duplicate = 0;
  const size = await numberSetting('ingest.max_batch_records');
  for (let start = 0; start < records.length; start += size) {
    const outcome = await ingestRecords('console_upload', randomUUID(), null, records.slice(start, start + size));
    accepted += outcome.accepted;
    duplicate += outcome.duplicate;
    rejected += outcome.rejected;
    for (const r of outcome.rejects) if (problems.length < MAX_PROBLEMS) problems.push({ row: rowOf[start + r.record_index], reason: r.reason });
  }
  await sql.begin(async (tx) => {
    // The file is no longer needed once its entries are stored, so it is deleted.
    await tx`update record_uploads set status = 'imported', content = null, preview = '[]', mapping = ${tx.json(mapping as never)},
      accepted = ${accepted}, duplicate = ${duplicate}, rejected = ${rejected}, problems = ${tx.json(problems as never)}, imported_at = now()
      where id = ${id}::bigint`;
    await tx`insert into engine_state (key, value) values ('upload_mappings', ${tx.json({ [up.headers.join('\u001f')]: mapping } as never)})
      on conflict (key) do update set value = engine_state.value || excluded.value, updated_at = now()`;
  });
  await audit(user, 'upload.imported', 'record_upload', id, { accepted, duplicate, rejected });
  back(path, { notice: 'imported' });
}

export async function discardUpload(form: FormData): Promise<void> {
  const user = await requireUser('admin');
  const id = field(form, 'id', 18);
  if (!/^\d{1,18}$/.test(id)) back('/console/sources', { error: 'source' });
  await db()`update record_uploads set status = 'discarded', content = null, preview = '[]' where id = ${id}::bigint and status = 'mapping'`;
  await audit(user, 'upload.discarded', 'record_upload', id, {});
  back('/console/sources', { notice: 'discarded' });
}
