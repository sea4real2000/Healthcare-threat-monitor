// The hospital installation's backup service (the "backup" service in docker-compose.hospital.yml).
// The console asks for a backup or a restore by writing a request into the shared backups folder, and this
// service does it, because only it can read the database files, the secrets and the HTTPS certificate authority.
//
// A backup holds the database, the secrets and the certificate authority, so a new installation restored from it
// keeps every account, connection and Windows computer working. It is locked with the passphrase the
// administrator chose, which is never stored.
//
// Folders under HTM_BACKUP_DIR (default /backups), shared with the console:
//   requests/<id>.json   a request from the console, removed as soon as it is read
//   status/<id>.json     how a request is going, read by the console
//   incoming/<id>        an uploaded backup waiting to be restored
//   ready/<id>.htmbackup a finished backup waiting to be downloaded
//   service.json         written every few seconds, so the console can tell the service is running
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chownSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import postgres from 'postgres';
import { BackupError, readBackup, writeBackup } from './backup_format.mjs';

const DIR = process.env.HTM_BACKUP_DIR ?? '/backups';
const SECRETS = process.env.HTM_SECRETS_DIR ?? '/secrets';
// Caddy's data volume. Its certificate authority is what Windows computers and browsers trust.
const CA = join(process.env.HTM_CADDY_DATA ?? '/caddy', 'caddy/pki/authorities/local');
const ISSUED = join(process.env.HTM_CADDY_DATA ?? '/caddy', 'caddy/certificates/local');
const CA_FILES = ['root.crt', 'root.key', 'intermediate.crt', 'intermediate.key'];
const DB_HOST = process.env.HTM_DB_HOST ?? 'db';
// The console runs as this user, and must be able to read what this service leaves for it.
const CONSOLE_UID = Number(process.env.HTM_CONSOLE_UID ?? 1000);
const POLL_MS = Number(process.env.HTM_BACKUP_POLL_MS ?? 2000);
const MIGRATIONS = new URL('../../supabase/migrations/', import.meta.url);
const ID = /^[a-f0-9]{32}$/;
const folders = ['requests', 'status', 'incoming', 'ready', 'work'];

const log = (message) => console.log(`backup: ${message}`);
const secrets = () => JSON.parse(readFileSync(join(SECRETS, 'secrets.json'), 'utf8'));
const databaseUrl = () => `postgres://htm:${secrets().db_password}@${DB_HOST}:5432/htm`;
const sha = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

function giveToConsole(path) {
  chownSync(path, CONSOLE_UID, CONSOLE_UID);
}

// This version, from the console's package.json copied into the image.
const VERSION = (() => {
  try {
    return JSON.parse(readFileSync(new URL('../package.full.json', import.meta.url), 'utf8')).version ?? '';
  } catch {
    return '';
  }
})();

function status(id, fields) {
  const file = join(DIR, 'status', `${id}.json`);
  const before = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
  writeFileSync(`${file}.new`, JSON.stringify({ ...before, ...fields, id, at: new Date().toISOString() }), { mode: 0o644 });
  renameSync(`${file}.new`, file);
  giveToConsole(file);
}

function run(command, args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve(out) : reject(new Error(`${command} failed: ${(err || out).trim().split('\n').slice(-3).join(' ')}`))));
  });
}

async function withDatabase(work) {
  const sql = postgres(databaseUrl(), { prepare: false, max: 1, ssl: false, onnotice: () => {}, connect_timeout: 10 });
  try {
    return await work(sql);
  } finally {
    await sql.end();
  }
}

async function setting(key) {
  return withDatabase(async (sql) => {
    const [row] = await sql`select value from settings where key = ${key}`;
    if (!row || typeof row.value !== 'number') throw new Error(`settings row "${key}" is missing or is not a number`);
    return row.value;
  });
}

const migrationFiles = () => readdirSync(MIGRATIONS).filter((f) => /^\d{4}_[a-z_]+\.sql$/.test(f)).sort().map((f) => f.replace(/\.sql$/, ''));

async function audit(action, detail) {
  await withDatabase((sql) => sql`select audit_append('system', 'backup', 'Backup service', ${action}, 'backup', ${detail.id}, ${sql.json(detail)}::jsonb)`);
}

async function makeBackup(id, request) {
  const work = join(DIR, 'work', id);
  mkdirSync(work, { recursive: true, mode: 0o700 });
  try {
    status(id, { kind: 'backup', state: 'working', step: 'database' });
    const dump = join(work, 'database.dump');
    await run('pg_dump', ['-h', DB_HOST, '-U', 'htm', '-d', 'htm', '--format=custom', '--no-owner', '-f', dump], { PGPASSWORD: secrets().db_password });
    status(id, { step: 'locking' });
    const files = [
      { name: 'database.dump', path: dump },
      { name: 'secrets.json', path: join(SECRETS, 'secrets.json') },
      ...CA_FILES.filter((f) => existsSync(join(CA, f))).map((f) => ({ name: `ca_${f}`, path: join(CA, f) })),
    ];
    const recorded = await withDatabase((sql) => sql`select version from schema_migrations order by version`);
    const manifest = {
      product: 'healthcare-threat-monitor',
      format: 1,
      version: VERSION,
      made_at: new Date().toISOString(),
      made_by: request.by?.name ?? '',
      migrations: recorded.map((r) => r.version),
      files: files.map((f) => f.name),
    };
    const out = join(DIR, 'ready', `${id}.htmbackup`);
    await writeBackup(out, manifest, files, request.passphrase);
    giveToConsole(out);
    const size = statSync(out).size;
    await audit('backup.created', { id, by: request.by ?? null, bytes: size, files: manifest.files });
    status(id, { state: 'done', step: 'ready', bytes: size, made_at: manifest.made_at });
    log(`backup ${id} ready, ${size} bytes`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

async function restoreBackup(id, request) {
  if (!ID.test(request.upload ?? '')) throw new BackupError('no_upload', 'the uploaded file was not found. Upload it again');
  const upload = join(DIR, 'incoming', request.upload);
  if (!existsSync(upload)) throw new BackupError('no_upload', 'the uploaded file was not found. Upload it again');
  const work = join(DIR, 'work', id);
  mkdirSync(work, { recursive: true, mode: 0o700 });
  try {
    status(id, { kind: 'restore', state: 'working', step: 'unlocking' });
    const { manifest, names } = await readBackup(upload, request.passphrase, work);
    if (manifest.product !== 'healthcare-threat-monitor' || !names.includes('database.dump') || !names.includes('secrets.json')) {
      throw new BackupError('not_a_backup', 'this file is not a complete Healthcare Threat Monitor backup');
    }
    const known = new Set(migrationFiles());
    const unknown = (manifest.migrations ?? []).filter((m) => !known.has(m));
    if (unknown.length) throw new BackupError('newer_version', `this backup was made by a newer version (${manifest.version}). Update this installation first`);

    // The database first: if it fails, nothing else has changed.
    status(id, { step: 'database' });
    const password = secrets().db_password;
    await withDatabase((sql) => sql`select pg_terminate_backend(pid) from pg_stat_activity where datname = 'htm' and pid <> pg_backend_pid()`);
    await run('pg_restore', ['-h', DB_HOST, '-U', 'htm', '-d', 'htm', '--clean', '--if-exists', '--no-owner', '--single-transaction', join(work, 'database.dump')],
      { PGPASSWORD: password, PGOPTIONS: '-c lock_timeout=60s' });
    // A backup from an earlier version gets the migrations it does not have yet.
    status(id, { step: 'updating' });
    await run(process.execPath, [new URL('./migrate.mjs', import.meta.url).pathname], { DATABASE_URL: databaseUrl(), DATABASE_SSL: 'disable' });
    // Everyone signs in again, on the restored accounts.
    await withDatabase((sql) => sql`delete from sessions`);

    // The secrets, keeping this installation's own database password, which the database was made with.
    status(id, { step: 'secrets' });
    const restored = JSON.parse(readFileSync(join(work, 'secrets.json'), 'utf8'));
    const file = join(SECRETS, 'secrets.json');
    const owner = statSync(file);
    writeFileSync(`${file}.new`, JSON.stringify({ ...restored, db_password: password }), { mode: 0o600 });
    chownSync(`${file}.new`, owner.uid, owner.gid);
    renameSync(`${file}.new`, file);
    // The same script that made the secrets writes the console's and background service's settings from them.
    // Both notice the change and start again with the restored keys.
    await run(process.execPath, [new URL('./demo_setup.mjs', import.meta.url).pathname, 'secrets'], { HTM_SECRETS_DIR: SECRETS, HTM_MODE: 'hospital' });
    for (const f of readdirSync(SECRETS)) {
      const path = join(SECRETS, f);
      if (statSync(path).uid !== owner.uid) chownSync(path, owner.uid, owner.gid);
    }

    // The certificate authority, so Windows computers and browsers that trust the old installation trust this one.
    let caMoved = false;
    if (names.includes('ca_root.crt') && names.includes('ca_root.key') && existsSync(CA)) {
      const same = existsSync(join(CA, 'root.crt')) && sha(join(CA, 'root.crt')) === sha(join(work, 'ca_root.crt'));
      if (!same) {
        status(id, { step: 'certificate' });
        // The certificate for this address is made again from the restored authority when the HTTPS service starts.
        rmSync(ISSUED, { recursive: true, force: true });
        for (const f of CA_FILES) {
          if (!names.includes(`ca_${f}`)) continue;
          writeFileSync(join(CA, `${f}.new`), readFileSync(join(work, `ca_${f}`)), { mode: f.endsWith('.key') ? 0o600 : 0o644 });
        }
        // root.crt last: the HTTPS service starts again when it changes, and by then the rest is in place.
        for (const f of [...CA_FILES.filter((x) => x !== 'root.crt'), 'root.crt']) {
          if (existsSync(join(CA, `${f}.new`))) renameSync(join(CA, `${f}.new`), join(CA, f));
        }
        caMoved = true;
      }
    }
    await audit('backup.restored', { id, made_at: manifest.made_at, version: manifest.version, by: request.by ?? null, certificate_authority: caMoved ? 'restored' : 'kept' });
    status(id, { state: 'done', step: 'restored', made_at: manifest.made_at, version: manifest.version, certificate_authority: caMoved });
    log(`restore ${id} done, from a backup made ${manifest.made_at}`);
  } finally {
    rmSync(work, { recursive: true, force: true });
    rmSync(upload, { force: true });
  }
}

/** Removes finished backups and uploads older than the backups.keep_hours setting. */
async function tidy() {
  let hours;
  try {
    hours = await setting('backups.keep_hours');
  } catch {
    return; // the database may be restarting
  }
  const cutoff = Date.now() - hours * 3600 * 1000;
  for (const folder of ['ready', 'incoming', 'status']) {
    for (const f of readdirSync(join(DIR, folder))) {
      const path = join(DIR, folder, f);
      if (statSync(path).mtimeMs < cutoff) rmSync(path, { force: true });
    }
  }
}

async function handle(file) {
  const id = file.replace(/\.json$/, '');
  const path = join(DIR, 'requests', file);
  let request;
  try {
    request = JSON.parse(readFileSync(path, 'utf8'));
  } finally {
    // The request holds the passphrase, so it is gone from the disk before any work starts.
    unlinkSync(path);
  }
  if (!ID.test(id)) return;
  try {
    if (request.kind === 'backup') await makeBackup(id, request);
    else if (request.kind === 'restore') await restoreBackup(id, request);
    else throw new BackupError('unknown', `unknown request: ${request.kind}`);
  } catch (err) {
    const known = err instanceof BackupError;
    log(`${request.kind} ${id} failed: ${err.message}`);
    status(id, { kind: request.kind, state: 'failed', code: known ? err.code : 'failed', message: err.message });
  }
}

function prepare() {
  mkdirSync(DIR, { recursive: true });
  for (const f of folders) {
    const path = join(DIR, f);
    mkdirSync(path, { recursive: true });
    // The console writes requests and uploads; only this service reads the work folder.
    if (f === 'work') chownSync(path, 0, 0);
    else giveToConsole(path);
  }
  giveToConsole(DIR);
  // Anything left from a restart part way through is not trusted.
  rmSync(join(DIR, 'work'), { recursive: true, force: true });
  mkdirSync(join(DIR, 'work'), { mode: 0o700 });
}

async function main() {
  prepare();
  log(`watching ${DIR}`);
  let tidied = 0;
  for (;;) {
    writeFileSync(join(DIR, 'service.json'), JSON.stringify({ at: new Date().toISOString(), version: VERSION }));
    for (const file of readdirSync(join(DIR, 'requests')).filter((f) => f.endsWith('.json')).sort()) await handle(file);
    if (Date.now() - tidied > 10 * 60 * 1000) {
      await tidy();
      tidied = Date.now();
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

main().catch((err) => {
  console.error(`backup: stopped: ${err.message}`);
  process.exit(1);
});
