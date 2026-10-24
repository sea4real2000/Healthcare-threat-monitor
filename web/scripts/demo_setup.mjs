// Prepares an installation started by docker compose: the demo (docker-compose.yml) or a hospital's
// own installation (docker-compose.hospital.yml, with HTM_MODE=hospital). Runs in two steps.
//   node scripts/demo_setup.mjs secrets   makes the secrets on first start and keeps them after that
//   node scripts/demo_setup.mjs database  applies the migrations, loads the photos, sets the mode's
//                                         settings on first start, and prints a link to set up the first administrator
// Secrets are random, made on this machine, and stored only in the demo's private Docker volume.
import { spawnSync } from 'node:child_process';
import { createHash, createHmac, randomInt, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import postgres from 'postgres';

const dir = process.env.HTM_SECRETS_DIR ?? '/secrets';
const step = process.argv[2];
const file = (name) => join(dir, name);

const mode = process.env.HTM_MODE === 'hospital' ? 'hospital' : 'demo';

// The setup code proves the first administrator can see this installation's own screen or its setup log.
// No easily confused characters: no 0, O, 1, I or L.
const CODE_LETTERS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const codeHash = (code) => createHash('sha256').update(code.replace(/[^A-Za-z0-9]/g, '').toUpperCase(), 'utf8').digest('hex');
const collectorId = mode === 'hospital' ? 'hospital_service' : 'sim_hospital_01';

function makeSecrets() {
  const hex = () => randomBytes(32).toString('hex');
  const existing = existsSync(file('secrets.json')) ? JSON.parse(readFileSync(file('secrets.json'), 'utf8')) : {};
  const wanted = ['db_password', 'ingest', 'auth', 'siem', 'audit', 'sources'];
  const s = { ...existing };
  for (const k of wanted) if (!s[k]) s[k] = hex();
  const added = wanted.filter((k) => !existing[k]);
  const collector = createHmac('sha256', s.ingest).update(`collector:${collectorId}`, 'utf8').digest('hex');
  const dbUrl = `postgres://htm:${s.db_password}@db:5432/htm`;
  writeFileSync(file('secrets.json'), JSON.stringify(s), { mode: 0o600 });
  // The database container reads its password from this file as its own user, so it must be readable.
  writeFileSync(file('db_password'), s.db_password, { mode: 0o644 });
  writeFileSync(
    file('console.env'),
    [`DATABASE_URL=${dbUrl}`, 'DATABASE_SSL=disable', `INGEST_SIGNING_KEY=${s.ingest}`, `AUTH_SECRET=${s.auth}`,
      `SIEM_WEBHOOK_KEY=${s.siem}`, `AUDIT_EXPORT_KEY=${s.audit}`, `SOURCES_SECRET=${s.sources}`, ''].join('\n'),
    { mode: 0o644 },
  );
  writeFileSync(
    file('worker.env'),
    [`DATABASE_URL=${dbUrl}?sslmode=disable`, `HTM_COLLECTOR_ID=${collectorId}`, `HTM_COLLECTOR_SECRET=${collector}`,
      `SIEM_WEBHOOK_KEY=${s.siem}`, `SOURCES_SECRET=${s.sources}`, ''].join('\n'),
    { mode: 0o644 },
  );
  if (mode === 'hospital' && !existsSync(file('setup_code'))) {
    const code = Array.from({ length: 10 }, () => CODE_LETTERS[randomInt(CODE_LETTERS.length)]).join('');
    // Readable by the computer's own administrator, who shows it on the installation's screen. Not a secret once used.
    writeFileSync(file('setup_code'), `${code.slice(0, 5)} ${code.slice(5)}\n`, { mode: 0o644 });
  }
  console.log(added.length === wanted.length ? 'secrets created' : added.length ? `secrets kept, added: ${added.join(', ')}` : 'secrets already exist, keeping them');
}

function run(script, args, env) {
  const r = spawnSync(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'inherit'], env: { ...process.env, ...env } });
  const out = r.stdout.toString();
  if (r.status !== 0) {
    process.stdout.write(out);
    throw new Error(`${script} failed`);
  }
  return out;
}

async function prepareDatabase() {
  const s = JSON.parse(readFileSync(file('secrets.json'), 'utf8'));
  const env = { DATABASE_URL: `postgres://htm:${s.db_password}@db:5432/htm`, DATABASE_SSL: 'disable' };
  process.stdout.write(run('scripts/migrate.mjs', [], env));
  process.stdout.write(run('scripts/seed_images.mjs', [], env));

  const sql = postgres(env.DATABASE_URL, { prepare: false, max: 1, ssl: false, onnotice: () => {} });
  let admins;
  try {
    // First start only, so later changes made in Settings are never undone.
    const [first] = await sql`select not exists (select 1 from engine_state where key in ('demo_setup_done', 'install_setup_done')) as yes`;
    if (first.yes && mode === 'demo' && process.env.HTM_DEMO_LOGIN !== '0') {
      // The demo login is the point of this demo. Switch it off in Settings, Public demo.
      await sql`update settings set value = 'true'::jsonb, updated_at = now() where key = 'demo.enabled'`;
    }
    if (first.yes && mode === 'hospital') {
      // A hospital's own installation: no simulated hospital, no simulated endpoint product and no public demo login.
      await sql`update settings set value = 'false'::jsonb, updated_at = now()
        where key in ('engine.simulate', 'response.simulated_connector', 'demo.enabled')`;
    }
    await sql`insert into engine_state (key, value) values ('install_setup_done', ${sql.json({ mode })}) on conflict (key) do nothing`;
    [admins] = await sql`select count(*)::int as n from users where role = 'admin' and status = 'active'`;
  } finally {
    await sql.end();
  }

  const origin = process.env.HTM_PUBLIC_URL ?? 'http://localhost:3000';
  console.log('');
  if (mode === 'demo') {
    console.log(`Open ${origin} once the console reports healthy. Press "Try the demo" on the sign in page to launch an attack.`);
  } else {
    console.log(`Open ${origin} once the console reports healthy. Your browser may warn about the certificate the first time: see the installation guide.`);
  }
  if (admins.n === 0 && mode === 'hospital' && existsSync(file('setup_code'))) {
    // The first visit in a browser sets up the administrator, with the code shown on this installation's screen.
    const code = readFileSync(file('setup_code'), 'utf8').trim();
    const sql2 = postgres(env.DATABASE_URL, { prepare: false, max: 1, ssl: false, onnotice: () => {} });
    try {
      await sql2`insert into engine_state (key, value) values ('first_run', ${sql2.json({ hash: codeHash(code) })})
        on conflict (key) do update set value = excluded.value, updated_at = now()`;
    } finally {
      await sql2.end();
    }
    console.log(`To set up the administrator in a browser, open ${origin}/welcome and enter the setup code ${code}`);
  }
  if (admins.n === 0) {
    const email = (process.env.HTM_ADMIN_EMAIL || (mode === 'demo' ? 'admin@demo.local' : 'admin@hospital.local')).toLowerCase();
    const link = run('scripts/invite_admin.mjs', [email, 'Administrator', origin], env).trim();
    console.log(mode === 'demo' ? 'To change rules and settings, set up the administrator account with this one time link:' : 'Set up your administrator account with this one time link, then open Setup in the console:');
    console.log(link);
    console.log(`The account signs in as ${email}.`);
  } else {
    console.log('An administrator account already exists. Sign in with it.');
  }
}

if (step === 'secrets') makeSecrets();
else if (step === 'database') await prepareDatabase();
else {
  console.error('Usage: node scripts/demo_setup.mjs secrets|database');
  process.exit(1);
}
