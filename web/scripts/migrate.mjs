// Applies every migration in supabase/migrations, in order. Each file is safe to run again,
// so this can be run on a new database and again after an upgrade.
// Usage (in the web folder): DATABASE_URL=... npm run db:migrate
// On Supabase, use the direct connection string (Project Settings, Database), not the pooler.
import { readdirSync, readFileSync } from 'node:fs';
import postgres from 'postgres';

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('Usage: DATABASE_URL=... npm run db:migrate');
  process.exit(1);
}
const folder = new URL('../../supabase/migrations/', import.meta.url);
const files = readdirSync(folder).filter((f) => /^\d{4}_[a-z_]+\.sql$/.test(f)).sort();
const local = /@(localhost|127\.0\.0\.1|\[::1\])[:/]/.test(url);
const ssl = process.env.DATABASE_SSL === 'disable' || (local && process.env.DATABASE_SSL !== 'require') ? false : 'require';
const sql = postgres(url, { prepare: false, max: 1, ssl, onnotice: () => {}, connect_timeout: 10 });
// Applying a migration again while the console and background service are running, as an update does,
// can meet their locks. Postgres then cancels one side and rolls it back, so the file is simply tried again.
const RETRY_CODES = new Set(['40P01', '55P03']); // deadlock detected, lock not available
const ATTEMPTS = 8;
try {
  await sql`set lock_timeout = '10s'`;
  // Text is read back wrongly from a database that is not UTF8, so refuse one plainly instead of failing later.
  const [{ server_encoding: encoding }] = await sql`show server_encoding`;
  if (encoding !== 'UTF8') throw new Error(`the database uses ${encoding} encoding. Create it with UTF8 encoding, for example: createdb -E UTF8 -T template0 htm`);
  for (const file of files) {
    const text = readFileSync(new URL(file, folder), 'utf8');
    for (let attempt = 1; ; attempt++) {
      try {
        await sql.unsafe(text);
        break;
      } catch (err) {
        if (!RETRY_CODES.has(err.code) || attempt >= ATTEMPTS) throw err;
        console.log(`${file}: ${err.message}, trying again (${attempt} of ${ATTEMPTS - 1})`);
        await new Promise((r) => setTimeout(r, 1000 * attempt));
      }
    }
    console.log(`applied ${file}`);
  }
  const rows = await sql`select version from schema_migrations order by version`;
  console.log(`${rows.length} migrations recorded: ${rows.map((r) => r.version).join(', ')}`);
} catch (err) {
  console.error(`migration failed: ${err.message}`);
  process.exitCode = 1;
} finally {
  await sql.end();
}
