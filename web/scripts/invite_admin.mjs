// Creates the first administrator and prints a one time setup link.
// Usage (in the web folder, with DATABASE_URL set):
//   npm run admin:invite -- you@example.org "Your Name" https://your.console.address
// Open the printed link to choose a password and connect an authenticator app.
import { createHash, randomBytes } from 'node:crypto';
import postgres from 'postgres';

const [email, name, origin = 'http://localhost:3000'] = process.argv.slice(2);
if (!process.env.DATABASE_URL || !email || !name || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
  console.error('Usage: DATABASE_URL=... npm run admin:invite -- you@example.org "Your Name" https://your.console.address');
  process.exit(1);
}
const url = process.env.DATABASE_URL;
const local = /@(localhost|127\.0\.0\.1)[:/]/.test(url);
const sql = postgres(url, { prepare: false, max: 1, ssl: process.env.DATABASE_SSL === 'disable' || local ? false : 'require', onnotice: () => {} });
const token = randomBytes(32).toString('base64url');
const hash = createHash('sha256').update(token, 'utf8').digest('hex');
try {
  const rows = await sql`
    insert into users (email, display_name, role, setup_token_hash, setup_expires_at, created_by)
    values (${email.toLowerCase()}, ${name}, 'admin', ${hash}, now() + interval '48 hours', 'command line')
    on conflict (email) do update set setup_token_hash = excluded.setup_token_hash, setup_expires_at = excluded.setup_expires_at
    where users.status = 'invited'
    returning id::text`;
  if (rows.length === 0) {
    console.error('An active account with that email already exists.');
    process.exitCode = 1;
  } else {
    await sql`select audit_append('system', 'command_line', 'Command line', 'user.invited', 'user', ${rows[0].id}, '{"role":"admin"}'::jsonb)`;
    console.log(`${origin.replace(/\/$/, '')}/setup?token=${token}`);
  }
} finally {
  await sql.end();
}
