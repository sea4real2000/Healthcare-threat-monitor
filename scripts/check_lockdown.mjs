// Checks a hosted Supabase project from the outside, the way a visitor's browser would reach it.
// Usage: SUPABASE_URL=https://xxxx.supabase.co SUPABASE_ANON_KEY=... node scripts/check_lockdown.mjs
// Exits with an error if the public key can read a row from, or write a row to, any platform table.

const url = (process.env.SUPABASE_URL ?? '').replace(/\/$/, '');
const key = process.env.SUPABASE_ANON_KEY ?? '';
if (!url || !key) {
  console.error('Set SUPABASE_URL and SUPABASE_ANON_KEY (the public anon key, not the service key).');
  process.exit(2);
}

const tables = [
  'settings', 'copy', 'sources', 'departments', 'staff', 'assets', 'patients', 'collectors', 'ingest_batches', 'ingest_rejects',
  'events', 'schema_migrations', 'scenario_runs', 'ground_truth', 'rules', 'baseline_values', 'detector_exceptions', 'models',
  'model_training_labels', 'incidents', 'incident_entities', 'alerts', 'engine_state', 'users', 'sessions', 'rate_limits', 'feedback',
  'response_actions', 'siem_outbox', 'siem_inbox', 'audit_log', 'evaluation_runs', 'compliance_controls', 'email_log', 'site_images',
];
const headers = { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' };
let leaks = 0;

for (const table of tables) {
  const read = await fetch(`${url}/rest/v1/${table}?select=*&limit=1`, { headers });
  let rows = [];
  if (read.ok) rows = await read.json().catch(() => []);
  const readLeak = read.ok && Array.isArray(rows) && rows.length > 0;

  const write = await fetch(`${url}/rest/v1/${table}`, { method: 'POST', headers, body: '{}' });
  // A permission failure is 401 or 403. Anything else means the request got past the permission check.
  const writeLeak = ![401, 403, 404].includes(write.status);

  if (readLeak || writeLeak) leaks += 1;
  console.log(
    `${table.padEnd(22)} read: ${readLeak ? 'LEAK' : 'blocked'} (${read.status})   write: ${writeLeak ? 'LEAK' : 'blocked'} (${write.status})`,
  );
}

console.log(leaks === 0 ? 'RESULT: PASS. The public key can read and write nothing.' : `RESULT: FAIL. ${leaks} table(s) exposed.`);
process.exit(leaks === 0 ? 0 : 1);
