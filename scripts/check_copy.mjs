// Checks that every label the console asks for exists in the seed migrations.
// Usage: node scripts/check_copy.mjs      Exits with an error and lists the missing keys.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const seeded = new Set();
for (const file of readdirSync(join(root, 'supabase/migrations'))) {
  const sql = readFileSync(join(root, 'supabase/migrations', file), 'utf8');
  const start = sql.indexOf('insert into copy');
  if (start < 0) continue;
  for (const block of sql.split('insert into copy').slice(1)) {
    for (const m of block.split('on conflict')[0].matchAll(/\(\s*'([a-z0-9_.]+)'\s*,/g)) seeded.add(m[1]);
  }
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else if (/\.tsx?$/.test(name)) out.push(path);
  }
  return out;
}

const missing = new Map();
let used = 0;
for (const file of walk(join(root, 'web'))) {
  const text = readFileSync(file, 'utf8');
  // Keys written out in full inside a t(...) call, including both sides of a choice.
  for (const call of text.matchAll(/\bt\(([^;]*?)[,)]/g)) {
    for (const m of call[1].matchAll(/'([a-z_]+(?:\.[a-z0-9_]+)+)'/g)) {
      used += 1;
      if (!seeded.has(m[1])) missing.set(m[1], file.replace(root, ''));
    }
  }
}

if (missing.size > 0) {
  console.error(`Missing copy for ${missing.size} key(s):`);
  for (const [key, file] of missing) console.error(`  ${key}   (${file})`);
  process.exit(1);
}
console.log(`RESULT: PASS. ${used} label uses checked against ${seeded.size} seeded keys.`);
