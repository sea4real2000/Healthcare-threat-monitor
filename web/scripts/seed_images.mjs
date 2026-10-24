// Loads the starter photographs in seed/images into the landing page.
// Usage (in the web folder, with DATABASE_URL set):
//   npm run images:seed              fills only the places that have no picture
//   npm run images:seed -- --replace also replaces pictures that are already there
// After this, change any picture in the console under Settings, Images.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import postgres from 'postgres';

if (!process.env.DATABASE_URL) {
  console.error('Usage: DATABASE_URL=... npm run images:seed');
  process.exit(1);
}
const replace = process.argv.includes('--replace');
const folder = new URL('../seed/images/', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('manifest.json', folder), 'utf8'));
const url = process.env.DATABASE_URL;
const local = /@(localhost|127\.0\.0\.1)[:/]/.test(url);
const sql = postgres(url, { prepare: false, max: 1, ssl: process.env.DATABASE_SSL === 'disable' || local ? false : 'require', onnotice: () => {} });
try {
  for (const item of manifest) {
    const bytes = readFileSync(new URL(item.file, folder));
    if (bytes.toString('latin1', 0, 4) !== 'RIFF' || bytes.toString('latin1', 8, 12) !== 'WEBP') throw new Error(`${item.file} is not a WebP picture`);
    const digest = createHash('sha256').update(bytes).digest('hex');
    const rows = await sql`
      update site_images set bytes = ${bytes}, content_type = 'image/webp', size_bytes = ${bytes.length}, width = ${item.width}, height = ${item.height},
        sha256 = ${digest}, alt = ${item.alt}, updated_at = now(), updated_by = 'command line'
      where slot = ${item.slot} and (bytes is null or ${replace}) returning slot`;
    if (rows.length === 0) {
      console.log(`${item.slot}: left as it is`);
      continue;
    }
    await sql`select audit_append('system', 'command_line', 'Command line', 'setting.image_saved', 'site_image', ${item.slot},
      ${sql.json({ sha256: digest, bytes: bytes.length, type: 'image/webp', width: item.width, height: item.height })}::jsonb)`;
    console.log(`${item.slot}: loaded ${item.file}, ${Math.round(bytes.length / 1000)} KB`);
  }
} finally {
  await sql.end();
}
