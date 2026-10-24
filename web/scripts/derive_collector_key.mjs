// Prints the signing secret for one collector.
// Usage: INGEST_SIGNING_KEY=... npm run collector:key -- sim_hospital_01
// Give the printed value to the collector as HTM_COLLECTOR_SECRET. Never commit it.
import { createHmac } from 'node:crypto';

const masterKey = process.env.INGEST_SIGNING_KEY ?? '';
const collectorId = process.argv[2] ?? '';
if (masterKey.length < 32) {
  console.error('INGEST_SIGNING_KEY must be set and at least 32 characters long.');
  process.exit(1);
}
if (!/^[A-Za-z0-9_]{3,64}$/.test(collectorId)) {
  console.error('Give a collector id made of letters, digits and underscores.');
  process.exit(1);
}
console.log(createHmac('sha256', masterKey).update(`collector:${collectorId}`, 'utf8').digest('hex'));
