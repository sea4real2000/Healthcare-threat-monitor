import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { deriveCollectorSecret } from './signing';

// Builds the one file installer an administrator downloads for a group of Windows computers. It carries the
// collector's files from web/collectors/windows, this group's settings and secret, and, on a hospital
// installation, the installation's own root certificate, so each computer trusts that and nothing else.

const FILES = ['HtmCollector.cs', 'htm-collector.ps1', 'install.ps1', 'uninstall.ps1'] as const;
const MAX_CERT_BYTES = 20000;

export interface RootCertificate {
  pem: string;
  fingerprint: string;
}

function collectorFile(name: string): string {
  return readFileSync(join(process.cwd(), 'collectors', 'windows', name), 'utf8');
}

/** The installation's own root certificate, served by its HTTPS server to the internal network. Null when there is none. */
export async function rootCertificate(): Promise<RootCertificate | null> {
  const url = process.env.HTM_TRUST_URL;
  if (!url) return null;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(3000), cache: 'no-store' });
    if (!res.ok) return null;
    const text = (await res.text()).slice(0, MAX_CERT_BYTES);
    const match = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(text);
    if (!match) return null;
    const cert = new X509Certificate(match[0]);
    // Only a certificate authority belongs here. Anything else is ignored rather than trusted.
    if (!cert.ca) return null;
    return { pem: `${match[0]}\n`, fingerprint: createHash('sha256').update(cert.raw).digest('hex') };
  } catch {
    return null;
  }
}

/** Groups the fingerprint in pairs, as Windows and browsers show it. */
export function showFingerprint(hex: string): string {
  return hex.toUpperCase().match(/.{2}/g)?.join(':') ?? hex;
}

function hereString(name: string, content: string): string {
  // A single quoted here string ends at a line starting with '@, so no file may contain one.
  if (/^'@/m.test(content)) throw new Error(`${name} contains a line that would end its here string`);
  // Windows line endings throughout, inside the embedded files as well as around them.
  return `@'\r\n${content.replace(/\r?\n/g, '\r\n').replace(/\r\n$/, '')}\r\n'@`;
}

export function buildInstaller(input: { collectorId: string; groupName: string; apiUrl: string; root: RootCertificate | null; intervalMinutes: number }): string {
  const key = process.env.INGEST_SIGNING_KEY;
  if (!key || key.length < 32) throw new Error('INGEST_SIGNING_KEY is not configured');
  const config = {
    api_url: input.apiUrl,
    collector_id: input.collectorId,
    secret: deriveCollectorSecret(key, input.collectorId),
    root_certificate: input.root?.pem ?? null,
    interval_minutes: input.intervalMinutes,
  };
  const files: [string, string][] = FILES.map((f) => [f, collectorFile(f)]);
  files.push(['config.json', JSON.stringify(config, null, 2)]);
  const groupLine = input.groupName.replace(/[\r\n#<>]/g, ' ').slice(0, 80);
  return [
    '<#',
    '  Healthcare Threat Monitor: Windows collector installer',
    `  Group: ${groupLine}`,
    `  Sends to: ${input.apiUrl}`,
    input.root ? `  Trusts only the certificate authority with SHA-256 fingerprint ${showFingerprint(input.root.fingerprint)}` : '  Trusts certificates the way this computer normally does',
    '',
    '  This file holds the secret for its group of computers. Keep it like a password, and delete it once',
    '  the computers are set up. Anyone with it can send Windows events in the name of these computers.',
    '',
    '  Run in Windows PowerShell opened with "Run as administrator":',
    '      powershell -ExecutionPolicy Bypass -File .\\<this file>',
    '  Add -SkipAuditPolicy to leave Windows auditing as it is, for example when Group Policy sets it.',
    '  The collector\'s source is in the project\'s repository, under web/collectors/windows.',
    '#>',
    'param([switch]$SkipAuditPolicy, [switch]$NoTest)',
    "$ErrorActionPreference = 'Stop'",
    '$files = [ordered]@{',
    ...files.map(([name, content]) => `'${name}' = ${hereString(name, content)}`),
    '}',
    "$temp = Join-Path ([IO.Path]::GetTempPath()) ('htm-install-' + [guid]::NewGuid().ToString('N'))",
    'New-Item -ItemType Directory -Path $temp | Out-Null',
    'try {',
    '    $utf8 = New-Object Text.UTF8Encoding $false',
    '    foreach ($name in $files.Keys) { [IO.File]::WriteAllText((Join-Path $temp $name), $files[$name], $utf8) }',
    "    & (Join-Path $temp 'install.ps1') -SkipAuditPolicy:$SkipAuditPolicy -NoTest:$NoTest",
    '    $code = $LASTEXITCODE',
    '} finally {',
    '    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue',
    '}',
    'exit $code',
    '',
  ].join('\r\n');
}
