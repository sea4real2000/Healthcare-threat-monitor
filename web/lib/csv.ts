/**
 * Reads a spreadsheet saved as CSV. Handles quoted fields, commas and line breaks inside quotes,
 * Windows line endings, a leading byte order mark, and the semicolon separator some spreadsheet
 * programs use in countries where the comma is the decimal mark.
 */
export interface Table {
  headers: string[];
  rows: string[][];
}

export class CsvError extends Error {}

function detectSeparator(firstLine: string): ',' | ';' | '\t' {
  const count = (c: string) => firstLine.split(c).length - 1;
  const counts: [',' | ';' | '\t', number][] = [[',', count(',')], [';', count(';')], ['\t', count('\t')]];
  counts.sort((a, b) => b[1] - a[1]);
  return counts[0][1] > 0 ? counts[0][0] : ',';
}

export function parseCsv(input: string, maxRows = 100000): Table {
  let text = input.replace(/^﻿/, '');
  if (text.includes('\u0000')) throw new CsvError('not_text');
  const firstLine = text.slice(0, text.search(/\r?\n|$/));
  const sep = detectSeparator(firstLine);
  const records: string[][] = [];
  let field = '';
  let row: string[] = [];
  let quoted = false;
  let i = 0;
  text = text.replace(/\r\n?/g, '\n');
  while (i < text.length) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        quoted = false;
      } else field += c;
      i += 1;
      continue;
    }
    if (c === '"' && field === '') quoted = true;
    else if (c === sep) {
      row.push(field);
      field = '';
    } else if (c === '\n') {
      row.push(field);
      records.push(row);
      if (records.length > maxRows + 1) throw new CsvError('too_many_rows');
      row = [];
      field = '';
    } else field += c;
    i += 1;
  }
  if (quoted) throw new CsvError('unclosed_quote');
  if (field !== '' || row.length > 0) {
    row.push(field);
    records.push(row);
  }
  const nonEmpty = records.filter((r) => r.some((v) => v.trim() !== ''));
  if (nonEmpty.length === 0) throw new CsvError('empty');
  const headers = nonEmpty[0].map((h) => h.trim());
  if (headers.every((h) => h === '')) throw new CsvError('no_headers');
  const rows = nonEmpty.slice(1).map((r) => headers.map((_, k) => (r[k] ?? '').trim()));
  if (rows.length > maxRows) throw new CsvError('too_many_rows');
  return { headers, rows };
}

/** Turns a header such as "Staff ID" or "staff_id" into "staff_id", so templates match loosely. */
export function headerKey(h: string): string {
  return h
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_|_$/g, '');
}

/** Writes rows as CSV, quoting only where needed. Used for the downloadable templates. */
export function toCsv(rows: string[][]): string {
  const cell = (v: string) => (/[",\n;]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  return rows.map((r) => r.map(cell).join(',')).join('\r\n') + '\r\n';
}
