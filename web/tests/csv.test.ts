import { describe, expect, it } from 'vitest';
import { CsvError, headerKey, parseCsv, toCsv } from '../lib/csv';

describe('parseCsv', () => {
  it('reads a simple file', () => {
    expect(parseCsv('id,name\nA,Alpha\nB,Beta\n')).toEqual({ headers: ['id', 'name'], rows: [['A', 'Alpha'], ['B', 'Beta']] });
  });
  it('handles quotes, commas, quotes inside quotes and line breaks inside a field', () => {
    const t = parseCsv('id,note\r\n1,"Ward 3, bay ""B"""\r\n2,"two\nlines"\r\n');
    expect(t.rows).toEqual([['1', 'Ward 3, bay "B"'], ['2', 'two\nlines']]);
  });
  it('strips a byte order mark and reads semicolon files', () => {
    expect(parseCsv('﻿id;name\n1;Ann\n')).toEqual({ headers: ['id', 'name'], rows: [['1', 'Ann']] });
  });
  it('pads short rows, skips blank lines and keeps no trailing empty row', () => {
    expect(parseCsv('a,b,c\n1\n\n2,3,4').rows).toEqual([['1', '', ''], ['2', '3', '4']]);
  });
  it('refuses binary, empty and unclosed input', () => {
    expect(() => parseCsv('PK\u0003\u0004\u0000\u0000')).toThrow(CsvError);
    expect(() => parseCsv('   \n  ')).toThrow(CsvError);
    expect(() => parseCsv('a,b\n"open,2')).toThrow(CsvError);
  });
  it('enforces the row limit', () => {
    expect(() => parseCsv('a\n1\n2\n3\n', 2)).toThrow(CsvError);
  });
  it('round trips what toCsv writes', () => {
    const rows = [['id', 'note'], ['1', 'has, comma'], ['2', 'has "quote"']];
    const back = parseCsv(toCsv(rows));
    expect([back.headers, ...back.rows]).toEqual(rows);
  });
  it('normalises headers', () => {
    expect(headerKey(' Staff ID ')).toBe('staff_id');
    expect(headerKey('Department-ID')).toBe('department_id');
  });
});
