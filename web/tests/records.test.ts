import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { actionCode, RowError, toAuditEvent } from '../lib/records';

interface Case {
  row: Record<string, string>;
  timezone: string;
  dayFirst: boolean;
  assetIps?: Record<string, string>;
  expect?: Record<string, string | null>;
  error?: string;
}
const shared = JSON.parse(readFileSync(new URL('../../shared/record_conversion_cases.json', import.meta.url), 'utf8')) as {
  options: { sourceName: string; idPrefix: string };
  cases: Case[];
};

describe('toAuditEvent, shared examples', () => {
  shared.cases.forEach((c, i) => {
    it(`case ${i + 1}: ${c.row.time || '(no time)'} ${c.error ?? ''}`, () => {
      const run = () =>
        toAuditEvent(c.row, {
          timezone: c.timezone,
          dayFirst: c.dayFirst,
          sourceName: shared.options.sourceName,
          idPrefix: shared.options.idPrefix,
          assetIps: new Map(Object.entries(c.assetIps ?? {})),
        });
      if (c.error) {
        expect(run).toThrow(RowError);
        expect(run).toThrow(c.error);
        return;
      }
      const p = run().payload as {
        id: string;
        recorded: string;
        action: string;
        outcome?: string;
        agent: { who: { identifier: { value: string } }; network?: { address: string } }[];
      };
      const got: Record<string, string | null> = {
        id: p.id,
        recorded: p.recorded,
        action: p.action,
        outcome: p.outcome ?? null,
        user: p.agent[0].who.identifier.value,
        address: p.agent[0].network?.address ?? null,
      };
      for (const [k, v] of Object.entries(c.expect ?? {})) expect(got[k], k).toBe(v);
    });
  });
});

describe('actionCode', () => {
  it('reads common words', () => {
    expect(['View', 'opened', 'PRINT', 'r', 'Create', 'amend', 'remove'].map(actionCode)).toEqual(['R', 'R', 'R', 'R', 'C', 'U', 'D']);
  });
});
