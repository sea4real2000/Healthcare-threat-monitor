import { db } from './db';

const TTL_MS = 5000;
let settingsCache: { at: number; data: Map<string, unknown> } | null = null;
let copyCache: { at: number; data: Map<string, string> } | null = null;

/** Drops the short lived cache, so an edit made in this process shows at once. Other server instances catch up within seconds. */
export function clearSettingsCache(): void {
  settingsCache = null;
  copyCache = null;
}

async function loadSettings(): Promise<Map<string, unknown>> {
  if (settingsCache && Date.now() - settingsCache.at < TTL_MS) return settingsCache.data;
  const rows = await db()<{ key: string; value: unknown }[]>`select key, value from settings`;
  const data = new Map(rows.map((r) => [r.key, r.value]));
  settingsCache = { at: Date.now(), data };
  return data;
}

async function loadCopy(): Promise<Map<string, string>> {
  if (copyCache && Date.now() - copyCache.at < TTL_MS) return copyCache.data;
  const rows = await db()<{ key: string; value: string }[]>`select key, value from copy`;
  const data = new Map(rows.map((r) => [r.key, r.value]));
  copyCache = { at: Date.now(), data };
  return data;
}

/**
 * Reads a numeric setting. A missing or invalid row is an error on purpose:
 * limits live in the settings table, not in code, so there is no silent fallback.
 */
export async function numberSetting(key: string): Promise<number> {
  const value = (await loadSettings()).get(key);
  const n = typeof value === 'number' ? value : Number.NaN;
  if (!Number.isFinite(n)) throw new Error(`settings row "${key}" is missing or is not a number`);
  return n;
}

export async function textSetting(key: string): Promise<string> {
  const value = (await loadSettings()).get(key);
  if (typeof value !== 'string') throw new Error(`settings row "${key}" is missing or is not text`);
  return value;
}

/** Reads a true or false setting. A missing or invalid row is an error, as with numbers. */
export async function flagSetting(key: string): Promise<boolean> {
  const value = (await loadSettings()).get(key);
  if (typeof value !== 'boolean') throw new Error(`settings row "${key}" is missing or is not true or false`);
  return value;
}

export type Translate = (key: string, vars?: Record<string, string | number>) => string;

/**
 * Returns the copy lookup. A key with no row renders as the key itself,
 * so a missing label is visible on the page and never hidden behind a default.
 */
export async function getCopy(): Promise<Translate> {
  const copy = await loadCopy();
  return (key, vars) => {
    let text = copy.get(key) ?? key;
    if (vars) {
      for (const [name, v] of Object.entries(vars)) text = text.replaceAll(`{${name}}`, String(v));
    }
    return text;
  };
}
