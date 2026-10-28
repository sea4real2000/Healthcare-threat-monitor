// Types for backup_format.mjs, for the console's tests.
export const MAGIC: Buffer;
export const FORMAT: number;
export type Cost = { log2N: number; r: number; p: number };
export type BackupFile = { name: string; path?: string; data?: Buffer };
export class BackupError extends Error {
  code: string;
}
export function writeBackup(out: string, manifest: object, files: BackupFile[], passphrase: string, cost?: Cost): Promise<void>;
export function readHeader(file: string): { size: number; cost: Cost; salt: Buffer; iv: Buffer };
export function readBackup(file: string, passphrase: string, dir: string): Promise<{ manifest: Record<string, unknown>; names: string[] }>;
