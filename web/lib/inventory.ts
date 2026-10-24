import { isIP } from 'node:net';
import { db } from './db';

// The hospital inventory: departments, staff, computers and devices, and patients.
// The same checks serve the signed inventory API and the setup wizard in the console.

// Letters, numbers, dots, underscores and hyphens. Windows computer names often contain hyphens.
export const ID = /^[A-Za-z0-9_.-]{1,64}$/;
export const PATIENT_REF = /^[A-Za-z0-9_.-]{1,64}$/;
export const ASSET_KINDS = ['workstation', 'server', 'medical_device', 'network'] as const;
export const STAFF_STATUSES = ['active', 'terminated'] as const;
export const PATIENT_FLAGS = ['vip', 'staff'] as const;
export const MAX_ROWS = 20000;

type Row = Record<string, unknown>;
export type Checked<T> = { ok: true; value: T } | { ok: false; reason: string };

export interface Department { id: string; name: string; zone: string }
export interface Staff { id: string; display_name: string; role: string; department_id: string | null; status: string }
export interface Asset { id: string; kind: string; role: string; os: string | null; ip: string | null; department_id: string | null; zone: string; attributes: Row }
export interface Patient { ref: string; department_id: string | null; flag: string | null }
export interface Inventory { departments: Department[]; staff: Staff[]; assets: Asset[]; patients: Patient[] }

function text(v: unknown, max = 120): string | null {
  if (typeof v === 'number' && Number.isFinite(v)) v = String(v);
  return typeof v === 'string' && v.trim() !== '' && v.trim().length <= max ? v.trim() : null;
}

/** Spreadsheets often hold a blank or a dash where a value is missing. */
function optional(v: unknown, max = 120): string | null {
  const t = text(v, max);
  return t === null || t === '-' ? null : t;
}

export function checkDepartment(d: Row): Checked<Department> {
  const id = text(d.id, 64);
  const name = text(d.name);
  const zone = text(d.zone, 40) ?? 'clinical';
  if (!id || !ID.test(id)) return { ok: false, reason: 'department_id' };
  if (!name) return { ok: false, reason: 'department_name' };
  return { ok: true, value: { id: id.toUpperCase(), name, zone: zone.toLowerCase() } };
}

export function checkStaff(s: Row): Checked<Staff> {
  const id = text(s.id, 64);
  const displayName = text(s.display_name);
  const role = text(s.role, 40);
  const status = (optional(s.status, 20) ?? 'active').toLowerCase();
  if (!id || !ID.test(id)) return { ok: false, reason: 'staff_id' };
  if (!displayName) return { ok: false, reason: 'staff_name' };
  if (!role) return { ok: false, reason: 'staff_role' };
  if (!(STAFF_STATUSES as readonly string[]).includes(status)) return { ok: false, reason: 'staff_status' };
  return { ok: true, value: { id: id.toLowerCase(), display_name: displayName, role: role.toLowerCase(), department_id: optional(s.department_id, 64)?.toUpperCase() ?? null, status } };
}

export function checkAsset(a: Row): Checked<Asset> {
  const id = text(a.id, 64);
  const kind = text(a.kind, 40)?.toLowerCase().replace(/\s+/g, '_') ?? null;
  const role = text(a.role, 60);
  const zone = text(a.zone, 40) ?? (kind === 'medical_device' ? 'device' : kind === 'server' ? 'server' : 'clinical');
  const ip = optional(a.ip, 45);
  if (!id || !ID.test(id)) return { ok: false, reason: 'asset_id' };
  if (!kind || !(ASSET_KINDS as readonly string[]).includes(kind)) return { ok: false, reason: 'asset_kind' };
  if (!role) return { ok: false, reason: 'asset_role' };
  if (ip && !isIP(ip)) return { ok: false, reason: 'asset_ip' };
  return {
    ok: true,
    value: {
      id: id.toUpperCase(),
      kind,
      role: role.toLowerCase().replace(/\s+/g, '_'),
      os: optional(a.os, 60),
      ip,
      department_id: optional(a.department_id, 64)?.toUpperCase() ?? null,
      zone: zone.toLowerCase(),
      attributes: a.attributes && typeof a.attributes === 'object' && !Array.isArray(a.attributes) ? (a.attributes as Row) : {},
    },
  };
}

export function checkPatient(p: Row): Checked<Patient> {
  const ref = text(p.ref, 64);
  const flag = optional(p.flag, 10)?.toLowerCase() ?? null;
  if (!ref || !PATIENT_REF.test(ref)) return { ok: false, reason: 'patient_ref' };
  if (flag && !(PATIENT_FLAGS as readonly string[]).includes(flag)) return { ok: false, reason: 'patient_flag' };
  return { ok: true, value: { ref, department_id: optional(p.department_id, 64)?.toUpperCase() ?? null, flag } };
}

/** Department ids referenced by the rows but not present in the database or in the same upload. */
export async function unknownDepartments(ids: (string | null)[], alsoKnown: string[] = []): Promise<string[]> {
  const wanted = [...new Set(ids.filter((x): x is string => Boolean(x)))];
  if (wanted.length === 0) return [];
  const rows = await db()<{ id: string }[]>`select id from departments where id = any(${wanted})`;
  const known = new Set([...rows.map((r) => r.id), ...alsoKnown]);
  return wanted.filter((id) => !known.has(id));
}

/**
 * Inserts or updates the inventory in one transaction. An update never touches an asset's status
 * or last seen time, so an isolated machine stays isolated when the inventory is sent again.
 */
export async function saveInventory(inv: Inventory, collectorId: string | null = null): Promise<void> {
  const sql = db();
  await sql.begin(async (tx) => {
    if (inv.departments.length > 0) {
      await tx`
        insert into departments (id, name, zone)
        select t.id, t.name, t.zone
        from jsonb_to_recordset(${tx.json(inv.departments as never)}::jsonb) as t(id text, name text, zone text)
        on conflict (id) do update set name = excluded.name, zone = excluded.zone`;
    }
    if (inv.staff.length > 0) {
      await tx`
        insert into staff (id, display_name, role, department_id, status)
        select t.id, t.display_name, t.role, t.department_id, t.status
        from jsonb_to_recordset(${tx.json(inv.staff as never)}::jsonb)
          as t(id text, display_name text, role text, department_id text, status text)
        on conflict (id) do update set display_name = excluded.display_name, role = excluded.role,
          department_id = excluded.department_id, status = excluded.status, updated_at = now()
        where (staff.display_name, staff.role, staff.department_id, staff.status)
          is distinct from (excluded.display_name, excluded.role, excluded.department_id, excluded.status)`;
    }
    if (inv.assets.length > 0) {
      await tx`
        insert into assets (id, kind, role, os, ip, department_id, zone, attributes)
        select t.id, t.kind, t.role, t.os, t.ip, t.department_id, t.zone, t.attributes
        from jsonb_to_recordset(${tx.json(inv.assets as never)}::jsonb)
          as t(id text, kind text, role text, os text, ip inet, department_id text, zone text, attributes jsonb)
        on conflict (id) do update set kind = excluded.kind, role = excluded.role, os = excluded.os,
          ip = excluded.ip, department_id = excluded.department_id, zone = excluded.zone,
          attributes = excluded.attributes, updated_at = now()`;
    }
    if (inv.patients.length > 0) {
      await tx`
        insert into patients (ref, department_id, flag)
        select t.ref, t.department_id, t.flag
        from jsonb_to_recordset(${tx.json(inv.patients as never)}::jsonb) as t(ref text, department_id text, flag text)
        on conflict (ref) do update set department_id = excluded.department_id, flag = excluded.flag, updated_at = now()
        where (patients.department_id, patients.flag) is distinct from (excluded.department_id, excluded.flag)`;
    }
    if (collectorId) await tx`update collectors set last_seen_at = now() where id = ${collectorId}`;
  });
}
