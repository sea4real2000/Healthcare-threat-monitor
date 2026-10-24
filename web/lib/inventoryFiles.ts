import { headerKey, type Table } from './csv';
import { checkAsset, checkDepartment, checkPatient, checkStaff, type Asset, type Checked, type Department, type Patient, type Staff } from './inventory';

// The four spreadsheets the setup wizard accepts, the column names each understands,
// and the template a hospital downloads and fills in.

export const KINDS = ['departments', 'staff', 'assets', 'patients'] as const;
export type Kind = (typeof KINDS)[number];

interface FieldDef {
  key: string;
  required: boolean;
  aliases: string[];
}

export const FIELDS: Record<Kind, FieldDef[]> = {
  departments: [
    { key: 'id', required: true, aliases: ['id', 'department_code', 'department_id', 'code'] },
    { key: 'name', required: true, aliases: ['name', 'department_name', 'department'] },
    { key: 'zone', required: false, aliases: ['zone', 'network_zone'] },
  ],
  staff: [
    { key: 'id', required: true, aliases: ['id', 'staff_id', 'user_id', 'username', 'user_name', 'login', 'employee_id'] },
    { key: 'display_name', required: true, aliases: ['display_name', 'full_name', 'name', 'staff_name'] },
    { key: 'role', required: true, aliases: ['role', 'job', 'job_title', 'position', 'cadre'] },
    { key: 'department_id', required: false, aliases: ['department_id', 'department_code', 'department', 'dept', 'ward'] },
    { key: 'status', required: false, aliases: ['status', 'employment_status'] },
  ],
  assets: [
    { key: 'id', required: true, aliases: ['id', 'name', 'asset_id', 'hostname', 'computer_name', 'computer', 'device_name', 'device'] },
    { key: 'kind', required: true, aliases: ['kind', 'type', 'asset_type'] },
    { key: 'role', required: true, aliases: ['role', 'purpose', 'use', 'used_for'] },
    { key: 'os', required: false, aliases: ['os', 'operating_system', 'system'] },
    { key: 'ip', required: false, aliases: ['ip', 'ip_address', 'address'] },
    { key: 'department_id', required: false, aliases: ['department_id', 'department_code', 'department', 'dept', 'ward'] },
    { key: 'zone', required: false, aliases: ['zone', 'network_zone'] },
  ],
  patients: [
    { key: 'ref', required: true, aliases: ['ref', 'patient_id', 'patient_number', 'patient_no', 'patient', 'mrn', 'hospital_number'] },
    { key: 'department_id', required: false, aliases: ['department_id', 'department_code', 'department', 'dept', 'ward'] },
    { key: 'flag', required: false, aliases: ['flag', 'special', 'protected'] },
  ],
};

export const TEMPLATES: Record<Kind, string[][]> = {
  departments: [
    ['department_code', 'department_name'],
    ['ED', 'Emergency department'],
    ['MAT', 'Maternity'],
  ],
  staff: [
    ['staff_id', 'full_name', 'role', 'department_code', 'status'],
    ['ade.okafor', 'Ade Okafor', 'nurse', 'ED', 'active'],
    ['f.bello', 'Fatima Bello', 'doctor', 'MAT', 'active'],
  ],
  assets: [
    ['name', 'type', 'role', 'operating_system', 'ip_address', 'department_code'],
    ['ED-PC-01', 'workstation', 'nurses station', 'Windows 11', '10.10.1.21', 'ED'],
    ['PUMP-07', 'medical device', 'infusion pump', '', '10.20.0.7', 'MAT'],
  ],
  patients: [
    ['patient_id', 'department_code', 'flag'],
    ['P100231', 'ED', ''],
    ['P100232', 'MAT', 'vip'],
  ],
};

const KIND_WORDS: Record<string, string> = {
  computer: 'workstation',
  pc: 'workstation',
  desktop: 'workstation',
  laptop: 'workstation',
  workstation: 'workstation',
  server: 'server',
  medical_device: 'medical_device',
  device: 'medical_device',
  medical_equipment: 'medical_device',
  network: 'network',
  router: 'network',
  switch: 'network',
  firewall: 'network',
};

export interface RowProblem {
  row: number;
  reason: string;
  detail?: string;
}

export type Parsed = {
  departments: Department[];
  staff: Staff[];
  assets: Asset[];
  patients: Patient[];
};

/** Matches the spreadsheet's headers to the fields, by any of their accepted names. */
export function matchHeaders(kind: Kind, headers: string[]): { index: Record<string, number>; missing: string[] } {
  const keys = headers.map(headerKey);
  const index: Record<string, number> = {};
  for (const f of FIELDS[kind]) {
    const at = keys.findIndex((k) => f.aliases.includes(k));
    if (at >= 0) index[f.key] = at;
  }
  const missing = FIELDS[kind].filter((f) => f.required && index[f.key] === undefined).map((f) => f.key);
  return { index, missing };
}

const CHECKS: Record<Kind, (r: Record<string, unknown>) => Checked<unknown>> = {
  departments: checkDepartment,
  staff: checkStaff,
  assets: checkAsset,
  patients: checkPatient,
};

/** Checks one row typed into a form, or read from a spreadsheet. */
export function checkRow(kind: Kind, values: Record<string, string>): Checked<unknown> {
  const v: Record<string, unknown> = { ...values };
  if (kind === 'assets' && typeof v.kind === 'string') {
    const word = v.kind.trim().toLowerCase().replace(/\s+/g, '_');
    v.kind = KIND_WORDS[word] ?? word;
  }
  return CHECKS[kind](v);
}

/** Reads every row of a spreadsheet. Returns the clean rows and every problem, by spreadsheet row number. */
export function readRows(kind: Kind, table: Table): { rows: unknown[]; problems: RowProblem[] } {
  const { index, missing } = matchHeaders(kind, table.headers);
  if (missing.length > 0) return { rows: [], problems: missing.map((m) => ({ row: 1, reason: 'missing_column', detail: m })) };
  const rows: unknown[] = [];
  const problems: RowProblem[] = [];
  const seen = new Map<string, number>();
  table.rows.forEach((r, i) => {
    const values: Record<string, string> = {};
    for (const [key, at] of Object.entries(index)) values[key] = r[at] ?? '';
    const checked = checkRow(kind, values);
    // Row 1 is the header, so the first data row is row 2, as the spreadsheet shows it.
    if (!checked.ok) {
      problems.push({ row: i + 2, reason: checked.reason });
      return;
    }
    const value = checked.value as { id?: string; ref?: string };
    const id = value.id ?? value.ref ?? '';
    if (seen.has(id)) {
      problems.push({ row: i + 2, reason: 'duplicate', detail: `${id}, row ${seen.get(id)}` });
      return;
    }
    seen.set(id, i + 2);
    rows.push(checked.value);
  });
  return { rows, problems };
}
