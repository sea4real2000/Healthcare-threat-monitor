import { NextResponse } from 'next/server';
import { authenticateCollector, deny, readLimitedBody } from '@/lib/auth';
import { checkAsset, checkDepartment, checkPatient, checkStaff, MAX_ROWS, saveInventory, type Checked, type Inventory } from '@/lib/inventory';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';


type Row = Record<string, unknown>;

function rows(v: unknown): Row[] | null {
  if (v == null) return [];
  if (!Array.isArray(v) || v.length > MAX_ROWS) return null;
  return v.every((r) => r && typeof r === 'object' && !Array.isArray(r)) ? (v as Row[]) : null;
}

/**
 * Registers or updates the hospital inventory: departments, staff and assets.
 * An update never touches an asset's status or last seen time, so an isolated
 * machine stays isolated when the inventory is sent again.
 */
export async function POST(req: Request) {
  try {
    const read = await readLimitedBody(req);
    if (!read.ok) return read.response;
    const auth = await authenticateCollector(req, read.body);
    if (!auth.ok) return auth.response;

    let parsed: Row;
    try {
      parsed = JSON.parse(read.body);
    } catch {
      return deny(400, 'body_not_json');
    }
    const departments = rows(parsed?.departments);
    const staff = rows(parsed?.staff);
    const assets = rows(parsed?.assets);
    const patients = rows(parsed?.patients);
    if (!departments || !staff || !assets || !patients) return deny(400, 'bad_inventory_shape');

    const reasons: Record<string, string> = {
      department_id: 'bad_department', department_name: 'bad_department',
      staff_id: 'bad_staff', staff_name: 'bad_staff', staff_role: 'bad_staff', staff_status: 'bad_staff',
      asset_id: 'bad_asset', asset_kind: 'bad_asset', asset_role: 'bad_asset', asset_ip: 'bad_asset_ip',
      patient_ref: 'bad_patient', patient_flag: 'bad_patient',
    };
    const inv: Inventory = { departments: [], staff: [], assets: [], patients: [] };
    const parts: [Row[], (r: Row) => Checked<unknown>, unknown[]][] = [
      [departments, checkDepartment, inv.departments],
      [staff, checkStaff, inv.staff],
      [assets, checkAsset, inv.assets],
      [patients, checkPatient, inv.patients],
    ];
    for (const [list, check, out] of parts) {
      for (const row of list) {
        const r = check(row);
        if (!r.ok) return deny(400, reasons[r.reason] ?? 'bad_inventory_shape');
        out.push(r.value);
      }
    }
    await saveInventory(inv, auth.collectorId);
    const cleanDepartments = inv.departments, cleanStaff = inv.staff, cleanAssets = inv.assets, cleanPatients = inv.patients;

    return NextResponse.json(
      {
        ok: true,
        departments: cleanDepartments.length,
        staff: cleanStaff.length,
        assets: cleanAssets.length,
        patients: cleanPatients.length,
      },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } catch (err) {
    const code = (err as { code?: string })?.code;
    if (code === '23503') return deny(400, 'unknown_department_reference');
    console.error('[inventory] failed', err);
    return deny(500, 'internal_error');
  }
}
