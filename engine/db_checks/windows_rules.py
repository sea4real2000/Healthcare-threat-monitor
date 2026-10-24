"""Checks that the rules in a migrated database catch ransomware steps as Windows itself records them.

The Windows collector sends events from the Security and System logs. After normalization these carry the
command line exactly as it was typed, often with a full path and .exe. Run on a database with every migration
applied, with the engine folder as the working folder:
    DATABASE_URL=... python -m db_checks.windows_rules
Reads only. Exits non zero on the first failure.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from detection.pipeline import connect
from detection.rules import RuleEngine

T = datetime(2026, 10, 22, 10, 0, tzinfo=timezone.utc)


def ev(**over) -> dict:
    base = {"id": 1, "source": "windows", "occurred_at": T, "category": "process", "action": "process_start", "outcome": "success",
            "actor_user": "abaker", "host": "WSED001", "src_ip": None, "dst_ip": None, "dst_port": None, "attributes": {},
            "actor": {"role": "nurse"}, "asset": {"kind": "workstation", "role": "clinical_workstation"}}
    base.update(over)
    return base


# Each case: the event as the Windows normalizer produces it, and the rule that must fire.
CASES = [
    ("vssadmin run by its full path", "ransom_shadow_copy_delete",
     ev(attributes={"process_name": "vssadmin.exe", "parent_name": "cmd.exe", "command_line": '"C:\\Windows\\system32\\vssadmin.exe" delete shadows /all /quiet'})),
    ("vssadmin.exe typed with its extension", "ransom_shadow_copy_delete",
     ev(attributes={"process_name": "vssadmin.exe", "command_line": "vssadmin.exe Delete Shadows /All /Quiet"})),
    ("wmic deleting shadow copies", "ransom_shadow_copy_delete",
     ev(attributes={"process_name": "wmic.exe", "command_line": "wmic.exe shadowcopy delete /nointeractive"})),
    ("recovery switched off with bcdedit", "ransom_shadow_copy_delete",
     ev(attributes={"process_name": "bcdedit.exe", "command_line": "bcdedit /set {default} recoveryenabled No"})),
    ("Word starting PowerShell", "office_spawns_script",
     ev(attributes={"process_name": "powershell.exe", "parent_name": "winword.exe", "command_line": "powershell -enc SQBFAFgA"})),
    ("credential dumping through comsvcs", "credential_dump",
     ev(attributes={"process_name": "rundll32.exe", "command_line": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"})),
    ("the security log cleared", "windows_security_log_cleared",
     ev(category="defense_evasion", action="audit_log_cleared", attributes={"event_id": 1102})),
    ("the shadow copy service stopped", "ransom_backup_service_stopped",
     ev(category="service", action="service_state_changed", actor_user=None,
        attributes={"event_id": 7036, "service_name": "Volume Shadow Copy", "service_state": "stopped"})),
]


def main() -> int:
    conn = connect()
    with conn.cursor() as cur:
        cur.execute("select * from rules where enabled order by id")
        rows = cur.fetchall()
    conn.rollback()
    engine = RuleEngine()
    engine.load_rules(rows)
    if engine.errors:
        print(f"FAIL: rules that do not load: {engine.errors}")
        return 1
    for i, (what, rule_id, event) in enumerate(CASES):
        event["id"] = i + 1
        fired = {d.detector_id for d in engine.process(dict(event))}
        if rule_id not in fired:
            print(f"FAIL: {what} did not fire {rule_id} (fired: {sorted(fired) or 'nothing'})")
            return 1
        print(f"PASS: {what} fires {rule_id}")
    # Ordinary activity must stay quiet.
    quiet = ev(attributes={"process_name": "vssadmin.exe", "command_line": "vssadmin list shadows"})
    fired = {d.detector_id for d in engine.process(quiet)}
    if "ransom_shadow_copy_delete" in fired:
        print("FAIL: listing shadow copies was reported as deleting them")
        return 1
    print("PASS: listing shadow copies stays quiet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
