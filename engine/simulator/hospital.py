"""The simulated hospital: departments, staff, machines, medical devices and patients.

Everything here is built from engine/config/hospital.json and a seed, so the same
seed always gives the same hospital. No real person or patient is represented.
"""

from __future__ import annotations

import csv
import json
import random
import uuid
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "hospital.json"

FIRST_NAMES = [
    "Amara", "Daniel", "Grace", "Hassan", "Ines", "Jamal", "Keiko", "Liam", "Maya", "Noah",
    "Olivia", "Priya", "Quentin", "Rosa", "Samuel", "Tunde", "Uma", "Victor", "Wei", "Ximena",
    "Yusuf", "Zoe", "Adaeze", "Bruno", "Chloe", "Diego", "Elena", "Farid", "Gabriel", "Hannah",
]
LAST_NAMES = [
    "Adeyemi", "Baker", "Chen", "Diaz", "Eze", "Fischer", "Garcia", "Hughes", "Ibrahim", "Jones",
    "Khan", "Lopez", "Mensah", "Nguyen", "Okafor", "Patel", "Quinn", "Reyes", "Silva", "Taylor",
    "Usman", "Varga", "Walker", "Xu", "Young", "Zhang", "Bello", "Costa", "Dlamini", "Evans",
]

CLINICAL_ROLES = {"physician", "nurse", "pharmacist", "technician"}


@dataclass
class Staff:
    id: str
    display_name: str
    role: str
    department_id: str
    remote: bool = False
    floats: bool = False
    status: str = "active"
    shift: str = "day"
    home: str | None = None

    def on_shift(self, hour: int) -> bool:
        return (7 <= hour < 19) == (self.shift == "day")


@dataclass
class Asset:
    id: str
    kind: str
    role: str
    ip: str
    zone: str
    os: str | None = None
    department_id: str | None = None
    attributes: dict = field(default_factory=dict)


@dataclass
class Hospital:
    config: dict
    departments: list[dict]
    staff: list[Staff]
    assets: list[Asset]
    patients: list[str]
    patients_by_department: dict[str, list[str]]
    patient_flags: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.patient_department = {p: d for d, ps in self.patients_by_department.items() for p in ps}
        self.all_staff = self.staff
        # People who have left keep a directory entry but never act.
        self.staff = [s for s in self.all_staff if s.status == "active"]
        self.asset_by_id = {a.id: a for a in self.assets}
        self.workstations_by_department: dict[str, list[Asset]] = {}
        for a in self.assets:
            if a.kind == "workstation":
                self.workstations_by_department.setdefault(a.department_id or "", []).append(a)
        self.workstations = [a for a in self.assets if a.kind == "workstation"]
        self.servers = [a for a in self.assets if a.kind == "server"]
        self.devices = [a for a in self.assets if a.kind == "medical_device"]
        self.clinicians = [s for s in self.staff if s.role in CLINICAL_ROLES]
        self.admins = [s for s in self.staff if s.role == "it_admin"]
        self.remote_staff = [s for s in self.staff if s.remote]

    def server(self, asset_id: str) -> Asset:
        return self.asset_by_id[asset_id]

    def inventory(self) -> dict:
        """The payload the inventory API expects."""
        return {
            "departments": [{"id": d["id"], "name": d["name"], "zone": d["zone"]} for d in self.departments],
            "staff": [
                {"id": s.id, "display_name": s.display_name, "role": s.role, "department_id": s.department_id, "status": s.status}
                for s in self.all_staff
            ],
            "patients": [
                {"ref": p, "department_id": self.patient_department.get(p), "flag": self.patient_flags.get(p)}
                for p in self.patients
            ],
            "assets": [
                {
                    "id": a.id, "kind": a.kind, "role": a.role, "os": a.os, "ip": a.ip,
                    "department_id": a.department_id, "zone": a.zone, "attributes": a.attributes,
                }
                for a in self.assets
            ],
        }

    def summary(self) -> dict:
        kinds: dict[str, int] = {}
        for a in self.assets:
            kinds[a.kind] = kinds.get(a.kind, 0) + 1
        return {
            "hospital": self.config["hospital_name"],
            "departments": len(self.departments),
            "staff": len(self.staff),
            "assets": kinds,
            "patients": len(self.patients),
        }


def load_config(path: str | Path | None = None) -> dict:
    with open(path or DEFAULT_CONFIG, encoding="utf-8") as fh:
        return json.load(fh)


def load_synthea_patients(path: str | Path) -> list[str]:
    """Reads patient identifiers from a Synthea patients.csv export. Only the Id column is used."""
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or "Id" not in reader.fieldnames:
            raise ValueError(f"{path} is not a Synthea patients.csv file: no Id column")
        ids = [row["Id"].strip() for row in reader if row.get("Id", "").strip()]
    if not ids:
        raise ValueError(f"{path} holds no patients")
    return ids


def build_hospital(config: dict, seed: int | None = None, synthea_patients: str | Path | None = None) -> Hospital:
    rng = random.Random(config["seed"] if seed is None else seed)
    departments = config["departments"]
    staff: list[Staff] = []
    assets: list[Asset] = []
    used_ids: set[str] = set()
    remote_share = float(config.get("remote_staff_share", 0))

    for dept in departments:
        for n in range(1, int(dept["workstations"]) + 1):
            assets.append(Asset(
                id=f"WS{dept['id']}{n:03d}", kind="workstation", role="clinical_workstation" if dept["zone"] == "clinical" else "office_workstation",
                os="Windows 11", ip=f"{dept['subnet']}.{10 + n}", zone=dept["zone"], department_id=dept["id"],
            ))
        for role, count in dept["staff"].items():
            for _ in range(int(count)):
                first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
                base = f"{first[0]}{last}".lower()
                user_id, n = base, 1
                while user_id in used_ids:
                    n += 1
                    user_id = f"{base}{n}"
                used_ids.add(user_id)
                staff.append(Staff(
                    id=user_id, display_name=f"{first} {last}", role=role, department_id=dept["id"],
                    remote=role in {"physician", "billing", "it_admin"} and rng.random() < remote_share * 2.2,
                    shift="night" if role in CLINICAL_ROLES and rng.random() < float(config.get("night_shift_share", 0.3)) else "day",
                ))

    for srv in config["servers"]:
        assets.append(Asset(id=srv["id"], kind="server", role=srv["role"], os=srv["os"], ip=srv["ip"], zone="server", department_id="IT"))
    for net in config["network"]:
        assets.append(Asset(id=net["id"], kind="network", role=net["role"], ip=net["ip"], zone="network", department_id="IT"))
    for group in config["devices"]:
        for n in range(1, int(group["count"]) + 1):
            assets.append(Asset(
                id=f"{group['prefix']}{n:04d}", kind="medical_device", role=group["role"], os="Embedded",
                ip=f"{group['subnet']}.{10 + n}", zone="device",
                department_id=group["departments"][(n - 1) % len(group["departments"])],
                attributes={"gateway": group["gateway"], "port": group["port"], "protocol": group["protocol"]},
            ))

    if synthea_patients:
        patients = load_synthea_patients(synthea_patients)
    else:
        patients = [str(uuid.UUID(int=rng.getrandbits(128), version=4)) for _ in range(int(config["patients"]))]

    clinical = [d["id"] for d in departments if d["zone"] == "clinical"]
    by_department: dict[str, list[str]] = {d: [] for d in clinical}
    for p in patients:
        by_department[rng.choice(clinical)].append(p)
    for d in clinical:
        if not by_department[d]:
            by_department[d].append(rng.choice(patients))

    desks: dict[str, list[str]] = {}
    for a in assets:
        if a.kind == "workstation":
            desks.setdefault(a.department_id or "", []).append(a.id)
    for person in staff:
        person.home = rng.choice(desks[person.department_id])
    nurses = [s for s in staff if s.role == "nurse"]
    for person in rng.sample(nurses, min(int(config.get("float_nurses", 0)), len(nurses))):
        person.floats = True
    leavers = [s for s in staff if not s.floats and s.role != "it_admin"]
    for person in rng.sample(leavers, min(int(config.get("terminated_staff", 0)), len(leavers))):
        person.status = "terminated"
    flags: dict[str, str] = {}
    unflagged = list(patients)
    rng.shuffle(unflagged)
    for flag, count in config.get("flagged_patients", {}).items():
        for _ in range(min(int(count), len(unflagged))):
            flags[unflagged.pop()] = flag

    return Hospital(config=config, departments=departments, staff=staff, assets=assets,
                    patients=patients, patients_by_department=by_department, patient_flags=flags)
