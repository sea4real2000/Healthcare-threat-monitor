"""Scripted attack scenarios.

A scenario writes the log records an attack would leave behind. Nothing here is an
attack: no malware, no exploit and no working command is involved. Each record
carries a stage name so results can be scored against ground truth afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .generators import Generators, iso

# (seconds after the start, source, payload, stage, host the record comes from, stage that must have happened first)
# The last part models cause and effect: a server cannot be attacked through a foothold that was isolated in time.
Step = tuple[float, str, dict, str, str | None, str | None]


@dataclass
class Scenario:
    name: str
    hosts: list[str]
    users: list[str]
    steps: list[Step] = field(default_factory=list)

    def target(self) -> dict:
        return {"hosts": self.hosts, "users": self.users}


SCENARIOS = ["ransomware", "record_snooping", "device_compromise"]
C2_DOMAIN = "updatesyncservice.example"
DEVICE_C2_DOMAIN = "devicecloudsync.example"


class Builder:
    """Collects steps and stamps each record with its time."""

    def __init__(self, gen: Generators, start: datetime, scale: float) -> None:
        self.gen, self.start, self.scale = gen, start, scale
        self.steps: list[Step] = []

    def at(self, offset: float) -> datetime:
        return self.start + timedelta(seconds=offset * self.scale)

    def add(self, offset: float, stage: str, origin: str | None, record: tuple, requires: str | None = None) -> None:
        _, source, payload = record
        self.steps.append((offset * self.scale, source, payload, stage, origin, requires))


def ransomware(gen: Generators, start: datetime, scale: float = 1.0) -> Scenario:
    """Phishing, script execution, credential theft, lateral movement, then encryption of a clinical workstation."""
    h, rng = gen.h, gen.rng
    victim = rng.choice([s for s in h.clinicians if not s.floats])
    ws = gen.workstation_for(victim)
    admin = rng.choice(h.admins)
    files = h.server("SRVFILE01")
    b = Builder(gen, start, scale)
    c2_ip = gen.external_ip()

    t = b.at(0)
    b.add(0, "delivery", None, (t, "email", {
        "message_id": gen.next_id("mail"), "received": iso(t), "sender": "accounts@invoiceportal.example",
        "recipient": f"{victim.id}@{gen.mail_domain}", "subject_hash": f"{rng.getrandbits(64):016x}",
        "verdict": "clean", "action": "delivered", "urls": 1, "spf": "pass", "dkim": "fail",
        "attachments": [{"name": "Invoice_8841.docm", "ext": "docm", "size": 184320}],
    }))

    word = {"name": "winword.exe", "pid": rng.randint(1000, 30000), "parent": "outlook.exe"}
    shell = {"name": "powershell.exe", "pid": rng.randint(1000, 30000), "parent": "winword.exe"}
    b.add(95, "execution", ws.id, gen.edr(b.at(95), ws.id, victim.id, "process_start",
                                          process={**word, "cmdline": '"WINWORD.EXE" /n "Invoice_8841.docm"'}))
    b.add(100, "execution", ws.id, gen.edr(b.at(100), ws.id, victim.id, "process_start", process={
        **shell, "cmdline": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand [simulated]"}))

    for k in range(rng.randint(5, 8)):
        off = 130 + k * 60 + rng.uniform(0, 8)
        b.add(off, "command_and_control", ws.id, gen.dns(b.at(off), ws.ip, f"cdn.{C2_DOMAIN}", answer=c2_ip))
        b.add(off + 0.2, "command_and_control", ws.id, gen.firewall(b.at(off + 0.2), ws.ip, c2_ip, 443, "tcp", ws.zone, "internet",
                                                                    rng.randint(900, 4000), rng.randint(2000, 60000)))

    b.add(300, "credential_access", ws.id, gen.edr(b.at(300), ws.id, victim.id, "process_start", process={
        "name": "rundll32.exe", "pid": rng.randint(1000, 30000), "parent": "powershell.exe",
        "cmdline": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump [simulated]"}))
    b.add(302, "credential_access", ws.id, gen.edr(b.at(302), ws.id, victim.id, "file_write", process={"name": "rundll32.exe"},
                                                   file={"path": "C:\\Windows\\Temp\\d.dmp", "ext": "dmp"}))

    for k in range(10):
        off = 420 + k * 6
        b.add(off, "lateral_movement", ws.id, gen.windows_event(b.at(off), "SRVDC01", 4625, {
            "TargetUserName": admin.id, "LogonType": 3, "IpAddress": ws.ip, "FailureReason": "Unknown user name or bad password"}))
    b.add(505, "lateral_movement", ws.id, gen.windows_event(b.at(505), ws.id, 4672, {
        "TargetUserName": victim.id, "PrivilegeList": "SeDebugPrivilege SeTcbPrivilege"}))
    others = rng.sample([w for w in h.workstations if w.id != ws.id], 5)
    for k, target in enumerate([h.server("SRVDC01"), files, h.server("SRVPHARM01"), *others]):
        off = 510 + k * 9
        b.add(off, "lateral_movement", ws.id, gen.windows_event(b.at(off), target.id, 4624, {
            "TargetUserName": admin.id, "LogonType": 3, "IpAddress": ws.ip}))
        b.add(off + 0.3, "lateral_movement", ws.id, gen.firewall(b.at(off + 0.3), ws.ip, target.ip, 445, "tcp", ws.zone, target.zone,
                                                                 rng.randint(2000, 9000), rng.randint(2000, 9000)))

    for host in (ws, files):
        user = victim.id if host is ws else admin.id
        # The file server is reached with the stolen administrator account, so it needs the lateral movement to have happened.
        needs = None if host is ws else "lateral_movement"
        cmd = {"name": "cmd.exe", "pid": rng.randint(1000, 30000), "parent": "powershell.exe"}
        b.add(900, "inhibit_recovery", host.id, gen.edr(b.at(900), host.id, user, "process_start", process={
            "name": "vssadmin.exe", "pid": rng.randint(1000, 30000), "parent": "cmd.exe", "cmdline": "vssadmin delete shadows /all /quiet"}), requires=needs)
        b.add(904, "inhibit_recovery", host.id, gen.edr(b.at(904), host.id, user, "process_start", process={
            **cmd, "cmdline": "cmd.exe /c wbadmin delete catalog -quiet"}), requires=needs)
        b.add(906, "inhibit_recovery", host.id, gen.windows_event(b.at(906), host.id, 7036, {
            "ServiceName": "Volume Shadow Copy", "State": "stopped"}, channel="System"), requires=needs)

        enc = {"name": "svchosts.exe", "pid": rng.randint(1000, 30000), "parent": "powershell.exe"}
        root = f"C:\\Users\\{victim.id}\\Documents" if host is ws else "D:\\Shares\\Clinical"
        off = 960.0
        n = 0
        while off < 1200:
            off += rng.uniform(0.5, 1.0)
            n += 1
            ext = rng.choice(["docx", "xlsx", "pdf", "jpg", "dcm"])
            path = f"{root}\\folder{n % 12}\\file{n}.{ext}"
            b.add(off, "impact", host.id, gen.edr(b.at(off), host.id, user, "file_rename", process=enc,
                                                  file={"path": path, "ext": ext, "new_path": path + ".locked"}), requires=needs)
            if n % 40 == 1:
                b.add(off + 0.1, "impact", host.id, gen.edr(b.at(off + 0.1), host.id, user, "file_write", process=enc, file={
                    "path": f"{root}\\folder{n % 12}\\HOW_TO_RESTORE_FILES.txt", "ext": "txt"}), requires=needs)

    return Scenario("ransomware", [ws.id, files.id], [victim.id, admin.id], sorted(b.steps, key=lambda s: s[0]))


def record_snooping(gen: Generators, start: datetime, scale: float = 1.0) -> Scenario:
    """A member of staff opens many records of patients they have no care relationship with."""
    h, rng = gen.h, gen.rng
    person = rng.choice([s for s in h.clinicians if s.role in ("nurse", "technician") and not s.floats])
    ws = gen.workstation_for(person)
    ehr = h.server("SRVEHRAPP01")
    outside = [p for p in h.patients if h.patient_department.get(p) != person.department_id]
    flagged = [p for p in h.patient_flags if h.patient_department.get(p) != person.department_id]
    chosen = rng.sample(outside, rng.randint(45, 75))
    if flagged:
        chosen[rng.randrange(len(chosen))] = rng.choice(flagged)
    b = Builder(gen, start, scale)
    span = 2400.0
    for k, patient in enumerate(chosen):
        off = k * span / len(chosen) + rng.uniform(0, 12)
        t = b.at(off)
        b.add(off, "collection", ws.id, gen.firewall(t, ws.ip, ehr.ip, 443, "tcp", ws.zone, "server",
                                                     rng.randint(1200, 5000), rng.randint(8000, 90000)))
        for j, resource in enumerate(["Patient"] + (["DocumentReference"] if rng.random() < 0.5 else [])):
            when = t + timedelta(seconds=(0.2 + j * 2.5) * scale)
            entities = [{"what": {"reference": f"Patient/{patient}"}}]
            if resource != "Patient":
                entities.append({"what": {"reference": f"{resource}/{rng.getrandbits(48):012x}"}})
            b.steps.append(((off + 0.2 + j * 2.5) * scale, "ehr", {
                "resourceType": "AuditEvent", "id": gen.next_id("ehr"),
                "type": {"system": "http://terminology.hl7.org/CodeSystem/audit-event-type", "code": "rest"},
                "subtype": [{"system": "http://hl7.org/fhir/restful-interaction", "code": "read"}],
                "action": "R", "recorded": iso(when), "outcome": "0",
                "purposeOfEvent": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/v3-ActReason", "code": "TREAT"}]}],
                "agent": [{"who": {"identifier": {"value": person.id}}, "role": [{"coding": [{"code": person.role}]}],
                           "requestor": True, "network": {"address": ws.ip, "type": "2"}}],
                "source": {"observer": {"display": ehr.id}}, "entity": entities,
            }, "collection", ws.id, None))
    return Scenario("record_snooping", [ws.id], [person.id], sorted(b.steps, key=lambda s: s[0]))


def device_compromise(gen: Generators, start: datetime, scale: float = 1.0) -> Scenario:
    """An infusion pump is taken over: it probes its neighbours, calls out, then floods its gateway.

    When the CICIoMT2024 dataset has been loaded, the probing and flooding traffic takes its
    packet rates, sizes and flag counts from rows captured in that dataset.
    """
    h, rng = gen.h, gen.rng
    captured = getattr(gen, "device_dataset", None) or {}
    recon_rows = captured.get("recon", [])
    flood_rows = captured.get("mqtt", []) + captured.get("ddos", []) + captured.get("dos", [])
    device = rng.choice([d for d in h.devices if d.role == "infusion_pump"])
    gateway = h.server(device.attributes["gateway"])
    b = Builder(gen, start, scale)

    def flow(off: float, stage: str, dst_ip: str, port: int, proto: str, packets: int, size: int, duration: float, syn: int) -> None:
        t = b.at(off)
        b.add(off, stage, device.id, (t, "medical_device", {
            "flow_id": gen.next_id("dev"), "start": round(t.timestamp(), 3), "device": device.id, "device_type": device.role,
            "src_ip": device.ip, "dst_ip": dst_ip, "dst_port": port, "protocol": proto, "packets": packets, "bytes": packets * size,
            "duration_s": duration, "rate_pps": round(packets / duration, 2), "flags": {"syn": syn, "rst": rng.randint(0, 2)},
        }))

    neighbours = [a for a in h.devices + h.servers if a.id not in (device.id, gateway.id)]
    for k, peer in enumerate(rng.sample(neighbours, min(36, len(neighbours)))):
        offset = k * 3.2 + rng.uniform(0, 1)
        port = rng.choice([22, 23, 80, 443, 502, 1883, 8080, 8883])
        if recon_rows:
            row = rng.choice(recon_rows)
            flow(offset, "discovery", peer.ip, port, row.protocol, row.packets, max(row.bytes // row.packets, 40),
                 round(max(row.packets / row.rate_pps, 0.05), 3) if row.rate_pps > 0 else 0.4, row.syn)
        else:
            flow(offset, "discovery", peer.ip, port, "tcp", rng.randint(2, 6), 60, 0.4, 2)

    c2_ip = gen.external_ip()
    for k in range(6):
        off = 150 + k * 110 + rng.uniform(0, 6)
        b.add(off, "command_and_control", device.id, gen.dns(b.at(off), device.ip, f"telemetry.{DEVICE_C2_DOMAIN}", answer=c2_ip))
        b.add(off + 0.3, "command_and_control", device.id, gen.firewall(b.at(off + 0.3), device.ip, c2_ip, 8883, "tcp", "device", "internet",
                                                                         rng.randint(400, 2000), rng.randint(400, 6000),
                                                                         action="allow" if k % 2 == 0 else "deny"))
        flow(off + 0.4, "command_and_control", c2_ip, 8883, "mqtt", rng.randint(8, 30), 180, 1.5, 1)

    off = 200.0
    while off < 800:
        if flood_rows:
            row = rng.choice(flood_rows)
            duration = round(rng.uniform(3, 6), 2)
            flow(off, "impact", gateway.ip, device.attributes["port"], row.protocol if row.protocol != "tcp" else "mqtt",
                 max(row.packets, round(row.rate_pps * duration)), max(row.bytes // row.packets, 40), duration, max(row.syn, 1))
        else:
            packets = rng.randint(30000, 90000)
            flow(off, "impact", gateway.ip, device.attributes["port"], "mqtt", packets, 80, round(rng.uniform(3, 6), 2), rng.randint(400, 3000))
        off += rng.uniform(8, 14)

    return Scenario("device_compromise", [device.id], [], sorted(b.steps, key=lambda s: s[0]))


BUILDERS = {"ransomware": ransomware, "record_snooping": record_snooping, "device_compromise": device_compromise}


def build(name: str, gen: Generators, start: datetime, scale: float = 1.0) -> Scenario:
    if name not in BUILDERS:
        raise ValueError(f"unknown scenario: {name}")
    return BUILDERS[name](gen, start, scale)


def event_key(source: str, payload: dict) -> str:
    """The identifier the ingestion API will store for a record, so ground truth can point at it."""
    if source == "windows":
        return f"{payload['Computer']}:{payload['RecordId']}"
    field_name = {"ehr": "id", "edr": "event_id", "linux": "id", "firewall": "id", "vpn": "id", "dns": "id",
                  "email": "message_id", "medical_device": "flow_id", "cloud": "eventID"}[source]
    return str(payload[field_name])
