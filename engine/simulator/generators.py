"""Activity generators.

Each activity is something that happens in a hospital, such as a clinician opening
a chart. One activity writes the log records that every affected system would
write, each in that system's own format. Batch 1 holds normal activity only,
including the ordinary noise a real network has, such as mistyped passwords.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

from .hospital import Asset, Hospital, Staff

Record = tuple[datetime, str, dict]

BENIGN_DOMAINS = [
    "clinicalreference.example", "drugdatabase.example", "medsupply.example", "labportal.example",
    "insuranceverify.example", "continuingeducation.example", "news.example", "weather.example",
    "videomeeting.example", "softwareupdate.example", "cloudstorage.example", "search.example",
]
SENDER_DOMAINS = ["medsupply.example", "labportal.example", "insuranceverify.example", "newsletter.example", "partnerclinic.example"]
PROCESSES = [
    ("ehrclient.exe", "C:\\Program Files\\EHR\\ehrclient.exe"), ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"), ("winword.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
    ("excel.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"), ("teams.exe", "C:\\Users\\Public\\Teams\\teams.exe"),
    ("pacsviewer.exe", "C:\\Program Files\\PACS\\pacsviewer.exe"), ("acrord32.exe", "C:\\Program Files\\Adobe\\Reader\\AcroRd32.exe"),
]
DOC_EXTENSIONS = ["docx", "xlsx", "pdf", "txt", "tmp"]
FHIR_RESOURCES = ["Observation", "MedicationRequest", "DocumentReference", "DiagnosticReport", "Condition", "AllergyIntolerance"]
SERVICES = ["Windows Update", "Print Spooler", "Background Intelligent Transfer Service", "Windows Time"]
COUNTRIES_OTHER = ["CA", "GB", "MX", "DE"]
NAT_ADDRESS = "203.0.113.10"


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


class Generators:
    """Holds the hospital, the random source and the counters that make each record id unique."""

    def __init__(self, hospital: Hospital, rng: random.Random, run_id: str) -> None:
        self.h = hospital
        self.rng = rng
        self.run_id = run_id
        self.counter = 0
        self.noise = hospital.config["noise"]
        self.domain = hospital.config["internal_domain"]
        self.mail_domain = hospital.config["mail_domain"]
        self.pending: list[Record] = []
        # Assets the response connector has isolated. An isolated machine emits nothing.
        self.isolated: set[str] = set()
        self.activities = {
            "software_deployment": self.software_deployment,
            "archive_job": self.archive_job,
            "account_lockout": self.account_lockout,
            "device_firmware_check": self.device_firmware_check,
            "chart_access": self.chart_access,
            "logon": self.logon,
            "endpoint_activity": self.endpoint_activity,
            "web_browsing": self.web_browsing,
            "inbound_email": self.inbound_email,
            "vpn_session": self.vpn_session,
            "linux_server": self.linux_server,
            "device_telemetry": self.device_telemetry,
            "cloud_activity": self.cloud_activity,
            "service_change": self.service_change,
        }

    # Helpers

    def next_id(self, prefix: str) -> str:
        self.counter += 1
        return f"{self.run_id}_{prefix}{self.counter:09d}"

    def chance(self, key: str) -> bool:
        return self.rng.random() < float(self.noise[key])

    def workstation_for(self, person: Staff) -> Asset:
        """People mostly work at their own desk and sometimes borrow another in the department."""
        if person.home and self.rng.random() < 0.85:
            return self.h.asset_by_id[person.home]
        return self.rng.choice(self.h.workstations_by_department[person.department_id])

    def on_duty(self, pool: list[Staff], t: datetime) -> Staff:
        """Picks someone from the pool, nearly always a person whose shift covers this hour."""
        if self.rng.random() < 0.96:
            working = [s for s in pool if s.on_shift(t.hour)]
            if working:
                return self.rng.choice(working)
        return self.rng.choice(pool)

    def online(self, records: list[Record], *assets: Asset) -> list[Record]:
        """Drops an activity when any machine it starts from has been isolated."""
        return [] if any(a.id in self.isolated for a in assets) else records

    def browse_domain(self) -> str:
        """Mostly a short list of common sites, with a long tail of rarely visited ones."""
        if self.chance("rare_domain_share"):
            return f"site{self.rng.randrange(int(self.noise['rare_domain_pool'])):04d}.example"
        return self.rng.choice(BENIGN_DOMAINS)

    def external_ip(self) -> str:
        return f"198.51.100.{self.rng.randint(2, 250)}"

    def firewall(self, t: datetime, src: str, dst: str, port: int, proto: str, src_zone: str, dst_zone: str,
                 sent: int, rcvd: int, action: str = "allow") -> Record:
        return (t, "firewall", {
            "id": self.next_id("fw"), "ts": int(t.timestamp() * 1000), "fw": "FWCORE01", "action": action, "proto": proto,
            "src": src, "spt": self.rng.randint(49152, 65535), "dst": dst, "dpt": port,
            "sent": sent if action == "allow" else 0, "rcvd": rcvd if action == "allow" else 0,
            "src_zone": src_zone, "dst_zone": dst_zone,
            "rule": f"{action}_{src_zone}_to_{dst_zone}",
        })

    def dns(self, t: datetime, client: str, name: str, rcode: str = "NOERROR", answer: str | None = None) -> Record:
        return (t, "dns", {
            "id": self.next_id("dns"), "ts": iso(t), "client_ip": client, "qname": name + ".", "qtype": "A",
            "rcode": rcode, "resolver": "SRVDNS01", "answer": answer if rcode == "NOERROR" else None,
        })

    # Activities

    def chart_access(self, t: datetime) -> list[Record]:
        """A clinician opens a patient chart: EHR audit events, a firewall flow and sometimes a name lookup."""
        person = self.on_duty(self.h.clinicians, t)
        ws = self.workstation_for(person)
        if self.chance("float_cross_department_chart_share" if person.floats else "cross_department_chart_share"):
            patient = self.rng.choice(self.h.patients)
        else:
            patient = self.rng.choice(self.h.patients_by_department[person.department_id])
        ehr = self.h.server("SRVEHRAPP01")
        encounter = hashlib.sha1(f"{patient}{t.date()}".encode()).hexdigest()[:16]
        out: list[Record] = []
        if self.rng.random() < 0.2:
            out.append(self.dns(t - timedelta(milliseconds=120), ws.ip, f"ehr.{self.domain}", answer=ehr.ip))
        out.append(self.firewall(t - timedelta(milliseconds=40), ws.ip, ehr.ip, 443, "tcp", ws.zone, "server",
                                 self.rng.randint(1200, 9000), self.rng.randint(8000, 240000)))
        steps = [("Patient", "R", "read")]
        for _ in range(self.rng.randint(0, 3)):
            if self.chance("chart_update_share"):
                steps.append((self.rng.choice(FHIR_RESOURCES[:3]), "U", "update"))
            else:
                steps.append((self.rng.choice(FHIR_RESOURCES), "R", "read"))
        for i, (resource, action, interaction) in enumerate(steps):
            when = t + timedelta(seconds=i * self.rng.uniform(0.4, 6.0))
            entities = [{"what": {"reference": f"Patient/{patient}"}}]
            if resource != "Patient":
                entities.append({"what": {"reference": f"{resource}/{self.rng.getrandbits(48):012x}"}})
            entities.append({"what": {"reference": f"Encounter/{encounter}"}})
            out.append((when, "ehr", {
                "resourceType": "AuditEvent", "id": self.next_id("ehr"),
                "type": {"system": "http://terminology.hl7.org/CodeSystem/audit-event-type", "code": "rest"},
                "subtype": [{"system": "http://hl7.org/fhir/restful-interaction", "code": interaction}],
                "action": action, "recorded": iso(when), "outcome": "0",
                "purposeOfEvent": [{"coding": [{"system": "http://terminology.hl7.org/CodeSystem/v3-ActReason", "code": "TREAT"}]}],
                "agent": [{
                    "who": {"identifier": {"value": person.id}}, "role": [{"coding": [{"code": person.role}]}],
                    "requestor": True, "network": {"address": ws.ip, "type": "2"},
                }],
                "source": {"observer": {"display": ehr.id}},
                "entity": entities,
            }))
        return self.online(out, ws)

    def windows_event(self, t: datetime, computer: str, event_id: int, data: dict, channel: str = "Security") -> Record:
        return (t, "windows", {
            "RecordId": self.next_id("win"), "TimeCreated": iso(t), "Computer": computer,
            "EventID": event_id, "Channel": channel, "Data": data,
        })

    def logon(self, t: datetime) -> list[Record]:
        """A member of staff signs in at a workstation, sometimes after mistyping a password."""
        person = self.on_duty(self.h.staff, t)
        ws = self.workstation_for(person)
        out: list[Record] = []
        when = t
        if self.chance("failed_logon_share"):
            for _ in range(self.rng.randint(1, 2)):
                out.append(self.windows_event(when, ws.id, 4625, {
                    "TargetUserName": person.id, "LogonType": 2, "IpAddress": ws.ip, "FailureReason": "Unknown user name or bad password",
                }))
                when += timedelta(seconds=self.rng.uniform(3, 12))
        out.append(self.windows_event(when, ws.id, 4624, {"TargetUserName": person.id, "LogonType": self.rng.choice([2, 2, 7]), "IpAddress": ws.ip}))
        out.append(self.windows_event(when + timedelta(milliseconds=180), "SRVDC01", 4624, {"TargetUserName": person.id, "LogonType": 3, "IpAddress": ws.ip}))
        if person.role == "it_admin":
            out.append(self.windows_event(when + timedelta(milliseconds=220), ws.id, 4672, {
                "TargetUserName": person.id, "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege",
            }))
        if self.rng.random() < 0.3:
            out.append(self.windows_event(when + timedelta(seconds=self.rng.uniform(20, 55)), ws.id, 4634, {"TargetUserName": person.id, "LogonType": 2}))
        return self.online(out, ws)

    def endpoint_activity(self, t: datetime) -> list[Record]:
        """Ordinary programs starting and saving files on a workstation."""
        person = self.on_duty(self.h.staff, t)
        ws = self.workstation_for(person)
        name, path = self.rng.choice(PROCESSES)
        pid = self.rng.randint(1000, 30000)
        base = {"hostname": ws.id, "user": person.id, "sensor_version": "7.4.1"}
        out: list[Record] = [(t, "edr", {
            **base, "event_id": self.next_id("edr"), "timestamp": iso(t), "event_type": "process_start",
            "process": {"name": name, "pid": pid, "parent": "explorer.exe", "cmdline": f'"{path}"'},
        })]
        if self.rng.random() < 0.35:
            ext = self.rng.choice(DOC_EXTENSIONS)
            when = t + timedelta(seconds=self.rng.uniform(2, 40))
            out.append((when, "edr", {
                **base, "event_id": self.next_id("edr"), "timestamp": iso(when), "event_type": "file_write",
                "process": {"name": name, "pid": pid, "parent": "explorer.exe"},
                "file": {"path": f"C:\\Users\\{person.id}\\Documents\\file{self.rng.randint(1, 400)}.{ext}", "ext": ext},
            }))
        if self.rng.random() < 0.05:
            when = t + timedelta(seconds=self.rng.uniform(1, 10))
            out.append((when, "edr", {
                **base, "event_id": self.next_id("edr"), "timestamp": iso(when), "event_type": "network_connect",
                "process": {"name": name, "pid": pid, "parent": "explorer.exe"},
                "network": {"dst_ip": self.h.server("SRVFILE01").ip, "dst_port": 445, "protocol": "tcp"},
            }))
        return self.online(out, ws)

    def web_browsing(self, t: datetime) -> list[Record]:
        """A name lookup followed by an outbound connection through the firewall."""
        ws = self.rng.choice(self.h.workstations)
        if ws.id in self.isolated:
            return []
        name = self.browse_domain()
        if self.chance("dns_nxdomain_share"):
            return [self.dns(t, ws.ip, f"{self.rng.choice(['wwww', 'portal2', 'old'])}.{name}", rcode="NXDOMAIN")]
        dst = self.external_ip()
        out = [self.dns(t, ws.ip, f"www.{name}", answer=dst)]
        if self.chance("firewall_deny_share"):
            out.append(self.firewall(t + timedelta(milliseconds=60), ws.ip, dst, self.rng.choice([8080, 8443, 21]), "tcp", ws.zone, "internet", 0, 0, action="deny"))
        else:
            out.append(self.firewall(t + timedelta(milliseconds=60), ws.ip, dst, 443, "tcp", ws.zone, "internet",
                                     self.rng.randint(600, 30000), self.rng.randint(4000, 900000)))
        return out

    def inbound_email(self, t: datetime) -> list[Record]:
        """One message arriving at the mail gateway with its security verdict."""
        person = self.rng.choice(self.h.staff)
        verdicts = self.noise["email_verdicts"]
        verdict = self.rng.choices(list(verdicts), weights=list(verdicts.values()))[0]
        action = {"clean": "delivered", "spam": "quarantined", "phish": "quarantined", "malware": "blocked"}[verdict]
        attachments = []
        if verdict == "malware" or self.rng.random() < 0.18:
            ext = "zip" if verdict == "malware" else self.rng.choice(["pdf", "docx", "xlsx", "png"])
            attachments.append({"name": f"attachment{self.rng.randint(1, 99)}.{ext}", "ext": ext, "size": self.rng.randint(8000, 4000000)})
        return [(t, "email", {
            "message_id": self.next_id("mail"), "received": iso(t),
            "sender": f"{self.rng.choice(['info', 'orders', 'noreply', 'support', 'results'])}@{self.rng.choice(SENDER_DOMAINS)}",
            "recipient": f"{person.id}@{self.mail_domain}",
            "subject_hash": f"{self.rng.getrandbits(64):016x}", "verdict": verdict, "action": action,
            "attachments": attachments, "urls": self.rng.randint(0, 4) + (2 if verdict == "phish" else 0),
            "spf": "pass" if verdict == "clean" else self.rng.choice(["pass", "fail", "softfail"]),
            "dkim": "pass" if verdict == "clean" else self.rng.choice(["pass", "fail"]),
        })]

    def vpn_session(self, t: datetime) -> list[Record]:
        """A remote member of staff connects. The matching session end is queued for later."""
        if not self.h.remote_staff:
            return []
        person = self.rng.choice(self.h.remote_staff)
        client = f"198.51.100.{self.rng.randint(2, 250)}"
        country = self.rng.choice(COUNTRIES_OTHER) if self.chance("vpn_foreign_country_share") else "US"
        base = {"gateway": "VPNGW01", "user": person.id, "client_ip": client, "country": country,
                "device_id": f"LT{sum(map(ord, person.id)) % 9000 + 1000}"}
        if self.chance("vpn_failed_share"):
            return [(t, "vpn", {**base, "id": self.next_id("vpn"), "time": iso(t), "event": "auth_failed"})]
        assigned = f"10.99.0.{self.rng.randint(10, 250)}"
        duration = int(self.rng.uniform(10, 240) * 60)
        end = t + timedelta(seconds=duration)
        self.pending.append((end, "vpn", {
            **base, "id": self.next_id("vpn"), "time": iso(end), "event": "session_end", "assigned_ip": assigned,
            "duration_s": duration, "bytes_out": self.rng.randint(200000, 80000000), "bytes_in": self.rng.randint(1000000, 400000000),
        }))
        return [(t, "vpn", {**base, "id": self.next_id("vpn"), "time": iso(t), "event": "session_start", "assigned_ip": assigned})]

    def linux_server(self, t: datetime) -> list[Record]:
        """Administration and scheduled work on the Linux servers, written as syslog lines."""
        server = self.rng.choice([s for s in self.h.servers if s.os == "Linux"])
        base = {"id": self.next_id("lin"), "ts": iso(t), "host": server.id, "facility": "auth"}
        roll = self.rng.random()
        if roll < 0.45:
            return [(t, "linux", {**base, "facility": "cron", "program": "cron",
                                  "msg": f"(svcbackup) CMD (/opt/{server.role}/healthcheck.sh)"})]
        admin = self.rng.choice(self.h.admins)
        ws = self.workstation_for(admin)
        port = self.rng.randint(49152, 65535)
        if self.chance("ssh_failed_share"):
            return [(t, "linux", {**base, "program": "sshd", "msg": f"Failed password for {admin.id} from {ws.ip} port {port} ssh2"})]
        out: list[Record] = [(t, "linux", {**base, "program": "sshd", "msg": f"Accepted publickey for {admin.id} from {ws.ip} port {port} ssh2"})]
        if roll > 0.75:
            when = t + timedelta(seconds=self.rng.uniform(4, 50))
            out.append((when, "linux", {
                "id": self.next_id("lin"), "ts": iso(when), "host": server.id, "facility": "authpriv", "program": "sudo",
                "msg": f"{admin.id} : TTY=pts/0 ; PWD=/home/{admin.id} ; USER=root ; COMMAND=/usr/bin/systemctl status {server.role}",
            }))
        return out

    def device_telemetry(self, t: datetime) -> list[Record]:
        """A medical device reports to its gateway. Each device talks only to its own gateway."""
        device = self.rng.choice(self.h.devices)
        if device.id in self.isolated:
            return []
        gateway = self.h.server(device.attributes["gateway"])
        imaging = device.role == "imaging_modality"
        packets = self.rng.randint(400, 6000) if imaging else self.rng.randint(6, 40)
        size = self.rng.randint(900, 1400) if imaging else self.rng.randint(90, 220)
        duration = round(self.rng.uniform(2, 30) if imaging else self.rng.uniform(0.2, 3.0), 3)
        return [(t, "medical_device", {
            "flow_id": self.next_id("dev"), "start": round(t.timestamp(), 3), "device": device.id, "device_type": device.role,
            "src_ip": device.ip, "dst_ip": gateway.ip, "dst_port": device.attributes["port"], "protocol": device.attributes["protocol"],
            "packets": packets, "bytes": packets * size, "duration_s": duration, "rate_pps": round(packets / duration, 2),
            "flags": {"syn": 1, "rst": 0},
        })]

    def cloud_activity(self, t: datetime) -> list[Record]:
        """Backups, imaging retrieval and the occasional administrator sign in to the cloud account."""
        roll = self.rng.random()
        base = {"eventID": self.next_id("cld"), "eventTime": iso(t), "awsRegion": "us-east-1", "sourceIPAddress": NAT_ADDRESS}
        if roll < 0.5:
            return [(t, "cloud", {
                **base, "eventSource": "storage", "eventName": "PutObject", "userIdentity": {"userName": "svcbackup"},
                "requestParameters": {"bucketName": "rbgbackups", "key": f"nightly/{t:%Y%m%d}/part{self.rng.randint(1, 400):04d}.bak"},
                "additionalEventData": {"bytesTransferredIn": self.rng.randint(5000000, 90000000)}, "userAgent": "backupagent/3.2",
            })]
        if roll < 0.9:
            person = self.rng.choice(self.h.clinicians)
            name = "GetObject" if roll < 0.8 else "ListBucket"
            return [(t, "cloud", {
                **base, "eventSource": "storage", "eventName": name, "userIdentity": {"userName": person.id},
                "requestParameters": {"bucketName": "rbgimaging", "key": f"studies/{self.rng.getrandbits(40):010x}.dcm" if name == "GetObject" else None},
                "additionalEventData": {"bytesTransferredOut": self.rng.randint(400000, 60000000) if name == "GetObject" else 0},
                "userAgent": "pacsviewer/5.1",
            })]
        admin = self.rng.choice(self.h.admins)
        return [(t, "cloud", {**base, "eventSource": "iam", "eventName": "ConsoleLogin", "userIdentity": {"userName": admin.id}, "userAgent": "browser"})]

    def service_change(self, t: datetime) -> list[Record]:
        """A Windows service starting or stopping on a server."""
        server = self.rng.choice([s for s in self.h.servers if s.os and s.os.startswith("Windows")])
        return [self.windows_event(t, server.id, 7036, {"ServiceName": self.rng.choice(SERVICES), "State": self.rng.choice(["running", "stopped"])}, channel="System")]

    # Ordinary activity that looks unusual. These are the false positives a real network produces.

    def edr(self, t: datetime, host: str, user: str, event_type: str, **parts) -> Record:
        return (t, "edr", {"event_id": self.next_id("edr"), "timestamp": iso(t), "hostname": host, "user": user,
                           "event_type": event_type, "sensor_version": "7.4.1", **parts})

    def software_deployment(self, t: datetime) -> list[Record]:
        """An administrator installs software on a workstation: a burst of file writes from the installer."""
        admin = self.rng.choice(self.h.admins)
        ws = self.rng.choice(self.h.workstations)
        proc = {"name": "msiexec.exe", "pid": self.rng.randint(1000, 30000), "parent": "services.exe"}
        out = [self.edr(t, ws.id, admin.id, "process_start", process={**proc, "cmdline": "msiexec.exe /i \\\\SRVFILE01\\deploy\\clientupdate.msi /qn"})]
        for i in range(self.rng.randint(30, 70)):
            ext = self.rng.choice(["dll", "dll", "exe", "tmp", "xml"])
            out.append(self.edr(t + timedelta(seconds=1 + i * self.rng.uniform(0.3, 0.7)), ws.id, admin.id, "file_write", process=proc,
                                file={"path": f"C:\\Program Files\\ClientUpdate\\component{i}.{ext}", "ext": ext}))
        return self.online(out, ws)

    def archive_job(self, t: datetime) -> list[Record]:
        """A scheduled job on the file server renames documents into an archive folder."""
        server = self.h.server("SRVFILE01")
        proc = {"name": "robocopy.exe", "pid": self.rng.randint(1000, 30000), "parent": "taskeng.exe"}
        out = [self.edr(t, server.id, "svcbackup", "process_start", process={**proc, "cmdline": "robocopy.exe D:\\Shares\\Closed E:\\Archive /MOV"})]
        for i in range(self.rng.randint(20, 45)):
            name = f"case{self.rng.randint(1000, 9999)}.docx"
            out.append(self.edr(t + timedelta(seconds=1 + i * self.rng.uniform(0.6, 1.1)), server.id, "svcbackup", "file_rename", process=proc,
                                file={"path": f"D:\\Shares\\Closed\\{name}", "ext": "docx", "new_path": f"E:\\Archive\\{name}"}))
        return self.online(out, server)

    def account_lockout(self, t: datetime) -> list[Record]:
        """Someone forgets a changed password and keeps trying until they remember it."""
        person = self.rng.choice(self.h.staff)
        ws = self.workstation_for(person)
        out: list[Record] = []
        when = t
        for _ in range(self.rng.randint(8, 12)):
            out.append(self.windows_event(when, ws.id, 4625, {"TargetUserName": person.id, "LogonType": 2, "IpAddress": ws.ip,
                                                              "FailureReason": "Unknown user name or bad password"}))
            when += timedelta(seconds=self.rng.uniform(4, 14))
        out.append(self.windows_event(when, ws.id, 4624, {"TargetUserName": person.id, "LogonType": 2, "IpAddress": ws.ip}))
        return self.online(out, ws)

    def device_firmware_check(self, t: datetime) -> list[Record]:
        """A medical device checks the file server for a firmware update, a peer it rarely talks to."""
        device = self.rng.choice(self.h.devices)
        packets = self.rng.randint(20, 80)
        return self.online([(t, "medical_device", {
            "flow_id": self.next_id("dev"), "start": round(t.timestamp(), 3), "device": device.id, "device_type": device.role,
            "src_ip": device.ip, "dst_ip": self.h.server("SRVFILE01").ip, "dst_port": 443, "protocol": "tcp",
            "packets": packets, "bytes": packets * 600, "duration_s": 2.0, "rate_pps": round(packets / 2.0, 2), "flags": {"syn": 1, "rst": 0},
        })], device)

    def take_due(self, until: datetime) -> list[Record]:
        """Returns queued records, such as session ends, whose time has come."""
        due = [r for r in self.pending if r[0] <= until]
        if due:
            self.pending = [r for r in self.pending if r[0] > until]
        return due
