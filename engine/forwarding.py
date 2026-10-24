"""Forwards incidents to a SIEM or SOC.

Two formats leave the platform for every incident change:

  a JSON webhook, signed with HMAC SHA256 so the receiver can prove where it came from
  a CEF line inside an RFC 5424 syslog frame, for traditional SIEMs

Messages wait in the siem_outbox table, so nothing is lost if a destination is down.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

PRODUCT_VERSION = "0.8"
BAND_SEVERITY = {"high": 9, "medium": 6, "low": 3}
BAND_SYSLOG = {"high": 2, "medium": 4, "low": 6}
FACILITY_LOCAL4 = 20


def cef_header(value) -> str:
    """Escapes a CEF header field: backslash and pipe."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def cef_extension(value) -> str:
    """Escapes a CEF extension value: backslash, equals sign and line breaks."""
    return str(value).replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", "\\n")


def build_message(event_type: str, snapshot: dict, platform: str, audit_head: dict | None) -> dict:
    keep = ["id", "title", "category", "status", "band", "confidence", "severity", "opened_at", "last_activity_at", "primary_host",
            "primary_user", "hosts", "users", "sources", "detectors", "techniques", "alert_count", "decided_by_name", "decided_at", "decision_reason"]
    incident = {k: snapshot.get(k) for k in keep}
    if incident.get("confidence") is not None:
        incident["confidence"] = round(float(incident["confidence"]), 4)
    message = {"version": 1, "event_type": event_type, "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "platform": platform, "incident": incident}
    if snapshot.get("asset"):
        message["asset"] = snapshot["asset"]
    if audit_head:
        # The newest audit entry at the time of sending. A copy held outside the platform
        # makes it possible to notice if the end of the audit log is ever cut off.
        message["audit_head"] = audit_head
    return message


def to_cef(message: dict, vendor: str = "HTM") -> str:
    inc = message["incident"]
    ext = {
        "rt": int(time.time() * 1000), "externalId": inc["id"], "cat": inc.get("category"), "outcome": inc.get("status"),
        "cs1Label": "band", "cs1": inc.get("band"), "cfp1Label": "confidence", "cfp1": inc.get("confidence"),
        "cs2Label": "techniques", "cs2": ",".join(inc.get("techniques") or []), "cs3Label": "sources", "cs3": ",".join(inc.get("sources") or []),
        "cnt": inc.get("alert_count"), "dhost": inc.get("primary_host"), "duser": inc.get("primary_user"),
    }
    if message.get("asset"):
        ext["cs4Label"], ext["cs4"] = "asset", message["asset"].get("id")
    pairs = " ".join(f"{k}={cef_extension(v)}" for k, v in ext.items() if v not in (None, ""))
    header = "|".join(["CEF:0", cef_header(vendor), cef_header(message["platform"]), PRODUCT_VERSION,
                       cef_header(message["event_type"]), cef_header(inc.get("title") or ""), str(BAND_SEVERITY.get(inc.get("band"), 3))])
    return f"{header}|{pairs}"


def syslog_frame(cef: str, band: str | None, hostname: str = "htm", app: str = "htm") -> bytes:
    pri = FACILITY_LOCAL4 * 8 + BAND_SYSLOG.get(band or "", 6)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return f"<{pri}>1 {stamp} {hostname} {app} - - - {cef}".encode("utf-8")


def send_syslog(host: str, port: int, protocol: str, frame: bytes, timeout: float = 5.0) -> None:
    if protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(frame, (host, port))
        return
    with socket.create_connection((host, port), timeout=timeout) as sock:
        # Octet counting, as RFC 6587 describes, so a message may safely contain any character.
        sock.sendall(str(len(frame)).encode() + b" " + frame)


def sign_webhook(key: str, timestamp: str, path: str, body: bytes) -> str:
    canonical = ":".join(["v1", timestamp, "POST", path, hashlib.sha256(body).hexdigest()])
    return hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def send_webhook(url: str, key: str, message: dict, timeout: float = 10.0) -> int:
    body = json.dumps(message, separators=(",", ":"), default=str).encode("utf-8")
    timestamp = str(int(time.time()))
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "content-type": "application/json", "user-agent": "htm-forwarder/0.2",
        "x-htm-timestamp": timestamp, "x-htm-signature": sign_webhook(key, timestamp, urlparse(url).path, body),
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def flush(conn, settings: dict, api_url: str, limit: int = 50) -> int:
    """Sends waiting messages. Returns how many were handled."""
    key = os.environ.get("SIEM_WEBHOOK_KEY", "")
    url = settings.get("siem.webhook_url") or (api_url.rstrip("/") + "/api/siem/receive" if api_url else "")
    syslog_host = settings.get("siem.syslog_host") or ""
    with conn.cursor() as cur:
        cur.execute("select id, incident_id, event_type, snapshot, attempts from siem_outbox where status = 'pending' order by id limit %s", (limit,))
        rows = cur.fetchall()
        if not rows:
            conn.rollback()
            return 0
        cur.execute("select seq, hash from audit_log order by seq desc limit 1")
        head = cur.fetchone()
        for row in rows:
            message = build_message(row["event_type"], row["snapshot"], settings.get("platform.name", "HTM"), head)
            cef = to_cef(message)
            message["cef"] = cef
            errors, webhook_result, syslog_result = [], "not configured", "not configured"
            if url and key:
                try:
                    webhook_result = f"http {send_webhook(url, key, message)}"
                except urllib.error.HTTPError as err:
                    webhook_result = f"http {err.code}"
                    errors.append(f"webhook: http {err.code}")
                except (urllib.error.URLError, OSError) as err:
                    webhook_result = "unreachable"
                    errors.append(f"webhook: {err}")
            elif url:
                webhook_result = "no signing key"
            if syslog_host:
                try:
                    send_syslog(syslog_host, int(settings["siem.syslog_port"]), settings.get("siem.syslog_protocol", "tcp"),
                                syslog_frame(cef, message["incident"].get("band")))
                    syslog_result = "sent"
                except OSError as err:
                    syslog_result = "unreachable"
                    errors.append(f"syslog: {err}")
            attempts = row["attempts"] + 1
            status = "sent" if not errors else ("failed" if attempts >= settings["siem.max_attempts"] else "pending")
            cur.execute("""update siem_outbox set status = %s, attempts = %s, sent_at = case when %s = 'sent' then now() else sent_at end,
                webhook_result = %s, syslog_result = %s, last_error = %s where id = %s""",
                        (status, attempts, status, webhook_result, syslog_result, "; ".join(errors)[:500] or None, row["id"]))
    conn.commit()
    return len(rows)
